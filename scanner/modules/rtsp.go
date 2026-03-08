package modules

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// rtspPaths lists common RTSP stream paths to try.
// Many servers reject DESCRIBE on "/" with 400; real streams live under these paths.
var rtspPaths = []string{"/", "/stream", "/live", "/cam", "/Streaming/Channels/101", "/h264Preview_01_main", "/1"}

// RTSPHandler is an implementation of ModuleHandler for RTSP authentication.
// Tries common stream paths until one responds with 200 or 401 (auth challenge).
// For each viable path, tries Basic auth first, then falls back to Digest.
func RTSPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	cseq := 1

	for _, path := range rtspPaths {
		rtspURL := fmt.Sprintf("rtsp://%s%s", addr, path)

		// Try Basic auth
		basicCreds := base64.StdEncoding.EncodeToString(
			[]byte(credential.Username + ":" + credential.Password),
		)
		request := fmt.Sprintf(
			"DESCRIBE %s RTSP/1.0\r\nCSeq: %d\r\nAuthorization: Basic %s\r\nAccept: application/sdp\r\n\r\n",
			rtspURL, cseq, basicCreds,
		)
		cseq++

		if _, err = fmt.Fprint(conn, request); err != nil {
			return false, err
		}

		code, headers, err := readRTSPResponse(reader)
		if err != nil {
			return false, err
		}

		switch code {
		case 200:
			return true, nil
		case 401:
			// Check for Digest challenge in WWW-Authenticate header
			wwwAuth := headers["www-authenticate"]
			if !strings.HasPrefix(strings.ToLower(wwwAuth), "digest") {
				return false, nil // Basic rejected, no Digest offered
			}
			// Try Digest auth
			authHeader, err := buildDigestAuth(wwwAuth, credential.Username, credential.Password, "DESCRIBE", rtspURL)
			if err != nil {
				return false, nil // Can't parse challenge — treat as auth failure
			}
			digestReq := fmt.Sprintf(
				"DESCRIBE %s RTSP/1.0\r\nCSeq: %d\r\nAuthorization: %s\r\nAccept: application/sdp\r\n\r\n",
				rtspURL, cseq, authHeader,
			)
			cseq++
			if _, err = fmt.Fprint(conn, digestReq); err != nil {
				return false, err
			}
			code2, _, err := readRTSPResponse(reader)
			if err != nil {
				return false, err
			}
			switch code2 {
			case 200:
				return true, nil
			case 401, 403:
				return false, nil
			default:
				return false, fmt.Errorf("unexpected RTSP status %d", code2)
			}
		case 403:
			return false, nil
		case 400, 404, 451, 453:
			// Path not found or not supported — try next path
			continue
		default:
			return false, fmt.Errorf("unexpected RTSP status %d", code)
		}
	}

	// All paths returned 400/404 — server doesn't expose any known stream path
	return false, fmt.Errorf("no valid RTSP stream path found on %s", addr)
}

// readRTSPResponse reads an RTSP response status line and headers.
func readRTSPResponse(reader *bufio.Reader) (int, map[string]string, error) {
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, nil, err
	}
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		return 0, nil, fmt.Errorf("invalid RTSP response: %q", statusLine)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, nil, fmt.Errorf("non-numeric status %q: %w", fields[1], err)
	}

	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			headers[key] = val
		}
	}
	return code, headers, nil
}

// buildDigestAuth constructs a Digest Authorization header from a WWW-Authenticate challenge.
func buildDigestAuth(challenge, username, password, method, uri string) (string, error) {
	params := parseDigestChallenge(challenge)
	realm := params["realm"]
	nonce := params["nonce"]
	if realm == "" || nonce == "" {
		return "", fmt.Errorf("missing realm or nonce")
	}

	ha1 := utils.MD5Hex(username + ":" + realm + ":" + password)
	ha2 := utils.MD5Hex(method + ":" + uri)
	cnonce := fmt.Sprintf("%08x", rand.Uint32()) //nolint:gosec
	nc := "00000001"

	qop := params["qop"]
	var response string
	if strings.Contains(qop, "auth") {
		response = utils.MD5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
	} else {
		response = utils.MD5Hex(ha1 + ":" + nonce + ":" + ha2)
	}

	header := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, realm, nonce, uri, response)
	if strings.Contains(qop, "auth") {
		header += fmt.Sprintf(`, qop=auth, nc=%s, cnonce="%s"`, nc, cnonce)
	}
	if opaque := params["opaque"]; opaque != "" {
		header += fmt.Sprintf(`, opaque="%s"`, opaque)
	}
	return header, nil
}

// parseDigestChallenge extracts key=value pairs from a Digest WWW-Authenticate header.
func parseDigestChallenge(header string) map[string]string {
	result := make(map[string]string)
	// Strip "Digest " prefix (case-insensitive)
	if idx := strings.IndexByte(header, ' '); idx >= 0 {
		header = header[idx+1:]
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if eq := strings.IndexByte(part, '='); eq > 0 {
			key := strings.ToLower(strings.TrimSpace(part[:eq]))
			val := strings.TrimSpace(part[eq+1:])
			val = strings.Trim(val, `"`)
			result[key] = val
		}
	}
	return result
}


