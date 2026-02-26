package modules

import (
	"bufio"
	"context"
	"crypto/md5" //nolint:gosec
	"encoding/base64"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// RTSPHandler is an implementation of ModuleHandler for RTSP authentication.
// Tries Basic auth first, then falls back to Digest if the server requires it.
func RTSPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	rtspURL := fmt.Sprintf("rtsp://%s/", addr)
	reader := bufio.NewReader(conn)

	// First attempt: Basic auth
	basicCreds := base64.StdEncoding.EncodeToString(
		[]byte(credential.Username + ":" + credential.Password),
	)
	request := fmt.Sprintf(
		"DESCRIBE %s RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic %s\r\nAccept: application/sdp\r\n\r\n",
		rtspURL, basicCreds,
	)

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
			"DESCRIBE %s RTSP/1.0\r\nCSeq: 2\r\nAuthorization: %s\r\nAccept: application/sdp\r\n\r\n",
			rtspURL, authHeader,
		)
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
	default:
		return false, fmt.Errorf("unexpected RTSP status %d", code)
	}
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

	ha1 := md5hex(username + ":" + realm + ":" + password)
	ha2 := md5hex(method + ":" + uri)
	cnonce := fmt.Sprintf("%08x", rand.Uint32()) //nolint:gosec
	nc := "00000001"

	qop := params["qop"]
	var response string
	if strings.Contains(qop, "auth") {
		response = md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
	} else {
		response = md5hex(ha1 + ":" + nonce + ":" + ha2)
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

func md5hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec
	return fmt.Sprintf("%x", sum)
}
