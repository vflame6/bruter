package modules

import (
	"bufio"
	"context"
	"crypto/md5"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// SIPHandler is an implementation of ModuleHandler for SIP Digest authentication.
// Sends a REGISTER request, parses WWW-Authenticate, responds with Digest auth.
// Uses UDP by default; TCP fallback when the dialer supports it.
func SIPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	// SIP typically uses UDP, but we use TCP for reliable brute-forcing.
	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	callID := fmt.Sprintf("%d", rand.Int63())
	host := target.IP.String()

	// Send initial REGISTER (no auth).
	register := fmt.Sprintf(
		"REGISTER sip:%s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP %s\r\n"+
			"From: <sip:%s@%s>\r\n"+
			"To: <sip:%s@%s>\r\n"+
			"Call-ID: %s@%s\r\n"+
			"CSeq: 1 REGISTER\r\n"+
			"Content-Length: 0\r\n\r\n",
		host, host,
		credential.Username, host,
		credential.Username, host,
		callID, host,
	)

	if _, err = conn.Write([]byte(register)); err != nil {
		return false, err
	}

	// Read response — look for 401 with WWW-Authenticate.
	var realm, nonce string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "SIP/2.0 200") {
			// No auth required — still counts as valid.
			return true, nil
		}
		if strings.HasPrefix(line, "SIP/2.0 403") || strings.HasPrefix(line, "SIP/2.0 404") {
			return false, nil
		}

		if strings.HasPrefix(strings.ToLower(line), "www-authenticate:") {
			realm = extractField(line, "realm")
			nonce = extractField(line, "nonce")
		}

		// End of SIP message headers.
		if line == "" {
			break
		}
	}

	if nonce == "" {
		return false, fmt.Errorf("no WWW-Authenticate challenge received")
	}

	// Compute Digest response.
	uri := fmt.Sprintf("sip:%s", host)
	ha1 := md5hex(fmt.Sprintf("%s:%s:%s", credential.Username, realm, credential.Password))
	ha2 := md5hex(fmt.Sprintf("REGISTER:%s", uri))
	response := md5hex(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))

	// Send authenticated REGISTER.
	authRegister := fmt.Sprintf(
		"REGISTER sip:%s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP %s\r\n"+
			"From: <sip:%s@%s>\r\n"+
			"To: <sip:%s@%s>\r\n"+
			"Call-ID: %s@%s\r\n"+
			"CSeq: 2 REGISTER\r\n"+
			"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n"+
			"Content-Length: 0\r\n\r\n",
		host, host,
		credential.Username, host,
		credential.Username, host,
		callID, host,
		credential.Username, realm, nonce, uri, response,
	)

	if _, err = conn.Write([]byte(authRegister)); err != nil {
		return false, err
	}

	// Read final response.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "SIP/2.0 200") {
			return true, nil
		}
		if strings.HasPrefix(line, "SIP/2.0 401") || strings.HasPrefix(line, "SIP/2.0 403") {
			return false, nil
		}
		if line == "" {
			break
		}
	}

	return false, nil
}

// extractField extracts a quoted value from a SIP header like: realm="asterisk", nonce="abc123"
func extractField(header, field string) string {
	lower := strings.ToLower(header)
	idx := strings.Index(lower, field+"=")
	if idx == -1 {
		return ""
	}
	rest := header[idx+len(field)+1:]
	rest = strings.TrimPrefix(rest, "\"")
	end := strings.Index(rest, "\"")
	if end == -1 {
		end = strings.IndexAny(rest, ",\r\n ")
		if end == -1 {
			return rest
		}
	}
	return rest[:end]
}

// md5hex returns the hex-encoded MD5 hash of a string.
func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", h)
}
