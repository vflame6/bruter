package modules

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// HTTPProxyHandler is an implementation of ModuleHandler for HTTP proxy authentication.
// Sends a CONNECT request and checks for Proxy-Authenticate / 407 responses,
// then retries with Basic auth credentials.
func HTTPProxyHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Build Basic auth header.
	auth := base64.StdEncoding.EncodeToString(
		[]byte(fmt.Sprintf("%s:%s", credential.Username, credential.Password)),
	)

	// Send a GET request through the proxy with Proxy-Authorization.
	request := fmt.Sprintf(
		"GET http://www.example.com/ HTTP/1.0\r\n"+
			"Host: www.example.com\r\n"+
			"Proxy-Authorization: Basic %s\r\n"+
			"User-Agent: %s\r\n"+
			"\r\n",
		auth, dialer.UserAgent,
	)

	if _, err = conn.Write([]byte(request)); err != nil {
		return false, err
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	// Parse HTTP status code.
	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 2 {
		return false, fmt.Errorf("malformed HTTP response: %q", statusLine)
	}

	switch parts[1] {
	case "407":
		// Proxy authentication required — wrong credentials.
		return false, nil
	case "200", "301", "302", "303", "307", "308":
		// Proxy accepted our credentials and forwarded the request.
		return true, nil
	case "403":
		// Forbidden — valid creds but access denied, still counts as auth success.
		return true, nil
	default:
		// Other codes (502, 503, etc.) — treat as connection issue.
		return false, fmt.Errorf("unexpected proxy response: %s", parts[1])
	}
}
