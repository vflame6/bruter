package modules

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// winrmIdentifyBody is a minimal WS-Man Identify request.
// It triggers authentication without executing any command.
const winrmIdentifyBody = `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body>
    <wsmid:Identify/>
  </s:Body>
</s:Envelope>`

// WinRMHandler is an implementation of ModuleHandler for Windows Remote Management (WinRM).
// Default ports: 5985 (HTTP), 5986 (HTTPS).
// Uses HTTP Basic authentication against the /wsman endpoint.
func WinRMHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	scheme := "http"
	if target.Encryption {
		scheme = "https"
	}

	hostPort := target.Addr()
	url := fmt.Sprintf("%s://%s/wsman", scheme, hostPort)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(winrmIdentifyBody))
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(credential.Username, credential.Password)
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")

	// Set Host header when OriginalTarget is a domain (not bare IP)
	if net.ParseIP(target.OriginalTarget) == nil {
		host := target.OriginalTarget
		if h, _, err2 := net.SplitHostPort(target.OriginalTarget); err2 == nil {
			host = h
		}
		req.Host = host
	}

	resp, err := dialer.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
}
