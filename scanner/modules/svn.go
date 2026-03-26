package modules

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/vflame6/bruter/utils"
)

// SVNHandler is an implementation of ModuleHandler for Subversion over HTTP/WebDAV.
// Tests HTTP Basic authentication against an SVN server using the OPTIONS method.
// Supports plain HTTP and HTTPS.
func SVNHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	hostPort := target.Addr()

	scheme := "http"
	if target.Encryption {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s/", scheme, hostPort)

	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, url, nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(credential.Username, credential.Password)
	req.Header.Set("User-Agent", "SVN/1.14.0")

	// Set Host header for domain-based targets.
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
		resp.Body.Close()
	}()

	// 200, 204, 207 (Multi-Status) = authenticated.
	// 401 = wrong creds. Anything else = connection issue.
	switch resp.StatusCode {
	case 200, 204, 207:
		return true, nil
	case 401, 403:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}
}
