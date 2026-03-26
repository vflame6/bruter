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

// CouchDBHandler is an implementation of ModuleHandler for Apache CouchDB.
// Tests HTTP Basic authentication against the /_session endpoint.
func CouchDBHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	hostPort := target.Addr()

	scheme := "http"
	if target.Encryption {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s/_session", scheme, hostPort)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(credential.Username, credential.Password)
	req.Header.Set("User-Agent", "bruter")

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

	switch resp.StatusCode {
	case 200:
		return true, nil
	case 401, 403:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}
}
