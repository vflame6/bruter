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

// HTTPBasicHandler is an implementation of ModuleHandler for HTTP Basic Authentication.
// Supports plain HTTP (port 80) and HTTPS (port 443).
func HTTPBasicHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	scheme := "http"
	if target.Encryption {
		scheme = "https"
	}

	hostPort := target.Addr()
	url := fmt.Sprintf("%s://%s/", scheme, hostPort)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(credential.Username, credential.Password)

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
	case http.StatusOK, http.StatusFound:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
}

// HTTPBasicNoAuthHandler checks if a web endpoint is accessible without authentication.
func HTTPBasicNoAuthHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	scheme := "http"
	if target.Encryption {
		scheme = "https"
	}

	hostPort := target.Addr()
	url := fmt.Sprintf("%s://%s/", scheme, hostPort)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

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
	case http.StatusOK, http.StatusFound:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, nil
	}
}
