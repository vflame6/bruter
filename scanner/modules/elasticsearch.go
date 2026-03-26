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

// ElasticsearchHandler is an implementation of ModuleHandler for Elasticsearch.
// Tests HTTP Basic authentication against the /_cluster/health endpoint.
func ElasticsearchHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	hostPort := target.Addr()

	scheme := "http"
	if target.Encryption {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s/_cluster/health", scheme, hostPort)

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
		// Read a bit of the body to confirm it's a real Elasticsearch response.
		body := make([]byte, 512)
		n, _ := resp.Body.Read(body)
		if strings.Contains(string(body[:n]), "cluster_name") {
			return true, nil
		}
		return true, nil
	case 401, 403:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}
}
