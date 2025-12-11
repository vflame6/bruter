package scanner

import (
	"crypto/tls"
	"net/http"
	"time"
)

func NewHTTPClient(dialer *ProxyAwareDialer, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10, // Allow older TLS for compatibility
		},
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}
