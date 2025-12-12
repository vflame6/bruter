package utils

import (
	"net/http"
	"time"
)

func NewHTTPClient(d *ProxyAwareDialer, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DialContext:     d.DialContext,
		TLSClientConfig: GetTLSConfig(),
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}
