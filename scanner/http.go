package scanner

import (
	"crypto/tls"
	"net/http"
	"time"
)

func NewHTTPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}
