package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// VaultHandler is an implementation of ModuleHandler for HashiCorp Vault service
func VaultHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	reqJson, err := json.Marshal(map[string]string{
		"password": credential.Password,
	})
	if err != nil {
		return false, err
	}
	reqData := bytes.NewBuffer(reqJson)

	hostPort := target.Addr()
	var url string
	if target.Encryption {
		url = fmt.Sprintf("https://%s/v1/auth/userpass/login/%s", hostPort, credential.Username)
	} else {
		url = fmt.Sprintf("http://%s/v1/auth/userpass/login/%s", hostPort, credential.Username)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reqData)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Set Host header when the original input was a domain (not an IP).
	// This ensures virtual-hosted services receive the correct Host.
	if net.ParseIP(target.OriginalTarget) == nil {
		host := target.OriginalTarget
		if h, _, err2 := net.SplitHostPort(target.OriginalTarget); err2 == nil {
			host = h
		}
		req.Host = host
	}

	resp, err := dialer.HTTPClient.Do(req)
	if err != nil {
		// connection error
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	bodyString := string(body)

	// successful authentication
	if (resp.StatusCode == 200 && strings.Contains(bodyString, "client_token")) ||
		strings.Contains(bodyString, "auth methods cannot create root tokens") {
		return true, nil
	}
	// authentication error
	if strings.Contains(bodyString, "invalid username or password") ||
		strings.Contains(bodyString, "permission denied") {
		return false, nil
	}

	// any other response
	return false, errors.New(fmt.Sprintf("invalid server response, maybe the target is not a vault server: %v", err))
}
