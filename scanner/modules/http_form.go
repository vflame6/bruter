package modules

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// HTTPFormHandler is an implementation of ModuleHandler for HTTP form-based authentication.
// Uses POST to submit login forms. Requires target Extra fields to configure:
//   - "form_path":    URL path to POST to (e.g. "/login")
//   - "form_user":    form field name for username (e.g. "username")
//   - "form_pass":    form field name for password (e.g. "password")
//   - "form_fail":    string in response body indicating failure (e.g. "Invalid password")
//   - "form_success": string in response body indicating success (optional, alternative to form_fail)
//   - "form_extra":   additional POST parameters (e.g. "csrf_token=abc&submit=Login")
//
// Usage example:
//
//	bruter http-form -t target:80 -u admin -p passwords.txt \
//	  --form-path "/login" --form-user "username" --form-pass "password" \
//	  --form-fail "Invalid credentials"
func HTTPFormHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	hostPort := target.Addr()

	scheme := "http"
	if target.Encryption {
		scheme = "https"
	}

	// Get form configuration from target Extra.
	formPath, _ := target.GetExtra("form_path")
	formUser, _ := target.GetExtra("form_user")
	formPass, _ := target.GetExtra("form_pass")
	formFail, _ := target.GetExtra("form_fail")
	formSuccess, _ := target.GetExtra("form_success")
	formExtra, _ := target.GetExtra("form_extra")

	if formPath == "" {
		formPath = "/login"
	}
	if formUser == "" {
		formUser = "username"
	}
	if formPass == "" {
		formPass = "password"
	}

	targetURL := fmt.Sprintf("%s://%s%s", scheme, hostPort, formPath)

	// Build form data.
	formData := url.Values{}
	formData.Set(formUser, credential.Username)
	formData.Set(formPass, credential.Password)

	// Add extra parameters.
	if formExtra != "" {
		extraParams, err := url.ParseQuery(formExtra)
		if err == nil {
			for k, vals := range extraParams {
				for _, v := range vals {
					formData.Set(k, v)
				}
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

	// Read response body.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, err
	}
	body := string(bodyBytes)

	// Check success condition.
	if formSuccess != "" {
		if strings.Contains(body, formSuccess) {
			return true, nil
		}
		return false, nil
	}

	// Check failure condition.
	if formFail != "" {
		if strings.Contains(body, formFail) {
			return false, nil
		}
		return true, nil
	}

	// Fallback: 302 redirect often means successful login.
	if resp.StatusCode == 302 || resp.StatusCode == 301 || resp.StatusCode == 303 {
		return true, nil
	}
	if resp.StatusCode == 200 {
		// No fail/success string provided and 200 returned — ambiguous.
		return false, fmt.Errorf("cannot determine auth result without --form-fail or --form-success")
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false, nil
	}

	return false, nil
}
