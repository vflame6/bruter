package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/utils"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

// VaultChecker is an implementation of CommandChecker for HashiCorp Vault service
func VaultChecker(target net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, defaultUsername, defaultPassword string) (bool, bool, error) {
	success := false
	secure := false

	// try with encryption first
	probe, err := ProbeVault(target, port, true, timeout, defaultUsername, defaultPassword, dialer)
	if err == nil {
		secure = true
		if probe {
			success = true
		}
	} else {
		logger.Debugf("(%s:%d) failed to connect to Vault with encryption, trying plaintext", target, port)
		// connect via plaintext FTP
		probe, err = ProbeVault(target, port, false, timeout, defaultUsername, defaultPassword, dialer)
		if err == nil {
			if probe {
				success = true
			}
		} else {
			// if nothing succeeded, return error
			return false, false, err
		}
	}

	return success, secure, nil
}

// VaultHandler is an implementation of CommandHandler for HashiCorp Vault service
func VaultHandler(target net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, bool) {
	probe, err := ProbeVault(target, port, encryption, timeout, username, password, dialer)
	if err != nil {
		// not connected
		return false, false
	}

	// connected and authenticated or not
	return true, probe
}

func ProbeVault(ip net.IP, port int, encryption bool, timeout time.Duration, username, password string, dialer *utils.ProxyAwareDialer) (bool, error) {
	reqJson, err := json.Marshal(map[string]string{
		"password": password,
	})
	if err != nil {
		return false, err
	}
	reqData := bytes.NewBuffer(reqJson)

	var url string
	if encryption {
		url = fmt.Sprintf("https://%s:%d/v1/auth/userpass/login/%s", ip, port, username)
	} else {
		url = fmt.Sprintf("http://%s:%d/v1/auth/userpass/login/%s", ip, port, username)
	}

	client := utils.NewHTTPClient(dialer, timeout)

	resp, err := client.Post(url, "application/json", reqData)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	bodyString := string(body)

	if (resp.StatusCode == 200 && strings.Contains(bodyString, "client_token")) ||
		strings.Contains(bodyString, "auth methods cannot create root tokens") {
		return true, nil
	}
	if strings.Contains(bodyString, "invalid username or password") {
		return false, nil
	}
	if strings.Contains(bodyString, "permission denied") {
		logger.Debugf("(%s:%d) got permission denied from vault, probably got locked out the user %s", ip, port, username)
		return false, nil
	}

	logger.Debugf("(%s:%d) got unusual response from Vault: %s", ip, port, bodyString)

	return false, nil
}
