package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/vflame6/bruter/logger"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

// VaultChecker is an implementation of CheckerHandler for FTP service
func VaultChecker(target *Target, opts *Options) (bool, bool, error) {
	defaultUsername := "root"
	defaultPassword := "root"

	success := false
	secure := false

	logger.Debugf("trying default credentials on %s:%d", target.IP, target.Port)
	// try with encryption first
	probe, err := ProbeVault(target.IP, target.Port, true, opts.Timeout, defaultUsername, defaultPassword)
	if err == nil {
		secure = true
		if probe {
			RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
			success = true
		}
	} else {
		logger.Debugf("failed to connect to %s:%d with encryption, trying plaintext", target.IP, target.Port)
		// connect via plaintext FTP
		probe, err = ProbeVault(target.IP, target.Port, false, opts.Timeout, defaultUsername, defaultPassword)
		if err == nil {
			if probe {
				RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
				success = true
			}
		} else {
			// if nothing succeeded, return error
			return false, false, err
		}
	}

	return success, secure, nil
}

// VaultHandler is an implementation of CommandHandler for FTP service
func VaultHandler(opts *Options, target *Target, credential *Credential) (bool, bool) {
	probe, err := ProbeVault(target.IP, target.Port, target.Encryption, opts.Timeout, credential.Username, credential.Password)
	if err != nil {
		// not connected
		return false, false
	}

	// connected and authenticated or not
	return true, probe
}

func ProbeVault(ip net.IP, port int, encryption bool, timeout time.Duration, username, password string) (bool, error) {
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

	client := NewHTTPClient(timeout)

	resp, err := client.Post(url, "application/json", reqData)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	bodyString := string(body)

	if resp.StatusCode == 200 && strings.Contains(bodyString, "client_token") {
		return true, nil
	}
	if strings.Contains(bodyString, "invalid username or password") {
		return false, nil
	}
	if strings.Contains(bodyString, "permission denied") {
		logger.Debugf("got permission denied from vault, probably got locked out the user %s", username)
		return false, nil
	}

	logger.Debugf("got unusual response from Vault: %s", bodyString)

	return false, nil
}
