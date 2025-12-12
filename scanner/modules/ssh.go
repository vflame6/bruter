package modules

import (
	"errors"
	"fmt"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/utils"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	ErrSSHMethodNotAllowed = errors.New("ssh auth method not supported")
)

// SSHChecker is an implementation of CommandChecker for SSH service
func SSHChecker(target net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, defaultUsername, defaultPassword string) (bool, bool, error) {
	success := false
	// SSH is always encrypted, so we always return false for secure here

	check, err := ProbeSSH(target, port, timeout, dialer, defaultUsername, defaultPassword)
	if err != nil {
		if errors.Is(err, ErrSSHMethodNotAllowed) {
			logger.Infof("SSH server %s does not support password authentication", target)
		}

		// not connected
		return false, false, err
	}

	// connected and authenticated/not authenticated
	success = check

	return success, false, nil
}

// SSHHandler is an implementation of CommandHandler for SSH service
func SSHHandler(target net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, bool) {
	success, err := ProbeSSH(target, port, timeout, dialer, username, password)
	if err != nil {
		// not connected
		return false, false
	}

	// connected and authenticated/not authenticated
	return true, success
}

func ProbeSSH(ip net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, error) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	supported := ssh.SupportedAlgorithms()
	insecure := ssh.InsecureAlgorithms()

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout:         timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Config: ssh.Config{
			KeyExchanges: append(supported.KeyExchanges, insecure.KeyExchanges...),
			Ciphers:      append(supported.Ciphers, insecure.Ciphers...),
			MACs:         append(supported.MACs, insecure.MACs...),
		},
		HostKeyAlgorithms: append(supported.HostKeys, insecure.HostKeys...),
	}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		// failed to connect
		return false, err
	}
	defer conn.Close()

	sshConn, _, _, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		if errors.Is(classifySSHError(err), ErrSSHMethodNotAllowed) {
			// unsupported authentication method
			return false, err
		}
		// failed to authenticate
		return false, nil
	}

	// authentication succeeded
	_ = sshConn.Close()
	return true, nil
}

func classifySSHError(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Server explicitly tells us which methods it supports (and password isn't one)
	// Common patterns from various SSH servers:
	// - "No supported authentication methods available (server sent: publickey)"
	// - "Permission denied (publickey)"
	// - "Permission denied (publickey,keyboard-interactive)"
	// - "Permission denied (publickey,gssapi-keyex,gssapi-with-mic)"
	if containsAny(errStr,
		"server sent: publickey",
		"no supported authentication methods available",
		"permission denied (publickey)",
		"permission denied (publickey,",
		"disconnected: no supported authentication") {
		return fmt.Errorf("%w: %v", ErrSSHMethodNotAllowed, err)
	}

	// default
	return err
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
