package modules

import (
	"context"
	"errors"
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

// SSHHandler is an implementation of ModuleHandler for SSH service
func SSHHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	supported := ssh.SupportedAlgorithms()
	insecure := ssh.InsecureAlgorithms()

	config := &ssh.ClientConfig{
		User: credential.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(credential.Password),
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

	// SSH is always encrypted, so we don't check for target.Encryption here
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		// failed to connect
		return false, err
	}

	sshConn, _, _, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		// check for unsupported authentication method
		if errors.Is(classifySSHError(err), ErrSSHMethodNotAllowed) {
			logger.Infof("SSH server %s:%d does not support password authentication", target.IP, target.Port)
			return false, err
		}
		// failed to authenticate
		return false, nil
	}

	// authentication succeeded
	_ = sshConn.Close()
	_ = conn.Close()
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
	if utils.ContainsAny(errStr,
		"server sent: publickey",
		"no supported authentication methods available",
		"permission denied (publickey)",
		"permission denied (publickey,",
		"disconnected: no supported authentication") {
		return ErrSSHMethodNotAllowed
	}

	// default
	return err
}
