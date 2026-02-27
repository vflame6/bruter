package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// smtpLoginAuth implements the SMTP LOGIN authentication mechanism.
// Many Exchange/legacy servers only support LOGIN, not PLAIN.
type smtpLoginAuth struct {
	username, password string
}

func (a *smtpLoginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a *smtpLoginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	prompt := strings.ToLower(strings.TrimSpace(string(fromServer)))
	switch {
	case strings.Contains(prompt, "username"):
		return []byte(a.username), nil
	case strings.Contains(prompt, "password"):
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("unexpected LOGIN prompt: %q", fromServer)
	}
}

// SMTPHandler is an implementation of ModuleHandler for SMTP AUTH service.
// Supports plain TCP (STARTTLS opportunistic) and direct TLS (port 465).
func SMTPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()
	host := target.IP.String()

	var conn net.Conn
	var err error

	if target.Encryption {
		// Direct TLS (implicit TLS, e.g. port 465)
		tlsCfg := utils.GetTLSConfig()
		conn, err = dialer.DialTLSContext(ctx, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return false, err
	}

	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return false, err
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return false, err
	}
	defer func() { _ = client.Quit() }()

	// Attempt STARTTLS if not already TLS and server advertises it
	if !target.Encryption {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
				ServerName:         host,
			}
			_ = client.StartTLS(tlsCfg) // best-effort; don't fail if unavailable
		}
	}

	// Try PLAIN auth first, fall back to LOGIN if PLAIN fails or isn't supported
	plainAuth := smtp.PlainAuth("", credential.Username, credential.Password, host)
	authErr := client.Auth(plainAuth)

	if authErr == nil {
		return true, nil
	}

	// Check if PLAIN was rejected with a mechanism error — try LOGIN as fallback
	plainMsg := strings.ToLower(authErr.Error())
	plainIsAuthFailure := strings.Contains(plainMsg, "535") ||
		strings.Contains(plainMsg, "534") ||
		strings.Contains(plainMsg, "authentication") ||
		strings.Contains(plainMsg, "credentials") ||
		strings.Contains(plainMsg, "invalid") ||
		strings.Contains(plainMsg, "denied")

	if plainIsAuthFailure {
		// Definitive auth rejection on PLAIN — creds are wrong, no point trying LOGIN
		return false, nil
	}

	// PLAIN failed for non-auth reason (unsupported mechanism, etc.) — try LOGIN
	// Need a fresh connection since the SMTP state may be broken after failed AUTH
	if target.Encryption {
		tlsCfg := utils.GetTLSConfig()
		conn, err = dialer.DialTLSContext(ctx, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return false, err
	}
	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return false, err
	}
	client2, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return false, err
	}
	defer func() { _ = client2.Quit() }()

	if !target.Encryption {
		if ok, _ := client2.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
				ServerName:         host,
			}
			_ = client2.StartTLS(tlsCfg)
		}
	}

	loginAuth := &smtpLoginAuth{username: credential.Username, password: credential.Password}
	authErr = client2.Auth(loginAuth)
	if authErr == nil {
		return true, nil
	}

	msg := strings.ToLower(authErr.Error())
	if strings.Contains(msg, "535") ||
		strings.Contains(msg, "534") ||
		strings.Contains(msg, "authentication") ||
		strings.Contains(msg, "credentials") ||
		strings.Contains(msg, "invalid") ||
		strings.Contains(msg, "denied") {
		return false, nil
	}

	return false, authErr
}
