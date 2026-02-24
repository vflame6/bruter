package modules

import (
	"context"
	"crypto/tls"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// SMTPHandler is an implementation of ModuleHandler for SMTP AUTH service.
// Supports plain TCP (STARTTLS opportunistic) and direct TLS (port 465).
func SMTPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))
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

	// Try PLAIN auth first, fall back to LOGIN
	var authErr error
	if ok, _ := client.Extension("AUTH"); ok {
		auth := smtp.PlainAuth("", credential.Username, credential.Password, host)
		authErr = client.Auth(auth)
	} else {
		// No AUTH extension advertised — attempt anyway (some servers omit the EHLO line)
		auth := smtp.PlainAuth("", credential.Username, credential.Password, host)
		authErr = client.Auth(auth)
	}

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
