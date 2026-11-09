package modules

import (
	"context"
	"fmt"
	"time"

	"github.com/vflame6/bruter/utils"
)

// SOCKS5Handler is an implementation of ModuleHandler for SOCKS5 username/password
// sub-negotiation (RFC 1928 + RFC 1929).
func SOCKS5Handler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Step 1 — Method selection: propose Username/Password (0x02).
	if _, err = conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return false, err
	}

	resp := make([]byte, 2)
	if _, err = utils.ReadFull(conn, resp); err != nil {
		return false, err
	}
	switch resp[1] {
	case 0xFF:
		return false, nil // no acceptable method
	case 0x02:
		// continue to sub-negotiation
	default:
		return false, fmt.Errorf("server chose unexpected method 0x%02x", resp[1])
	}

	// Step 2 — Username/password sub-negotiation (RFC 1929).
	user := []byte(credential.Username)
	pass := []byte(credential.Password)

	payload := make([]byte, 0, 3+len(user)+len(pass))
	payload = append(payload, 0x01)            // VER
	payload = append(payload, byte(len(user))) //nolint:gosec // length fits in byte; username length validated implicitly
	payload = append(payload, user...)
	payload = append(payload, byte(len(pass))) //nolint:gosec
	payload = append(payload, pass...)

	if _, err = conn.Write(payload); err != nil {
		return false, err
	}

	authResp := make([]byte, 2)
	if _, err = utils.ReadFull(conn, authResp); err != nil {
		return false, err
	}

	if authResp[1] == 0x00 {
		return true, nil // auth success
	}
	return false, nil // auth failure
}

// SOCKS5NoAuthHandler checks if a SOCKS5 proxy allows connections without authentication.
func SOCKS5NoAuthHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Propose "no authentication" method (0x00)
	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false, err
	}

	resp := make([]byte, 2)
	if _, err = utils.ReadFull(conn, resp); err != nil {
		return false, err
	}

	// Server accepted no-authentication method
	if resp[0] == 0x05 && resp[1] == 0x00 {
		return true, nil
	}

	return false, nil
}
