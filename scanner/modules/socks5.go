package modules

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/vflame6/bruter/utils"
)

// SOCKS5Handler is an implementation of ModuleHandler for SOCKS5 username/password
// sub-negotiation (RFC 1928 + RFC 1929).
func SOCKS5Handler(_ context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	conn, err := dialer.Dial("tcp", addr)
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
	if _, err = readFull(conn, resp); err != nil {
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
	if _, err = readFull(conn, authResp); err != nil {
		return false, err
	}

	if authResp[1] == 0x00 {
		return true, nil // auth success
	}
	return false, nil // auth failure
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
