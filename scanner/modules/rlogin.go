package modules

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/vflame6/bruter/utils"
)

// RloginHandler is an implementation of ModuleHandler for BSD rlogin (port 513).
// Sends null + client_user\0 + server_user\0 + terminal_type/speed\0.
// A 0x00 response byte = session accepted (host-based trust, no password).
func RloginHandler(_ context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	payload := fmt.Sprintf("\x00%s\x00%s\x00vt100/9600\x00",
		credential.Username,
		credential.Username,
	)
	if _, err = conn.Write([]byte(payload)); err != nil {
		return false, err
	}

	resp := make([]byte, 1)
	if _, err = readFull(conn, resp); err != nil {
		return false, err
	}
	if resp[0] == 0x00 {
		return true, nil
	}
	return false, nil
}
