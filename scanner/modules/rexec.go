package modules

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/vflame6/bruter/utils"
)

// RexecHandler is an implementation of ModuleHandler for BSD rexec (port 512).
// Sends null + username\0 + password\0 + command\0, reads one byte: 0x00=ok, 0x01=fail.
func RexecHandler(_ context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Protocol: \x00 stderr-port\0 user\0 password\0 command\0
	payload := fmt.Sprintf("\x00\x00%s\x00%s\x00id\x00",
		credential.Username,
		credential.Password,
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
