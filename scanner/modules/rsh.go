package modules

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/vflame6/bruter/utils"
)

// RshHandler is an implementation of ModuleHandler for BSD rsh (port 514).
// Host-based trust protocol — a 0x00 response means the client IP is trusted.
func RshHandler(_ context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Protocol: stderr-port\0 client-user\0 server-user\0 command\0
	payload := fmt.Sprintf("0\x00%s\x00%s\x00id\x00",
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
