package modules

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// POP3Handler is an implementation of ModuleHandler for POP3 USER/PASS auth (RFC 1939).
// Supports plain TCP (port 110) and TLS (port 995).
func POP3Handler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	var conn net.Conn
	var err error

	if target.Encryption {
		conn, err = dialer.DialTLSContext(ctx, "tcp", addr, utils.GetTLSConfig())
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, err
	}

	reader := bufio.NewReader(conn)

	// Read greeting — expect "+OK"
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return false, fmt.Errorf("unexpected POP3 greeting: %q", greeting)
	}

	// Send USER
	if _, err = fmt.Fprintf(conn, "USER %s\r\n", credential.Username); err != nil {
		return false, err
	}
	userResp, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(userResp, "+OK") {
		// USER rejected — treat as auth error
		return false, nil
	}

	// Send PASS
	if _, err = fmt.Fprintf(conn, "PASS %s\r\n", credential.Password); err != nil {
		return false, err
	}
	passResp, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	if strings.HasPrefix(passResp, "+OK") {
		return true, nil
	}
	// -ERR = wrong password or locked
	return false, nil
}
