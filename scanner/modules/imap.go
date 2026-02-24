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

// IMAPHandler is an implementation of ModuleHandler for IMAP LOGIN auth (RFC 3501).
// Supports plain TCP (port 143) and TLS (port 993).
func IMAPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
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

	// Read greeting — expect "* OK"
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(greeting, "* OK") {
		return false, fmt.Errorf("unexpected IMAP greeting: %q", greeting)
	}

	// Send LOGIN command
	tag := "a001"
	cmd := fmt.Sprintf("%s LOGIN \"%s\" \"%s\"\r\n", tag, credential.Username, credential.Password)
	if _, err = fmt.Fprint(conn, cmd); err != nil {
		return false, err
	}

	// Read responses until we see our tagged response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		if strings.HasPrefix(line, tag+" OK") {
			return true, nil
		}
		if strings.HasPrefix(line, tag+" NO") || strings.HasPrefix(line, tag+" BAD") {
			return false, nil
		}
		// Untagged lines (e.g. "* CAPABILITY") — keep reading
	}
}
