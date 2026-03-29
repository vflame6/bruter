package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// VMAuthdHandler is an implementation of ModuleHandler for VMware vmauthd (port 902).
// Protocol: connect → read banner → TLS upgrade if required → USER/PASS authentication.
func VMAuthdHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Read initial banner.
	banner, err := readLine(conn)
	if err != nil {
		return false, err
	}

	// Upgrade to TLS if the server requires it.
	var activeConn = conn
	if strings.Contains(banner, "SSL Required") {
		tlsConn := tls.Client(conn, utils.GetTLSConfig())
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return false, err
		}
		activeConn = tlsConn
		_ = activeConn.SetDeadline(time.Now().Add(timeout))
	}

	// Send USER command.
	if _, err := fmt.Fprintf(activeConn, "USER %s\r\n", credential.Username); err != nil {
		return false, err
	}

	resp, err := readLine(activeConn)
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(resp, "331 ") {
		return false, nil
	}

	// Send PASS command.
	if _, err := fmt.Fprintf(activeConn, "PASS %s\r\n", credential.Password); err != nil {
		return false, err
	}

	resp, err = readLine(activeConn)
	if err != nil {
		return false, err
	}

	if strings.HasPrefix(resp, "230 ") {
		return true, nil
	}
	return false, nil
}

// readLine reads from conn until \n, returning the trimmed string.
func readLine(conn net.Conn) (string, error) {
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}
