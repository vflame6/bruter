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

// TelnetHandler is an implementation of ModuleHandler for Telnet login authentication.
// Handles IAC negotiation bytes and standard Unix login prompts.
func TelnetHandler(_ context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	var (
		conn net.Conn
		err  error
	)
	if target.Encryption {
		conn, err = dialer.DialTLS("tcp", addr, utils.GetTLSConfig())
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Wait for login prompt.
	if _, err = readUntilPrompt(reader, []string{"login:", "username:", "user:"}); err != nil {
		return false, err
	}

	// Send username.
	if _, err = fmt.Fprintf(conn, "%s\r\n", credential.Username); err != nil {
		return false, err
	}

	// Wait for password prompt.
	if _, err = readUntilPrompt(reader, []string{"password:", "passwd:"}); err != nil {
		return false, err
	}

	// Send password.
	if _, err = fmt.Fprintf(conn, "%s\r\n", credential.Password); err != nil {
		return false, err
	}

	// Read response until shell prompt or failure indicator.
	banner, err := readUntilPrompt(reader, []string{"$", "#", ">", "incorrect", "failed", "denied"})
	if err != nil {
		return false, err
	}

	lower := strings.ToLower(banner)
	if strings.Contains(lower, "$") || strings.Contains(lower, "#") || strings.Contains(lower, ">") {
		return true, nil
	}
	return false, nil
}
