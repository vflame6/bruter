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

// CiscoHandler is an implementation of ModuleHandler for Cisco IOS Telnet login.
// Uses the shared readUntilPrompt helper from telnet_util.go.
func CiscoHandler(_ context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Wait for first prompt — Cisco may ask Username: or jump straight to Password:.
	initial, err := readUntilPrompt(reader, []string{"Username:", "login:", "Password:"})
	if err != nil {
		return false, err
	}

	lower := strings.ToLower(initial)
	if strings.Contains(lower, "username:") || strings.Contains(lower, "login:") {
		// Send username.
		if _, err = fmt.Fprintf(conn, "%s\r\n", credential.Username); err != nil {
			return false, err
		}
		// Wait for password prompt.
		if _, err = readUntilPrompt(reader, []string{"Password:"}); err != nil {
			return false, err
		}
	}

	// Send password.
	if _, err = fmt.Fprintf(conn, "%s\r\n", credential.Password); err != nil {
		return false, err
	}

	// Read response.
	banner, err := readUntilPrompt(reader, []string{">", "#", "% Login invalid", "% Bad passwords", "Authentication failed"})
	if err != nil {
		return false, err
	}

	b := banner
	if strings.Contains(b, ">") || strings.Contains(b, "#") {
		return true, nil
	}
	return false, nil
}
