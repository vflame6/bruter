package modules

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// TelnetHandler is an implementation of ModuleHandler for Telnet login authentication.
// Handles IAC negotiation bytes and standard Unix login prompts.
func TelnetHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
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

// TelnetNoPasswordHandler checks if a telnet service drops directly to a shell
// without requiring login or password prompts.
func TelnetNoPasswordHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	banner, err := readUntilPrompt(reader, []string{"$", "#", ">", "login:", "username:", "password:"})
	if err != nil {
		return false, err
	}

	lower := strings.ToLower(banner)
	loginRequired := strings.Contains(lower, "login:") || strings.Contains(lower, "username:") || strings.Contains(lower, "password:")
	hasShell := strings.Contains(lower, "$") || strings.Contains(lower, "#") || strings.Contains(lower, ">")

	if hasShell && !loginRequired {
		return true, nil
	}

	return false, nil
}
