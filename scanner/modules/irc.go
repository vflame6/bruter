package modules

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// IRCHandler is an implementation of ModuleHandler for IRC server password authentication.
// Sends PASS/NICK/USER and waits for 001 (welcome) or 464 (password mismatch).
func IRCHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send registration sequence.
	_, err = fmt.Fprintf(conn, "PASS %s\r\nNICK %s\r\nUSER %s 0 * :%s\r\n",
		credential.Password,
		credential.Username,
		credential.Username,
		credential.Username,
	)
	if err != nil {
		return false, err
	}

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		switch {
		case strings.Contains(line, " 001 "):
			return true, nil // RPL_WELCOME — authenticated
		case strings.Contains(line, " 464 "):
			return false, nil // ERR_PASSWDMISMATCH
		case strings.Contains(line, " 433 "):
			// ERR_NICKNAMEINUSE — auth not yet checked; keep reading
		case strings.HasPrefix(line, "PING "):
			// Server requires PONG during registration (e.g. InspIRCd).
			token := strings.TrimSpace(strings.TrimPrefix(line, "PING "))
			_, _ = fmt.Fprintf(conn, "PONG %s\r\n", token)
		}
	}
}
