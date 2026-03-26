package modules

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// NNTPHandler is an implementation of ModuleHandler for NNTP AUTHINFO auth (RFC 4643).
// Supports plain TCP (port 119) and TLS (port 563).
func NNTPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read greeting — expect "200" (posting allowed) or "201" (no posting).
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(greeting, "200") && !strings.HasPrefix(greeting, "201") {
		return false, fmt.Errorf("unexpected NNTP greeting: %q", strings.TrimSpace(greeting))
	}

	// Send AUTHINFO USER.
	if _, err = fmt.Fprintf(conn, "AUTHINFO USER %s\r\n", credential.Username); err != nil {
		return false, err
	}
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	// 381 = password required; anything else = error.
	if !strings.HasPrefix(resp, "381") {
		return false, nil
	}

	// Send AUTHINFO PASS.
	if _, err = fmt.Fprintf(conn, "AUTHINFO PASS %s\r\n", credential.Password); err != nil {
		return false, err
	}
	resp, err = reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	// 281 = authentication accepted.
	if strings.HasPrefix(resp, "281") {
		return true, nil
	}
	return false, nil
}
