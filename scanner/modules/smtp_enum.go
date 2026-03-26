package modules

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// SMTPEnumHandler is an implementation of ModuleHandler for SMTP user enumeration.
// Tries VRFY first, falls back to RCPT TO if VRFY is disabled.
// Username field is the email/user to enumerate; password is ignored.
func SMTPEnumHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read greeting.
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(greeting, "220") {
		return false, fmt.Errorf("unexpected SMTP greeting: %q", strings.TrimSpace(greeting))
	}

	// Send EHLO.
	if _, err = fmt.Fprintf(conn, "EHLO bruter\r\n"); err != nil {
		return false, err
	}
	// Read all EHLO response lines (250- continuation, 250 final).
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
		if !strings.HasPrefix(line, "250-") {
			return false, fmt.Errorf("EHLO rejected: %q", strings.TrimSpace(line))
		}
	}

	// Try VRFY first.
	if _, err = fmt.Fprintf(conn, "VRFY %s\r\n", credential.Username); err != nil {
		return false, err
	}
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	code := ""
	if len(resp) >= 3 {
		code = resp[:3]
	}

	switch code {
	case "250", "251", "252":
		// User exists.
		return true, nil
	case "550", "551", "553":
		// User does not exist.
		return false, nil
	case "502":
		// VRFY disabled — fall back to RCPT TO.
	default:
		// Unknown response from VRFY — try RCPT TO.
	}

	// Fall back to RCPT TO method.
	if _, err = fmt.Fprintf(conn, "MAIL FROM:<test@bruter.local>\r\n"); err != nil {
		return false, err
	}
	resp, err = reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(resp, "250") {
		return false, nil
	}

	if _, err = fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", credential.Username); err != nil {
		return false, err
	}
	resp, err = reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	if strings.HasPrefix(resp, "250") || strings.HasPrefix(resp, "251") {
		return true, nil
	}
	return false, nil
}
