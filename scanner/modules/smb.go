package modules

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/vflame6/bruter/utils"
)

// SMBHandler is an implementation of ModuleHandler for SMB2/3 authentication.
// Uses NTLM authentication via go-smb2.
func SMBHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     credential.Username,
			Password: credential.Password,
			Domain:   "",
		},
	}

	session, err := d.DialContext(ctx, conn)
	if err == nil {
		_ = session.Logoff()
		return true, nil
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "logon failure") ||
		strings.Contains(msg, "wrong password") ||
		strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "status_logon_failure") {
		return false, nil
	}
	return false, err
}
