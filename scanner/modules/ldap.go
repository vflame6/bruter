package modules

import (
	"context"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/vflame6/bruter/utils"
)

// LDAPHandler is an implementation of ModuleHandler for LDAP/LDAPS simple bind authentication.
// Supports plain LDAP (port 389) and LDAPS (port 636) with TLS.
// Routes connections through ProxyAwareDialer for SOCKS5 proxy support.
func LDAPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	netConn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}

	conn := ldap.NewConn(netConn, target.Encryption)
	conn.Start()
	defer func() { _ = conn.Close() }()

	// Close connection if context is cancelled.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	conn.SetTimeout(timeout)

	if err = conn.Bind(credential.Username, credential.Password); err == nil {
		return true, nil
	}

	if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
		return false, nil
	}
	return false, err
}
