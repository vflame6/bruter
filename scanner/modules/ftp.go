package modules

import (
	"context"
	"net"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/vflame6/bruter/utils"
)

// FTPHandler is an implementation of ModuleHandler for FTP service
func FTPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	var conn *ftp.ServerConn
	var err error

	connString := target.Addr()

	// Wrap dialer to respect ctx cancellation
	dialFn := func(network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	if target.Encryption {
		conn, err = ftp.Dial(
			connString,
			ftp.DialWithTimeout(timeout),
			ftp.DialWithDialFunc(dialFn),
			ftp.DialWithExplicitTLS(utils.GetTLSConfig()),
		)
	} else {
		conn, err = ftp.Dial(
			connString,
			ftp.DialWithTimeout(timeout),
			ftp.DialWithDialFunc(dialFn),
		)
	}
	if err != nil {
		// not connected
		return false, err
	}
	defer func() { _ = conn.Quit() }()

	// test authentication
	err = conn.Login(credential.Username, credential.Password)
	if err != nil {
		// connected, but not authenticated
		return false, nil
	}

	// connected and authenticated
	return true, nil
}
