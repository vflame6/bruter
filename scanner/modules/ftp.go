package modules

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/utils"
	"net"
	"time"
)

// FTPChecker is an implementation of CommandChecker for FTP service
func FTPChecker(target net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, defaultUsername, defaultPassword string) (bool, bool, error) {
	success := false
	secure := false

	// try with encryption first
	conn, err := GetFTPConnection(target, port, true, timeout, dialer)
	if err == nil {
		secure = true
		err = conn.Login(defaultUsername, defaultPassword)
		if err == nil {
			success = true
		}
		conn.Quit()
	} else {
		logger.Debugf("failed to connect to %s:%d with encryption, trying plaintext", target, port)
		// connect via plaintext FTP
		conn, err := GetFTPConnection(target, port, false, timeout, dialer)
		if err == nil {
			err = conn.Login(defaultUsername, defaultPassword)
			if err == nil {
				success = true
			}
			conn.Quit()
		} else {
			// if nothing succeeded, return error
			return false, false, err
		}
	}

	return success, secure, nil
}

// FTPHandler is an implementation of CommandHandler for FTP service
func FTPHandler(target net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, bool) {
	conn, err := GetFTPConnection(target, port, encryption, timeout, dialer)
	if err != nil {
		// not connected
		return false, false
	}
	defer conn.Quit()
	err = conn.Login(username, password)
	if err != nil {
		// connected, but not authenticated
		return true, false
	}

	// connected and authenticated
	return true, true
}

func GetFTPConnection(ip net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer) (*ftp.ServerConn, error) {
	connString := fmt.Sprintf("%s:%d", ip, port)

	if encryption {
		conn, err := ftp.Dial(
			connString,
			ftp.DialWithTimeout(timeout),
			ftp.DialWithDialFunc(dialer.Dial),
			ftp.DialWithExplicitTLS(utils.GetTLSConfig()),
		)
		if err != nil {
			return nil, err
		}
		return conn, nil
	} else {
		conn, err := ftp.Dial(
			connString,
			ftp.DialWithTimeout(timeout),
			ftp.DialWithDialFunc(dialer.Dial),
		)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}
