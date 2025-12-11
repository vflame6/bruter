package scanner

import (
	"crypto/tls"
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/vflame6/bruter/logger"
	"net"
	"time"
)

// FTPChecker is an implementation of CheckerHandler for FTP service
func FTPChecker(target *Target, opts *Options) (bool, bool, error) {
	defaultUsername := "anonymous"
	defaultPassword := "anonymous"

	success := false
	secure := false

	// try with encryption first
	conn, err := GetFTPConnection(target.IP, target.Port, true, opts.Timeout, opts.ProxyDialer)
	if err == nil {
		secure = true
		err = conn.Login(defaultUsername, defaultPassword)
		if err == nil {
			RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
			success = true
		}
		conn.Quit()
	} else {
		logger.Debugf("failed to connect to %s:%d with encryption, trying plaintext", target.IP, target.Port)
		// connect via plaintext FTP
		conn, err := GetFTPConnection(target.IP, target.Port, false, opts.Timeout, opts.ProxyDialer)
		if err == nil {
			err = conn.Login(defaultUsername, defaultPassword)
			if err == nil {
				RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
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
func FTPHandler(opts *Options, target *Target, credential *Credential) (bool, bool) {
	conn, err := GetFTPConnection(target.IP, target.Port, target.Encryption, opts.Timeout, opts.ProxyDialer)
	if err != nil {
		// not connected
		return false, false
	}
	defer conn.Quit()
	err = conn.Login(credential.Username, credential.Password)
	if err != nil {
		// connected, but not authenticated
		return true, false
	}

	// connected and authenticated
	return true, true
}

func GetFTPConnection(ip net.IP, port int, encryption bool, timeout time.Duration, dialer *ProxyAwareDialer) (*ftp.ServerConn, error) {
	connString := fmt.Sprintf("%s:%d", ip, port)

	if encryption {
		conn, err := ftp.Dial(
			connString,
			ftp.DialWithTimeout(timeout),
			ftp.DialWithDialFunc(dialer.Dial),
			ftp.DialWithExplicitTLS(&tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10, // Allow older TLS for compatibility
			}),
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
