package scanner

import (
	"crypto/tls"
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/vflame6/bruter/logger"
	"net"
	"sync"
	"time"
)

// FTPChecker is an implementation of CheckerHandler for FTP service
// the return values are:
// DEFAULT (bool) for test if the target has default credentials
// ENCRYPTION (bool) for test if the target is using encryption
// ERROR (error) for connection errors
func FTPChecker(target *Target, opts *Options) (bool, bool, error) {
	defaultUsername := "anonymous"
	defaultPassword := "anonymous"

	success := false
	secure := false

	// try with encryption first
	conn, err := GetFTPConnection(target.IP, target.Port, true, opts.Timeout)
	if err == nil {
		secure = true
		logger.Debugf("trying default credentials on %s:%d", target.IP, target.Port)
		err = conn.Login(defaultUsername, defaultPassword)
		if err == nil {
			RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
			success = true
		}
		conn.Quit()
	} else {
		logger.Debugf("failed to connect to %s:%d with encryption, trying plaintext", target.IP, target.Port)
		// connect via plaintext FTP
		conn, err := GetFTPConnection(target.IP, target.Port, false, opts.Timeout)
		if err == nil {
			logger.Debugf("trying default credentials on %s:%d", target.IP, target.Port)
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
func FTPHandler(wg *sync.WaitGroup, credentials <-chan *Credential, opts *Options, target *Target) {
	defer wg.Done()

	for {
		credential, ok := <-credentials
		if !ok {
			break
		}
		// shutdown all threads if --stop-on-success is used and password is found
		if opts.StopOnSuccess && target.Success {
			break
		}
		logger.Debugf("trying %s:%d with credential %s:%s", target.IP, target.Port, credential.Username, credential.Password)
		conn, err := GetFTPConnection(target.IP, target.Port, target.Encryption, opts.Timeout)
		if err != nil {
			if opts.Delay > 0 {
				time.Sleep(opts.Delay)
			}
			continue
		}
		defer conn.Quit()
		err = conn.Login(credential.Username, credential.Password)
		if err != nil {
			if opts.Delay > 0 {
				time.Sleep(opts.Delay)
			}
			continue
		}
		RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, credential.Username, credential.Password)

		if opts.Delay > 0 {
			time.Sleep(opts.Delay)
		}
	}
}

func GetFTPConnection(ip net.IP, port int, encryption bool, timeout time.Duration) (*ftp.ServerConn, error) {
	connString := fmt.Sprintf("%s:%d", ip, port)

	if encryption {
		conn, err := ftp.Dial(
			connString,
			ftp.DialWithTimeout(timeout),
			ftp.DialWithExplicitTLS(&tls.Config{
				InsecureSkipVerify: true,
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
		)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}
