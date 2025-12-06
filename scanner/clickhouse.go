package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vflame6/bruter/logger"
	"net"
	"strconv"
	"strings"
	"time"
)

// ClickHouseChecker is an implementation of CheckerHandler for ClickHouse service
// the return values are:
// DEFAULT (bool) for test if the target has default credentials
// ENCRYPTION (bool) for test if the target is using encryption
// ERROR (error) for connection errors
func ClickHouseChecker(target *Target, opts *Options) (bool, bool, error) {
	defaultUsername := "default"
	defaultPassword := ""

	// Try TLS first
	conn, errType, err := TestClickHouseConnection(target.IP, target.Port, true, defaultUsername, defaultPassword, opts.Timeout)
	if err == nil {
		defer conn.Close()

		RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
		return true, true, nil
	}

	// If it's an auth error, no point trying without TLS with same credentials
	if errType == "auth_error" {
		return false, true, nil
	}

	// If it's a TLS error, try plaintext
	if errType == "tls_error" {
		logger.Debugf("failed to connect to %s:%d with TLS, trying plaintext", target.IP, target.Port)
		conn, errType, err = TestClickHouseConnection(target.IP, target.Port, false, defaultUsername, defaultPassword, opts.Timeout)
		if err == nil {
			defer conn.Close()
			RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
			return true, false, nil
		}

		if errType == "auth_error" {
			return false, false, nil
		}
	}

	return false, false, fmt.Errorf("connection failed or the service is invalid: %w", err)
}

// ClickHouseHandler is an implementation of CommandHandler for ClickHouse service
// the return values are:
// IsConnected (bool) to test if connection to the target is successful
// IsAuthenticated (bool) to test if authentication is successful
func ClickHouseHandler(opts *Options, target *Target, credential *Credential) (bool, bool) {
	// get connection object
	conn, err := GetClickHouseConnection(target.IP, target.Port, target.Encryption, credential.Username, credential.Password, opts.Timeout)
	if err != nil {
		// something wrong with library I guess, we do not perform connection here
		return false, false
	}
	defer conn.Close()

	// test connection and authentication
	err = conn.Ping(context.Background())
	if err != nil {
		errType := classifyClickHouseError(err)
		if errType != "auth_error" {
			// if errType is not auth_error, then the connection is failed
			return false, false
		}

		// connected and not authenticated
		return true, false
	}

	// connected and authenticated
	return true, true
}

func GetClickHouseConnection(address net.IP, port int, secure bool, username, password string, timeout time.Duration) (driver.Conn, error) {
	addr := net.JoinHostPort(address.String(), strconv.Itoa(port))

	opts := &clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: username,
			Password: password,
		},
		DialTimeout: timeout,
	}

	if secure {
		opts.TLS = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func TestClickHouseConnection(address net.IP, port int, secure bool, username, password string, timeout time.Duration) (driver.Conn, string, error) {
	addr := net.JoinHostPort(address.String(), strconv.Itoa(port))

	opts := &clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: username,
			Password: password,
		},
		DialTimeout: timeout,
	}

	if secure {
		opts.TLS = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, classifyClickHouseError(err), err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		return nil, classifyClickHouseError(err), err
	}

	return conn, "", nil
}

func classifyClickHouseError(err error) string {
	if err == nil {
		return "no error"
	}

	// Check for ClickHouse protocol errors (including auth)
	var chErr *clickhouse.Exception
	if errors.As(err, &chErr) {
		// Error codes: https://github.com/ClickHouse/ClickHouse/blob/master/src/Common/ErrorCodes.cpp
		switch chErr.Code {
		case 516: // AUTHENTICATION_FAILED
			return "auth_error"
		case 192: // UNKNOWN_USER
			return "auth_error"
		case 193: // WRONG_PASSWORD
			return "auth_error"
		case 194: // REQUIRED_PASSWORD
			return "auth_error"
		default:
			return "clickhouse_error"
		}
	}

	// Check for TLS errors
	var tlsRecordErr tls.RecordHeaderError
	if errors.As(err, &tlsRecordErr) {
		return "tls_error"
	}

	// Check for certificate errors
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "tls_error"
	}

	// Some TLS errors come as plain errors with specific messages
	if strings.Contains(err.Error(), "tls:") ||
		strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
		return "tls_error"
	}

	// Network errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout_error"
		}
		return "network_error"
	}

	// Connection refused
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "connection_error"
	}

	return "unknown_error"
}
