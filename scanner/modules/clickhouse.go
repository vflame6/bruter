package modules

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/utils"
	"net"
	"strconv"
	"strings"
	"time"
)

// ClickHouseChecker is an implementation of CommandChecker for ClickHouse service
func ClickHouseChecker(target net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, defaultUsername, defaultPassword string) (bool, bool, error) {
	// Try TLS first
	conn, errType, err := TestClickHouseConnection(target, port, true, defaultUsername, defaultPassword, timeout, dialer)
	if err == nil {
		defer conn.Close()
		return true, true, nil
	}

	// If it's an auth error, no point trying without TLS with same credentials
	if errType == "auth_error" {
		return false, true, nil
	}

	// If it's a TLS error, try plaintext
	if errType == "tls_error" {
		logger.Debugf("failed to connect to %s:%d with TLS, trying plaintext", target, port)
		conn, errType, err = TestClickHouseConnection(target, port, false, defaultUsername, defaultPassword, timeout, dialer)
		if err == nil {
			defer conn.Close()
			return true, false, nil
		}

		if errType == "auth_error" {
			return false, false, nil
		}
	}

	return false, false, fmt.Errorf("connection failed or the service is invalid: %w", err)
}

// ClickHouseHandler is an implementation of CommandHandler for ClickHouse service
func ClickHouseHandler(target net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, bool) {
	// get connection object
	conn, err := GetClickHouseConnection(target, port, encryption, username, password, timeout, dialer)
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

func GetClickHouseConnection(address net.IP, port int, secure bool, username, password string, timeout time.Duration, d *utils.ProxyAwareDialer) (driver.Conn, error) {
	addr := net.JoinHostPort(address.String(), strconv.Itoa(port))

	opts := &clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: username,
			Password: password,
		},
		DialTimeout: timeout,
		DialContext: func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		},
	}

	if secure {
		opts.TLS = utils.GetTLSConfig()
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func TestClickHouseConnection(address net.IP, port int, secure bool, username, password string, timeout time.Duration, d *utils.ProxyAwareDialer) (driver.Conn, string, error) {
	addr := net.JoinHostPort(address.String(), strconv.Itoa(port))

	opts := &clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: username,
			Password: password,
		},
		DialTimeout: timeout,
		DialContext: func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		},
	}

	if secure {
		opts.TLS = utils.GetTLSConfig()
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
