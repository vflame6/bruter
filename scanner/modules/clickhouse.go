package modules

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/vflame6/bruter/utils"
)

var ErrClickHouseAuth = errors.New("authentication error")

// ClickHouseHandler is an implementation of ModuleHandler for ClickHouse service
func ClickHouseHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	opts := &clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: credential.Username,
			Password: credential.Password,
		},
		DialTimeout: timeout,
		DialContext: func(ctx context.Context, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		},
	}

	if target.Encryption {
		opts.TLS = utils.GetTLSConfig()
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		// connection object creation error
		// something wrong with library I guess, we do not perform connection here
		return false, err
	}
	defer func() { _ = conn.Close() }()

	// test connection and authentication
	err = conn.Ping(ctx)
	if err != nil {
		errType := classifyClickHouseError(err)
		if errors.Is(errType, ErrClickHouseAuth) {
			// if errType is auth_error, then the authentication is failed
			return false, nil
		}
		// connected error
		return false, err
	}

	// connected and authenticated
	return true, nil
}

func classifyClickHouseError(err error) error {
	// Check for ClickHouse protocol errors (including auth)
	var chErr *clickhouse.Exception
	if errors.As(err, &chErr) {
		// Error codes: https://github.com/ClickHouse/ClickHouse/blob/master/src/Common/ErrorCodes.cpp
		switch chErr.Code {
		case 516: // AUTHENTICATION_FAILED
			return ErrClickHouseAuth
		case 192: // UNKNOWN_USER
			return ErrClickHouseAuth
		case 193: // WRONG_PASSWORD
			return ErrClickHouseAuth
		case 194: // REQUIRED_PASSWORD
			return ErrClickHouseAuth
		default:
			return err
		}
	}

	return err
}
