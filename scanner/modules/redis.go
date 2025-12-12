package modules

import (
	"database/sql"
	"fmt"
	"github.com/lib/pq"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/utils"
	"net"
	"strings"
	"time"
)

// RedisChecker is an implementation of CommandChecker for Redis service
func RedisChecker(target net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, defaultUsername, defaultPassword string) (bool, bool, error) {
	var err error

	// try to connect with TLS
	_, err = GetPostgresConnection(target, port, true, dialer, defaultUsername, defaultPassword)
	if err != nil {
		if strings.Contains(err.Error(), "pq: password authentication failed for user") {
			// connected but authentication error
			return false, true, nil
		}
		// do nothing on connection error
	} else {
		// connected and authenticated
		return true, true, nil
	}

	// try without TLS
	logger.Debugf("failed to connect to %s:%d with encryption, trying plaintext", target, port)
	_, err = GetPostgresConnection(target, port, false, dialer, defaultUsername, defaultPassword)
	if err != nil {
		if strings.Contains(err.Error(), "pq: password authentication failed for user") {
			// connected, but authentication error
			return false, false, nil
		}
		// return error on connection error
		return false, false, err
	}
	// connected and authenticated
	return true, false, nil
}

// RedisHandler is an implementation of CommandHandler for Redis service
func RedisHandler(target net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, bool) {
	_, err := GetPostgresConnection(target, port, encryption, dialer, username, password)
	if err != nil {
		if strings.Contains(err.Error(), "pq: password authentication failed for user") {
			// authentication error
			return true, false
		}
		// not connected
		return false, false
	}

	return true, true
}

func GetRedisConnection(target net.IP, port int, encryption bool, d *utils.ProxyAwareDialer, username, password string) (*sql.DB, error) {
	// Build connection string
	// sslmode is set based on encryption, but actual TLS is handled by our dialer
	sslmode := "disable"
	if encryption {
		sslmode = "require"
	}

	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=postgres sslmode=%s",
		target, port, username, password, sslmode,
	)

	connector, err := pq.NewConnector(connStr)
	if err != nil {
		return nil, err
	}

	// Use TLS wrapper or plain dialer based on encryption flag
	if encryption {
		connector.Dialer(&utils.TLSDialerWrapper{Dialer: d})
	} else {
		connector.Dialer(d)
	}

	db := sql.OpenDB(connector)

	err = db.Ping()

	return db, err
}
