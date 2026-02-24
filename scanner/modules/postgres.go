package modules

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/lib/pq"
	"github.com/vflame6/bruter/utils"
	"strings"
	"time"
)

// PostgresHandler is an implementation of ModuleHandler for PostgreSQL service
func PostgresHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	// Build connection string
	// sslmode is set based on encryption, but actual TLS is handled by our dialer
	sslmode := "disable"
	if target.Encryption {
		sslmode = "require"
	}

	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=postgres sslmode=%s",
		target.IP, target.Port, credential.Username, credential.Password, sslmode,
	)

	connector, err := pq.NewConnector(connStr)
	if err != nil {
		return false, err
	}

	// Use TLS wrapper or plain dialer based on encryption flag
	if target.Encryption {
		connector.Dialer(&utils.TLSDialerWrapper{Dialer: dialer})
	} else {
		connector.Dialer(dialer)
	}

	db := sql.OpenDB(connector)

	err = db.PingContext(ctx)

	if err != nil {
		if strings.Contains(err.Error(), "pq: password authentication failed for user") {
			// authentication error
			return false, nil
		}
		// not connected
		return false, err
	}

	// connected and authenticated
	return true, nil
}
