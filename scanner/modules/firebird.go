package modules

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/nakagami/firebirdsql"
	"github.com/vflame6/bruter/utils"
)

// FirebirdHandler is an implementation of ModuleHandler for Firebird SQL database.
// Uses firebirdsql pure-Go driver (port 3050). No external Firebird client required.
func FirebirdHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	// DSN format: user:password@host:port/database
	// Default database path for Firebird.
	dbPath := "employee"

	dsn := fmt.Sprintf("%s:%s@%s:%d/%s",
		credential.Username,
		credential.Password,
		target.IP.String(),
		target.Port,
		dbPath,
	)

	db, err := sql.Open("firebirdsql", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()

	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(timeout)

	authCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err = db.PingContext(authCtx)
	if err != nil {
		if authCtx.Err() != nil {
			return false, err
		}
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "password") || strings.Contains(msg, "user name") ||
			strings.Contains(msg, "not defined") || strings.Contains(msg, "login") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
