package modules

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"time"

	_ "github.com/sijms/go-ora/v2"
	"github.com/vflame6/bruter/utils"
)

// OracleHandler is an implementation of ModuleHandler for Oracle Database.
// Uses go-ora to authenticate via Oracle Net protocol (port 1521).
// No external Oracle client libraries required.
func OracleHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	connString := fmt.Sprintf("oracle://%s:%s@%s:%d/",
		url.QueryEscape(credential.Username),
		url.QueryEscape(credential.Password),
		target.IP.String(),
		target.Port,
	)

	db, err := sql.Open("oracle", connString)
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
			// Timeout = connection issue, not auth failure.
			return false, err
		}
		// Oracle returns ORA-01017 for invalid username/password.
		return false, nil
	}

	return true, nil
}
