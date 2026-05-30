package modules

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
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

	connector := go_ora.NewConnector(connString)
	if oraConn, ok := connector.(*go_ora.OracleConnector); ok {
		oraConn.Dialer(dialer) // proxy/interface support via ProxyAwareDialer
	}

	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()

	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(timeout)

	authCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := db.PingContext(authCtx)
	if err != nil {
		if authCtx.Err() != nil {
			return false, err
		}
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "ora-01017") || strings.Contains(msg, "invalid username") ||
			strings.Contains(msg, "invalid password") || strings.Contains(msg, "logon denied") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
