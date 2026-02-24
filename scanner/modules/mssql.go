package modules

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb" // register mssql driver
	"github.com/vflame6/bruter/utils"
)

// MSSQLHandler is an implementation of ModuleHandler for Microsoft SQL Server.
func MSSQLHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	secs := int(timeout.Seconds())
	connStr := fmt.Sprintf("sqlserver://%s:%s@%s?dial+timeout=%d&connection+timeout=%d",
		url.QueryEscape(credential.Username),
		url.QueryEscape(credential.Password),
		net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port)),
		secs, secs,
	)
	if !target.Encryption {
		connStr += "&encrypt=disable"
	}

	db, err := sql.Open("mssql", connStr)
	if err != nil {
		return false, err
	}
	defer func() { _ = db.Close() }()

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err = db.PingContext(pingCtx); err == nil {
		return true, nil
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "login failed") || strings.Contains(msg, "18456") {
		return false, nil
	}
	return false, err
}
