package modules

import (
	"context"
	"strings"
	"time"

	"github.com/gocql/gocql"
	"github.com/vflame6/bruter/utils"
)

// CassandraHandler is an implementation of ModuleHandler for Apache Cassandra CQL.
// Uses gocql to authenticate via the CQL native protocol (port 9042).
func CassandraHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	cluster := gocql.NewCluster(target.IP.String())
	cluster.Port = target.Port
	cluster.Timeout = timeout
	cluster.ConnectTimeout = timeout
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: credential.Username,
		Password: credential.Password,
	}
	cluster.Consistency = gocql.One
	cluster.DisableInitialHostLookup = true
	cluster.NumConns = 1

	if target.Encryption {
		cluster.SslOpts = &gocql.SslOptions{
			EnableHostVerification: false,
		}
	}

	session, err := cluster.CreateSession()
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "auth") || strings.Contains(msg, "credential") ||
			strings.Contains(msg, "username") || strings.Contains(msg, "password") {
			return false, nil
		}
		return false, err
	}
	defer session.Close()

	return true, nil
}
