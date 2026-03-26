package modules

import (
	"context"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/vflame6/bruter/utils"
)

// Neo4jHandler is an implementation of ModuleHandler for Neo4j Bolt protocol.
// Uses the official neo4j-go-driver to authenticate (port 7687).
func Neo4jHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	scheme := "bolt"
	if target.Encryption {
		scheme = "bolt+s"
	}

	uri := scheme + "://" + target.Addr()

	driver, err := neo4j.NewDriverWithContext(uri,
		neo4j.BasicAuth(credential.Username, credential.Password, ""),
		func(config *neo4j.Config) {
			config.SocketConnectTimeout = timeout
			config.ConnectionAcquisitionTimeout = timeout
			config.MaxConnectionPoolSize = 1
			if target.Encryption {
				config.TlsConfig = utils.GetTLSConfig()
			}
		},
	)
	if err != nil {
		return false, err
	}
	defer func() { _ = driver.Close(ctx) }()

	authCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err = driver.VerifyConnectivity(authCtx)
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "unauthorized") || strings.Contains(msg, "authentication") ||
			strings.Contains(msg, "credentials") || strings.Contains(msg, "invalid") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
