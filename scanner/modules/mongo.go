package modules

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/vflame6/bruter/utils"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"net"
	"strconv"
	"strings"
	"time"
)

// MongoHandler is an implementation of ModuleHandler for MongoDB service
func MongoHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	opts := options.Client().
		SetHosts([]string{addr}).
		SetTimeout(timeout).
		SetServerSelectionTimeout(timeout).
		SetDialer(dialer)

	if target.Encryption {
		opts.SetTLSConfig(utils.GetTLSConfig())
	}

	if credential.Username != "" {
		opts.SetAuth(options.Credential{
			Username: credential.Username,
			Password: credential.Password,
		})
	}

	client, err := mongo.Connect(opts)
	if err != nil {
		return false, err
	}

	// Verify connection
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer client.Disconnect(opCtx)

	// ListDatabaseNames requires authentication
	_, err = client.ListDatabaseNames(opCtx, bson.D{})
	if err != nil {
		if classifyMongoError(err) == "auth_error" {
			// authentication error
			return false, nil
		}
		// connection error
		return false, err
	}

	// connected and authenticated
	return true, nil
}

func classifyMongoError(err error) string {
	if err == nil {
		return "no_error"
	}

	errStr := err.Error()

	// TLS errors
	var tlsRecordErr tls.RecordHeaderError
	if errors.As(err, &tlsRecordErr) {
		return "tls_error"
	}

	if strings.Contains(errStr, "tls:") ||
		strings.Contains(errStr, "first record does not look like a TLS handshake") ||
		strings.Contains(errStr, "certificate") {
		return "tls_error"
	}

	// Auth errors
	if strings.Contains(errStr, "authentication failed") ||
		strings.Contains(errStr, "Authentication failed") ||
		strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "auth error") {
		return "auth_error"
	}

	// Network errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout_error"
		}
		return "network_error"
	}

	return "unknown_error"
}
