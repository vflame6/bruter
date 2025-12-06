package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/vflame6/bruter/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"net"
	"strconv"
	"strings"
	"time"
)

// MongoChecker is an implementation of CheckerHandler for MongoDB service
func MongoChecker(target *Target, opts *Options) (bool, bool, error) {
	defaultUsername := ""
	defaultPassword := ""

	logger.Debugf("trying default credentials on %s:%d", target.IP, target.Port)
	// Try TLS first
	client, err := GetDefaultMongoConnection(target.IP, target.Port, true, opts.Timeout)
	if err == nil {
		defer client.Disconnect(context.Background())
		RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
		return true, true, nil
	}

	errType := classifyMongoError(err)
	if errType == "auth_error" {
		return false, true, nil
	}

	logger.Debugf("failed to connect to %s:%d with encryption, trying plaintext", target.IP, target.Port)
	// Try plaintext
	client, err = GetDefaultMongoConnection(target.IP, target.Port, false, opts.Timeout)
	if err == nil {
		defer client.Disconnect(context.Background())
		RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
		return true, false, nil
	}
	errType = classifyMongoError(err)
	if errType == "auth_error" {
		return false, false, nil
	}

	return false, false, fmt.Errorf("connection failed: %w", err)
}

// MongoHandler is an implementation of CommandHandler for MongoDB service
// the return values are:
// IsConnected (bool) to test if connection to the target is successful
// IsAuthenticated (bool) to test if authentication is successful
func MongoHandler(opts *Options, target *Target, credential *Credential) (bool, bool) {
	client, err := GetAuthenticatedMongoConnection(target.IP, target.Port, target.Encryption, opts.Timeout, credential.Username, credential.Password)
	if err != nil {
		// check if it is a connection error
		if classifyMongoError(err) != "auth_error" {
			return false, false
		}
		// connected but not authenticated
		return true, false
	}
	_ = client.Disconnect(context.Background())

	// connected and authenticated
	return true, true
}

func GetDefaultMongoConnection(address net.IP, port int, secure bool, timeout time.Duration) (*mongo.Client, error) {
	addr := net.JoinHostPort(address.String(), strconv.Itoa(port))

	opts := options.Client().
		SetHosts([]string{addr}).
		SetTimeout(timeout).
		SetServerSelectionTimeout(timeout)

	if secure {
		opts.SetTLSConfig(&tls.Config{
			InsecureSkipVerify: true,
		})
	}

	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// ListDatabaseNames requires authentication
	_, err = client.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		client.Disconnect(context.Background())
		return nil, fmt.Errorf("failed to list databases: %w", err)
	}

	return client, nil
}

func GetAuthenticatedMongoConnection(address net.IP, port int, secure bool, timeout time.Duration, username, password string) (*mongo.Client, error) {
	addr := net.JoinHostPort(address.String(), strconv.Itoa(port))

	opts := options.Client().
		SetHosts([]string{addr}).
		SetTimeout(timeout).
		SetServerSelectionTimeout(timeout)

	if secure {
		opts.SetTLSConfig(&tls.Config{
			InsecureSkipVerify: true,
		})
	}

	if username != "" {
		opts.SetAuth(options.Credential{
			Username: username,
			Password: password,
		})
	}

	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ListDatabaseNames requires authentication
	_, err = client.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		client.Disconnect(context.Background())
		return nil, fmt.Errorf("failed to verify connection: %w", err)
	}

	return client, nil
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
