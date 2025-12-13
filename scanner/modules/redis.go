package modules

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/utils"
	"net"
	"time"
)

// RedisChecker is an implementation of CommandChecker for Redis service
func RedisChecker(target net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, defaultUsername, defaultPassword string) (bool, bool, error) {
	var err error

	// try to connect with TLS
	_, err = GetRedisConnection(target, port, true, timeout, dialer, defaultUsername, defaultPassword)
	if err != nil {
		if redis.IsAuthError(err) {
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
	_, err = GetRedisConnection(target, port, false, timeout, dialer, defaultUsername, defaultPassword)
	if err != nil {
		if redis.IsAuthError(err) {
			// connected, but authentication error
			return false, false, nil
		}
		// return error on connection error
		return false, false, err
	}
	// connected and authenticated
	return true, false, nil
}

// RedisHandler is an implementation of ModuleHandler for Redis service
func RedisHandler(target net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, bool) {
	_, err := GetRedisConnection(target, port, encryption, timeout, dialer, username, password)
	if err != nil {
		if redis.IsAuthError(err) {
			// authentication error
			return true, false
		}
		// not connected
		return false, false
	}

	// connected and authenticated
	return true, true
}

func GetRedisConnection(target net.IP, port int, encryption bool, timeout time.Duration, d *utils.ProxyAwareDialer, username, password string) (*redis.Client, error) {
	addr := fmt.Sprintf("%s:%d", target.String(), port)

	// Create the Redis client options
	options := &redis.Options{
		Addr:     addr,          // Redis server address
		Dialer:   d.DialContext, // Set the custom dialer function
		DB:       0,
		Username: username,
	}

	if password != "" {
		options.Password = password
	}

	if encryption {
		options.TLSConfig = utils.GetTLSConfig()
	}

	client := redis.NewClient(options)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel() // Release resources when main returns

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return client, nil
}
