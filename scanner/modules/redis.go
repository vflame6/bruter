package modules

import (
	"context"
	"github.com/redis/go-redis/v9"
	"github.com/vflame6/bruter/utils"
	"net"
	"strconv"
	"time"
)

// RedisHandler is an implementation of ModuleHandler for Redis service
func RedisHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	// Create the Redis client options
	options := &redis.Options{
		Addr:     addr,               // Redis server address
		Dialer:   dialer.DialContext, // Set the custom dialer function
		DB:       0,
		Username: credential.Username,
	}

	if credential.Password != "" {
		options.Password = credential.Password
	}

	if target.Encryption {
		options.TLSConfig = utils.GetTLSConfig()
	}

	client := redis.NewClient(options)

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := client.Ping(pingCtx).Err()

	if err != nil {
		if redis.IsAuthError(err) {
			// authentication error
			return false, nil
		}
		// not connected
		return false, err
	}

	// connected and authenticated
	return true, nil
}
