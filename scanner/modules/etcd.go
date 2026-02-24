package modules

import (
	"context"
	"github.com/vflame6/bruter/utils"
	etcd "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"strconv"
	"time"
)

var etcdLoggerCfg = zap.Config{
	Encoding:         "console",
	Level:            zap.NewAtomicLevelAt(zap.DebugLevel),
	OutputPaths:      []string{"/dev/null"},
	ErrorOutputPaths: []string{"/dev/null"},
}

var etcdLogger, _ = etcdLoggerCfg.Build()

// EtcdHandler is an implementation of ModuleHandler for etcd service
func EtcdHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	var client *etcd.Client
	var err error

	dialOptions := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		}),
	}

	if target.Encryption {
		client, err = etcd.New(etcd.Config{
			Logger:      etcdLogger,
			DialOptions: dialOptions,
			Endpoints:   []string{net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))},
			DialTimeout: timeout,
			TLS:         utils.GetTLSConfig(),
		})
	} else {
		client, err = etcd.New(etcd.Config{
			Logger:      etcdLogger,
			DialOptions: dialOptions,
			Endpoints:   []string{net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))},
			DialTimeout: timeout,
		})
	}
	if err != nil {
		// connection error
		return false, err
	}
	defer client.Close()

	authCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	_, err = client.Authenticate(authCtx, credential.Username, credential.Password)
	if err != nil {
		// authentication error
		return false, nil
	}

	// successful connection and authentication
	return true, nil
}
