package modules

import (
	"context"
	"github.com/vflame6/bruter/logger"
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

// EtcdChecker is an implementation of CommandChecker for etcd service
func EtcdChecker(target net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, defaultUsername, defaultPassword string) (bool, bool, error) {
	success := false
	secure := false

	// try with encryption first
	probe, err := ProbeEtcd(target, port, true, timeout, dialer, defaultUsername, defaultPassword)
	if err == nil {
		secure = true
		if probe {
			success = true
		}
	} else {
		logger.Debugf("(%s:%d) failed to connect to etcd with encryption, trying plaintext", target, port)
		// connect via plaintext FTP
		probe, err = ProbeEtcd(target, port, false, timeout, dialer, defaultUsername, defaultPassword)
		if err == nil {
			if probe {
				success = true
			}
		} else {
			// if nothing succeeded, return error
			return false, false, err
		}
	}

	return success, secure, nil
}

// EtcdHandler is an implementation of CommandHandler for etcd service
func EtcdHandler(target net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, bool) {
	probe, err := ProbeEtcd(target, port, encryption, timeout, dialer, username, password)
	if err != nil {
		// not connected
		return false, false
	}

	// connected and authenticated or not
	return true, probe
}

func ProbeEtcd(ip net.IP, port int, encryption bool, timeout time.Duration, d *utils.ProxyAwareDialer, username, password string) (bool, error) {
	var client *etcd.Client
	var err error

	dialOptions := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}),
	}

	if encryption {
		client, err = etcd.New(etcd.Config{
			Logger:      etcdLogger,
			DialOptions: dialOptions,
			Endpoints:   []string{net.JoinHostPort(ip.String(), strconv.Itoa(port))},
			DialTimeout: timeout,
			TLS:         utils.GetTLSConfig(),
		})
	} else {
		client, err = etcd.New(etcd.Config{
			Logger:      etcdLogger,
			DialOptions: dialOptions,
			Endpoints:   []string{net.JoinHostPort(ip.String(), strconv.Itoa(port))},
			DialTimeout: timeout,
		})
	}
	if err != nil {
		// connection error
		return false, err
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, err = client.Authenticate(ctx, username, password)
	if err != nil {
		// authentication error
		return false, nil
	}

	// successful connection and authentication
	return true, nil
}
