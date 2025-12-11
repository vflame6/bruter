package scanner

import (
	"context"
	"crypto/tls"
	"github.com/vflame6/bruter/logger"
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

// EtcdChecker is an implementation of CheckerHandler for etcd service
func EtcdChecker(target *Target, opts *Options) (bool, bool, error) {
	defaultUsername := "root"
	defaultPassword := "123"

	success := false
	secure := false

	// try with encryption first
	probe, err := ProbeEtcd(target.IP, target.Port, true, opts.Timeout, opts.ProxyDialer, defaultUsername, defaultPassword)
	if err == nil {
		secure = true
		if probe {
			RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
			success = true
		}
	} else {
		logger.Debugf("(%s:%d) failed to connect to etcd with encryption, trying plaintext", target.IP, target.Port)
		// connect via plaintext FTP
		probe, err = ProbeEtcd(target.IP, target.Port, false, opts.Timeout, opts.ProxyDialer, defaultUsername, defaultPassword)
		if err == nil {
			if probe {
				RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
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
func EtcdHandler(opts *Options, target *Target, credential *Credential) (bool, bool) {
	probe, err := ProbeEtcd(target.IP, target.Port, target.Encryption, opts.Timeout, opts.ProxyDialer, credential.Username, credential.Password)
	if err != nil {
		// not connected
		return false, false
	}

	// connected and authenticated or not
	return true, probe
}

func ProbeEtcd(ip net.IP, port int, encryption bool, timeout time.Duration, d *ProxyAwareDialer, username, password string) (bool, error) {
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
			TLS: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10, // Allow older TLS for compatibility
			},
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
