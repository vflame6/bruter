package modules

import (
	"context"
	"github.com/vflame6/bruter/utils"
	"net"
	"sync"
	"time"
)

// Modules stores all available services for bruteforce
var Modules = map[string]Module{
	"amqp":       {5672, AMQPHandler, "guest", "guest"},
	"clickhouse": {9000, ClickHouseHandler, "default", ""},
	"etcd":       {2379, EtcdHandler, "root", "123"},
	"ftp":        {21, FTPHandler, "anonymous", "anonymous"},
	"mongo":      {27017, MongoHandler, "", ""},
	"postgres":   {5432, PostgresHandler, "postgres", "postgres"},
	"redis":      {6379, RedisHandler, "default", ""},
	"smpp":       {2775, SMPPHandler, "smppclient1", "password"},
	"ssh":        {22, SSHHandler, "root", "123456"},
	"vault":      {8200, VaultHandler, "admin", "admin"},
}

type Module struct {
	DefaultPort     int
	Handler         ModuleHandler
	DefaultUsername string
	DefaultPassword string
}

// Target is a struct for each bruteforce target
// by default, Encryption is set to true to try to connect with encryption at default check
type Target struct {
	IP             net.IP
	Port           int
	OriginalTarget string // raw input string before DNS resolution (e.g. "hostname:8080" or "::1")
	Encryption     bool
	Success        bool
	Retries        int
	Mutex          sync.Mutex
}

type Credential struct {
	Username string
	Password string
}

// ModuleHandler is a type function for one bruteforce thread
// the return values are:
// IsAuthenticated (bool) to test if authentication is successful
// ERROR (error) for any errors
type ModuleHandler func(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error)
