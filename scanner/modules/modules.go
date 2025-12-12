package modules

import (
	"github.com/vflame6/bruter/utils"
	"net"
	"time"
)

// Commands stores all available services for bruteforce
var Commands = map[string]Command{
	"amqp":       {5672, AMQPHandler, AMQPChecker, "guest", "guest"},
	"clickhouse": {9000, ClickHouseHandler, ClickHouseChecker, "default", ""},
	"etcd":       {2379, EtcdHandler, EtcdChecker, "root", "123"},
	"ftp":        {21, FTPHandler, FTPChecker, "anonymous", "anonymous"},
	"mongo":      {27017, MongoHandler, MongoChecker, "", ""},
	"postgres":   {5432, PostgresHandler, PostgresChecker, "postgres", "postgres"},
	"smpp":       {2775, SMPPHandler, SMPPChecker, "smppclient1", "password"},
	"ssh":        {22, SSHHandler, SSHChecker, "root", "123456"},
	"vault":      {8200, VaultHandler, VaultChecker, "admin", "admin"},
}

type Command struct {
	DefaultPort     int
	Handler         CommandHandler
	Checker         CommandChecker
	DefaultUsername string
	DefaultPassword string
}

// CommandChecker is a type function for service checker function
// the return values are:
// DEFAULT (bool) for test if the target has default credentials
// ENCRYPTION (bool) for test if the target is using encryption
// ERROR (error) for connection errors
// if checker could not be implemented for target service, the checker must return false, false, nil
type CommandChecker func(target net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, defaultUsername, defaultPassword string) (bool, bool, error)

// CommandHandler is a type function for one bruteforce thread
// the return values are:
// IsConnected (bool) to test if connection to the target is successful
// IsAuthenticated (bool) to test if authentication is successful
type CommandHandler func(target net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, bool)
