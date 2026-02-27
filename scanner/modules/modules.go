package modules

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/vflame6/bruter/utils"
)

// Modules stores all available services for bruteforce
var Modules = map[string]Module{
	"amqp":         {5672, AMQPHandler, "guest", "guest"},
	"asterisk":     {5038, AsteriskHandler, "admin", "admin"},
	"cisco":        {23, CiscoHandler, "cisco", "cisco"},
	"cisco-enable": {23, CiscoEnableHandler, "cisco", "cisco"},
	"cobaltstrike": {50050, CobaltStrikeHandler, "", "password"},
	"clickhouse":   {9000, ClickHouseHandler, "default", ""},
	"etcd":         {2379, EtcdHandler, "root", "123"},
	"ftp":          {21, FTPHandler, "anonymous", "anonymous"},
	"http-basic":   {80, HTTPBasicHandler, "admin", "admin"},
	"imap":         {143, IMAPHandler, "admin", "admin"},
	"irc":          {6667, IRCHandler, "bruter", "password"},
	"ldap":         {389, LDAPHandler, "cn=admin,dc=example,dc=com", "admin"},
	"ldaps":        {636, LDAPHandler, "cn=admin,dc=example,dc=com", "admin"},
	"mongo":        {27017, MongoHandler, "", ""},
	"mssql":        {1433, MSSQLHandler, "sa", "sa"},
	"mysql":        {3306, MySQLHandler, "root", "root"},
	"pop3":         {110, POP3Handler, "admin", "admin"},
	"postgres":     {5432, PostgresHandler, "postgres", "postgres"},
	"redis":        {6379, RedisHandler, "default", ""},
	"rexec":        {512, RexecHandler, "root", "root"},
	"rlogin":       {513, RloginHandler, "root", ""},
	"rsh":          {514, RshHandler, "root", ""},
	"rtsp":         {554, RTSPHandler, "admin", "admin"},
	"smpp":         {2775, SMPPHandler, "smppclient1", "password"},
	"smb":          {445, SMBHandler, "Administrator", ""},
	"socks5":       {1080, SOCKS5Handler, "admin", "admin"},
	"snmp":         {161, SNMPHandler, "", "public"},
	"smtp":         {25, SMTPHandler, "admin", "admin"},
	"ssh":          {22, SSHHandler, "root", "123456"},
	"sshkey":       {22, SSHKeyHandler, "root", "/path/to/key"},
	"teamspeak":    {10011, TeamSpeakHandler, "serveradmin", "admin"},
	"telnet":       {23, TelnetHandler, "admin", "admin"},
	"vault":        {8200, VaultHandler, "admin", "admin"},
	"xmpp":         {5222, XMPPHandler, "admin", "admin"},
	"rdp":          {3389, RDPHandler, "Administrator", "password"},
	"vnc":          {5900, VNCHandler, "", "admin"},
	"winrm":        {5985, WinRMHandler, "Administrator", "password"},
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

// Addr returns the target address as "host:port". The result is cached after the first call.
func (t *Target) Addr() string {
	return net.JoinHostPort(t.IP.String(), strconv.Itoa(t.Port))
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
