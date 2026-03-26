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
	"amqp":          {5672, AMQPHandler, "guest", "guest"},
	"asterisk":      {5038, AsteriskHandler, "admin", "admin"},
	"cassandra":     {9042, CassandraHandler, "cassandra", "cassandra"},
	"cisco":         {23, CiscoHandler, "cisco", "cisco"},
	"cisco-enable":  {23, CiscoEnableHandler, "cisco", "cisco"},
	"cobaltstrike":  {50050, CobaltStrikeHandler, "", "password"},
	"clickhouse":    {9000, ClickHouseHandler, "default", ""},
	"couchdb":       {5984, CouchDBHandler, "admin", "admin"},
	"elasticsearch": {9200, ElasticsearchHandler, "elastic", "elastic"},
	"etcd":          {2379, EtcdHandler, "root", "123"},
	"firebird":      {3050, FirebirdHandler, "SYSDBA", "masterkey"},
	"ftp":           {21, FTPHandler, "anonymous", "anonymous"},
	"http-basic":    {80, HTTPBasicHandler, "admin", "admin"},
	"http-form":     {80, HTTPFormHandler, "admin", "admin"},
	"http-proxy":    {8080, HTTPProxyHandler, "admin", "admin"},
	"imap":          {143, IMAPHandler, "admin", "admin"},
	"influxdb":      {8086, InfluxDBHandler, "admin", "admin"},
	"irc":           {6667, IRCHandler, "bruter", "password"},
	"ldap":          {389, LDAPHandler, "cn=admin,dc=example,dc=com", "admin"},
	"ldaps":         {636, LDAPHandler, "cn=admin,dc=example,dc=com", "admin"},
	"memcached":     {11211, MemcachedHandler, "admin", "admin"},
	"mongo":         {27017, MongoHandler, "", ""},
	"mssql":         {1433, MSSQLHandler, "sa", "sa"},
	"mysql":         {3306, MySQLHandler, "root", "root"},
	"neo4j":         {7687, Neo4jHandler, "neo4j", "neo4j"},
	"nntp":          {119, NNTPHandler, "admin", "admin"},
	"oracle":        {1521, OracleHandler, "system", "oracle"},
	"pop3":          {110, POP3Handler, "admin", "admin"},
	"postgres":      {5432, PostgresHandler, "postgres", "postgres"},
	"radmin":        {4899, RadminHandler, "", "password"},
	"redis":         {6379, RedisHandler, "default", ""},
	"rexec":         {512, RexecHandler, "root", "root"},
	"rlogin":        {513, RloginHandler, "root", ""},
	"rpcap":         {2002, RPCAPHandler, "admin", "admin"},
	"rsh":           {514, RshHandler, "root", ""},
	"rtsp":          {554, RTSPHandler, "admin", "admin"},
	"s7":            {102, S7Handler, "", ""},
	"sip":           {5060, SIPHandler, "admin", "admin"},
	"smpp":          {2775, SMPPHandler, "smppclient1", "password"},
	"smb":           {445, SMBHandler, "Administrator", ""},
	"smtp":          {25, SMTPHandler, "admin", "admin"},
	"smtp-enum":     {25, SMTPEnumHandler, "admin", ""},
	"snmp":          {161, SNMPHandler, "", "public"},
	"socks5":        {1080, SOCKS5Handler, "admin", "admin"},
	"ssh":           {22, SSHHandler, "root", "123456"},
	"sshkey":        {22, SSHKeyHandler, "root", "/path/to/key"},
	"svn":           {3690, SVNHandler, "admin", "admin"},
	"teamspeak":     {10011, TeamSpeakHandler, "serveradmin", "admin"},
	"telnet":        {23, TelnetHandler, "admin", "admin"},
	"vault":         {8200, VaultHandler, "admin", "admin"},
	"vmauthd":       {902, VMAuthdHandler, "root", "vmware"},
	"xmpp":          {5222, XMPPHandler, "admin", "admin"},
	"rdp":           {3389, RDPHandler, "Administrator", "password"},
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
	Extra          map[string]string // module-specific data populated during probe (e.g. RTSP path)
}

// SetExtra stores a key-value pair in the target's Extra map (thread-safe via Mutex).
func (t *Target) SetExtra(key, value string) {
	t.Mutex.Lock()
	defer t.Mutex.Unlock()
	if t.Extra == nil {
		t.Extra = make(map[string]string)
	}
	t.Extra[key] = value
}

// GetExtra retrieves a value from the target's Extra map (thread-safe via Mutex).
func (t *Target) GetExtra(key string) (string, bool) {
	t.Mutex.Lock()
	defer t.Mutex.Unlock()
	if t.Extra == nil {
		return "", false
	}
	v, ok := t.Extra[key]
	return v, ok
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
