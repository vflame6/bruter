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
	"amqp":     {DefaultPort: 5672, Handler: AMQPHandler, DefaultUsername: "guest", DefaultPassword: "guest"},
	"asterisk": {DefaultPort: 5038, Handler: AsteriskHandler, DefaultUsername: "admin", DefaultPassword: "admin"},
	"cassandra": {
		DefaultPort: 9042, Handler: CassandraHandler, DefaultUsername: "cassandra", DefaultPassword: "cassandra",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: CassandraNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"cisco": {
		DefaultPort: 23, Handler: CiscoHandler, DefaultUsername: "cisco", DefaultPassword: "cisco",
		VulnChecks: []VulnCheck{
			{Name: "no-password", Handler: CiscoHandler, Creds: []Credential{
				{Username: "", Password: ""},
			}},
		},
		DefaultCreds: []Credential{
			{Username: "admin", Password: ""},
			{Username: "admin", Password: "admin"},
		},
	},
	"cisco-enable": {DefaultPort: 23, Handler: CiscoEnableHandler, DefaultUsername: "cisco", DefaultPassword: "cisco"},
	"cobaltstrike": {DefaultPort: 50050, Handler: CobaltStrikeHandler, DefaultUsername: "", DefaultPassword: "password"},
	"clickhouse": {
		DefaultPort: 9000, Handler: ClickHouseHandler, DefaultUsername: "default", DefaultPassword: "",
		VulnChecks: []VulnCheck{
			{Name: "default-no-password", Handler: ClickHouseHandler, Creds: []Credential{
				{Username: "default", Password: ""},
			}},
		},
	},
	"couchdb": {
		DefaultPort: 5984, Handler: CouchDBHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: CouchDBNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"elasticsearch": {
		DefaultPort: 9200, Handler: ElasticsearchHandler, DefaultUsername: "elastic", DefaultPassword: "elastic",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: ElasticsearchNoAuthHandler, Creds: []Credential{{}}},
		},
		DefaultCreds: []Credential{
			{Username: "elastic", Password: "changeme"},
		},
	},
	"etcd": {
		DefaultPort: 2379, Handler: EtcdHandler, DefaultUsername: "root", DefaultPassword: "123",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: EtcdNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"firebird": {DefaultPort: 3050, Handler: FirebirdHandler, DefaultUsername: "SYSDBA", DefaultPassword: "masterkey"},
	"ftp": {
		DefaultPort: 21, Handler: FTPHandler, DefaultUsername: "anonymous", DefaultPassword: "anonymous",
		VulnChecks: []VulnCheck{
			{Name: "anonymous-login", Handler: FTPHandler, Creds: []Credential{
				{Username: "anonymous", Password: ""},
				{Username: "anonymous", Password: "anonymous"},
				{Username: "ftp", Password: "ftp"},
			}},
		},
		DefaultCreds: []Credential{
			{Username: "admin", Password: "admin"},
		},
	},
	"http-basic": {
		DefaultPort: 80, Handler: HTTPBasicHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: HTTPBasicNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"http-form": {DefaultPort: 80, Handler: HTTPFormHandler, DefaultUsername: "admin", DefaultPassword: "admin"},
	"http-proxy": {
		DefaultPort: 8080, Handler: HTTPProxyHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: HTTPProxyNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"imap": {DefaultPort: 143, Handler: IMAPHandler, DefaultUsername: "admin", DefaultPassword: "admin"},
	"influxdb": {
		DefaultPort: 8086, Handler: InfluxDBHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: InfluxDBNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"irc": {
		DefaultPort: 6667, Handler: IRCHandler, DefaultUsername: "bruter", DefaultPassword: "password",
		VulnChecks: []VulnCheck{
			{Name: "no-password", Handler: IRCNoPasswordHandler, Creds: []Credential{{}}},
		},
	},
	"ldap": {
		DefaultPort: 389, Handler: LDAPHandler, DefaultUsername: "cn=admin,dc=example,dc=com", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "anonymous-bind", Handler: LDAPHandler, Creds: []Credential{
				{Username: "", Password: ""},
			}},
		},
	},
	"memcached": {
		DefaultPort: 11211, Handler: MemcachedHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: MemcachedNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"mongo": {
		DefaultPort: 27017, Handler: MongoHandler, DefaultUsername: "", DefaultPassword: "",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: MongoHandler, Creds: []Credential{
				{Username: "", Password: ""},
			}},
		},
		DefaultCreds: []Credential{
			{Username: "admin", Password: "admin"},
			{Username: "admin", Password: "password"},
		},
	},
	"mssql": {
		DefaultPort: 1433, Handler: MSSQLHandler, DefaultUsername: "sa", DefaultPassword: "sa",
		VulnChecks: []VulnCheck{
			{Name: "empty-password", Handler: MSSQLHandler, Creds: []Credential{
				{Username: "sa", Password: ""},
			}},
		},
		DefaultCreds: []Credential{
			{Username: "sa", Password: "Password1"},
		},
	},
	"mysql": {
		DefaultPort: 3306, Handler: MySQLHandler, DefaultUsername: "root", DefaultPassword: "root",
		VulnChecks: []VulnCheck{
			{Name: "empty-password", Handler: MySQLHandler, Creds: []Credential{
				{Username: "root", Password: ""},
			}},
		},
		DefaultCreds: []Credential{
			{Username: "root", Password: "mysql"},
		},
	},
	"neo4j": {
		DefaultPort: 7687, Handler: Neo4jHandler, DefaultUsername: "neo4j", DefaultPassword: "neo4j",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: Neo4jNoAuthHandler, Creds: []Credential{{}}},
		},
		DefaultCreds: []Credential{
			{Username: "neo4j", Password: "changeme"},
		},
	},
	"nntp": {
		DefaultPort: 119, Handler: NNTPHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: NNTPNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"oracle": {
		DefaultPort: 1521, Handler: OracleHandler, DefaultUsername: "system", DefaultPassword: "oracle",
		DefaultCreds: []Credential{
			{Username: "system", Password: "manager"},
			{Username: "sys", Password: "change_on_install"},
		},
	},
	"pop3": {DefaultPort: 110, Handler: POP3Handler, DefaultUsername: "admin", DefaultPassword: "admin"},
	"postgres": {
		DefaultPort: 5432, Handler: PostgresHandler, DefaultUsername: "postgres", DefaultPassword: "postgres",
		VulnChecks: []VulnCheck{
			{Name: "trust-auth", Handler: PostgresHandler, Creds: []Credential{
				{Username: "postgres", Password: ""},
			}},
		},
	},
	"radmin": {DefaultPort: 4899, Handler: RadminHandler, DefaultUsername: "", DefaultPassword: "password"},
	"redis": {
		DefaultPort: 6379, Handler: RedisHandler, DefaultUsername: "default", DefaultPassword: "",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: RedisHandler, Creds: []Credential{
				{Username: "default", Password: ""},
			}},
		},
	},
	"rexec": {DefaultPort: 512, Handler: RexecHandler, DefaultUsername: "root", DefaultPassword: "root"},
	"rlogin": {
		DefaultPort: 513, Handler: RloginHandler, DefaultUsername: "root", DefaultPassword: "",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: RloginHandler, Creds: []Credential{
				{Username: "root", Password: ""},
			}},
		},
	},
	"rpcap": {
		DefaultPort: 2002, Handler: RPCAPHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: RPCAPNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"rsh": {
		DefaultPort: 514, Handler: RshHandler, DefaultUsername: "root", DefaultPassword: "",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: RshHandler, Creds: []Credential{
				{Username: "root", Password: ""},
			}},
		},
	},
	"rtsp": {
		DefaultPort: 554, Handler: RTSPHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: RTSPNoAuthHandler, Creds: []Credential{{}}},
		},
		DefaultCreds: []Credential{
			{Username: "admin", Password: "12345"},
			{Username: "admin", Password: "password"},
		},
	},
	"s7": {
		DefaultPort: 102, Handler: S7Handler, DefaultUsername: "", DefaultPassword: "",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: S7Handler, Creds: []Credential{
				{Username: "", Password: ""},
			}},
		},
	},
	"sip": {
		DefaultPort: 5060, Handler: SIPHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: SIPHandler, Creds: []Credential{
				{Username: "test", Password: "test"},
			}},
		},
	},
	"smpp": {DefaultPort: 2775, Handler: SMPPHandler, DefaultUsername: "smppclient1", DefaultPassword: "password"},
	"smb": {
		DefaultPort: 445, Handler: SMBHandler, DefaultUsername: "Administrator", DefaultPassword: "",
		VulnChecks: []VulnCheck{
			{Name: "null-session", Handler: SMBHandler, Creds: []Credential{
				{Username: "", Password: ""},
				{Username: "Guest", Password: ""},
			}},
		},
		DefaultCreds: []Credential{
			{Username: "Administrator", Password: "password"},
			{Username: "admin", Password: "admin"},
		},
	},
	"smtp":      {DefaultPort: 25, Handler: SMTPHandler, DefaultUsername: "admin", DefaultPassword: "admin"},
	"smtp-enum": {DefaultPort: 25, Handler: SMTPEnumHandler, DefaultUsername: "admin", DefaultPassword: ""},
	"snmp": {
		DefaultPort: 161, Handler: SNMPHandler, DefaultUsername: "", DefaultPassword: "public",
		VulnChecks: []VulnCheck{
			{Name: "default-community", Handler: SNMPHandler, Creds: []Credential{
				{Username: "", Password: "public"},
				{Username: "", Password: "private"},
			}},
		},
	},
	"socks5": {
		DefaultPort: 1080, Handler: SOCKS5Handler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: SOCKS5NoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"ssh": {
		DefaultPort: 22, Handler: SSHHandler, DefaultUsername: "root", DefaultPassword: "123456",
		VulnChecks: []VulnCheck{
			{Name: "ssh-hole", Handler: SSHHoleHandler, Creds: []Credential{
				{Username: "root", Password: SSHHoleProbePassword()},
				{Username: "alpine", Password: SSHHoleProbePassword()},
			}},
		},
		DefaultCreds: []Credential{
			{Username: "root", Password: "root"},
			{Username: "root", Password: "toor"},
			{Username: "admin", Password: "admin"},
			{Username: "pi", Password: "raspberry"},
			{Username: "ubuntu", Password: "ubuntu"},
		},
	},
	"sshkey": {DefaultPort: 22, Handler: SSHKeyHandler, DefaultUsername: "root", DefaultPassword: "/path/to/key"},
	"svn": {
		DefaultPort: 3690, Handler: SVNHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "anonymous-access", Handler: SVNNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"teamspeak": {DefaultPort: 10011, Handler: TeamSpeakHandler, DefaultUsername: "serveradmin", DefaultPassword: "admin"},
	"telnet": {
		DefaultPort: 23, Handler: TelnetHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-password", Handler: TelnetNoPasswordHandler, Creds: []Credential{{}}},
		},
		DefaultCreds: []Credential{
			{Username: "admin", Password: ""},
			{Username: "root", Password: "root"},
			{Username: "root", Password: ""},
		},
	},
	"vault": {
		DefaultPort: 8200, Handler: VaultHandler, DefaultUsername: "admin", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: VaultNoAuthHandler, Creds: []Credential{{}}},
		},
	},
	"vmauthd": {DefaultPort: 902, Handler: VMAuthdHandler, DefaultUsername: "root", DefaultPassword: "vmware"},
	"xmpp":    {DefaultPort: 5222, Handler: XMPPHandler, DefaultUsername: "admin", DefaultPassword: "admin"},
	"rdp": {
		DefaultPort: 3389, Handler: RDPHandler, DefaultUsername: "Administrator", DefaultPassword: "password",
		DefaultCreds: []Credential{
			{Username: "Administrator", Password: ""},
			{Username: "admin", Password: "admin"},
		},
	},
	"vnc": {
		DefaultPort: 5900, Handler: VNCHandler, DefaultUsername: "", DefaultPassword: "admin",
		VulnChecks: []VulnCheck{
			{Name: "no-auth", Handler: VNCNoAuthHandler, Creds: []Credential{{}}},
		},
		DefaultCreds: []Credential{
			{Username: "", Password: "password"},
			{Username: "", Password: ""},
			{Username: "", Password: "1234"},
		},
	},
	"winrm": {
		DefaultPort: 5985, Handler: WinRMHandler, DefaultUsername: "Administrator", DefaultPassword: "password",
		DefaultCreds: []Credential{
			{Username: "Administrator", Password: ""},
		},
	},
}

// VulnCheck defines an authentication vulnerability check for a module.
// Each check has its own handler and credentials specific to the vulnerability.
type VulnCheck struct {
	Name    string
	Handler ModuleHandler
	Creds   []Credential
}

type Module struct {
	DefaultPort     int
	Handler         ModuleHandler
	DefaultUsername string
	DefaultPassword string
	VulnChecks      []VulnCheck
	DefaultCreds    []Credential
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

// Addr returns the target address as "host:port".
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
