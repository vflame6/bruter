// Package parser provides nmap output file parsing (GNMAP and XML formats).
// It extracts host:port + service name triples and maps nmap service names
// to bruter module names.
package parser

import "fmt"

// Target represents a discovered service from nmap output.
type Target struct {
	Host    string // IP or hostname
	Port    int    // port number
	Service string // bruter module name (mapped from nmap service)
}

// String returns "host:port (service)".
func (t Target) String() string {
	return fmt.Sprintf("%s:%d (%s)", t.Host, t.Port, t.Service)
}

// serviceMap maps nmap service names to bruter module names.
// Keys are lowercase nmap service names from nmap-services / scan output.
var serviceMap = map[string]string{
	"ftp":            "ftp",
	"ssh":            "ssh",
	"telnet":         "telnet",
	"smtp":           "smtp",
	"http":           "http-basic",
	"http-alt":       "http-basic",
	"http-proxy":     "http-basic",
	"pop3":           "pop3",
	"pop3s":          "pop3",
	"imap":           "imap",
	"imaps":          "imap",
	"snmp":           "snmp",
	"ldap":           "ldap",
	"ldaps":          "ldaps",
	"ms-sql-s":       "mssql",
	"ms-sql-m":       "mssql",
	"mysql":          "mysql",
	"postgresql":     "postgres",
	"redis":          "redis",
	"mongodb":        "mongo",
	"mongod":         "mongo",
	"vnc":            "vnc",
	"vnc-http":       "vnc",
	"amqp":           "amqp",
	"amqps":          "amqp",
	"smpp":           "smpp",
	"smb":            "smb",
	"microsoft-ds":   "smb",
	"netbios-ssn":    "smb",
	"socks5":         "socks5",
	"socks":          "socks5",
	"rtsp":           "rtsp",
	"xmpp-client":    "xmpp",
	"xmpp-server":    "xmpp",
	"jabber":         "xmpp",
	"rexec":          "rexec",
	"rlogin":         "rlogin",
	"rsh":            "rsh",
	"shell":          "rsh",
	"login":          "rlogin",
	"exec":           "rexec",
	"irc":            "irc",
	"ircs":           "irc",
	"asterisk":       "asterisk",
	"clickhouse":     "clickhouse",
	"etcd-client":    "etcd",
	"vault":          "vault",
	"teamspeak":      "teamspeak",
	"cobaltstrike":   "cobaltstrike",
	"wsman":          "winrm",
	"wsmans":         "winrm",
	"winrm":          "winrm",
	"ms-wbt-server":  "rdp",
	"https":          "http-basic",
	"https-alt":      "http-basic",
	"submission":     "smtp",
	"smtps":          "smtp",
}

// MapService maps an nmap service name to a bruter module name.
// Returns the module name and true if found, or ("", false) if unmapped.
func MapService(nmapService string) (string, bool) {
	mod, ok := serviceMap[nmapService]
	return mod, ok
}
