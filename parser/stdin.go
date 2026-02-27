package parser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// stdinEntry represents a union of supported JSON input formats.
type stdinEntry struct {
	// fingerprintx / naabu fields
	Host    string `json:"host"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service"`

	// alternative field names
	Protocol string `json:"protocol"`
}

// portServiceMap maps common ports to bruter module names (fallback when no service field).
var portServiceMap = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	80:    "http-basic",
	110:   "pop3",
	143:   "imap",
	161:   "snmp",
	389:   "ldap",
	443:   "http-basic",
	445:   "smb",
	993:   "imap",
	995:   "pop3",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgres",
	5672:  "amqp",
	5900:  "vnc",
	5985:  "winrm",
	6379:  "redis",
	8080:  "http-basic",
	8443:  "http-basic",
	9000:  "clickhouse",
	9200:  "elasticsearch",
	27017: "mongo",
}

// ParseStdin reads lines from r and parses them as JSON (fingerprintx/naabu)
// or plain text (host:port). Returns parsed targets.
func ParseStdin(r io.Reader) ([]Target, error) {
	var targets []Target
	sc := bufio.NewScanner(r)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		var t *Target
		var err error

		if line[0] == '{' {
			t, err = parseJSONLine(line)
		} else {
			t, err = parsePlainLine(line)
		}

		if err != nil {
			// skip unparseable lines
			continue
		}
		if t != nil {
			targets = append(targets, *t)
		}
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	return targets, nil
}

func parseJSONLine(line string) (*Target, error) {
	var e stdinEntry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		return nil, err
	}

	host := e.Host
	if host == "" {
		host = e.IP
	}
	if host == "" || e.Port == 0 {
		return nil, fmt.Errorf("missing host or port")
	}

	// Determine service: prefer explicit service field, then protocol, then port mapping
	svc := strings.ToLower(e.Service)
	if svc == "" {
		svc = strings.ToLower(e.Protocol)
	}

	// Map to bruter module name
	module := mapService(svc, e.Port)
	if module == "" {
		return nil, fmt.Errorf("unknown service for port %d", e.Port)
	}

	return &Target{Host: host, Port: e.Port, Service: module}, nil
}

func parsePlainLine(line string) (*Target, error) {
	// Expected format: host:port
	lastColon := strings.LastIndex(line, ":")
	if lastColon < 0 {
		return nil, fmt.Errorf("invalid format: %s", line)
	}

	host := line[:lastColon]
	portStr := line[lastColon+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}

	module := portServiceMap[port]
	if module == "" {
		return nil, fmt.Errorf("unknown service for port %d", port)
	}

	return &Target{Host: host, Port: port, Service: module}, nil
}

// mapService maps a service name (from JSON) to a bruter module name.
func mapService(svc string, port int) string {
	if svc != "" {
		// Try the existing serviceMap first
		if m, ok := serviceMap[svc]; ok {
			return m
		}
		// Some tools use the module name directly
		if isKnownModule(svc) {
			return svc
		}
	}
	// Fall back to port mapping
	return portServiceMap[port]
}

// isKnownModule checks if a string is a valid bruter module name.
func isKnownModule(name string) bool {
	known := map[string]bool{
		"amqp": true, "asterisk": true, "clickhouse": true, "cisco": true,
		"cisco_enable": true, "etcd": true, "ftp": true, "http-basic": true,
		"imap": true, "irc": true, "ldap": true, "ldaps": true,
		"mongo": true, "mssql": true, "mysql": true, "oracle": true,
		"pop3": true, "postgres": true, "rdp": true, "redis": true,
		"rexec": true, "rlogin": true, "rsh": true, "rtsp": true,
		"smb": true, "smpp": true, "smtp": true, "snmp": true,
		"socks5": true, "ssh": true, "sshkey": true, "teamspeak": true,
		"telnet": true, "vnc": true, "winrm": true, "xmpp": true,
	}
	return known[name]
}
