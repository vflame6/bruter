package modules

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestModuleRegistryContainsExpectedServices(t *testing.T) {
	want := []string{
		"amqp", "asterisk", "cassandra", "cisco", "cisco-enable", "clickhouse",
		"cobaltstrike", "couchdb", "elasticsearch", "etcd", "firebird", "ftp",
		"http-basic", "http-form", "http-proxy", "imap", "influxdb", "irc",
		"ldap", "memcached", "mongo", "mssql", "mysql", "neo4j", "nntp",
		"oracle", "pop3", "postgres", "radmin", "rdp", "redis", "rexec",
		"rlogin", "rpcap", "rsh", "rtsp", "s7", "sip", "smb", "smpp",
		"smtp", "smtp-enum", "snmp", "socks5", "ssh", "sshkey", "svn",
		"teamspeak", "telnet", "vault", "vmauthd", "vnc", "winrm", "xmpp",
	}

	got := make([]string, 0, len(Modules))
	for name := range Modules {
		got = append(got, name)
	}
	sort.Strings(got)
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("module registry service names mismatch\ngot:  %v\nwant: %v", got, want)
	}
}

func TestModuleRegistryEntriesAreRunnable(t *testing.T) {
	for name, module := range Modules {
		t.Run(name, func(t *testing.T) {
			if strings.TrimSpace(name) != name || strings.ContainsAny(name, " \t\n") {
				t.Fatalf("service name %q must be CLI-safe", name)
			}
			if module.DefaultPort <= 0 || module.DefaultPort > 65535 {
				t.Fatalf("DefaultPort = %d, want 1..65535", module.DefaultPort)
			}
			if module.Handler == nil {
				t.Fatal("Handler is nil")
			}
		})
	}
}
