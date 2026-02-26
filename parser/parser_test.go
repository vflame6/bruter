package parser

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleGNMAP = `# Nmap 7.94 scan initiated Thu Feb 26 00:00:00 2026 as: nmap -sV -oG output.gnmap 192.168.1.0/24
Host: 192.168.1.1 (router.local)	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//https///	Ignored State: filtered (997)
Host: 192.168.1.10 ()	Ports: 3306/open/tcp//mysql///, 6379/open/tcp//redis///, 5432/open/tcp//postgresql///
Host: 192.168.1.20 ()	Ports: 445/open/tcp//microsoft-ds///, 21/open/tcp//ftp///, 25/open/tcp//smtp///
Host: 192.168.1.30 ()	Ports: 8080/open/tcp//http-alt///, 161/open/udp//snmp///, 5900/open/tcp//vnc///
Host: 192.168.1.40 ()	Ports: 23/closed/tcp//telnet///
# Nmap done at Thu Feb 26 00:01:00 2026 -- 256 IP addresses scanned
`

const sampleXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX output.xml 192.168.1.0/24">
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl"/></port>
    </ports>
  </host>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port>
      <port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql"/></port>
      <port protocol="tcp" portid="9999"><state state="open"/><service name="unknown"/></port>
      <port protocol="tcp" portid="8080"><state state="closed"/><service name="http-alt"/></port>
    </ports>
  </host>
  <host>
    <address addr="2001:db8::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>
`

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseGNMAP(t *testing.T) {
	path := writeTempFile(t, "scan.gnmap", sampleGNMAP)
	targets, err := ParseGNMAP(path)
	if err != nil {
		t.Fatal(err)
	}

	// Expected: ssh, http-basic, http-basic (https), mysql, redis, postgres, smb, ftp, smtp, http-basic (http-alt), snmp, vnc
	// NOT telnet (closed)
	if len(targets) != 12 {
		t.Fatalf("expected 12 targets, got %d: %v", len(targets), targets)
	}

	// Check first host
	assertTarget(t, targets[0], "192.168.1.1", 22, "ssh")
	assertTarget(t, targets[1], "192.168.1.1", 80, "http-basic")
	assertTarget(t, targets[2], "192.168.1.1", 443, "http-basic")
}

func TestParseXML(t *testing.T) {
	path := writeTempFile(t, "scan.xml", sampleXML)
	targets, err := ParseXML(path)
	if err != nil {
		t.Fatal(err)
	}

	// Expected: ssh(22), http-basic(80), https→http-basic(443), mysql(3306), postgres(5432), ssh(22 ipv6)
	// NOT: unknown(9999), closed http-alt(8080)
	if len(targets) != 6 {
		t.Fatalf("expected 6 targets, got %d: %v", len(targets), targets)
	}

	assertTarget(t, targets[0], "192.168.1.1", 22, "ssh")
	assertTarget(t, targets[1], "192.168.1.1", 80, "http-basic")
	assertTarget(t, targets[2], "192.168.1.1", 443, "http-basic") // https via tunnel=ssl
	assertTarget(t, targets[3], "192.168.1.10", 3306, "mysql")
	assertTarget(t, targets[4], "192.168.1.10", 5432, "postgres")
	assertTarget(t, targets[5], "2001:db8::1", 22, "ssh")
}

const sampleNessus = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="192.168.1.1">
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0" pluginID="10267" pluginName="SSH Server Type"/>
      <ReportItem port="80" svc_name="www" protocol="tcp" severity="0" pluginID="10107" pluginName="HTTP Server Type"/>
      <ReportItem port="3306" svc_name="mysql" protocol="tcp" severity="0" pluginID="10719" pluginName="MySQL"/>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Scan Information"/>
    </ReportHost>
    <ReportHost name="192.168.1.10">
      <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="0" pluginID="11011" pluginName="SMB"/>
      <ReportItem port="5432" svc_name="postgresql" protocol="tcp" severity="0" pluginID="22222" pluginName="PostgreSQL"/>
    </ReportHost>
  </Report>
</NessusClientData_v2>
`

const sampleNexpose = `<?xml version="1.0" ?>
<NexposeReport version="2.0">
  <nodes>
    <node address="10.0.0.1">
      <endpoints>
        <endpoint port="22" status="open" protocol="tcp">
          <services><service name="ssh"/></services>
        </endpoint>
        <endpoint port="21" status="open" protocol="tcp">
          <services><service name="ftp"/></services>
        </endpoint>
        <endpoint port="8080" status="closed" protocol="tcp">
          <services><service name="http"/></services>
        </endpoint>
      </endpoints>
    </node>
    <node address="10.0.0.2">
      <endpoints>
        <endpoint port="3306" status="open" protocol="tcp">
          <services><service name="mysql"/></services>
        </endpoint>
      </endpoints>
    </node>
  </nodes>
</NexposeReport>
`

func TestParseNessus(t *testing.T) {
	path := writeTempFile(t, "scan.nessus", sampleNessus)
	targets, err := ParseNessus(path)
	if err != nil {
		t.Fatal(err)
	}

	// Expected: ssh(22), http-basic(80 via www), mysql(3306), smb(445 via cifs), postgres(5432)
	// NOT: port 0 general
	if len(targets) != 5 {
		t.Fatalf("expected 5 targets, got %d: %v", len(targets), targets)
	}

	assertTarget(t, targets[0], "192.168.1.1", 22, "ssh")
	assertTarget(t, targets[1], "192.168.1.1", 80, "http-basic")
	assertTarget(t, targets[2], "192.168.1.1", 3306, "mysql")
	assertTarget(t, targets[3], "192.168.1.10", 445, "smb")
	assertTarget(t, targets[4], "192.168.1.10", 5432, "postgres")
}

func TestParseNexpose(t *testing.T) {
	path := writeTempFile(t, "scan.xml", sampleNexpose)
	targets, err := ParseNexpose(path)
	if err != nil {
		t.Fatal(err)
	}

	// Expected: ssh(22), ftp(21), mysql(3306)
	// NOT: http(8080) — closed
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d: %v", len(targets), targets)
	}

	assertTarget(t, targets[0], "10.0.0.1", 22, "ssh")
	assertTarget(t, targets[1], "10.0.0.1", 21, "ftp")
	assertTarget(t, targets[2], "10.0.0.2", 3306, "mysql")
}

func TestDetectFormatNessus(t *testing.T) {
	path := writeTempFile(t, "scan.nessus", sampleNessus)
	f, _ := DetectFormat(path)
	if f != FormatNessus {
		t.Errorf("expected Nessus, got %d", f)
	}
}

func TestDetectFormatNexpose(t *testing.T) {
	path := writeTempFile(t, "scan.xml", sampleNexpose)
	f, _ := DetectFormat(path)
	if f != FormatNexpose {
		t.Errorf("expected Nexpose, got %d", f)
	}
}

func TestParseFileNessus(t *testing.T) {
	path := writeTempFile(t, "scan.nessus", sampleNessus)
	targets, err := ParseFile(path, FormatUnknown)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 5 {
		t.Fatalf("expected 5 targets, got %d", len(targets))
	}
}

func TestDetectFormat(t *testing.T) {
	gnmapPath := writeTempFile(t, "scan.gnmap", sampleGNMAP)
	xmlPath := writeTempFile(t, "scan.xml", sampleXML)
	emptyPath := writeTempFile(t, "empty.txt", "nothing here\n")

	f, _ := DetectFormat(gnmapPath)
	if f != FormatGNMAP {
		t.Errorf("expected GNMAP, got %d", f)
	}

	f, _ = DetectFormat(xmlPath)
	if f != FormatXML {
		t.Errorf("expected XML, got %d", f)
	}

	f, _ = DetectFormat(emptyPath)
	if f != FormatUnknown {
		t.Errorf("expected Unknown, got %d", f)
	}
}

func TestParseFile(t *testing.T) {
	gnmapPath := writeTempFile(t, "scan.gnmap", sampleGNMAP)

	// Auto-detect
	targets, err := ParseFile(gnmapPath, FormatUnknown)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 12 {
		t.Fatalf("expected 12 targets, got %d", len(targets))
	}

	// Force format
	xmlPath := writeTempFile(t, "scan.xml", sampleXML)
	targets, err = ParseFile(xmlPath, FormatXML)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 6 {
		t.Fatalf("expected 6 targets, got %d", len(targets))
	}
}

func TestMapService(t *testing.T) {
	tests := []struct {
		nmap   string
		bruter string
		ok     bool
	}{
		{"ssh", "ssh", true},
		{"microsoft-ds", "smb", true},
		{"ms-sql-s", "mssql", true},
		{"unknown-thing", "", false},
	}
	for _, tt := range tests {
		mod, ok := MapService(tt.nmap)
		if ok != tt.ok || mod != tt.bruter {
			t.Errorf("MapService(%q) = (%q, %v), want (%q, %v)", tt.nmap, mod, ok, tt.bruter, tt.ok)
		}
	}
}

func assertTarget(t *testing.T, got Target, host string, port int, service string) {
	t.Helper()
	if got.Host != host || got.Port != port || got.Service != service {
		t.Errorf("expected %s:%d (%s), got %s:%d (%s)", host, port, service, got.Host, got.Port, got.Service)
	}
}
