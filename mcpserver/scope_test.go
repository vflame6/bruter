package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeScope(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadScopeParsesEntries(t *testing.T) {
	path := writeScope(t, `# engagement 2026-11
10.10.20.0/24

192.168.1.50
dc01.corp.local
2001:db8::/32
`)

	scope, err := LoadScope(path)
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	if got := len(scope.Entries()); got != 4 {
		t.Fatalf("loaded %d entries, want 4 (comments and blanks ignored): %v", got, scope.Entries())
	}
}

func TestScopeAllows(t *testing.T) {
	path := writeScope(t, "10.10.20.0/24\n192.168.1.50\ndc01.corp.local\n2001:db8::/32\n")
	scope, err := LoadScope(path)
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}

	in := []string{
		"10.10.20.1",
		"10.10.20.255",
		"10.10.20.14:445",
		"192.168.1.50",
		"192.168.1.50:22",
		"dc01.corp.local",
		"DC01.CORP.LOCAL",
		"dc01.corp.local:88",
		"2001:db8::1",
		"[2001:db8::1]:445",
	}
	for _, target := range in {
		if !scope.Allows(target) {
			t.Errorf("Allows(%q) = false, want true", target)
		}
	}

	out := []string{
		"10.10.21.1",
		"192.168.1.51",
		"8.8.8.8",
		"dc02.corp.local",
		"corp.local",
		"evil.example",
		"2001:dead::1",
		"",
		"   ",
	}
	for _, target := range out {
		if scope.Allows(target) {
			t.Errorf("Allows(%q) = true, want false", target)
		}
	}
}

func TestScopeRejectsSmuggledSecondTarget(t *testing.T) {
	// net.SplitHostPort does not validate the port, so "10.0.0.5:22,10.9.9.9"
	// used to yield host 10.0.0.5 and pass the check. The scanner's target
	// reader splits on commas, so the second host would then be dialled.
	path := writeScope(t, "10.10.20.0/24\ndc01.corp.local\n")
	scope, err := LoadScope(path)
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}

	smuggled := []string{
		"10.10.20.5:22,10.9.9.9",
		"10.10.20.5,10.9.9.9",
		"dc01.corp.local:88,evil.example",
		"dc01.corp.local,evil.example",
		"10.10.20.5:22 10.9.9.9",
		"10.10.20.5\n10.9.9.9",
		"10.10.20.5:not-a-port",
		"10.10.20.5:0",
		"10.10.20.5:99999",
		"10.10.20.5:-1",
		"./10.10.20.5",
		`dc01.corp.local\evil`,
	}
	for _, target := range smuggled {
		if scope.Allows(target) {
			t.Errorf("Allows(%q) = true; a target that can expand into more than one host must be refused", target)
		}
	}

	// The legitimate forms must still work.
	for _, target := range []string{"10.10.20.5", "10.10.20.5:22", "dc01.corp.local", "dc01.corp.local:88"} {
		if !scope.Allows(target) {
			t.Errorf("Allows(%q) = false, want true", target)
		}
	}
}

func TestScopeDoesNotResolveHostnames(t *testing.T) {
	// localhost resolves to 127.0.0.1, but the scope lists the address only.
	// Resolving first would make the scope depend on whatever DNS says at the
	// time, which is not a scope decision.
	path := writeScope(t, "127.0.0.1\n")
	scope, err := LoadScope(path)
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	if scope.Allows("localhost") {
		t.Error("a hostname was accepted because it resolves into scope; scope must be literal")
	}
}

func TestNilScopeAllowsNothing(t *testing.T) {
	// A server started without --mcp-scope must deny everything, not
	// everything-by-default.
	var scope *Scope
	for _, target := range []string{"127.0.0.1", "10.0.0.1", "example.com", ""} {
		if scope.Allows(target) {
			t.Errorf("a nil scope allowed %q", target)
		}
	}
	if got := scope.Entries(); got != nil {
		t.Errorf("Entries() on a nil scope = %v, want nil", got)
	}
	if got := scope.Reject([]string{"10.0.0.1"}); len(got) != 1 {
		t.Errorf("Reject on a nil scope = %v, want every target rejected", got)
	}
}

func TestLoadScopeRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty file":        "\n# only comments\n",
		"bad cidr":          "10.10.20.0/33\n",
		"host with port":    "10.10.20.5:445\n",
		"nonsense":          "not a host!\n",
		"url":               "https://dc01.corp.local\n",
		"wildcard":          "*.corp.local\n",
		"ip range notation": "10.10.20.1-10.10.20.50\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadScope(writeScope(t, body)); err == nil {
				t.Errorf("LoadScope accepted %q", strings.TrimSpace(body))
			}
		})
	}
}

func TestLoadScopeMissingFile(t *testing.T) {
	if _, err := LoadScope(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Fatal("expected an error for a missing scope file")
	}
}

func TestScopeRejectReportsOnlyOutOfScope(t *testing.T) {
	path := writeScope(t, "10.10.20.0/24\n")
	scope, err := LoadScope(path)
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}

	got := scope.Reject([]string{"10.10.20.5", "8.8.8.8", "10.10.20.6:22", "1.1.1.1"})
	want := []string{"8.8.8.8", "1.1.1.1"}
	if len(got) != len(want) {
		t.Fatalf("Reject = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Reject[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
