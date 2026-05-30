package wordlists

import (
	"strings"
	"testing"
)

func TestDefaultWordlistsAreEmbeddedAndTrimmed(t *testing.T) {
	assertWordlist(t, "DefaultUsernames", DefaultUsernames, 38, []string{"admin", "root", "www-data"})
	assertWordlist(t, "DefaultPasswords", DefaultPasswords, 1418, []string{"admin", "password", "zxcvbnm"})

	if len(DefaultSSHKeys) != 9 {
		t.Fatalf("DefaultSSHKeys length = %d, want 9", len(DefaultSSHKeys))
	}
	for i, key := range DefaultSSHKeys {
		if !strings.Contains(key, "-----BEGIN ") || !strings.Contains(key, " PRIVATE KEY-----") {
			t.Fatalf("DefaultSSHKeys[%d] does not look like a PEM private key", i)
		}
		if strings.Contains(key, "# Source:") {
			t.Fatalf("DefaultSSHKeys[%d] contains source comment; parser should return PEM blocks only", i)
		}
	}
}

func TestParseLinesDropsBlankAndTrimsWhitespace(t *testing.T) {
	got := parseLines("\n admin \n\troot\t\n\nuser\n")
	want := []string{"admin", "root", "user"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseLines() = %q, want %q", got, want)
	}
}

func assertWordlist(t *testing.T, name string, got []string, wantLen int, required []string) {
	t.Helper()
	if len(got) != wantLen {
		t.Fatalf("%s length = %d, want %d", name, len(got), wantLen)
	}
	seen := make(map[string]bool, len(got))
	for i, value := range got {
		if strings.TrimSpace(value) != value || value == "" {
			t.Fatalf("%s[%d] = %q, want non-empty trimmed value", name, i, value)
		}
		seen[value] = true
	}
	for _, value := range required {
		if !seen[value] {
			t.Fatalf("%s missing required value %q", name, value)
		}
	}
}
