package wordlists

import "testing"

func TestDefaultUsernames(t *testing.T) {
	if len(DefaultUsernames) != 17 {
		t.Errorf("expected 17 default usernames, got %d", len(DefaultUsernames))
	}
	// Check first and last
	if DefaultUsernames[0] != "root" {
		t.Errorf("expected first username to be 'root', got %q", DefaultUsernames[0])
	}
	if DefaultUsernames[16] != "azureuser" {
		t.Errorf("expected last username to be 'azureuser', got %q", DefaultUsernames[16])
	}
}

func TestDefaultPasswords(t *testing.T) {
	if len(DefaultPasswords) < 190 {
		t.Errorf("expected ~199 default passwords, got %d", len(DefaultPasswords))
	}
	if DefaultPasswords[0] != "123456" {
		t.Errorf("expected first password to be '123456', got %q", DefaultPasswords[0])
	}
}

func TestDefaultSSHKeys(t *testing.T) {
	if len(DefaultSSHKeys) != 9 {
		t.Errorf("expected 9 SSH bad keys, got %d", len(DefaultSSHKeys))
	}
	for i, key := range DefaultSSHKeys {
		if len(key) == 0 {
			t.Errorf("SSH key %d is empty", i)
		}
		if key[:5] != "-----" {
			t.Errorf("SSH key %d doesn't start with PEM header: %q", i, key[:20])
		}
	}
}

func TestNoDuplicateUsernames(t *testing.T) {
	seen := make(map[string]bool)
	for _, u := range DefaultUsernames {
		if seen[u] {
			t.Errorf("duplicate username: %q", u)
		}
		seen[u] = true
	}
}
