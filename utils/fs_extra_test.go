package utils

import (
	"os"
	"path/filepath"
	"testing"
)

// --- CountLinesInFile error cases ---

func TestCountLinesInFile_NonexistentFile(t *testing.T) {
	_, err := CountLinesInFile("/tmp/bruter_nonexistent_file_xyz.txt")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestCountLinesInFile_LargeLineCount(t *testing.T) {
	content := ""
	for i := 0; i < 1000; i++ {
		content += "line\n"
	}
	path := writeTempFile(t, content)
	got, err := CountLinesInFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1000 {
		t.Errorf("got %d lines, want 1000", got)
	}
}

func TestCountLinesInFile_SingleNewline(t *testing.T) {
	path := writeTempFile(t, "\n")
	got, err := CountLinesInFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

// --- LoadLines ---

func TestLoadLines_FileWithLines(t *testing.T) {
	path := writeTempFile(t, "alpha\nbeta\ngamma\n")
	lines := LoadLines(path)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(lines), lines)
	}
	want := []string{"alpha", "beta", "gamma"}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("lines[%d] = %q, want %q", i, lines[i], w)
		}
	}
}

func TestLoadLines_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "")
	lines := LoadLines(path)
	if len(lines) != 0 {
		t.Errorf("expected 0 lines for empty file, got %d: %v", len(lines), lines)
	}
}

func TestLoadLines_NonexistentPath(t *testing.T) {
	input := "not_a_real_file_12345"
	lines := LoadLines(input)
	if len(lines) != 1 || lines[0] != input {
		t.Errorf("expected [%q], got %v", input, lines)
	}
}

func TestLoadLines_IncludesEmptyLines(t *testing.T) {
	// LoadLines does NOT skip empty lines (unlike ParseFileByLine)
	path := writeTempFile(t, "first\n\nsecond\n")
	lines := LoadLines(path)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (including blank), got %d: %v", len(lines), lines)
	}
	if lines[1] != "" {
		t.Errorf("expected empty string at index 1, got %q", lines[1])
	}
}

// --- LoadSSHKeyPaths ---

func TestLoadSSHKeyPaths_NonexistentPath(t *testing.T) {
	input := "/tmp/bruter_noexist_key_xyz"
	paths := LoadSSHKeyPaths(input)
	if len(paths) != 1 || paths[0] != input {
		t.Errorf("expected [%q], got %v", input, paths)
	}
}

func TestLoadSSHKeyPaths_PEMFile(t *testing.T) {
	pemContent := `-----BEGIN OPENSSH TEST KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----END OPENSSH TEST KEY-----
`
	path := writeTempFile(t, pemContent)
	paths := LoadSSHKeyPaths(path)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path for PEM file, got %d: %v", len(paths), paths)
	}
	if paths[0] != path {
		t.Errorf("expected path %q, got %q", path, paths[0])
	}
}

func TestLoadSSHKeyPaths_ListOfPaths(t *testing.T) {
	content := "/home/user/.ssh/id_rsa\n/home/user/.ssh/id_ed25519\n"
	path := writeTempFile(t, content)
	paths := LoadSSHKeyPaths(path)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(paths), paths)
	}
	if paths[0] != "/home/user/.ssh/id_rsa" {
		t.Errorf("paths[0] = %q", paths[0])
	}
	if paths[1] != "/home/user/.ssh/id_ed25519" {
		t.Errorf("paths[1] = %q", paths[1])
	}
}

func TestLoadSSHKeyPaths_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "")
	paths := LoadSSHKeyPaths(path)
	// Empty non-PEM file → LoadLines returns nil slice
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for empty file, got %d: %v", len(paths), paths)
	}
}

func TestLoadSSHKeyPaths_RSAPEMFile(t *testing.T) {
	pemContent := `-----BEGIN RSA TEST KEY-----
MIIEpAIBAAKCAQEA2Z3qX2BTLS4e0ek55tFNFVhDMkMOKj0g/HVXhU3kn5MF
-----END RSA TEST KEY-----
`
	path := writeTempFile(t, pemContent)
	paths := LoadSSHKeyPaths(path)
	if len(paths) != 1 || paths[0] != path {
		t.Errorf("expected PEM file to return its own path, got %v", paths)
	}
}

// --- IsFileExists extra cases ---

func TestIsFileExists_EmptyPath(t *testing.T) {
	if IsFileExists("") {
		t.Error("expected false for empty path")
	}
}

func TestIsFileExists_SymlinkToExistingFile(t *testing.T) {
	f, err := os.CreateTemp("", "bruter_symlink_test_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	link := filepath.Join(os.TempDir(), "bruter_symlink_test_link")
	_ = os.Remove(link) // clean up any leftover
	if err := os.Symlink(f.Name(), link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })

	if !IsFileExists(link) {
		t.Error("expected true for symlink to existing file")
	}
}

// --- ParseFileByLine extra cases ---

func TestParseFileByLine_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "")
	lines := collectLines(ParseFileByLine(path))
	if len(lines) != 0 {
		t.Errorf("expected 0 lines for empty file, got %d: %v", len(lines), lines)
	}
}

func TestParseFileByLine_OnlyEmptyLines(t *testing.T) {
	path := writeTempFile(t, "\n\n\n")
	lines := collectLines(ParseFileByLine(path))
	if len(lines) != 0 {
		t.Errorf("expected 0 non-empty lines, got %d: %v", len(lines), lines)
	}
}

func TestParseFileByLine_WhitespaceLines(t *testing.T) {
	path := writeTempFile(t, "  hello  \nworld\n")
	lines := collectLines(ParseFileByLine(path))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "  hello  " {
		t.Errorf("lines[0] = %q, expected whitespace preserved", lines[0])
	}
}
