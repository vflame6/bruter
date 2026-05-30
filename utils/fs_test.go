package utils

import (
	"os"
	"path/filepath"
	"testing"
)

// --- IsFileExists ---

func TestIsFileExists_ExistingFile(t *testing.T) {
	f, err := os.CreateTemp("", "bruter_fs_test_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	if !IsFileExists(f.Name()) {
		t.Errorf("IsFileExists(%q) = false, want true", f.Name())
	}
}

func TestIsFileExists_MissingFile(t *testing.T) {
	path := filepath.Join(os.TempDir(), "bruter_does_not_exist_xyz.txt")
	if IsFileExists(path) {
		t.Errorf("IsFileExists(%q) = true, want false", path)
	}
}

func TestIsFileExists_Directory(t *testing.T) {
	dir, err := os.MkdirTemp("", "bruter_dir_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// Directories exist but are not files — IsFileExists uses os.Stat which
	// returns true for directories too. Verify the actual behaviour.
	if !IsFileExists(dir) {
		t.Errorf("IsFileExists(%q) = false for a directory, want true (os.Stat succeeds)", dir)
	}
}

// --- CountLinesInFile ---

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "bruter_count_test_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	return f.Name()
}

func TestCountLinesInFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name:    "empty file",
			content: "",
			want:    0,
		},
		{
			name:    "one line no trailing newline",
			content: "hello",
			want:    1,
		},
		{
			name:    "one line with trailing newline",
			content: "hello\n",
			want:    1,
		},
		{
			name:    "multiple lines",
			content: "line1\nline2\nline3\n",
			want:    3,
		},
		{
			name:    "multiple lines last line no newline",
			content: "line1\nline2\nline3",
			want:    3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, tt.content)
			got, err := CountLinesInFile(path)
			if err != nil {
				t.Fatalf("CountLinesInFile error: %v", err)
			}
			if got != tt.want {
				t.Errorf("CountLinesInFile = %d, want %d", got, tt.want)
			}
		})
	}
}

// --- ParseFileByLine ---

func collectLines(ch <-chan string) []string {
	var out []string
	for line := range ch {
		out = append(out, line)
	}
	return out
}

func TestParseFileByLine_FileWithLines(t *testing.T) {
	path := writeTempFile(t, "alpha\nbeta\ngamma\n")
	lines := collectLines(ParseFileByLine(path))
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(lines), lines)
	}
	want := []string{"alpha", "beta", "gamma"}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("line[%d] = %q, want %q", i, lines[i], w)
		}
	}
}

func TestParseFileByLine_NonFileStringIsSingleValue(t *testing.T) {
	// A string that is not a file path is sent as-is
	input := "not_a_real_file_path_xyz"
	lines := collectLines(ParseFileByLine(input))
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d: %v", len(lines), lines)
	}
	if lines[0] != input {
		t.Errorf("line[0] = %q, want %q", lines[0], input)
	}
}

func TestParseFileByLine_EmptyLinesSkipped(t *testing.T) {
	path := writeTempFile(t, "first\n\nsecond\n\nthird\n")
	lines := collectLines(ParseFileByLine(path))
	if len(lines) != 3 {
		t.Fatalf("expected 3 non-empty lines, got %d: %v", len(lines), lines)
	}
}
