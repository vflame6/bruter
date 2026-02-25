package scanner

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vflame6/bruter/scanner/modules"
)

// Sample GNMAP content with a few services
const sampleGNMAP = `# Nmap 7.94SVN scan initiated
Host: 192.168.1.1 ()	Status: Up
Host: 192.168.1.1 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///	Ignored State: closed (998)
Host: 192.168.1.2 ()	Status: Up
Host: 192.168.1.2 ()	Ports: 21/open/tcp//ftp///, 3306/open/tcp//mysql///	Ignored State: closed (998)
`

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "bruter_nmap_test_*.gnmap")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	_, _ = f.WriteString(content)
	f.Close()
	return f.Name()
}

func TestNmapSummary_Valid(t *testing.T) {
	path := writeTempFile(t, sampleGNMAP)
	defer os.Remove(path)

	summary, err := NmapSummary(path)
	if err != nil {
		t.Fatalf("NmapSummary error: %v", err)
	}
	if !strings.Contains(summary, "4 targets") {
		t.Errorf("summary should mention 4 targets: %s", summary)
	}
	if !strings.Contains(summary, "ssh") {
		t.Errorf("summary should mention ssh: %s", summary)
	}
}

func TestNmapSummary_Empty(t *testing.T) {
	path := writeTempFile(t, "# Nmap scan\n")
	defer os.Remove(path)

	summary, err := NmapSummary(path)
	if err != nil {
		t.Fatalf("NmapSummary error: %v", err)
	}
	if !strings.Contains(summary, "no supported services") {
		t.Errorf("expected 'no supported services', got: %s", summary)
	}
}

func TestNmapSummary_InvalidFile(t *testing.T) {
	_, err := NmapSummary("/nonexistent/file.gnmap")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestRunNmap_ContextCancelled(t *testing.T) {
	path := writeTempFile(t, sampleGNMAP)
	defer os.Remove(path)

	s := &Scanner{
		Opts:    &Options{Parallel: 1, Threads: 1, Timeout: time.Second},
		Targets: make(chan *modules.Target, 10),
		Results: make(chan *Result, 10),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Drain results in background
	go func() {
		for range s.Results {
		}
	}()

	err := s.RunNmap(ctx, path)
	if err != nil {
		t.Fatalf("RunNmap error: %v", err)
	}
}

func TestRunNmap_InvalidFile(t *testing.T) {
	s := &Scanner{
		Opts:    &Options{Parallel: 1, Threads: 1, Timeout: time.Second},
		Targets: make(chan *modules.Target, 10),
		Results: make(chan *Result, 10),
	}

	err := s.RunNmap(context.Background(), "/nonexistent/file.gnmap")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestRunNmapWithResults_ContextCancelled(t *testing.T) {
	path := writeTempFile(t, sampleGNMAP)
	defer os.Remove(path)

	s := &Scanner{
		Opts:    &Options{Parallel: 1, Threads: 1, Timeout: time.Second},
		Targets: make(chan *modules.Target, 10),
		Results: make(chan *Result, 10),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.RunNmapWithResults(ctx, path)
	if err != nil {
		t.Fatalf("RunNmapWithResults error: %v", err)
	}
}
