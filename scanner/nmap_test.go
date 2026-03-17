package scanner

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vflame6/bruter/parser"
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
	// 3 supported targets: ssh, ftp, mysql (http is excluded — http-basic is manual-only)
	if !strings.Contains(summary, "3 targets") {
		t.Errorf("summary should mention 3 targets: %s", summary)
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
		Opts:       &Options{ConcurrentServices: 5, Parallel: 1, Threads: 1, Timeout: time.Second},
		Targets:    make(chan *modules.Target, 10),
		Results:    make(chan *Result, 10),
		Attempts:   &atomic.Int64{},
		Successes:  &atomic.Int64{},
		globalDone: &atomic.Bool{},
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
		Opts:       &Options{ConcurrentServices: 5, Parallel: 1, Threads: 1, Timeout: time.Second},
		Targets:    make(chan *modules.Target, 10),
		Results:    make(chan *Result, 10),
		Attempts:   &atomic.Int64{},
		Successes:  &atomic.Int64{},
		globalDone: &atomic.Bool{},
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
		Opts:       &Options{ConcurrentServices: 5, Parallel: 1, Threads: 1, Timeout: time.Second},
		Targets:    make(chan *modules.Target, 10),
		Results:    make(chan *Result, 10),
		Attempts:   &atomic.Int64{},
		Successes:  &atomic.Int64{},
		globalDone: &atomic.Bool{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.RunNmapWithResults(ctx, path)
	if err != nil {
		t.Fatalf("RunNmapWithResults error: %v", err)
	}
}

// --- groupByHost tests ---

func TestGroupByHost_MultiHost(t *testing.T) {
	s := &Scanner{Opts: &Options{Defaults: false, ConcurrentServices: 5}}

	targets := []parser.Target{
		{Host: "10.0.0.1", Port: 22, Service: "ssh"},
		{Host: "10.0.0.1", Port: 3306, Service: "mysql"},
		{Host: "10.0.0.2", Port: 21, Service: "ftp"},
	}

	groups := s.groupByHost(targets)

	if len(groups) != 2 {
		t.Fatalf("expected 2 host groups, got %d", len(groups))
	}

	// First host should have 2 services, second should have 1
	if len(groups[0]) != 2 {
		t.Errorf("host 10.0.0.1: expected 2 services, got %d", len(groups[0]))
	}
	if len(groups[1]) != 1 {
		t.Errorf("host 10.0.0.2: expected 1 service, got %d", len(groups[1]))
	}
}

func TestGroupByHost_ServiceDedup(t *testing.T) {
	s := &Scanner{Opts: &Options{Defaults: false, ConcurrentServices: 5}}

	// Both ports 139 and 445 map to "smb" — dedup should keep 445
	targets := []parser.Target{
		{Host: "10.0.0.1", Port: 139, Service: "smb"},
		{Host: "10.0.0.1", Port: 445, Service: "smb"},
	}

	groups := s.groupByHost(targets)

	if len(groups) != 1 {
		t.Fatalf("expected 1 host group, got %d", len(groups))
	}
	if len(groups[0]) != 1 {
		t.Fatalf("expected 1 service after dedup, got %d", len(groups[0]))
	}
	if groups[0][0].target.Port != 445 {
		t.Errorf("expected port 445 (higher), got %d", groups[0][0].target.Port)
	}
	if groups[0][0].command != "smb" {
		t.Errorf("expected command 'smb', got %q", groups[0][0].command)
	}
}

func TestGroupByHost_SSHKeyExpansion(t *testing.T) {
	s := &Scanner{Opts: &Options{Defaults: true, ConcurrentServices: 5}}

	targets := []parser.Target{
		{Host: "10.0.0.1", Port: 22, Service: "ssh"},
	}

	groups := s.groupByHost(targets)

	if len(groups) != 1 {
		t.Fatalf("expected 1 host group, got %d", len(groups))
	}

	commands := make(map[string]bool)
	for _, svc := range groups[0] {
		commands[svc.command] = true
	}

	if !commands["ssh"] {
		t.Error("expected 'ssh' service to be present")
	}
	if !commands["sshkey"] {
		t.Error("expected 'sshkey' service to be auto-expanded")
	}
	if len(groups[0]) != 2 {
		t.Errorf("expected exactly 2 services (ssh + sshkey), got %d", len(groups[0]))
	}
}

func TestGroupByHost_SSHKeyNoDoubleExpansion(t *testing.T) {
	s := &Scanner{Opts: &Options{Defaults: true, ConcurrentServices: 5}}

	// Both ssh and sshkey already present — should not duplicate sshkey
	targets := []parser.Target{
		{Host: "10.0.0.1", Port: 22, Service: "ssh"},
		{Host: "10.0.0.1", Port: 22, Service: "sshkey"},
	}

	groups := s.groupByHost(targets)

	if len(groups) != 1 {
		t.Fatalf("expected 1 host group, got %d", len(groups))
	}

	sshkeyCount := 0
	for _, svc := range groups[0] {
		if svc.command == "sshkey" {
			sshkeyCount++
		}
	}
	if sshkeyCount != 1 {
		t.Errorf("expected exactly 1 sshkey entry, got %d", sshkeyCount)
	}
}
