package scanner

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGetResults_JSONMode_FieldNamesAndTypes(t *testing.T) {
	results := make(chan *Result, 1)
	ts := time.Now()

	results <- &Result{
		Command:        "ssh",
		IP:             net.ParseIP("1.2.3.4"),
		Port:           22,
		Username:       "root",
		Password:       "toor",
		OriginalTarget: "myhost:22",
		Timestamp:      ts,
	}
	close(results)

	// Write to a temp file so we can capture JSONL output
	f, err := os.CreateTemp("", "bruter_json_test_*.jsonl")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()

	var wg sync.WaitGroup
	var successes atomic.Int64
	wg.Add(1)
	GetResults(results, f, &wg, &successes, true /* jsonMode */)
	wg.Wait()
	if err := f.Close(); err != nil {
		t.Fatalf("close output file: %v", err)
	}

	// Read and parse
	raw, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	line := strings.TrimSpace(string(raw))
	if line == "" {
		t.Fatal("expected JSONL output, got empty file")
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v (line=%q)", err, line)
	}

	// Verify required fields exist and have correct types
	checks := []struct {
		key      string
		wantType string
	}{
		{"target", "string"},
		{"port", "number"},
		{"protocol", "string"},
		{"username", "string"},
		{"password", "string"},
		{"timestamp", "number"},
	}
	for _, c := range checks {
		v, ok := got[c.key]
		if !ok {
			t.Errorf("field %q missing in JSONL output", c.key)
			continue
		}
		switch c.wantType {
		case "string":
			if _, ok := v.(string); !ok {
				t.Errorf("field %q: want string, got %T", c.key, v)
			}
		case "number":
			if _, ok := v.(float64); !ok {
				t.Errorf("field %q: want number, got %T", c.key, v)
			}
		}
	}

	// Verify specific values
	if got["target"] != "myhost:22" {
		t.Errorf("target = %v, want myhost:22", got["target"])
	}
	if got["protocol"] != "ssh" {
		t.Errorf("protocol = %v, want ssh", got["protocol"])
	}
	if got["username"] != "root" {
		t.Errorf("username = %v, want root", got["username"])
	}
	if got["password"] != "toor" {
		t.Errorf("password = %v, want toor", got["password"])
	}

	// Verify timestamp non-zero and matches
	tsVal, _ := got["timestamp"].(float64)
	if tsVal == 0 {
		t.Error("timestamp is zero")
	}
	if int64(tsVal) != ts.Unix() {
		t.Errorf("timestamp = %d, want %d", int64(tsVal), ts.Unix())
	}

	// Verify successes counter
	if successes.Load() != 1 {
		t.Errorf("successes = %d, want 1", successes.Load())
	}
}

func TestGetResults_PlainTextMode(t *testing.T) {
	results := make(chan *Result, 1)
	results <- &Result{
		Command:  "redis",
		IP:       net.ParseIP("10.0.0.1"),
		Port:     6379,
		Username: "default",
		Password: "secret",
	}
	close(results)

	f, err := os.CreateTemp("", "bruter_text_test_*.txt")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()

	var wg sync.WaitGroup
	var successes atomic.Int64
	wg.Add(1)
	GetResults(results, f, &wg, &successes, false /* plainText */)
	wg.Wait()
	if err := f.Close(); err != nil {
		t.Fatalf("close output file: %v", err)
	}

	raw, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	line := strings.TrimSpace(string(raw))

	if !strings.Contains(line, "[redis]") {
		t.Errorf("plain text output missing [redis]: %q", line)
	}
	if !strings.Contains(line, "default") {
		t.Errorf("plain text output missing username: %q", line)
	}
	if strings.HasPrefix(line, "{") {
		t.Errorf("plain text output should not be JSON: %q", line)
	}
}
