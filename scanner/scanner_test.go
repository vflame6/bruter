package scanner

import (
	"testing"
	"time"
)

func validOptions() *Options {
	return &Options{
		Parallel: 4,
		Threads:  2,
		Timeout:  5 * time.Second,
		Retries:  3,
		Proxy:    "",
	}
}

func TestNewScanner_ValidOptions(t *testing.T) {
	opts := validOptions()
	s, err := NewScanner(opts)
	if err != nil {
		t.Fatalf("NewScanner with valid options returned error: %v", err)
	}
	if s == nil {
		t.Fatal("NewScanner returned nil scanner")
	}
}

func TestNewScanner_InvalidConcurrency(t *testing.T) {
	tests := []struct {
		name     string
		parallel int
		threads  int
	}{
		{"parallel zero", 0, 2},
		{"parallel negative", -1, 2},
		{"threads zero", 4, 0},
		{"threads negative", 4, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := validOptions()
			opts.Parallel = tt.parallel
			opts.Threads = tt.threads
			_, err := NewScanner(opts)
			if err == nil {
				t.Errorf("NewScanner(parallel=%d, threads=%d) expected error, got nil",
					tt.parallel, tt.threads)
			}
		})
	}
}

func TestNewScanner_NegativeRetries(t *testing.T) {
	opts := validOptions()
	opts.Retries = -1
	_, err := NewScanner(opts)
	if err == nil {
		t.Error("NewScanner(retries=-1) expected error, got nil")
	}
}

func TestNewScanner_InvalidProxyAuth(t *testing.T) {
	// ProxyAuthentication must be "user:pass" format; missing colon → error
	opts := validOptions()
	opts.Proxy = "127.0.0.1:1080"
	opts.ProxyAuthentication = "invalidnocodon"
	_, err := NewScanner(opts)
	if err == nil {
		t.Error("NewScanner with invalid proxy auth expected error, got nil")
	}
}

func TestNewScanner_ZeroRetriesAllowed(t *testing.T) {
	// Retries=0 disables retry logic — should be valid
	opts := validOptions()
	opts.Retries = 0
	_, err := NewScanner(opts)
	if err != nil {
		t.Errorf("NewScanner(retries=0) unexpected error: %v", err)
	}
}

func TestNewScanner_IfaceEmptyBackwardCompat(t *testing.T) {
	// Iface="" should behave exactly as before (no binding) — no error
	opts := validOptions()
	opts.Iface = ""
	_, err := NewScanner(opts)
	if err != nil {
		t.Errorf("NewScanner(iface=\"\") unexpected error: %v", err)
	}
}

func TestNewScanner_IfaceInvalidFallsBack(t *testing.T) {
	// An invalid interface name logs a warning but NewScanner still succeeds
	opts := validOptions()
	opts.Iface = "nonexistent_iface_xyz"
	_, err := NewScanner(opts)
	if err != nil {
		t.Errorf("NewScanner with invalid iface should fall back gracefully, got: %v", err)
	}
}
