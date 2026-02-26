package scanner

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
)

// mockHandler returns a ModuleHandler that succeeds for a specific credential pair.
func mockHandler(successUser, successPass string) modules.ModuleHandler {
	return func(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *modules.Target, cred *modules.Credential) (bool, error) {
		if cred.Username == successUser && cred.Password == successPass {
			return true, nil
		}
		return false, nil
	}
}

// alwaysFailHandler returns false with no error (reachable but no match).
func alwaysFailHandler() modules.ModuleHandler {
	return func(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *modules.Target, cred *modules.Credential) (bool, error) {
		return false, nil
	}
}

// errorHandler returns an error on every attempt.
func errorHandler() modules.ModuleHandler {
	return func(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *modules.Target, cred *modules.Credential) (bool, error) {
		return false, net.UnknownNetworkError("mock error")
	}
}

// countingHandler counts how many times it's called.
func countingHandler(counter *atomic.Int64) modules.ModuleHandler {
	return func(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *modules.Target, cred *modules.Credential) (bool, error) {
		counter.Add(1)
		return false, nil
	}
}

func newTestTarget(ip string, port int) *modules.Target {
	return &modules.Target{
		IP:             net.ParseIP(ip),
		Port:           port,
		OriginalTarget: ip,
		Encryption:     true,
	}
}

func newTestScanner(opts *Options) *Scanner {
	if opts.Parallel == 0 {
		opts.Parallel = 1
	}
	if opts.Threads == 0 {
		opts.Threads = 1
	}
	return &Scanner{
		Opts:    opts,
		Targets: make(chan *modules.Target, 10),
		Results: make(chan *Result, 10),
	}
}

// --- ThreadHandler tests ---

func TestThreadHandler_BasicSuccess(t *testing.T) {
	s := newTestScanner(&Options{
		Threads: 1,
	})

	handler := mockHandler("admin", "pass123")
	target := newTestTarget("127.0.0.1", 22)

	creds := make(chan *modules.Credential, 3)
	creds <- &modules.Credential{Username: "admin", Password: "wrong"}
	creds <- &modules.Credential{Username: "admin", Password: "pass123"}
	creds <- &modules.Credential{Username: "admin", Password: "other"}
	close(creds)

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	go s.ThreadHandler(ctx, &wg, creds, handler, target)
	wg.Wait()

	if s.Attempts.Load() != 3 {
		t.Errorf("attempts = %d, want 3", s.Attempts.Load())
	}
	// Should have one result
	select {
	case r := <-s.Results:
		if r.Username != "admin" || r.Password != "pass123" {
			t.Errorf("unexpected result: %s:%s", r.Username, r.Password)
		}
	default:
		t.Error("expected a result, got none")
	}
}

func TestThreadHandler_ContextCancellation(t *testing.T) {
	var counter atomic.Int64
	// Slow handler so cancellation has time to fire
	handler := func(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *modules.Target, cred *modules.Credential) (bool, error) {
		counter.Add(1)
		time.Sleep(2 * time.Millisecond)
		return false, nil
	}

	s := newTestScanner(&Options{Threads: 1})
	target := newTestTarget("127.0.0.1", 22)

	creds := make(chan *modules.Credential, 200)
	for i := 0; i < 200; i++ {
		creds <- &modules.Credential{Username: "user", Password: "pass"}
	}
	close(creds)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go s.ThreadHandler(ctx, &wg, creds, handler, target)
	wg.Wait()

	if counter.Load() >= 200 {
		t.Errorf("expected cancellation to stop early, but processed all %d", counter.Load())
	}
}

func TestThreadHandler_StopOnSuccess(t *testing.T) {
	s := newTestScanner(&Options{
		Threads:       1,
		StopOnSuccess: true,
	})

	// Handler succeeds on first cred
	handler := mockHandler("admin", "found")
	target := newTestTarget("127.0.0.1", 22)

	creds := make(chan *modules.Credential, 5)
	creds <- &modules.Credential{Username: "admin", Password: "found"}
	creds <- &modules.Credential{Username: "admin", Password: "extra1"}
	creds <- &modules.Credential{Username: "admin", Password: "extra2"}
	close(creds)

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	go s.ThreadHandler(ctx, &wg, creds, handler, target)
	wg.Wait()

	// With StopOnSuccess, after first success, target.Success=true → thread breaks
	if s.Attempts.Load() > 2 {
		t.Errorf("StopOnSuccess: expected ≤2 attempts, got %d", s.Attempts.Load())
	}
	if !target.Success {
		t.Error("target.Success should be true")
	}
}

func TestThreadHandler_GlobalStop(t *testing.T) {
	s := newTestScanner(&Options{
		Threads:    1,
		GlobalStop: true,
	})

	handler := mockHandler("admin", "found")
	target := newTestTarget("127.0.0.1", 22)

	creds := make(chan *modules.Credential, 5)
	creds <- &modules.Credential{Username: "admin", Password: "found"}
	creds <- &modules.Credential{Username: "admin", Password: "extra1"}
	creds <- &modules.Credential{Username: "admin", Password: "extra2"}
	close(creds)

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	go s.ThreadHandler(ctx, &wg, creds, handler, target)
	wg.Wait()

	if !s.globalDone.Load() {
		t.Error("globalDone should be true after success with GlobalStop")
	}
	// Should have stopped early
	if s.Attempts.Load() > 2 {
		t.Errorf("GlobalStop: expected ≤2 attempts, got %d", s.Attempts.Load())
	}
}

func TestThreadHandler_RetryLimit(t *testing.T) {
	s := newTestScanner(&Options{
		Threads: 1,
		Retries: 3,
	})

	handler := errorHandler()
	target := newTestTarget("127.0.0.1", 22)

	creds := make(chan *modules.Credential, 10)
	for i := 0; i < 10; i++ {
		creds <- &modules.Credential{Username: "user", Password: "pass"}
	}
	close(creds)

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	go s.ThreadHandler(ctx, &wg, creds, handler, target)
	wg.Wait()

	// Should stop after retries exceeded
	if s.Attempts.Load() > 4 {
		t.Errorf("RetryLimit: expected ≤4 attempts (3 retries + 1 that sees limit), got %d", s.Attempts.Load())
	}
	if target.Retries < 3 {
		t.Errorf("target.Retries = %d, want ≥3", target.Retries)
	}
}

// --- SendCredentials tests ---

func TestSendCredentials_AllSent(t *testing.T) {
	users := []string{"a", "b"}
	passwords := []string{"1", "2", "3"}
	creds := make(chan *modules.Credential, 10)
	done := make(chan struct{})

	ctx := context.Background()
	SendCredentials(ctx, creds, users, passwords, nil, done)

	var count int
	for range creds {
		count++
	}
	if count != 6 {
		t.Errorf("expected 6 credential pairs, got %d", count)
	}
}

func TestSendCredentials_DoneChannelStopsEarly(t *testing.T) {
	users := make([]string, 100)
	passwords := make([]string, 100)
	for i := range users {
		users[i] = "u"
		passwords[i] = "p"
	}

	creds := make(chan *modules.Credential) // unbuffered to block
	done := make(chan struct{})

	go func() {
		time.Sleep(10 * time.Millisecond)
		close(done)
	}()

	ctx := context.Background()
	SendCredentials(ctx, creds, users, passwords, nil, done)

	// Channel should be closed now
	_, ok := <-creds
	if ok {
		t.Error("expected credentials channel to be closed after done signal")
	}
}

func TestSendCredentials_ContextCancellation(t *testing.T) {
	users := make([]string, 100)
	passwords := make([]string, 100)
	for i := range users {
		users[i] = "u"
		passwords[i] = "p"
	}

	creds := make(chan *modules.Credential) // unbuffered
	done := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	SendCredentials(ctx, creds, users, passwords, nil, done)

	_, ok := <-creds
	if ok {
		t.Error("expected credentials channel to be closed after context cancellation")
	}
}

// --- ParallelHandler tests ---

func TestParallelHandler_DispatchesToTarget(t *testing.T) {
	handler := mockHandler("default", "default")
	module := &modules.Module{
		DefaultPort:     22,
		Handler:         handler,
		DefaultUsername: "default",
		DefaultPassword: "default",
	}

	s := newTestScanner(&Options{
		Parallel:     1,
		Threads:      1,
		UsernameList: []string{"admin"},
		PasswordList: []string{"pass"},
	})

	target := newTestTarget("127.0.0.1", 22)

	go func() {
		s.Targets <- target
		close(s.Targets)
	}()

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	go s.ParallelHandler(ctx, &wg, module)
	wg.Wait()
	close(s.Results)

	var results []Result
	for r := range s.Results {
		results = append(results, *r)
	}

	// probe succeeds with default creds → at least one result
	if len(results) == 0 {
		t.Error("expected at least one result from ParallelHandler")
	}
}

func TestParallelHandler_GlobalStopStopsProcessing(t *testing.T) {
	// Handler always succeeds
	handler := func(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *modules.Target, cred *modules.Credential) (bool, error) {
		return true, nil
	}

	module := &modules.Module{
		DefaultPort:     22,
		Handler:         handler,
		DefaultUsername: "root",
		DefaultPassword: "root",
	}

	s := newTestScanner(&Options{
		Parallel:     1,
		Threads:      1,
		GlobalStop:   true,
		UsernameList: []string{"a"},
		PasswordList: []string{"b"},
	})

	// Send multiple targets
	go func() {
		for i := 0; i < 5; i++ {
			s.Targets <- newTestTarget("127.0.0.1", 22+i)
		}
		close(s.Targets)
	}()

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	go s.ParallelHandler(ctx, &wg, module)

	// Drain results
	go func() {
		for range s.Results {
		}
	}()

	wg.Wait()
	close(s.Results)

	if !s.globalDone.Load() {
		t.Error("globalDone should be set")
	}
}

func TestParallelHandler_ContextCancellation(t *testing.T) {
	var callCount atomic.Int64
	handler := func(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *modules.Target, cred *modules.Credential) (bool, error) {
		callCount.Add(1)
		return false, nil
	}

	module := &modules.Module{
		DefaultPort:     22,
		Handler:         handler,
		DefaultUsername: "root",
		DefaultPassword: "root",
	}

	s := newTestScanner(&Options{
		Parallel:     1,
		Threads:      1,
		UsernameList: []string{"a", "b", "c"},
		PasswordList: []string{"1", "2", "3"},
	})

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for i := 0; i < 20; i++ {
			select {
			case s.Targets <- newTestTarget("127.0.0.1", 22):
			case <-ctx.Done():
				break
			}
		}
		close(s.Targets)
	}()

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go s.ParallelHandler(ctx, &wg, module)

	go func() {
		for range s.Results {
		}
	}()

	wg.Wait()
	close(s.Results)
	// If we got here, context cancellation worked (didn't hang)
}

// --- NewScanner validation tests ---

func TestNewScanner_InvalidConcurrency(t *testing.T) {
	_, err := NewScanner(&Options{Parallel: 0, Threads: 1})
	if err == nil {
		t.Error("expected error for Parallel=0")
	}

	_, err = NewScanner(&Options{Parallel: 1, Threads: 0})
	if err == nil {
		t.Error("expected error for Threads=0")
	}

	_, err = NewScanner(&Options{Parallel: -1, Threads: 1})
	if err == nil {
		t.Error("expected error for negative Parallel")
	}
}

func TestNewScanner_InvalidRetries(t *testing.T) {
	_, err := NewScanner(&Options{Parallel: 1, Threads: 1, Retries: -1})
	if err == nil {
		t.Error("expected error for negative Retries")
	}
}

func TestNewScanner_ValidOptions(t *testing.T) {
	s, err := NewScanner(&Options{Parallel: 2, Threads: 4, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Opts.Parallel != 2 {
		t.Errorf("Parallel = %d, want 2", s.Opts.Parallel)
	}
}

// --- ParseTarget tests ---

func TestParseTarget_IPv4WithPort(t *testing.T) {
	target, err := ParseTarget("127.0.0.1:8080", 22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Port != 8080 {
		t.Errorf("port = %d, want 8080", target.Port)
	}
	if !target.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IP = %v, want 127.0.0.1", target.IP)
	}
}

func TestParseTarget_IPv4DefaultPort(t *testing.T) {
	target, err := ParseTarget("127.0.0.1", 22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Port != 22 {
		t.Errorf("port = %d, want 22", target.Port)
	}
}

func TestParseTarget_IPv6WithPort(t *testing.T) {
	target, err := ParseTarget("[::1]:443", 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Port != 443 {
		t.Errorf("port = %d, want 443", target.Port)
	}
	if !target.IP.Equal(net.ParseIP("::1")) {
		t.Errorf("IP = %v, want ::1", target.IP)
	}
}

func TestParseTarget_IPv6DefaultPort(t *testing.T) {
	target, err := ParseTarget("::1", 22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Port != 22 {
		t.Errorf("port = %d, want 22", target.Port)
	}
}

func TestParseTarget_InvalidPort(t *testing.T) {
	_, err := ParseTarget("127.0.0.1:99999", 22)
	if err == nil {
		t.Error("expected error for port > 65535")
	}

	_, err = ParseTarget("127.0.0.1:0", 22)
	if err == nil {
		t.Error("expected error for port 0")
	}
}

func TestParseTarget_EncryptionDefault(t *testing.T) {
	target, err := ParseTarget("127.0.0.1", 22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !target.Encryption {
		t.Error("Encryption should default to true")
	}
}

// --- probe tests ---

func TestProbe_SuccessWithEncryption(t *testing.T) {
	handler := mockHandler("root", "root")
	module := &modules.Module{
		Handler:         handler,
		DefaultUsername: "root",
		DefaultPassword: "root",
	}

	s := newTestScanner(&Options{Threads: 1})
	target := newTestTarget("127.0.0.1", 22)

	reachable, defaultCreds := s.probe(context.Background(), module, target)
	if !reachable {
		t.Error("expected reachable=true")
	}
	if !defaultCreds {
		t.Error("expected defaultCreds=true")
	}
	if !target.Success {
		t.Error("target.Success should be true")
	}
}

func TestProbe_FallbackToPlaintext(t *testing.T) {
	callCount := 0
	// First call (encrypted) fails, second call (plaintext) succeeds
	handler := func(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *modules.Target, cred *modules.Credential) (bool, error) {
		callCount++
		if target.Encryption {
			return false, net.UnknownNetworkError("tls failed")
		}
		return false, nil // reachable but no default creds match
	}

	module := &modules.Module{
		Handler:         handler,
		DefaultUsername: "root",
		DefaultPassword: "root",
	}

	s := newTestScanner(&Options{Threads: 1})
	target := newTestTarget("127.0.0.1", 22)

	reachable, defaultCreds := s.probe(context.Background(), module, target)
	if !reachable {
		t.Error("expected reachable=true on plaintext fallback")
	}
	if defaultCreds {
		t.Error("expected defaultCreds=false")
	}
	if target.Encryption {
		t.Error("encryption should be false after fallback")
	}
	if callCount != 2 {
		t.Errorf("expected 2 handler calls, got %d", callCount)
	}
}

func TestProbe_Unreachable(t *testing.T) {
	handler := errorHandler()
	module := &modules.Module{
		Handler:         handler,
		DefaultUsername: "root",
		DefaultPassword: "root",
	}

	s := newTestScanner(&Options{Threads: 1})
	target := newTestTarget("127.0.0.1", 22)

	reachable, _ := s.probe(context.Background(), module, target)
	if reachable {
		t.Error("expected reachable=false")
	}
}

// --- Stop test ---

func TestStop_ClosesOutputFile(t *testing.T) {
	f, err := os.CreateTemp("", "bruter_stop_test_*")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(f.Name())

	s := newTestScanner(&Options{Threads: 1, OutputFile: f})
	s.Stop()

	if s.Opts.OutputFile != nil {
		t.Error("OutputFile should be nil after Stop")
	}
	// Double stop should not panic
	s.Stop()
}

// --- SendTargets test ---

func TestSendTargets_ContextCancellation(t *testing.T) {
	// Create a temp file with many targets
	targets := make(chan *modules.Target, 5)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Use a bare IP (no file)
	go SendTargets(ctx, targets, 22, "127.0.0.1")

	var count int
	for range targets {
		count++
	}
	// With cancelled context, should process very few or zero
	if count > 1 {
		t.Errorf("expected ≤1 targets with cancelled context, got %d", count)
	}
}
