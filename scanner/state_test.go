package scanner

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vflame6/bruter/scanner/modules"
)

func tempCheckpoint(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "bruter.state")
}

func TestStateKeySeparatesFields(t *testing.T) {
	// Without a separator, concatenation would make these identical.
	a := stateKey("10.0.0.1", "ssh", "ab", "c")
	b := stateKey("10.0.0.1", "ssh", "a", "bc")
	if a == b {
		t.Fatal("stateKey collides on field boundaries: fields are concatenated without a separator")
	}
}

func TestStateStoreRecordAndDone(t *testing.T) {
	store, err := OpenStateStore(tempCheckpoint(t))
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	if store.Done("10.0.0.1", "ssh", "root", "toor") {
		t.Fatal("a fresh checkpoint reported an attempt as already done")
	}

	store.Record("10.0.0.1", "ssh", "root", "toor")

	if !store.Done("10.0.0.1", "ssh", "root", "toor") {
		t.Error("recorded attempt is not reported as done")
	}
	if store.Done("10.0.0.2", "ssh", "root", "toor") {
		t.Error("a different host was reported as done")
	}
	if store.Done("10.0.0.1", "ftp", "root", "toor") {
		t.Error("a different service was reported as done")
	}
	if store.Done("10.0.0.1", "ssh", "root", "other") {
		t.Error("a different password was reported as done")
	}
}

func TestStateStoreSurvivesReopen(t *testing.T) {
	path := tempCheckpoint(t)

	first, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	if first.Loaded() != 0 {
		t.Fatalf("Loaded = %d on a new checkpoint, want 0", first.Loaded())
	}
	// More than stateFlushInterval, so both the flushed and buffered paths are
	// covered by the reopen.
	for i := 0; i < stateFlushInterval+5; i++ {
		first.Record("10.0.0.1", "ssh", "root", string(rune('a'+i%26))+time.Duration(i).String())
	}
	first.Record("10.0.0.1", "ssh", "root", "toor")
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = second.Close() }()

	if second.Loaded() != stateFlushInterval+6 {
		t.Errorf("Loaded = %d after reopen, want %d", second.Loaded(), stateFlushInterval+6)
	}
	if !second.Done("10.0.0.1", "ssh", "root", "toor") {
		t.Error("attempt recorded before Close was lost")
	}
}

func TestStateStoreToleratesTornFile(t *testing.T) {
	path := tempCheckpoint(t)

	// A process killed mid-write leaves a partial last line. Resuming must
	// still work rather than refusing to start.
	valid := stateKey("10.0.0.1", "ssh", "root", "toor")
	content := []byte("")
	content = append(content, []byte("0000000000000000\n")...)
	content = append(content, []byte(filepath.Base(""))...)
	content = append(content, []byte("not-a-hash\n")...)
	content = append(content, []byte("\n")...)
	content = append(content, []byte(hex16(valid))...)
	content = append(content, '\n')
	content = append(content, []byte("abc")...) // torn tail, no newline
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("OpenStateStore on a torn file: %v", err)
	}
	defer func() { _ = store.Close() }()

	if !store.Done("10.0.0.1", "ssh", "root", "toor") {
		t.Error("valid record before the torn tail was not loaded")
	}
}

func hex16(v uint64) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 16)
	for i := 15; i >= 0; i-- {
		out[i] = digits[v&0xf]
		v >>= 4
	}
	return string(out)
}

func TestStateStoreFileIsNotWorldReadable(t *testing.T) {
	path := tempCheckpoint(t)
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	store.Record("10.0.0.1", "ssh", "root", "toor")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("checkpoint mode = %o, want no group or other access", mode)
	}
}

func TestStateStoreNilIsInert(t *testing.T) {
	// Options.State is nil when --resume is not used; every call must be safe.
	var store *StateStore
	if store.Done("h", "s", "u", "p") {
		t.Error("nil store reported an attempt as done")
	}
	store.Record("h", "s", "u", "p")
	store.Flush()
	if err := store.Close(); err != nil {
		t.Errorf("Close on a nil store = %v", err)
	}
	if store.Loaded() != 0 {
		t.Error("Loaded on a nil store was not 0")
	}
}

func TestStateStoreConcurrentRecord(t *testing.T) {
	store, err := OpenStateStore(tempCheckpoint(t))
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pass := hex16(uint64(i))
			store.Record("10.0.0.1", "ssh", "root", pass)
			if !store.Done("10.0.0.1", "ssh", "root", pass) {
				t.Errorf("record %d not visible after Record returned", i)
			}
		}(i)
	}
	wg.Wait()
}

// --- resume behaviour in ThreadHandler ---

func TestThreadHandlerSkipsCheckpointedCredentials(t *testing.T) {
	store, err := OpenStateStore(tempCheckpoint(t))
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	store.Record("127.0.0.1", "ssh", "root", "already-tried")

	rec := &recorder{}
	s := newTestScanner(&Options{
		Threads: 1,
		Command: "ssh",
		State:   store,
	})

	target := newTestTarget("127.0.0.1", 22)
	creds := make(chan *modules.Credential, 4)
	creds <- &modules.Credential{Username: "root", Password: "already-tried"}
	creds <- &modules.Credential{Username: "root", Password: "fresh"}
	close(creds)

	var wg sync.WaitGroup
	wg.Add(1)
	go s.ThreadHandler(context.Background(), &wg, creds, rec.handler(), target)
	wg.Wait()

	entries := rec.snapshot()
	if len(entries) != 1 {
		t.Fatalf("handler ran %d times, want 1: the checkpointed pair should be skipped (%+v)", len(entries), entries)
	}
	if entries[0].Password != "fresh" {
		t.Errorf("handler tried %q, want the pair that was not in the checkpoint", entries[0].Password)
	}
	if s.Attempts.Load() != 1 {
		t.Errorf("Attempts = %d, want 1: skipped pairs must not count as attempts", s.Attempts.Load())
	}
}

func TestThreadHandlerRecordsEvaluatedCredentials(t *testing.T) {
	store, err := OpenStateStore(tempCheckpoint(t))
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	s := newTestScanner(&Options{
		Threads: 1,
		Command: "ssh",
		State:   store,
	})

	target := newTestTarget("127.0.0.1", 22)
	creds := make(chan *modules.Credential, 2)
	creds <- &modules.Credential{Username: "root", Password: "p1"}
	close(creds)

	var wg sync.WaitGroup
	wg.Add(1)
	go s.ThreadHandler(context.Background(), &wg, creds, mockHandler("nobody", "nothing"), target)
	wg.Wait()

	if !store.Done("127.0.0.1", "ssh", "root", "p1") {
		t.Error("an evaluated pair was not written to the checkpoint")
	}
}

func TestThreadHandlerDoesNotRecordErroredAttempts(t *testing.T) {
	store, err := OpenStateStore(tempCheckpoint(t))
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	s := newTestScanner(&Options{
		Threads: 1,
		Command: "ssh",
		Retries: 0,
		State:   store,
	})

	target := newTestTarget("127.0.0.1", 22)
	creds := make(chan *modules.Credential, 2)
	creds <- &modules.Credential{Username: "root", Password: "p1"}
	close(creds)

	var wg sync.WaitGroup
	wg.Add(1)
	go s.ThreadHandler(context.Background(), &wg, creds, errorHandler(), target)
	wg.Wait()

	// The connection failed, so the credential was never actually tested;
	// resuming has to try it again.
	if store.Done("127.0.0.1", "ssh", "root", "p1") {
		t.Error("a failed connection was checkpointed, so resume would skip an untested credential")
	}
}

func TestThreadHandlerSkipsPerAttemptDelayWhenSpraying(t *testing.T) {
	// In spray mode --delay is the gap between rounds. If ThreadHandler also
	// slept it per attempt, a round of n credentials would take n * delay.
	s := newTestScanner(&Options{
		Threads: 1,
		Command: "ssh",
		Delay:   300 * time.Millisecond,
		Spray:   true,
	})

	target := newTestTarget("127.0.0.1", 22)
	creds := make(chan *modules.Credential, 8)
	for i := 0; i < 5; i++ {
		creds <- &modules.Credential{Username: "root", Password: hex16(uint64(i))}
	}
	close(creds)

	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(1)
	go s.ThreadHandler(context.Background(), &wg, creds, mockHandler("nobody", "nothing"), target)
	wg.Wait()

	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Errorf("5 spray attempts took %s; --delay is being applied per attempt instead of per round", elapsed)
	}
}

func TestThreadHandlerAppliesPerAttemptDelayWhenNotSpraying(t *testing.T) {
	s := newTestScanner(&Options{
		Threads: 1,
		Command: "ssh",
		Delay:   40 * time.Millisecond,
	})

	target := newTestTarget("127.0.0.1", 22)
	creds := make(chan *modules.Credential, 4)
	for i := 0; i < 3; i++ {
		creds <- &modules.Credential{Username: "root", Password: hex16(uint64(i))}
	}
	close(creds)

	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(1)
	go s.ThreadHandler(context.Background(), &wg, creds, mockHandler("nobody", "nothing"), target)
	wg.Wait()

	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("3 attempts with a 40ms delay took only %s; --delay is not being applied", elapsed)
	}
}

// --- resume interaction with the spray budget ---

func TestRunSprayDoesNotSpendBudgetOnCheckpointedPairs(t *testing.T) {
	store, err := OpenStateStore(tempCheckpoint(t))
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	// alice:p1 was already tried last run. With a cap of 1 she must still get
	// her one attempt, spent on p2 rather than wasted re-trying p1.
	store.Record("127.0.0.1:9", "spraytest-resume", "alice", "p1")

	rec := &recorder{}
	registerTestModule(t, "spraytest-resume", modules.Module{
		DefaultPort: 9, Handler: rec.handler(),
		DefaultUsername: "svc", DefaultPassword: "svc",
	})

	s := newSprayScanner(&Options{
		Parallel: 1, Threads: 1, Timeout: time.Second,
		Delay:              time.Millisecond,
		Order:              OrderPassword,
		Spray:              true,
		NoStats:            true,
		MaxAttemptsPerUser: 1,
		UsernameList:       []string{"alice"},
		PasswordList:       []string{"p1", "p2"},
		State:              store,
	})

	if err := s.RunSpray(context.Background(), "spraytest-resume", "127.0.0.1:9"); err != nil {
		t.Fatalf("RunSpray: %v", err)
	}

	var tried []string
	for _, entry := range rec.snapshot() {
		if entry.Username == "alice" {
			tried = append(tried, entry.Password)
		}
	}

	if len(tried) != 1 {
		t.Fatalf("alice was tried %d times (%v), want exactly 1 under a cap of 1", len(tried), tried)
	}
	if tried[0] != "p2" {
		t.Errorf("alice's one attempt was spent on %q; p1 was already in the checkpoint", tried[0])
	}
}

// --- review follow-ups ---

func TestStateStoreAppendsCleanlyAfterATornLine(t *testing.T) {
	path := tempCheckpoint(t)

	// A process killed between a write and its flush leaves a partial line.
	// Appending straight onto it would corrupt the next record too.
	first := hex16(stateKey("10.0.0.1", "ssh", "root", "one"))
	if err := os.WriteFile(path, []byte(first+"\nabcdef"), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	store.Record("10.0.0.1", "ssh", "root", "two")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	if !reopened.Done("10.0.0.1", "ssh", "root", "two") {
		t.Error("the record written after a torn line was lost on reload")
	}
	if !reopened.Done("10.0.0.1", "ssh", "root", "one") {
		t.Error("the intact record before the torn line was lost")
	}
}

func TestStateStoreRecordAfterCloseDoesNotPanic(t *testing.T) {
	store, err := OpenStateStore(tempCheckpoint(t))
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Nothing in the current call graph does this, but nothing stops it
	// either, and a nil writer would panic.
	store.Record("10.0.0.1", "ssh", "root", "toor")
	store.Flush()
	if err := store.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
}

func TestStateStoreReportsWriteFailureOnce(t *testing.T) {
	store, err := OpenStateStore(tempCheckpoint(t))
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Close the underlying file behind the writer's back to simulate a disk
	// that has stopped accepting writes.
	store.mu.Lock()
	underlying := store.file
	store.mu.Unlock()
	_ = underlying.Close()

	for i := 0; i < stateFlushInterval*2; i++ {
		store.Record("10.0.0.1", "ssh", "root", hex16(uint64(i)))
	}
	store.Flush()

	store.mu.Lock()
	failed := store.failed
	store.mu.Unlock()

	if !failed {
		t.Error("a checkpoint that cannot be written was not marked failed, so the run would look fine")
	}
	// The in-memory set must still work so the current run skips duplicates.
	if !store.Done("10.0.0.1", "ssh", "root", hex16(0)) {
		t.Error("the in-memory record set stopped working after a write failure")
	}
}
