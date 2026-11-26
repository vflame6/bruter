package scanner

import (
	"bufio"
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/vflame6/bruter/logger"
)

// stateFlushInterval is how many records are buffered before the checkpoint is
// pushed to disk. A killed run loses at most this many records, which costs
// only a handful of repeated attempts on resume.
const stateFlushInterval = 128

// StateStore is an append-only checkpoint of evaluated credentials. It backs
// --resume: a run that dies after six hours picks up where it stopped instead
// of starting over.
//
// Records are the 64-bit FNV-1a hash of (host, service, username, password),
// not the values. A long run evaluates millions of pairs, and writing them
// verbatim would leave a complete list of every password tried sitting on
// disk. Hashing also keeps the file to 17 bytes per attempt. The cost is that
// a hash collision silently skips one attempt, which at 64 bits is not worth
// guarding against.
type StateStore struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	writer  *bufio.Writer
	done    map[uint64]struct{}
	pending int
	loaded  int

	// needsNewline is set when the file on disk ended mid-line, which happens
	// when the previous run was killed between a write and its flush.
	needsNewline bool

	// failed records that the checkpoint can no longer be written, so the
	// operator is told once rather than discovering it on the next resume.
	failed bool
}

// OpenStateStore loads an existing checkpoint, if the file is there, and opens
// it for appending. The returned store is safe for concurrent use.
func OpenStateStore(path string) (*StateStore, error) {
	s := &StateStore{path: path, done: make(map[uint64]struct{})}

	existing, err := os.Open(path)
	switch {
	case err == nil:
		if loadErr := s.load(existing); loadErr != nil {
			_ = existing.Close()
			return nil, fmt.Errorf("read checkpoint %s: %w", path, loadErr)
		}
		_ = existing.Close()
		s.loaded = len(s.done)
	case os.IsNotExist(err):
		// first run with this checkpoint
	default:
		return nil, fmt.Errorf("open checkpoint %s: %w", path, err)
	}

	// 0600: the checkpoint belongs to the operator, not the whole machine.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open checkpoint %s for append: %w", path, err)
	}

	s.file = file
	s.writer = bufio.NewWriter(file)
	return s, nil
}

func (s *StateStore) load(f *os.File) error {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, err := strconv.ParseUint(line, 16, 64)
		if err != nil {
			// A torn last line is normal after a kill; skip it rather than
			// refusing to resume.
			logger.Debugf("ignoring unreadable checkpoint record %q", line)
			continue
		}
		s.done[key] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// A run killed between a write and its flush leaves a partial final line.
	// Appending straight onto it would glue the next hash to the fragment and
	// lose that record as well, so note it and start a fresh line first.
	if info, err := f.Stat(); err == nil && info.Size() > 0 {
		var tail [1]byte
		if _, err := f.ReadAt(tail[:], info.Size()-1); err == nil && tail[0] != '\n' {
			s.needsNewline = true
		}
	}
	return nil
}

// Loaded reports how many attempts the checkpoint already held when it was
// opened.
func (s *StateStore) Loaded() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loaded
}

// Done reports whether this exact attempt has already been evaluated.
func (s *StateStore) Done(host, service, username, password string) bool {
	if s == nil {
		return false
	}
	key := stateKey(host, service, username, password)

	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.done[key]
	return ok
}

// Record marks an attempt as evaluated. Only attempts that actually reached
// the service should be recorded: a connection error means the credential was
// never tested, and resuming must try it again.
func (s *StateStore) Record(host, service, username, password string) {
	if s == nil {
		return
	}
	key := stateKey(host, service, username, password)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.done[key]; ok {
		return
	}
	s.done[key] = struct{}{}

	// Closed, or already broken: keep the in-memory set current so the rest of
	// this run still skips duplicates, but do not touch the writer.
	if s.writer == nil || s.failed {
		return
	}

	if s.needsNewline {
		if _, err := s.writer.WriteString("\n"); err != nil {
			s.markFailed(err)
			return
		}
		s.needsNewline = false
	}

	if _, err := fmt.Fprintf(s.writer, "%016x\n", key); err != nil {
		s.markFailed(err)
		return
	}

	s.pending++
	if s.pending >= stateFlushInterval {
		s.flushLocked()
	}
}

// markFailed reports a checkpoint that can no longer be written. Saying this
// once and loudly matters: the whole point of --resume is not having to redo
// the work, and a full disk would otherwise stop recording in silence.
func (s *StateStore) markFailed(err error) {
	if s.failed {
		return
	}
	s.failed = true
	logger.Failf("checkpoint %s can no longer be written (%v); --resume will not cover the rest of this run", s.path, err)
}

// Flush pushes buffered records to disk.
func (s *StateStore) Flush() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushLocked()
}

func (s *StateStore) flushLocked() {
	if s.writer == nil {
		return
	}
	if err := s.writer.Flush(); err != nil {
		s.markFailed(err)
		return
	}
	s.pending = 0
}

// Close flushes the checkpoint and releases the file.
func (s *StateStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.flushLocked()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	s.writer = nil
	return err
}

// stateKey hashes one attempt. The NUL separator stops ("ab","c") from
// colliding with ("a","bc").
func stateKey(host, service, username, password string) uint64 {
	h := fnv.New64a()
	for _, part := range []string{host, service, username, password} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}
