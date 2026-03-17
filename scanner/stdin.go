package scanner

import (
	"context"
	"fmt"
	"io"

	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/parser"
)

// RunStdin reads targets from an io.Reader (stdin), groups them by host,
// and runs matching modules — same host-first architecture as RunNmap.
func (s *Scanner) RunStdin(ctx context.Context, r io.Reader) error {
	targets, err := parser.ParseStdin(r)
	if err != nil {
		return fmt.Errorf("parsing stdin: %w", err)
	}
	if len(targets) == 0 {
		logger.Infof("no supported targets found on stdin")
		return nil
	}

	return s.runAllMode(ctx, "stdin", targets)
}

// RunStdinWithResults is like RunStdin but manages the results goroutine internally.
func (s *Scanner) RunStdinWithResults(ctx context.Context, r io.Reader) error {
	return s.runWithResults(ctx, func() error {
		return s.RunStdin(ctx, r)
	})
}
