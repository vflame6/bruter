package scanner

import (
	"context"
	"io"
	"sync"

	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/parser"
)

// RunStdin reads targets from an io.Reader (stdin), groups them by host,
// and runs matching modules — same host-first architecture as RunNmap.
func (s *Scanner) RunStdin(ctx context.Context, r io.Reader) error {
	targets, err := parser.ParseStdin(r)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		logger.Infof("no supported targets found on stdin")
		return nil
	}

	// Print service summary
	serviceCounts := make(map[string]int)
	for _, t := range targets {
		serviceCounts[t.Service]++
	}
	logger.Infof("found %d targets across %d services from stdin", len(targets), len(serviceCounts))
	for svc, count := range serviceCounts {
		logger.Infof("  %s: %d target(s)", svc, count)
	}

	// Pre-load credentials
	s.loadCredentials()

	// Build per-module password lists
	defaultPasswords, sshkeyPasswords := s.buildPasswordLists()

	// Print dashboard
	if !logger.IsQuiet() {
		s.printNmapConfig("stdin", len(targets), len(serviceCounts))
	}

	// Group by host and process with same architecture as RunNmap
	hostGroups := s.groupByHost(targets)

	uniqueHosts := len(hostGroups)
	logger.Infof("scanning %d unique hosts", uniqueHosts)

	parallel := s.Opts.Parallel
	if uniqueHosts < parallel {
		parallel = uniqueHosts
	}

	hostCh := make(chan []hostService, parallel*BufferMultiplier)
	go func() {
		for _, services := range hostGroups {
			select {
			case hostCh <- services:
			case <-ctx.Done():
				break
			}
		}
		close(hostCh)
	}()

	var hostWg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		hostWg.Add(1)
		go func() {
			defer hostWg.Done()
			for services := range hostCh {
				if ctx.Err() != nil {
					return
				}
				if s.Opts.GlobalStop && s.globalDone.Load() {
					return
				}
				s.processHost(ctx, services, defaultPasswords, sshkeyPasswords)
			}
		}()
	}

	hostWg.Wait()
	close(s.Results)

	return nil
}

// RunStdinWithResults is like RunStdin but manages the results goroutine internally.
func (s *Scanner) RunStdinWithResults(ctx context.Context, r io.Reader) error {
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go GetResults(s.Results, s.Opts.OutputFile, &resultsWg, s.Successes, s.Opts.JSON)

	// Start progress display (disabled in quiet mode).
	var progress *Progress
	if !logger.IsQuiet() {
		totalCreds := int64(len(s.Opts.UsernameList))*int64(len(s.Opts.PasswordList)) + int64(len(s.Opts.ComboList))
		progress = NewProgress(s, totalCreds)
		logger.SetProgressClearer(progress.Clear)
		progress.Start()
	}

	err := s.RunStdin(ctx, r)

	if progress != nil {
		progress.Stop()
		logger.SetProgressClearer(nil)
	}

	resultsWg.Wait()
	s.Stop()

	logger.Infof("Done: %d credential pairs tried, %d successful logins found",
		s.Attempts.Load(), s.Successes.Load())

	if ctx.Err() != nil {
		logger.Infof("Interrupted")
	}

	return err
}
