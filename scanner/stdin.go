package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/parser"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
	"github.com/vflame6/bruter/wordlists"
)

// RunStdin reads targets from an io.Reader (stdin), groups them by service,
// and runs matching modules in parallel — same logic as RunNmap.
func (s *Scanner) RunStdin(ctx context.Context, r io.Reader) error {
	targets, err := parser.ParseStdin(r)
	if err != nil {
		return fmt.Errorf("parsing stdin: %w", err)
	}
	if len(targets) == 0 {
		logger.Infof("no supported targets found on stdin")
		return nil
	}

	// Group targets by bruter module
	grouped := make(map[string][]parser.Target)
	for _, t := range targets {
		grouped[t.Service] = append(grouped[t.Service], t)
	}

	totalTargets := 0
	for _, tgts := range grouped {
		totalTargets += len(tgts)
	}
	logger.Infof("found %d targets across %d services from stdin", totalTargets, len(grouped))
	for svc, tgts := range grouped {
		logger.Infof("  %s: %d target(s)", svc, len(tgts))
	}

	// Pre-load usernames once (same for all modules)
	// -u and --defaults combine when both are specified
	if s.Opts.Usernames != "" {
		s.Opts.UsernameList = utils.LoadLines(s.Opts.Usernames)
	}
	if s.Opts.Defaults {
		s.Opts.UsernameList = append(s.Opts.UsernameList, wordlists.DefaultUsernames...)
	}

	// Pre-load passwords from file once (if user specified -p).
	// sshkey passwords are loaded lazily only when needed.
	var userPasswords []string
	if s.Opts.Passwords != "" {
		userPasswords = utils.LoadLines(s.Opts.Passwords)
	}
	var sshkeyPasswords []string
	var sshkeyLoaded bool

	// Run each module group
	for command, stdinTargets := range grouped {
		if ctx.Err() != nil {
			break
		}
		if s.Opts.GlobalStop && s.globalDone.Load() {
			break
		}

		mod, ok := modules.Modules[command]
		if !ok {
			logger.Debugf("skipping unknown module %s", command)
			continue
		}

		logger.Infof("executing %s module (%d targets)", command, len(stdinTargets))
		s.Opts.Command = command

		// Select passwords per module: combine user-specified + defaults when both present
		s.Opts.PasswordList = nil
		if command == "sshkey" {
			if !sshkeyLoaded && s.Opts.Passwords != "" {
				sshkeyPasswords = utils.LoadSSHKeyPaths(s.Opts.Passwords)
				sshkeyLoaded = true
			}
			if sshkeyPasswords != nil {
				s.Opts.PasswordList = append(s.Opts.PasswordList, sshkeyPasswords...)
			}
		} else if userPasswords != nil {
			s.Opts.PasswordList = append(s.Opts.PasswordList, userPasswords...)
		}
		if s.Opts.Defaults {
			if command == "sshkey" {
				s.Opts.PasswordList = append(s.Opts.PasswordList, wordlists.DefaultSSHKeys...)
			} else {
				s.Opts.PasswordList = append(s.Opts.PasswordList, wordlists.DefaultPasswords...)
			}
		}

		// Convert parser targets to scanner targets (resolve DNS)
		var scanTargets []*modules.Target
		for _, st := range stdinTargets {
			ip := net.ParseIP(st.Host)
			if ip == nil {
				resolved, err := utils.LookupAddr(st.Host)
				if err != nil {
					logger.Debugf("can't resolve %s: %v", st.Host, err)
					continue
				}
				ip = resolved
			}
			scanTargets = append(scanTargets, &modules.Target{
				IP:             ip,
				Port:           st.Port,
				OriginalTarget: net.JoinHostPort(st.Host, strconv.Itoa(st.Port)),
				Encryption:     true,
			})
		}

		if len(scanTargets) == 0 {
			continue
		}

		// Feed targets into channel
		targetCh := make(chan *modules.Target, len(scanTargets))
		for _, t := range scanTargets {
			targetCh <- t
		}
		close(targetCh)

		// Save and restore the main Targets channel
		origTargets := s.Targets
		s.Targets = targetCh

		// Determine parallelism for this batch
		parallel := s.Opts.Parallel
		if len(scanTargets) < parallel {
			parallel = len(scanTargets)
		}

		// Run parallel handlers
		var parallelWg sync.WaitGroup
		for i := 0; i < parallel; i++ {
			parallelWg.Add(1)
			go s.ParallelHandler(ctx, &parallelWg, &mod)
		}
		parallelWg.Wait()

		s.Targets = origTargets
	}

	// Close results channel so GetResults can finish draining.
	// The caller (RunStdinWithResults) waits for GetResults and prints stats.
	close(s.Results)

	return nil
}

// RunStdinWithResults is like RunStdin but manages the results goroutine internally.
func (s *Scanner) RunStdinWithResults(ctx context.Context, r io.Reader) error {
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go GetResults(s.Results, s.Opts.OutputFile, &resultsWg, &s.Successes, s.Opts.JSON)

	err := s.RunStdin(ctx, r)

	// Wait for all results to be processed before reading counters.
	resultsWg.Wait()
	s.Stop()

	logger.Infof("Done: %d credential pairs tried, %d successful logins found",
		s.Attempts.Load(), s.Successes.Load())

	return err
}
