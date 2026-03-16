package scanner

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/wordlists"
	"github.com/vflame6/bruter/parser"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
)

// RunNmap parses an nmap output file and runs bruter against all discovered
// services in parallel, grouped by module.
func (s *Scanner) RunNmap(ctx context.Context, nmapFile string) error {
	targets, err := parser.ParseFile(nmapFile, parser.FormatUnknown)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		logger.Infof("no supported services found in %s", nmapFile)
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
	logger.Infof("found %d targets across %d services in %s", totalTargets, len(grouped), nmapFile)
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
	if s.Opts.Passwords != "" {
		sshkeyPasswords = utils.LoadSSHKeyPaths(s.Opts.Passwords)
	}

	// Build default password list (non-sshkey) once
	var defaultPasswords []string
	if userPasswords != nil {
		defaultPasswords = append(defaultPasswords, userPasswords...)
	}
	if s.Opts.Defaults {
		defaultPasswords = append(defaultPasswords, wordlists.DefaultPasswords...)
	}
	// Set PasswordList for the dashboard (shows non-sshkey count)
	s.Opts.PasswordList = defaultPasswords

	// Print aggregate dashboard
	if !logger.IsQuiet() {
		s.printNmapConfig(nmapFile, totalTargets, len(grouped))
	}

	// Run modules concurrently, bounded by ConcurrentServices semaphore
	sem := make(chan struct{}, s.Opts.ConcurrentServices)
	var moduleWg sync.WaitGroup

	for command, nmapTargets := range grouped {
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

		// Build per-module password list to avoid race conditions
		var passwords []string
		if command == "sshkey" {
			if sshkeyPasswords != nil {
				passwords = append(passwords, sshkeyPasswords...)
			}
			if s.Opts.Defaults {
				passwords = append(passwords, wordlists.DefaultSSHKeys...)
			}
		} else {
			passwords = defaultPasswords
		}

		// Convert parser targets to scanner targets (resolve DNS)
		var scanTargets []*modules.Target
		for _, nt := range nmapTargets {
			ip := net.ParseIP(nt.Host)
			if ip == nil {
				resolved, resolveErr := utils.LookupAddr(nt.Host)
				if resolveErr != nil {
					logger.Debugf("can't resolve %s: %v", nt.Host, resolveErr)
					continue
				}
				ip = resolved
			}
			scanTargets = append(scanTargets, &modules.Target{
				IP:             ip,
				Port:           nt.Port,
				OriginalTarget: net.JoinHostPort(nt.Host, strconv.Itoa(nt.Port)),
				Encryption:     true,
			})
		}

		if len(scanTargets) == 0 {
			continue
		}

		// Acquire semaphore slot
		sem <- struct{}{}
		moduleWg.Add(1)

		go func(command string, mod modules.Module, scanTargets []*modules.Target, passwords []string) {
			defer moduleWg.Done()
			defer func() { <-sem }()

			logger.Infof("executing %s module (%d targets)", command, len(scanTargets))

			// Feed targets into channel
			targetCh := make(chan *modules.Target, len(scanTargets))
			for _, t := range scanTargets {
				targetCh <- t
			}
			close(targetCh)

			// Create a per-module scanner copy for thread-safe options
			modScanner := *s
			modOpts := *s.Opts
			modOpts.Command = command
			modOpts.PasswordList = passwords
			modScanner.Opts = &modOpts
			modScanner.Targets = targetCh

			// Determine parallelism for this batch
			parallel := modOpts.Parallel
			if len(scanTargets) < parallel {
				parallel = len(scanTargets)
			}

			// Run parallel handlers
			var parallelWg sync.WaitGroup
			for i := 0; i < parallel; i++ {
				parallelWg.Add(1)
				go modScanner.ParallelHandler(ctx, &parallelWg, &mod)
			}
			parallelWg.Wait()
		}(command, mod, scanTargets, passwords)
	}

	moduleWg.Wait()

	// Close results channel so GetResults can finish draining.
	// The caller (RunNmapWithResults) waits for GetResults and prints stats.
	close(s.Results)

	return nil
}

// RunNmapWithResults is like RunNmap but manages the results goroutine internally.
func (s *Scanner) RunNmapWithResults(ctx context.Context, nmapFile string) error {
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go GetResults(s.Results, s.Opts.OutputFile, &resultsWg, &s.Successes, s.Opts.JSON)

	// Start progress display (disabled in quiet mode).
	// totalCreds is approximate — uses default password list, actual may vary for sshkey.
	var progress *Progress
	if !logger.IsQuiet() {
		totalCreds := int64(len(s.Opts.UsernameList))*int64(len(s.Opts.PasswordList)) + int64(len(s.Opts.ComboList))
		progress = NewProgress(s, totalCreds)
		logger.SetProgressClearer(progress.Clear)
		progress.Start()
	}

	err := s.RunNmap(ctx, nmapFile)

	// Stop progress display before printing final stats
	if progress != nil {
		progress.Stop()
		logger.SetProgressClearer(nil)
	}

	// Wait for all results to be processed before reading counters.
	resultsWg.Wait()
	s.Stop()

	logger.Infof("Done: %d credential pairs tried, %d successful logins found",
		s.Attempts.Load(), s.Successes.Load())

	if ctx.Err() != nil {
		logger.Infof("Interrupted")
	}

	return err
}

// NmapSummary returns a formatted summary of what would be scanned from an nmap file.
func NmapSummary(nmapFile string) (string, error) {
	targets, err := parser.ParseFile(nmapFile, parser.FormatUnknown)
	if err != nil {
		return "", err
	}
	if len(targets) == 0 {
		return "no supported services found", nil
	}

	grouped := make(map[string]int)
	for _, t := range targets {
		grouped[t.Service]++
	}

	summary := fmt.Sprintf("%d targets across %d services:\n", len(targets), len(grouped))
	for svc, count := range grouped {
		summary += fmt.Sprintf("  %s: %d\n", svc, count)
	}
	return summary, nil
}
