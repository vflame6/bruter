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

	logger.Infof("found %d targets across %d services in %s", len(targets), len(grouped), nmapFile)
	for svc, tgts := range grouped {
		logger.Infof("  %s: %d target(s)", svc, len(tgts))
	}

	// Pre-load credentials once
	if s.Opts.Usernames != "" {
		s.Opts.UsernameList = utils.LoadLines(s.Opts.Usernames)
	} else if s.Opts.Defaults {
		s.Opts.UsernameList = wordlists.DefaultUsernames
	}
	if s.Opts.Passwords != "" {
		s.Opts.PasswordList = utils.LoadLines(s.Opts.Passwords)
	} else if s.Opts.Defaults {
		s.Opts.PasswordList = wordlists.DefaultPasswords
	}

	// Run each module group
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

		logger.Infof("executing %s module (%d targets)", command, len(nmapTargets))
		s.Opts.Command = command

		// Convert parser targets to scanner targets (resolve DNS)
		var scanTargets []*modules.Target
		for _, nt := range nmapTargets {
			ip := net.ParseIP(nt.Host)
			if ip == nil {
				resolved, err := utils.LookupAddr(nt.Host)
				if err != nil {
					logger.Debugf("can't resolve %s: %v", nt.Host, err)
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

	// Close results and wait for output
	close(s.Results)

	logger.Infof("Done: %d credential pairs tried, %d successful logins found",
		s.Attempts.Load(), s.Successes.Load())

	if ctx.Err() != nil {
		logger.Infof("Interrupted")
	}

	return nil
}

// RunNmapWithResults is like RunNmap but manages the results goroutine internally.
func (s *Scanner) RunNmapWithResults(ctx context.Context, nmapFile string) error {
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go GetResults(s.Results, s.Opts.OutputFile, &resultsWg, &s.Successes, s.Opts.JSON)

	err := s.RunNmap(ctx, nmapFile)

	resultsWg.Wait()
	s.Stop()

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
