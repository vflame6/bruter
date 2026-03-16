package scanner

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/parser"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
	"github.com/vflame6/bruter/wordlists"
)

// hostService pairs a resolved scanner target with its module name.
type hostService struct {
	command string
	target  *modules.Target
}

// RunNmap parses a scan output file and runs bruter against all discovered
// services. Hosts are processed in parallel (-C), with up to -N services
// per host running concurrently, each using -c threads.
func (s *Scanner) RunNmap(ctx context.Context, nmapFile string) error {
	targets, err := parser.ParseFile(nmapFile, parser.FormatUnknown)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		logger.Infof("no supported services found in %s", nmapFile)
		return nil
	}

	// Print service summary
	serviceCounts := make(map[string]int)
	for _, t := range targets {
		serviceCounts[t.Service]++
	}

	// Pre-load credentials
	s.loadCredentials()

	// Build per-module password lists (sshkey needs special handling)
	defaultPasswords, sshkeyPasswords := s.buildPasswordLists()

	// Print dashboard
	if !logger.IsQuiet() {
		s.printNmapConfig(nmapFile, len(targets), len(serviceCounts))
	}

	logger.Debugf("found %d targets across %d services in %s", len(targets), len(serviceCounts), nmapFile)
	for svc, count := range serviceCounts {
		logger.Debugf("  %s: %d target(s)", svc, count)
	}

	// Group targets by host, preserving all services per host
	hostGroups := s.groupByHost(targets)

	uniqueHosts := len(hostGroups)
	logger.Debugf("scanning %d unique hosts", uniqueHosts)

	// Process hosts in parallel, bounded by -C
	parallel := s.Opts.Parallel
	if uniqueHosts < parallel {
		parallel = uniqueHosts
	}

	// Feed host groups into a channel
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

	// Launch host workers
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

// processHost runs up to ConcurrentServices modules in parallel for a single host.
func (s *Scanner) processHost(ctx context.Context, services []hostService, defaultPasswords, sshkeyPasswords []string) {
	sem := make(chan struct{}, s.Opts.ConcurrentServices)
	var svcWg sync.WaitGroup

	for _, svc := range services {
		if ctx.Err() != nil {
			break
		}
		if s.Opts.GlobalStop && s.globalDone.Load() {
			break
		}

		mod, ok := modules.Modules[svc.command]
		if !ok {
			logger.Debugf("skipping unknown module %s", svc.command)
			continue
		}

		// Select password list for this module
		var passwords []string
		if svc.command == "sshkey" {
			passwords = sshkeyPasswords
		} else {
			passwords = defaultPasswords
		}

		sem <- struct{}{}
		svcWg.Add(1)

		go func(command string, mod modules.Module, target *modules.Target, passwords []string) {
			defer svcWg.Done()
			defer func() { <-sem }()

			logger.Debugf("executing %s on %s:%d", command, target.IP, target.Port)

			// Create per-service scanner to avoid shared state
			svcScanner := *s
			svcOpts := *s.Opts
			svcOpts.Command = command
			svcOpts.PasswordList = passwords
			svcScanner.Opts = &svcOpts

			// Feed single target
			targetCh := make(chan *modules.Target, 1)
			targetCh <- target
			close(targetCh)
			svcScanner.Targets = targetCh

			var wg sync.WaitGroup
			wg.Add(1)
			go svcScanner.ParallelHandler(ctx, &wg, &mod)
			wg.Wait()
		}(svc.command, mod, svc.target, passwords)
	}

	svcWg.Wait()
}

// groupByHost groups parsed targets by host IP/hostname, resolving DNS,
// and returns a slice of host groups (each group = all services on that host).
func (s *Scanner) groupByHost(targets []parser.Target) [][]hostService {
	// Use a map to group by resolved IP string
	type hostKey string
	hostMap := make(map[hostKey][]hostService)
	// Preserve insertion order
	var hostOrder []hostKey

	for _, t := range targets {
		ip := net.ParseIP(t.Host)
		if ip == nil {
			resolved, err := utils.LookupAddr(t.Host)
			if err != nil {
				logger.Debugf("can't resolve %s: %v", t.Host, err)
				continue
			}
			ip = resolved
		}

		key := hostKey(ip.String())
		if _, exists := hostMap[key]; !exists {
			hostOrder = append(hostOrder, key)
		}

		svc := hostService{
			command: t.Service,
			target: &modules.Target{
				IP:             ip,
				Port:           t.Port,
				OriginalTarget: net.JoinHostPort(t.Host, strconv.Itoa(t.Port)),
				Encryption:     true,
			},
		}

		// Deduplicate: if same module already exists for this host, keep the
		// higher port (e.g. 445 over 139 for SMB, 993 over 143 for IMAP).
		// This avoids bruteforcing the same service twice on different ports.
		replaced := false
		for i, existing := range hostMap[key] {
			if existing.command == svc.command {
				if svc.target.Port > existing.target.Port {
					hostMap[key][i] = svc
				}
				replaced = true
				break
			}
		}
		if !replaced {
			hostMap[key] = append(hostMap[key], svc)
		}
	}

	result := make([][]hostService, 0, len(hostOrder))
	for _, key := range hostOrder {
		result = append(result, hostMap[key])
	}
	return result
}

// loadCredentials pre-loads usernames, passwords, and combo lists into Options.
func (s *Scanner) loadCredentials() {
	if s.Opts.Usernames != "" {
		s.Opts.UsernameList = utils.LoadLines(s.Opts.Usernames)
	}
	if s.Opts.Defaults {
		s.Opts.UsernameList = append(s.Opts.UsernameList, wordlists.DefaultUsernames...)
	}

	if s.Opts.Combo != "" {
		for _, line := range utils.LoadLines(s.Opts.Combo) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				s.Opts.ComboList = append(s.Opts.ComboList, modules.Credential{
					Username: parts[0],
					Password: parts[1],
				})
			}
		}
	}
}

// buildPasswordLists creates the default and sshkey password lists.
// Returns (defaultPasswords, sshkeyPasswords).
func (s *Scanner) buildPasswordLists() ([]string, []string) {
	var userPasswords []string
	if s.Opts.Passwords != "" {
		userPasswords = utils.LoadLines(s.Opts.Passwords)
	}

	// Default (non-sshkey) passwords
	var defaultPasswords []string
	if userPasswords != nil {
		defaultPasswords = append(defaultPasswords, userPasswords...)
	}
	if s.Opts.Defaults {
		defaultPasswords = append(defaultPasswords, wordlists.DefaultPasswords...)
	}

	// SSH key paths
	var sshkeyPasswords []string
	if s.Opts.Passwords != "" {
		sshkeyPasswords = utils.LoadSSHKeyPaths(s.Opts.Passwords)
	}
	if s.Opts.Defaults {
		sshkeyPasswords = append(sshkeyPasswords, wordlists.DefaultSSHKeys...)
	}

	// Set on Options for dashboard display
	s.Opts.PasswordList = defaultPasswords

	return defaultPasswords, sshkeyPasswords
}

// RunNmapWithResults is like RunNmap but manages the results goroutine internally.
func (s *Scanner) RunNmapWithResults(ctx context.Context, nmapFile string) error {
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

	err := s.RunNmap(ctx, nmapFile)

	// Stop progress display before printing final stats
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
