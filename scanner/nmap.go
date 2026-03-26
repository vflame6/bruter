package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/parser"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
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

	return s.runAllMode(ctx, nmapFile, targets)
}

// RunNmapWithResults is like RunNmap but manages the results goroutine internally.
func (s *Scanner) RunNmapWithResults(ctx context.Context, nmapFile string) error {
	return s.runWithResults(ctx, func() error {
		return s.RunNmap(ctx, nmapFile)
	})
}

// runAllMode is the shared implementation for nmap and stdin auto-detect mode.
// It loads credentials, prints the dashboard, groups targets by host, and
// processes them with the host-first concurrency model.
func (s *Scanner) runAllMode(ctx context.Context, source string, targets []parser.Target) error {
	// Apply service filter if specified
	if s.Opts.ServiceFilter != "" {
		allowed := make(map[string]bool)
		for _, svc := range strings.Split(s.Opts.ServiceFilter, ",") {
			svc = strings.TrimSpace(svc)
			if svc != "" {
				allowed[svc] = true
			}
		}
		var filtered []parser.Target
		for _, t := range targets {
			if allowed[t.Service] {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			logger.Infof("no targets match service filter: %s", s.Opts.ServiceFilter)
			close(s.Results)
			return nil
		}
		targets = filtered
	}

	// Count services
	serviceCounts := make(map[string]int)
	for _, t := range targets {
		serviceCounts[t.Service]++
	}

	// Collect sorted service names for dashboard
	serviceNames := make([]string, 0, len(serviceCounts))
	for svc := range serviceCounts {
		serviceNames = append(serviceNames, svc)
	}
	sort.Strings(serviceNames)

	// Pre-load credentials
	s.loadCredentials()

	// Set target count for progress tracking
	s.TargetCount = int64(len(targets))

	// Build per-module password lists (sshkey needs special handling)
	defaultPasswords, sshkeyPasswords := s.buildPasswordLists()

	// Print dashboard
	if !logger.IsQuiet() {
		s.printDashboard(dashboardConfig{
			Source:       source,
			ServiceCount: len(serviceCounts),
			TargetCount:  len(targets),
			ServiceNames: serviceNames,
		})
	}

	// Start progress display (disabled in quiet or no-stats mode)
	var progress *Progress
	if !logger.IsQuiet() && !s.Opts.NoStats {
		totalCreds := int64(len(s.Opts.UsernameList))*int64(len(s.Opts.PasswordList)) + int64(len(s.Opts.ComboList))
		progress = NewProgress(s, totalCreds, s.TargetCount)
		logger.SetProgressClearer(progress.Clear)
		progress.Start()
	}

	logger.Debugf("found %d targets across %d services in %s", len(targets), len(serviceCounts), source)
	for svc, count := range serviceCounts {
		logger.Debugf("  %s: %d target(s)", svc, count)
	}

	// Group targets by host, preserving all services per host
	hostGroups := s.groupByHost(targets)
	logger.Debugf("scanning %d unique hosts", len(hostGroups))

	// Process hosts in parallel
	s.runHostGroups(ctx, hostGroups, defaultPasswords, sshkeyPasswords)

	if progress != nil {
		progress.Stop()
		logger.SetProgressClearer(nil)
	}

	close(s.Results)
	return nil
}

// runHostGroups processes host groups in parallel, bounded by -C (concurrent hosts).
// Each host runs up to -N services concurrently via processHost.
func (s *Scanner) runHostGroups(ctx context.Context, hostGroups [][]hostService, defaultPasswords, sshkeyPasswords []string) {
	parallel := s.Opts.Parallel
	if len(hostGroups) < parallel {
		parallel = len(hostGroups)
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
// It deduplicates same-module targets per host (keeps higher port) and
// expands SSH to include sshkey when --defaults is set.
func (s *Scanner) groupByHost(targets []parser.Target) [][]hostService {
	type hostKey string
	hostMap := make(map[hostKey][]hostService)
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

	// When --defaults is set, expand SSH targets to also run sshkey module.
	if s.Opts.Defaults {
		for key, services := range hostMap {
			for _, svc := range services {
				if svc.command == "ssh" {
					hasSshkey := false
					for _, existing := range services {
						if existing.command == "sshkey" {
							hasSshkey = true
							break
						}
					}
					if !hasSshkey {
						hostMap[key] = append(hostMap[key], hostService{
							command: "sshkey",
							target: &modules.Target{
								IP:             svc.target.IP,
								Port:           svc.target.Port,
								OriginalTarget: svc.target.OriginalTarget,
								Encryption:     true,
							},
						})
					}
					break
				}
			}
		}
	}

	result := make([][]hostService, 0, len(hostOrder))
	for _, key := range hostOrder {
		result = append(result, hostMap[key])
	}
	return result
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
