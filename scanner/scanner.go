package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
	"github.com/vflame6/bruter/wordlists"
)

// BufferMultiplier defines the multiply value for Golang channel buffers
const BufferMultiplier = 4

type Scanner struct {
	Opts        *Options
	Targets     chan *modules.Target
	Results     chan *Result
	Attempts    *atomic.Int64 // total credential pairs tried
	Successes   *atomic.Int64 // total successful logins found
	TargetCount int64         // total number of targets (set before progress starts)
	globalDone  *atomic.Bool  // set true on first success when GlobalStop=true
}

type Options struct {
	Usernames           string
	Passwords           string
	Defaults            bool                 // --defaults: use built-in wordlists
	Combo               string               // --combo: file with user:pass pairs
	UsernameList        []string             // pre-loaded usernames (populated in Run)
	PasswordList        []string             // pre-loaded passwords (populated in Run)
	ComboList           []modules.Credential // pre-loaded combo pairs (populated in Run)
	Command             string
	Timeout             time.Duration
	ConcurrentServices  int
	Parallel            int
	Threads             int
	Delay               time.Duration
	StopOnSuccess       bool
	Retries             int
	Proxy               string
	ProxyAuthentication string
	ProxyDialer         *utils.ProxyAwareDialer // --proxy
	UserAgent           string                  // --user-agent
	OutputFileName      string
	OutputFile          *os.File
	Verbose             bool   // --verbose: log every attempt with timestamp
	JSON                bool   // --json: output results as JSONL
	Iface               string // --iface: bind outgoing connections to this interface
	GlobalStop          bool   // --global-stop: stop entire run on first success across all hosts
	NoStats             bool   // --no-stats: disable progress bar
	UserAsPass          bool   // --user-as-pass: try username as password
	Blank               bool   // --blank: try empty password
	Reversed            bool   // --reversed: try reversed username as password
	ServiceFilter       string // --service: filter services in all mode
	Vulns               bool   // --vulns: run auth vulnerability checks and protocol default creds only
	Domain              string // --domain: AD/Kerberos realm, passed to modules via Target.Extra

	// Spraying
	Spray              bool          // --spray: lockout-safe campaign, one round per credential group
	Order              string        // --order: OrderPassword (default) or OrderUser
	Jitter             time.Duration // --jitter: random +/- applied to Delay between spray rounds
	MaxAttemptsPerUser int           // --max-attempts-per-user: global cap per username, 0 = unlimited

	// AccountBudget lets a caller that outlives one run keep a single budget
	// across all of them. Nil means RunSpray builds one from
	// MaxAttemptsPerUser for its own use.
	AccountBudget *AccountBudget

	// Checkpointing
	ResumeFile string      // --resume: path of the checkpoint to load and append to
	State      *StateStore // opened from ResumeFile in NewScanner; nil disables checkpointing
}

type Result struct {
	Command        string
	IP             net.IP
	Port           int
	Username       string
	Password       string
	OriginalTarget string    // raw input from Target.OriginalTarget
	Timestamp      time.Time // time of successful authentication
}

// dashboardConfig holds mode-specific info for the configuration dashboard.
type dashboardConfig struct {
	// Solo mode fields
	Module    string // module name (e.g. "ftp")
	Targets   string // target file or host string
	HostCount int    // number of hosts

	// Nmap/stdin mode fields
	Source       string   // scan file path or "stdin"
	ServiceCount int      // number of distinct services
	TargetCount  int      // total service:port targets
	ServiceNames []string // identified service names (sorted)

	// Vuln check info
	VulnCheckCount   int
	DefaultCredCount int
	VulnCheckNames   []string

	// Spray mode fields
	SprayRounds int // number of credential rounds the campaign will run
	SprayCreds  int // attempts per host after folding duplicate accounts
}

// printDashboard prints a configuration dashboard before the scan starts.
// Works for both solo module mode and all/nmap/stdin mode.
func (s *Scanner) printDashboard(cfg dashboardConfig) {
	o := s.Opts
	userCount := len(o.UsernameList)
	passCount := len(o.PasswordList)
	comboCount := len(o.ComboList)
	totalCreds := int64(userCount)*int64(passCount) + int64(comboCount)

	fmt.Println("-------------------------------------------------------")

	// Mode-specific header
	if cfg.Module != "" {
		// Solo module mode
		fmt.Printf(" [+] Module:              %s\n", cfg.Module)
		fmt.Printf(" [+] Targets:             %s (%d host(s))\n", cfg.Targets, cfg.HostCount)
	} else {
		// Nmap/stdin mode
		fmt.Printf(" [+] Source:              %s\n", cfg.Source)
		fmt.Printf(" [+] Services:            %s (%d)\n", strings.Join(cfg.ServiceNames, ", "), cfg.ServiceCount)
		fmt.Printf(" [+] Total targets:       %d\n", cfg.TargetCount)
	}

	// Vuln checks info
	if o.Vulns && cfg.VulnCheckCount > 0 {
		fmt.Printf(" [+] Vuln checks:         %d (%s)\n", cfg.VulnCheckCount, strings.Join(cfg.VulnCheckNames, ", "))
	}
	if o.Vulns && cfg.DefaultCredCount > 0 {
		fmt.Printf(" [+] Default creds:       %d\n", cfg.DefaultCredCount)
	}

	// Credentials (shared)
	switch {
	case o.Usernames != "" && o.Defaults:
		fmt.Printf(" [+] Usernames:           %s + built-in (%d)\n", o.Usernames, userCount)
	case o.Usernames != "":
		fmt.Printf(" [+] Usernames:           %s (%d)\n", o.Usernames, userCount)
	case o.Defaults && userCount > 0:
		fmt.Printf(" [+] Usernames:           built-in (%d)\n", userCount)
	}
	switch {
	case o.Passwords != "" && o.Defaults:
		fmt.Printf(" [+] Passwords:           %s + built-in (%d)\n", o.Passwords, passCount)
	case o.Passwords != "":
		fmt.Printf(" [+] Passwords:           %s (%d)\n", o.Passwords, passCount)
	case o.Defaults && passCount > 0:
		fmt.Printf(" [+] Passwords:           built-in (%d)\n", passCount)
	}
	if o.Combo != "" {
		fmt.Printf(" [+] Combo file:          %s (%d)\n", o.Combo, comboCount)
	}

	// Credential count. In spray mode the campaign's own total is used: it is
	// taken after duplicate accounts have been folded together, so the
	// username-times-password product would overstate it.
	if o.Spray && cfg.SprayCreds > 0 {
		totalCreds = int64(cfg.SprayCreds)
	}
	if cfg.Module != "" {
		fmt.Printf(" [+] Credential pairs:    %d\n", totalCreds)
	} else {
		fmt.Printf(" [+] Credential pairs:    %d (per service)\n", totalCreds)
	}

	// Concurrency (mode-dependent)
	if cfg.Module != "" {
		fmt.Printf(" [+] Concurrent hosts:    %d\n", o.Parallel)
		fmt.Printf(" [+] Threads per host:    %d\n", o.Threads)
	} else {
		fmt.Printf(" [+] Concurrent hosts:    %d\n", o.Parallel)
		fmt.Printf(" [+] Services per host:   %d\n", o.ConcurrentServices)
		fmt.Printf(" [+] Threads per service: %d\n", o.Threads)
	}

	// Common options
	fmt.Printf(" [+] Timeout:             %s\n", o.Timeout)

	if o.Spray {
		held := "password"
		if o.Order == OrderUser {
			held = "username"
		}
		fmt.Printf(" [+] Spray:               %d round(s), one %s per round\n", cfg.SprayRounds, held)
		if o.Jitter > 0 {
			fmt.Printf(" [+] Round delay:         %s +/- %s\n", o.Delay, o.Jitter)
		}
		if o.Jitter == 0 {
			fmt.Printf(" [+] Round delay:         %s\n", o.Delay)
		}
		if o.MaxAttemptsPerUser > 0 {
			fmt.Printf(" [+] Max per account:     %d attempt(s)\n", o.MaxAttemptsPerUser)
		}
		if o.Order == OrderUser {
			fmt.Printf(" [!] --order user empties one account's lockout budget at a time\n")
		}
	}
	if !o.Spray && o.Delay > 0 {
		fmt.Printf(" [+] Delay:               %s\n", o.Delay)
	}
	if o.Proxy != "" {
		fmt.Printf(" [+] Proxy:               %s\n", o.Proxy)
	}
	if o.OutputFileName != "" {
		fmt.Printf(" [+] Output:              %s\n", o.OutputFileName)
	}
	if o.ResumeFile != "" {
		fmt.Printf(" [+] Checkpoint:          %s (%d attempt(s) already done)\n",
			o.ResumeFile, o.State.Loaded())
	}
	if o.JSON {
		fmt.Printf(" [+] Format:              JSONL\n")
	}
	if o.StopOnSuccess {
		fmt.Printf(" [+] Stop on success:     yes\n")
	}
	if o.GlobalStop {
		fmt.Printf(" [+] Global stop:         yes\n")
	}
	if o.Verbose {
		fmt.Printf(" [+] Verbose:             yes\n")
	}
	if o.Iface != "" {
		fmt.Printf(" [+] Interface:           %s\n", o.Iface)
	}
	if o.Domain != "" {
		fmt.Printf(" [+] Realm:               %s\n", strings.ToUpper(o.Domain))
	}
	fmt.Println("-------------------------------------------------------")
}

// reverseString returns the input string reversed.
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// loadCredentials pre-loads usernames, passwords, and combo lists into Options.
// When --vulns is set without --defaults, no wordlists are loaded (vuln checks
// and default creds carry their own credentials in the module registry).
func (s *Scanner) loadCredentials() {
	// --vulns without --defaults: no wordlist loading needed
	if s.Opts.Vulns && !s.Opts.Defaults {
		// Still load user-supplied -u/-p if provided (for targeted vuln scans)
		if s.Opts.Usernames != "" {
			s.Opts.UsernameList = utils.LoadLines(s.Opts.Usernames)
		}
		if s.Opts.Passwords != "" {
			s.Opts.PasswordList = utils.LoadLines(s.Opts.Passwords)
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
		return
	}

	if s.Opts.Usernames != "" {
		s.Opts.UsernameList = utils.LoadLines(s.Opts.Usernames)
	}
	if s.Opts.Defaults {
		s.Opts.UsernameList = append(s.Opts.UsernameList, wordlists.DefaultUsernames...)
	}

	if s.Opts.Passwords != "" {
		if s.Opts.Command == "sshkey" {
			s.Opts.PasswordList = utils.LoadSSHKeyPaths(s.Opts.Passwords)
		} else {
			s.Opts.PasswordList = utils.LoadLines(s.Opts.Passwords)
		}
	}
	if s.Opts.Defaults {
		if s.Opts.Command == "sshkey" {
			s.Opts.PasswordList = append(s.Opts.PasswordList, wordlists.DefaultSSHKeys...)
		} else {
			s.Opts.PasswordList = append(s.Opts.PasswordList, wordlists.DefaultPasswords...)
		}
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

	var extraCreds []modules.Credential
	for _, user := range s.Opts.UsernameList {
		if s.Opts.Blank {
			extraCreds = append(extraCreds, modules.Credential{Username: user, Password: ""})
		}
		if s.Opts.UserAsPass {
			extraCreds = append(extraCreds, modules.Credential{Username: user, Password: user})
		}
		if s.Opts.Reversed {
			extraCreds = append(extraCreds, modules.Credential{Username: user, Password: reverseString(user)})
		}
	}
	if len(extraCreds) > 0 {
		s.Opts.ComboList = append(extraCreds, s.Opts.ComboList...)
	}
}

// collapseForEnum reduces the credential set for an enumeration module.
//
// Such a module ignores the password entirely, so a list of N passwords would
// otherwise probe every account N times and report N identical findings per
// account. One attempt per account is both correct and all the protocol can
// tell us.
func collapseForEnum(opts *Options, module *modules.Module) {
	if !module.EnumOnly {
		return
	}

	// Fold combo pairs into the username list: only the account matters.
	seen := make(map[string]struct{}, len(opts.UsernameList)+len(opts.ComboList))
	users := make([]string, 0, len(opts.UsernameList)+len(opts.ComboList))
	for _, user := range opts.UsernameList {
		if _, dup := seen[user]; dup {
			continue
		}
		seen[user] = struct{}{}
		users = append(users, user)
	}
	for _, cred := range opts.ComboList {
		if _, dup := seen[cred.Username]; dup {
			continue
		}
		seen[cred.Username] = struct{}{}
		users = append(users, cred.Username)
	}

	opts.UsernameList = users
	opts.PasswordList = []string{""}
	opts.ComboList = nil
}

// buildPasswordLists creates default and sshkey password lists for nmap/stdin mode.
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

// runWithResults wraps a scan function with progress display, results collection,
// and final stats — shared boilerplate for RunNmapWithResults and RunStdinWithResults.
func (s *Scanner) runWithResults(ctx context.Context, scanFunc func() error) error {
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go GetResults(s.Results, s.Opts.OutputFile, &resultsWg, s.Successes, s.Opts.JSON)

	// Run the scan function, which sets TargetCount, loads credentials,
	// and manages its own progress display.
	err := scanFunc()

	resultsWg.Wait()
	s.Stop()

	if ctx.Err() != nil {
		logger.Infof("Interrupted: %d credential pairs tried, %d successful logins found", s.Attempts.Load(), s.Successes.Load())
	} else {
		logger.Infof("Done: %d credential pairs tried, %d successful logins found", s.Attempts.Load(), s.Successes.Load())
	}

	return err
}

// NewScanner function creates new scanner object based on options
func NewScanner(options *Options) (*Scanner, error) {
	var outputFile *os.File
	var err error

	// validate options
	if options.ConcurrentServices <= 0 || options.Parallel <= 0 || options.Threads <= 0 {
		return nil, errors.New("invalid numbers for concurrency")
	}
	if options.Retries < 0 {
		return nil, errors.New("invalid number for retries")
	}

	// spraying options
	switch options.Order {
	case "":
		options.Order = OrderPassword
	case OrderPassword, OrderUser:
	default:
		return nil, fmt.Errorf("invalid --order %q, want %q or %q", options.Order, OrderPassword, OrderUser)
	}
	if options.Jitter < 0 {
		return nil, errors.New("--jitter cannot be negative")
	}
	if options.Jitter > options.Delay {
		return nil, errors.New("--jitter cannot exceed --delay")
	}
	if options.MaxAttemptsPerUser < 0 {
		return nil, errors.New("--max-attempts-per-user cannot be negative")
	}

	// resolve interface binding IP (nil = OS default)
	var localAddr net.IP
	if options.Iface != "" {
		ip, ifaceErr := utils.GetInterfaceIPv4(options.Iface)
		if ifaceErr != nil {
			logger.Infof("interface %q unavailable (%v), using default routing", options.Iface, ifaceErr)
		} else {
			localAddr = ip
		}
	}

	// custom dialer to handle connections, proxy settings and http clients
	dialer, err := utils.NewProxyAwareDialer(options.Proxy, options.ProxyAuthentication, options.Timeout, options.UserAgent, localAddr)
	if err != nil {
		return nil, err
	}
	options.ProxyDialer = dialer

	// if an --output option is used, create a file
	if options.OutputFileName != "" {
		if _, err := os.Stat(options.OutputFileName); err == nil {
			return nil, fmt.Errorf("output file %q already exists. Use a different filename to avoid data loss", options.OutputFileName)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("cannot check output file %q: %w", options.OutputFileName, err)
		}
		var err error
		outputFile, err = os.Create(options.OutputFileName)
		if err != nil {
			return nil, err
		}
		options.OutputFile = outputFile
	}

	// --resume: load the checkpoint before anything is attempted
	if options.ResumeFile != "" {
		state, stateErr := OpenStateStore(options.ResumeFile)
		if stateErr != nil {
			return nil, stateErr
		}
		options.State = state
		if loaded := state.Loaded(); loaded > 0 {
			logger.Infof("resuming from %s: %d attempt(s) already recorded, they will be skipped",
				options.ResumeFile, loaded)
		} else {
			logger.Infof("checkpointing to %s", options.ResumeFile)
		}
	}

	parallelTargets := make(chan *modules.Target, options.Parallel*BufferMultiplier)
	results := make(chan *Result, options.Parallel*BufferMultiplier)

	s := Scanner{
		Opts:       options,
		Targets:    parallelTargets,
		Results:    results,
		Attempts:   &atomic.Int64{},
		Successes:  &atomic.Int64{},
		globalDone: &atomic.Bool{},
	}

	return &s, nil
}

func (s *Scanner) Stop() {
	if s.Opts.OutputFile != nil {
		_ = s.Opts.OutputFile.Close()
		s.Opts.OutputFile = nil // prevent double-close
	}
	// Not cleared afterwards: workers hold this same Options pointer, and
	// StateStore.Close is already idempotent, so nilling it would only add a
	// field for them to race on.
	if err := s.Opts.State.Close(); err != nil {
		logger.Debugf("closing checkpoint %s: %v", s.Opts.ResumeFile, err)
	}
}

// Run method is used to handle parallel execution for a single module.
func (s *Scanner) Run(ctx context.Context, command, targets string) error {
	var count int
	var err error

	// check if command is valid
	c, ok := modules.Modules[command]
	if !ok {
		return errors.New("invalid command")
	}
	s.Opts.Command = command

	// check if delay is set
	if s.Opts.Delay > 0 {
		s.Opts.Threads = 1
	}

	// count targets: file (lines), comma-separated, or single host
	switch {
	case utils.IsFileExists(targets):
		count, err = utils.CountLinesInFile(targets)
		if err != nil {
			return err
		}
	case strings.Contains(targets, ","):
		count = len(strings.Split(targets, ","))
	default:
		count = 1
	}

	// pre-load credentials into memory once
	s.loadCredentials()
	collapseForEnum(s.Opts, &c)

	// set target count for progress tracking
	s.TargetCount = int64(count)

	// print startup configuration dashboard
	if !logger.IsQuiet() {
		cfg := dashboardConfig{
			Module:    command,
			Targets:   targets,
			HostCount: count,
		}
		if s.Opts.Vulns {
			cfg.VulnCheckCount = len(c.VulnChecks)
			cfg.DefaultCredCount = len(c.DefaultCreds)
			for _, vc := range c.VulnChecks {
				cfg.VulnCheckNames = append(cfg.VulnCheckNames, vc.Name)
			}
		}
		s.printDashboard(cfg)
	}

	// show which module is executed
	logger.Debugf("executing %s module", command)
	if count < s.Opts.Parallel {
		logger.Debugf("number of targets less than number of parallel targets, decreasing parallelism")
		s.Opts.Parallel = count
	}

	// start progress display (disabled in quiet or no-stats mode)
	var progress *Progress
	if !logger.IsQuiet() && !s.Opts.NoStats {
		totalCreds := int64(len(s.Opts.UsernameList))*int64(len(s.Opts.PasswordList)) + int64(len(s.Opts.ComboList))
		progress = NewProgress(s, totalCreds, s.TargetCount)
		logger.SetProgressClearer(progress.Clear)
		progress.Start()
	}

	// send targets to targets channel
	go SendTargets(ctx, s.Targets, c.DefaultPort, targets)

	// run parallel threads
	var parallelWg sync.WaitGroup
	for i := 0; i < s.Opts.Parallel; i++ {
		parallelWg.Add(1)
		go s.ParallelHandler(ctx, &parallelWg, &c)
	}

	// wait for GetResults to finish draining before returning
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go GetResults(s.Results, s.Opts.OutputFile, &resultsWg, s.Successes, s.Opts.JSON)
	parallelWg.Wait()
	close(s.Results)
	resultsWg.Wait()

	// stop progress display before printing final stats
	if progress != nil {
		progress.Stop()
		logger.SetProgressClearer(nil)
	}

	// flush/close output file after GetResults has finished draining
	s.Stop()

	// print exit stats on normal exit and on cancellation
	logger.Infof("Done: %d credential pairs tried, %d successful logins found",
		s.Attempts.Load(), s.Successes.Load())

	if ctx.Err() != nil {
		logger.Infof("Interrupted")
	}

	return nil
}

func (s *Scanner) ParallelHandler(ctx context.Context, wg *sync.WaitGroup, module *modules.Module) {
	defer wg.Done()

	for {
		// Exit on cancellation or global stop
		select {
		case <-ctx.Done():
			return
		default:
		}
		if s.Opts.GlobalStop && s.globalDone.Load() {
			return
		}

		target, ok := <-s.Targets
		if !ok {
			break
		}

		s.annotateTarget(target)

		// probe target: check reachability, TLS fallback, and default credentials
		reachable, defaultCredsWork := s.probe(ctx, module, target)
		if !reachable {
			continue
		}

		if defaultCredsWork {
			s.Results <- &Result{
				Command:        s.Opts.Command,
				IP:             target.IP,
				Port:           target.Port,
				Username:       module.DefaultUsername,
				Password:       module.DefaultPassword,
				OriginalTarget: target.OriginalTarget,
				Timestamp:      time.Now(),
			}
			if s.Opts.GlobalStop {
				s.globalDone.Store(true)
			}
			if s.Opts.StopOnSuccess || s.Opts.GlobalStop {
				continue
			}
		}

		// run vuln checks and default creds when --vulns or --defaults is set
		if s.Opts.Vulns {
			stopped := s.runVulnChecks(ctx, module, target)
			if stopped {
				continue
			}
			stopped = s.runDefaultCreds(ctx, module, target)
			if stopped {
				continue
			}
		}

		// skip wordlist brute-force when --vulns is set without --defaults
		if s.Opts.Vulns && !s.Opts.Defaults {
			continue
		}

		// wait for delay before start
		if s.Opts.Delay > 0 {
			time.Sleep(s.Opts.Delay)
		}

		// send credentials to threads
		credentials := make(chan *modules.Credential, s.Opts.Threads*BufferMultiplier)
		done := make(chan struct{})
		go SendCredentials(ctx, credentials, s.Opts.UsernameList, s.Opts.PasswordList, s.Opts.ComboList, s.Opts.Order, done)

		// run threads
		var threadWg sync.WaitGroup
		for i := 0; i < s.Opts.Threads; i++ {
			threadWg.Add(1)
			go s.ThreadHandler(ctx, &threadWg, credentials, module.Handler, target)
		}
		threadWg.Wait()
		close(done) // signal SendCredentials to stop if still running
	}
}

// annotateTarget attaches run options that modules need but cannot reach
// through the handler signature. Modules read them with Target.GetExtra.
func (s *Scanner) annotateTarget(target *modules.Target) {
	if s.Opts.Domain != "" {
		target.SetExtra(modules.TargetDomainKey, s.Opts.Domain)
	}
}

// probe checks if a target is reachable and whether default credentials work.
// It tries encrypted connection first, falling back to plaintext.
// Returns (reachable, defaultCredsWork).
func (s *Scanner) probe(ctx context.Context, module *modules.Module, target *modules.Target) (bool, bool) {
	// Enumeration modules answer "this account exists", so a default-credential
	// probe against them would be reported as a recovered password that was
	// never checked. Modules that opt out do so because the attempt would
	// spend a real account's lockout budget. Both only need reachability, and
	// a principal that does not exist cannot be locked out.
	report := module.ProbesDefaultCreds()

	cred := &modules.Credential{
		Username: module.DefaultUsername,
		Password: module.DefaultPassword,
	}
	if !report {
		cred = s.anonymousProbeCredential()
		logger.Debugf("probing %s for reachability only, without default credentials", target.Addr())
	} else {
		logger.Debugf("trying default credentials on %s:%d", target.IP, target.Port)
	}

	// try with encryption first (target.Encryption defaults to true)
	isSuccess, err := module.Handler(ctx, s.Opts.ProxyDialer, s.Opts.Timeout, target, cred)
	if err == nil {
		return true, s.recordProbeSuccess(target, isSuccess && report)
	}

	// fallback to plaintext
	logger.Debugf("failed to connect to %s:%d with encryption, trying plaintext", target.IP, target.Port)
	target.Encryption = false
	isSuccess, err = module.Handler(ctx, s.Opts.ProxyDialer, s.Opts.Timeout, target, cred)
	if err == nil {
		return true, s.recordProbeSuccess(target, isSuccess && report)
	}

	logger.Debugf("failed to connect to %s:%d: %v", target.IP, target.Port, err)
	return false, false
}

// recordProbeSuccess marks the target solved when the probe really did
// recover credentials, and returns what it was told so probe can pass it on.
func (s *Scanner) recordProbeSuccess(target *modules.Target, success bool) bool {
	if success {
		target.Mutex.Lock()
		target.Success = true
		target.Mutex.Unlock()
	}
	return success
}

// anonymousProbeCredential returns a credential for a principal that should
// not exist anywhere, qualified with the realm when one is known so that
// modules which require one can still answer.
func (s *Scanner) anonymousProbeCredential() *modules.Credential {
	username := randomPrincipal()
	if realm := s.probeRealm(); realm != "" {
		username += "@" + realm
	}
	return &modules.Credential{Username: username, Password: randomPrincipal()}
}

// probeRealm finds a realm to qualify the probe principal with: --domain if
// given, otherwise one carried by a username in the wordlist.
func (s *Scanner) probeRealm() string {
	if s.Opts.Domain != "" {
		return s.Opts.Domain
	}
	for _, user := range s.Opts.UsernameList {
		if i := strings.LastIndex(user, "@"); i > 0 && i < len(user)-1 {
			return user[i+1:]
		}
		if i := strings.Index(user, `\`); i > 0 && i < len(user)-1 {
			return user[:i]
		}
	}
	return ""
}

// runVulnChecks executes module-defined vulnerability checks (e.g. ssh-hole, anonymous login).
// Returns true if stop-on-success triggered and brute-force should be skipped.
func (s *Scanner) runVulnChecks(ctx context.Context, module *modules.Module, target *modules.Target) bool {
	for _, check := range module.VulnChecks {
		if ctx.Err() != nil {
			return true
		}
		if s.Opts.GlobalStop && s.globalDone.Load() {
			return true
		}
		if s.Opts.StopOnSuccess && targetSucceeded(target) {
			return true
		}

		for _, cred := range check.Creds {
			if ctx.Err() != nil {
				return true
			}

			c := cred
			logger.Debugf("vuln check %s: trying %s:%s on %s:%d", check.Name, c.Username, c.Password, target.IP, target.Port)
			s.Attempts.Add(1)

			ok, err := check.Handler(ctx, s.Opts.ProxyDialer, s.Opts.Timeout, target, &c)

			if s.Opts.Verbose {
				status := "FAIL"
				if err != nil {
					status = "ERROR"
				}
				if ok {
					status = "SUCCESS"
				}
				logger.Verbosef("%s %s %s:%s -> %s",
					check.Name,
					net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port)),
					c.Username, c.Password, status,
				)
			}

			if ok {
				target.Mutex.Lock()
				target.Success = true
				target.Mutex.Unlock()

				s.Results <- &Result{
					Command:        check.Name,
					IP:             target.IP,
					Port:           target.Port,
					Username:       c.Username,
					Password:       c.Password,
					OriginalTarget: target.OriginalTarget,
					Timestamp:      time.Now(),
				}
				if s.Opts.GlobalStop {
					s.globalDone.Store(true)
				}
				if s.Opts.StopOnSuccess || s.Opts.GlobalStop {
					return true
				}
				break
			}
		}
	}
	return false
}

// runDefaultCreds tests module-specific known default credentials.
// Returns true if stop-on-success triggered.
func (s *Scanner) runDefaultCreds(ctx context.Context, module *modules.Module, target *modules.Target) bool {
	for _, cred := range module.DefaultCreds {
		if ctx.Err() != nil {
			return true
		}
		if s.Opts.GlobalStop && s.globalDone.Load() {
			return true
		}
		if s.Opts.StopOnSuccess && targetSucceeded(target) {
			return true
		}

		c := cred
		logger.Debugf("default cred: trying %s:%s on %s:%d", c.Username, c.Password, target.IP, target.Port)
		s.Attempts.Add(1)

		ok, err := module.Handler(ctx, s.Opts.ProxyDialer, s.Opts.Timeout, target, &c)

		if s.Opts.Verbose {
			status := "FAIL"
			if err != nil {
				status = "ERROR"
			}
			if ok {
				status = "SUCCESS"
			}
			logger.Verbosef("%s %s %s:%s -> %s",
				s.Opts.Command,
				net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port)),
				c.Username, c.Password, status,
			)
		}

		if ok {
			target.Mutex.Lock()
			target.Success = true
			target.Mutex.Unlock()

			s.Results <- &Result{
				Command:        s.Opts.Command,
				IP:             target.IP,
				Port:           target.Port,
				Username:       c.Username,
				Password:       c.Password,
				OriginalTarget: target.OriginalTarget,
				Timestamp:      time.Now(),
			}
			if s.Opts.GlobalStop {
				s.globalDone.Store(true)
			}
			if s.Opts.StopOnSuccess || s.Opts.GlobalStop {
				return true
			}
		}
	}
	return false
}

func (s *Scanner) ThreadHandler(ctx context.Context, wg *sync.WaitGroup, credentials <-chan *modules.Credential, handler modules.ModuleHandler, target *modules.Target) {
	defer wg.Done()

	for {
		// Exit on cancellation
		select {
		case <-ctx.Done():
			return
		default:
		}

		credential, ok := <-credentials
		if !ok {
			break
		}
		// shutdown all threads if global stop triggered
		if s.Opts.GlobalStop && s.globalDone.Load() {
			return
		}
		// shutdown all threads if --stop-on-success is used and password is found
		if s.Opts.StopOnSuccess && targetSucceeded(target) {
			break
		}
		// shutdown all threads if number of max retries exceeded
		if s.Opts.Retries > 0 && targetRetries(target) >= s.Opts.Retries {
			break
		}

		// --resume: this pair was already evaluated against this service in an
		// earlier run, so there is nothing to learn from repeating it.
		if s.Opts.State.Done(target.OriginalTarget, s.Opts.Command, credential.Username, credential.Password) {
			logger.Debugf("skipping %s:%s on %s, already in the checkpoint", credential.Username, credential.Password, target.Addr())
			continue
		}

		logger.Debugf("trying %s:%s on %s:%d", credential.Username, credential.Password, target.IP, target.Port)
		s.Attempts.Add(1)
		// ignore error here because it is used on initial check with default credentials
		isSuccess, err := handler(ctx, s.Opts.ProxyDialer, s.Opts.Timeout, target, credential)

		// verbose: log every attempt with result status
		if s.Opts.Verbose {
			status := "FAIL"
			if err != nil {
				status = "ERROR"
			}
			if isSuccess {
				status = "SUCCESS"
			}
			logger.Verbosef("%s %s %s:%s -> %s",
				s.Opts.Command,
				net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port)),
				credential.Username,
				credential.Password,
				status,
			)
		}

		if err == nil {
			// The service answered, so this pair is settled either way and a
			// resumed run can skip it. Errored attempts are deliberately not
			// recorded: the credential was never actually tested.
			s.Opts.State.Record(target.OriginalTarget, s.Opts.Command, credential.Username, credential.Password)
		}

		if err != nil && s.Opts.Retries > 0 {
			target.Mutex.Lock()
			target.Retries++
			if target.Retries == s.Opts.Retries {
				logger.Failf("exceeded number of max retries on %s:%d, probably banned by the target", target.IP, target.Port)
			}
			target.Mutex.Unlock()
		}

		if isSuccess {
			target.Mutex.Lock()
			target.Success = true
			target.Mutex.Unlock()

			s.Results <- &Result{
				Command:        s.Opts.Command,
				IP:             target.IP,
				Port:           target.Port,
				Username:       credential.Username,
				Password:       credential.Password,
				OriginalTarget: target.OriginalTarget,
				Timestamp:      time.Now(),
			}
			if s.Opts.GlobalStop {
				s.globalDone.Store(true)
			}
		}

		// In spray mode --delay is the pause between rounds, applied once by
		// sprayPause; sleeping it per attempt as well would stretch a round
		// out by hours.
		if s.Opts.Delay > 0 && !s.Opts.Spray {
			time.Sleep(s.Opts.Delay)
		}
	}
}

// targetRetries reads Target.Retries under its mutex.
func targetRetries(target *modules.Target) int {
	target.Mutex.Lock()
	defer target.Mutex.Unlock()
	return target.Retries
}
