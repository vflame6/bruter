package scanner

import (
	"context"
	"errors"
	"fmt"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BufferMultiplier defines the multiply value for Golang channel buffers
const BufferMultiplier = 4

type Scanner struct {
	Opts       *Options
	Targets    chan *modules.Target
	Results    chan *Result
	Attempts   atomic.Int64 // total credential pairs tried
	Successes  atomic.Int64 // total successful logins found
	globalDone atomic.Bool  // set true on first success when GlobalStop=true
}

type Options struct {
	Usernames           string
	Passwords           string
	Combo               string   // --combo: file with user:pass pairs
	UsernameList        []string // pre-loaded usernames (populated in Run)
	PasswordList        []string // pre-loaded passwords (populated in Run)
	ComboList           []modules.Credential // pre-loaded combo pairs (populated in Run)
	Command             string
	Timeout             time.Duration
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

// NewScanner function creates new scanner object based on options
func NewScanner(options *Options) (*Scanner, error) {
	var outputFile *os.File
	var err error

	// validate options
	if options.Parallel <= 0 || options.Threads <= 0 {
		return nil, errors.New("invalid numbers for concurrency")
	}
	if options.Retries < 0 {
		return nil, errors.New("invalid number for retries")
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

	parallelTargets := make(chan *modules.Target, options.Parallel*BufferMultiplier)
	results := make(chan *Result, options.Parallel*BufferMultiplier)

	s := Scanner{
		Opts:    options,
		Targets: parallelTargets,
		Results: results,
	}

	return &s, nil
}

func (s *Scanner) Stop() {
	if s.Opts.OutputFile != nil {
		_ = s.Opts.OutputFile.Close()
		s.Opts.OutputFile = nil // prevent double-close
	}
}

// Run method is used to handle parallel execution
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

	// if number of targets is less than number of parallels, decrease parallels
	if utils.IsFileExists(targets) {
		count, err = utils.CountLinesInFile(targets)
		if err != nil {
			return err
		}
	} else {
		count = 1
	}
	if count < s.Opts.Parallel {
		logger.Debugf("number of targets less than number of parallel targets, decreasing parallelism")
		s.Opts.Parallel = count
	}

	// pre-load credentials into memory once
	s.Opts.UsernameList = utils.LoadLines(s.Opts.Usernames)
	s.Opts.PasswordList = utils.LoadLines(s.Opts.Passwords)

	// load combo wordlist if provided
	if s.Opts.Combo != "" {
		for _, line := range utils.LoadLines(s.Opts.Combo) {
			// split on first colon only (password may contain colons)
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				s.Opts.ComboList = append(s.Opts.ComboList, modules.Credential{
					Username: parts[0],
					Password: parts[1],
				})
			}
		}
	}

	// start progress display (disabled in quiet mode)
	var progress *Progress
	if !logger.IsQuiet() {
		totalCreds := int64(len(s.Opts.UsernameList))*int64(len(s.Opts.PasswordList)) + int64(len(s.Opts.ComboList))
		progress = NewProgress(s, totalCreds)
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

	// Bug 2 fix: wait for GetResults to finish draining before returning
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go GetResults(s.Results, s.Opts.OutputFile, &resultsWg, &s.Successes, s.Opts.JSON)
	parallelWg.Wait()
	close(s.Results)
	resultsWg.Wait()

	// stop progress display before printing final stats
	if progress != nil {
		progress.Stop()
		logger.SetProgressClearer(nil)
	}

	// Fix 2 & 4: flush/close output file after GetResults has finished draining
	s.Stop()

	// Fix 3: print exit stats on normal exit and on cancellation
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

		// wait for delay before start
		if s.Opts.Delay > 0 {
			time.Sleep(s.Opts.Delay)
		}

		// send credentials to threads
		// Bug 3 fix: pass a done channel so SendCredentials exits when threads stop early
		credentials := make(chan *modules.Credential, s.Opts.Threads*BufferMultiplier)
		done := make(chan struct{})
		go SendCredentials(ctx, credentials, s.Opts.UsernameList, s.Opts.PasswordList, s.Opts.ComboList, done)

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

// probe checks if a target is reachable and whether default credentials work.
// It tries encrypted connection first, falling back to plaintext.
// Returns (reachable, defaultCredsWork).
func (s *Scanner) probe(ctx context.Context, module *modules.Module, target *modules.Target) (bool, bool) {
	logger.Debugf("trying default credentials on %s:%d", target.IP, target.Port)
	cred := &modules.Credential{
		Username: module.DefaultUsername,
		Password: module.DefaultPassword,
	}

	// try with encryption first (target.Encryption defaults to true)
	isSuccess, err := module.Handler(ctx, s.Opts.ProxyDialer, s.Opts.Timeout, target, cred)
	if err == nil {
		if isSuccess {
			target.Mutex.Lock()
			target.Success = true
			target.Mutex.Unlock()
		}
		return true, isSuccess
	}

	// fallback to plaintext
	logger.Debugf("failed to connect to %s:%d with encryption, trying plaintext", target.IP, target.Port)
	target.Encryption = false
	isSuccess, err = module.Handler(ctx, s.Opts.ProxyDialer, s.Opts.Timeout, target, cred)
	if err == nil {
		if isSuccess {
			target.Mutex.Lock()
			target.Success = true
			target.Mutex.Unlock()
		}
		return true, isSuccess
	}

	logger.Debugf("failed to connect to %s:%d: %v", target.IP, target.Port, err)
	return false, false
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
		if s.Opts.StopOnSuccess && target.Success {
			break
		}
		// shutdown all threads if number of max retries exceeded
		if s.Opts.Retries > 0 && target.Retries >= s.Opts.Retries {
			break
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

		if err != nil && s.Opts.Retries > 0 {
			target.Mutex.Lock()
			target.Retries++
			if target.Retries == s.Opts.Retries {
				logger.Infof("exceeded number of max retries on %s:%d, probably banned by the target", target.IP, target.Port)
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

		if s.Opts.Delay > 0 {
			time.Sleep(s.Opts.Delay)
		}
	}
}
