package scanner

import (
	"errors"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
	"net"
	"os"
	"sync"
	"time"
)

// BufferMultiplier defines the multiply value for Golang channel buffers
const BufferMultiplier = 4

type Scanner struct {
	Opts    *Options
	Targets chan *Target
}

type Options struct {
	Usernames           string
	Passwords           string
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
	FileMutex           sync.Mutex
}

type Target struct {
	IP         net.IP
	Port       int
	Encryption bool
	Success    bool
	Retries    int
	Mutex      sync.Mutex
}

type Credential struct {
	Username string
	Password string
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

	// custom dialer to handle connections, proxy settings and http clients
	dialer, err := utils.NewProxyAwareDialer(options.Proxy, options.ProxyAuthentication, options.Timeout, options.UserAgent)
	if err != nil {
		return nil, err
	}
	options.ProxyDialer = dialer

	// if an --output option is used, create a file
	if options.OutputFileName != "" {
		var err error
		outputFile, err = os.Create(options.OutputFileName)
		if err != nil {
			return nil, err
		}
		options.OutputFile = outputFile
	}

	parallelTargets := make(chan *Target, options.Parallel*BufferMultiplier)

	s := Scanner{
		Targets: parallelTargets,
		Opts:    options,
	}

	return &s, nil
}

func (s *Scanner) Stop() {
	_ = s.Opts.OutputFile.Close()
}

// Run method is used to handle parallel execution
func (s *Scanner) Run(command, targets string) error {
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

	// send targets to targets channel
	go SendTargets(s.Targets, c.DefaultPort, targets)

	// run parallel threads
	var parallelWg sync.WaitGroup
	for i := 0; i < s.Opts.Parallel; i++ {
		parallelWg.Add(1)

		go s.ParallelHandler(&parallelWg, &c)
	}
	parallelWg.Wait()

	return nil
}

func (s *Scanner) ParallelHandler(wg *sync.WaitGroup, command *modules.Module) {
	defer wg.Done()

	for {
		target, ok := <-s.Targets
		if !ok {
			break
		}

		// check with checker
		logger.Debugf("trying default credentials on %s:%d", target.IP, target.Port)
		defaultCreds, encryption, err := command.Checker(target.IP, target.Port, s.Opts.Timeout, s.Opts.ProxyDialer, command.DefaultUsername, command.DefaultPassword)
		if err != nil {
			logger.Debug(err)
			continue
		}

		// assign if encryption is used
		target.Encryption = encryption

		if defaultCreds {
			RegisterSuccess(s.Opts.OutputFile, &s.Opts.FileMutex, s.Opts.Command, target, command.DefaultUsername, command.DefaultPassword)
			// skip target if default credentials are found and --stop-on-success is enabled
			if s.Opts.StopOnSuccess {
				continue
			}
		}

		// wait for delay before start
		if s.Opts.Delay > 0 {
			time.Sleep(s.Opts.Delay)
		}

		credentials := make(chan *Credential, s.Opts.Threads*BufferMultiplier)

		go SendCredentials(credentials, s.Opts.Usernames, s.Opts.Passwords)

		var threadWg sync.WaitGroup
		for i := 0; i < s.Opts.Threads; i++ {
			threadWg.Add(1)
			go ThreadHandler(command.Handler, &threadWg, credentials, s.Opts, target)
		}
		threadWg.Wait()
	}
}
