package scanner

import (
	"errors"
	"github.com/vflame6/bruter/logger"
	"net"
	"os"
	"sync"
	"time"
)

// BufferMultiplier defines the multiply value for Golang channel buffers
const BufferMultiplier = 4

// Commands stores all available services for bruteforce
var Commands = map[string]Command{
	"amqp":       {5672, AMQPHandler, AMQPChecker},
	"clickhouse": {9000, ClickHouseHandler, ClickHouseChecker},
	"etcd":       {2379, EtcdHandler, EtcdChecker},
	"ftp":        {21, FTPHandler, FTPChecker},
	"mongo":      {27017, MongoHandler, MongoChecker},
	"smpp":       {2775, SMPPHandler, SMPPChecker},
	"vault":      {8200, VaultHandler, VaultChecker},
}

type Command struct {
	DefaultPort int
	Handler     CommandHandler
	Checker     CheckerHandler
}

// CommandHandler is a type function for one bruteforce thread
// the return values are:
// IsConnected (bool) to test if connection to the target is successful
// IsAuthenticated (bool) to test if authentication is successful
type CommandHandler func(opts *Options, target *Target, credential *Credential) (bool, bool)

// CheckerHandler is a type function for service checker function
// the return values are:
// DEFAULT (bool) for test if the target has default credentials
// ENCRYPTION (bool) for test if the target is using encryption
// ERROR (error) for connection errors
// if checker could not be implemented for target service, the checker must return false, false, nil
type CheckerHandler func(target *Target, opts *Options) (bool, bool, error)

type Scanner struct {
	Opts     *Options
	Targets  chan *Target
	Port     int
	Parallel int
}

type Options struct {
	Command        string
	Timeout        time.Duration
	Threads        int
	Delay          time.Duration
	StopOnSuccess  bool
	Retries        int
	OutputFileName string
	OutputFile     *os.File
	Usernames      string
	Passwords      string
	FileMutex      sync.Mutex
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

func NewScanner(timeout int, output string, parallel, threads, delay int, stopOnSuccess bool, retries int, username, password string) (*Scanner, error) {
	var outputFile *os.File

	if output != "" {
		var err error
		outputFile, err = os.Create(output)
		if err != nil {
			return nil, err
		}
	}

	parallelTargets := make(chan *Target, parallel*BufferMultiplier)

	options := Options{
		Timeout:        time.Duration(timeout) * time.Second,
		Threads:        threads,
		Delay:          time.Duration(delay) * time.Millisecond,
		StopOnSuccess:  stopOnSuccess,
		Retries:        retries,
		OutputFileName: output,
		OutputFile:     outputFile,
		Usernames:      username,
		Passwords:      password,
	}

	s := Scanner{
		Targets:  parallelTargets,
		Opts:     &options,
		Parallel: parallel,
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
	c, ok := Commands[command]
	if !ok {
		return errors.New("invalid command")
	}

	s.Opts.Command = command

	// check if delay is set
	if s.Opts.Delay > 0 {
		s.Opts.Threads = 1
	}

	// if number of targets is less than number of parallels, decrease parallels
	if IsFileExists(targets) {
		count, err = CountLinesInFile(targets)
		if err != nil {
			return err
		}
	} else {
		count = 1
	}
	if count < s.Parallel {
		logger.Debugf("number of targets less than number of parallel targets, decreasing parallelism")
		s.Parallel = count
	}

	// send targets to targets channel
	go SendTargets(s.Targets, c.DefaultPort, targets)

	// run parallel threads
	var parallelWg sync.WaitGroup
	for i := 0; i < s.Parallel; i++ {
		parallelWg.Add(1)

		go s.ParallelHandler(&parallelWg, c.Checker, c.Handler)
	}
	parallelWg.Wait()

	return nil
}

func (s *Scanner) ParallelHandler(wg *sync.WaitGroup, checker CheckerHandler, handler CommandHandler) {
	defer wg.Done()

	for {
		target, ok := <-s.Targets
		if !ok {
			break
		}

		// check with checker
		logger.Debugf("trying default credentials on %s:%d", target.IP, target.Port)
		defaultCreds, encryption, err := checker(target, s.Opts)
		if err != nil {
			logger.Debug(err)
			continue
		}

		// assign if encryption is used
		target.Encryption = encryption

		// skip target if default credentials are found and --stop-on-success is enabled
		if defaultCreds && s.Opts.StopOnSuccess {
			continue
		}

		credentials := make(chan *Credential, s.Opts.Threads*BufferMultiplier)

		go SendCredentials(credentials, s.Opts.Usernames, s.Opts.Passwords)

		var threadWg sync.WaitGroup
		for i := 0; i < s.Opts.Threads; i++ {
			threadWg.Add(1)
			go ThreadHandler(handler, &threadWg, credentials, s.Opts, target)
		}
		threadWg.Wait()
	}
}
