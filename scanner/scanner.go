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

// Commands stores all available services for bruteforce
var Commands = map[string]Command{
	"amqp":       {5672, modules.AMQPHandler, modules.AMQPChecker, "guest", "guest"},
	"clickhouse": {9000, modules.ClickHouseHandler, modules.ClickHouseChecker, "default", ""},
	"etcd":       {2379, modules.EtcdHandler, modules.EtcdChecker, "root", "123"},
	"ftp":        {21, modules.FTPHandler, modules.FTPChecker, "anonymous", "anonymous"},
	"mongo":      {27017, modules.MongoHandler, modules.MongoChecker, "", ""},
	"smpp":       {2775, modules.SMPPHandler, modules.SMPPChecker, "smppclient1", "password"},
	"ssh":        {22, modules.SSHHandler, modules.SSHChecker, "root", "123456"},
	"vault":      {8200, modules.VaultHandler, modules.VaultChecker, "admin", "admin"},
}

type Command struct {
	DefaultPort     int
	Handler         modules.CommandHandler
	Checker         modules.CommandChecker
	DefaultUsername string
	DefaultPassword string
}

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
	ProxyDialer    *utils.ProxyAwareDialer // --proxy
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

func NewScanner(timeout int, output string, parallel, threads, delay int, stopOnSuccess bool, retries int, proxyStr, proxyAuthStr, username, password string) (*Scanner, error) {
	var outputFile *os.File
	var err error

	if output != "" {
		var err error
		outputFile, err = os.Create(output)
		if err != nil {
			return nil, err
		}
	}

	// custom dialer to handle proxy settings
	dialer, err := utils.NewProxyAwareDialer(proxyStr, proxyAuthStr, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, err
	}

	parallelTargets := make(chan *Target, parallel*BufferMultiplier)

	options := Options{
		Timeout:        time.Duration(timeout) * time.Second,
		Threads:        threads,
		Delay:          time.Duration(delay) * time.Millisecond,
		StopOnSuccess:  stopOnSuccess,
		Retries:        retries,
		ProxyDialer:    dialer,
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
	if utils.IsFileExists(targets) {
		count, err = utils.CountLinesInFile(targets)
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

		go s.ParallelHandler(&parallelWg, &c)
	}
	parallelWg.Wait()

	return nil
}

func (s *Scanner) ParallelHandler(wg *sync.WaitGroup, command *Command) {
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
