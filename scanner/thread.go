package scanner

import (
	"bufio"
	"fmt"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
	"os"
	"strings"
	"sync"
	"time"
)

func ThreadHandler(handler modules.CommandHandler, wg *sync.WaitGroup, credentials <-chan *Credential, opts *Options, target *Target) {
	defer wg.Done()

	for {
		credential, ok := <-credentials
		if !ok {
			break
		}
		// shutdown all threads if --stop-on-success is used and password is found
		if opts.StopOnSuccess && target.Success {
			break
		}
		// shutdown all threads if number of max retries exceeded
		if opts.Retries > 0 && target.Retries >= opts.Retries {
			break
		}
		logger.Debugf("trying %s:%s on %s:%d", credential.Username, credential.Password, target.IP, target.Port)

		isConnected, isSuccess := handler(target.IP, target.Port, target.Encryption, opts.Timeout, opts.ProxyDialer, credential.Username, credential.Password)

		if opts.Retries > 0 && !isConnected {
			target.Mutex.Lock()
			target.Retries++
			if target.Retries == opts.Retries {
				logger.Infof("exceeded number of max retries on %s:%d, probably banned by the target", target.IP, target.Port)
			}
			target.Mutex.Unlock()
		}

		if isSuccess {
			RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, credential.Username, credential.Password)
		}

		if opts.Delay > 0 {
			time.Sleep(opts.Delay)
		}
	}
}

func RegisterSuccess(outputFile *os.File, fileMutex *sync.Mutex, command string, target *Target, username, password string) {
	target.Mutex.Lock()
	target.Success = true
	target.Mutex.Unlock()

	successString := fmt.Sprintf("[%s] %s:%d [%s] [%s]", command, target.IP, target.Port, username, password)

	logger.Successf(successString)

	if outputFile != nil {
		fileMutex.Lock()
		_, _ = outputFile.WriteString(successString + "\n")
		fileMutex.Unlock()
	}
}

func SendTargets(targets chan *Target, defaultPort int, filename string) {
	// if filename is an actual file, parse it
	if utils.IsFileExists(filename) {
		file, err := os.Open(filename)
		if err != nil {
			logger.Infof("failed to open targets file %s: %v", filename, err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			target, err := ParseTarget(line, defaultPort)
			if err != nil {
				logger.Debugf("can't parse line %s as host or host:port, ignoring", line)
				continue
			}
			targets <- target
		}
	} else {
		// if filename is not a file, use it as target
		target, err := ParseTarget(filename, defaultPort)
		if err != nil {
			logger.Debugf("can't parse target %s as host or host:port, ignoring", target)
			return
		}
		targets <- target
	}

	close(targets)
}

func SendCredentials(credentials chan *Credential, usernames, passwords string) {
	for linePwd := range ParseFileByLine(passwords) {
		for lineUsername := range ParseFileByLine(usernames) {
			credentials <- &Credential{Username: lineUsername, Password: linePwd}
		}
	}

	close(credentials)
}

// ParseFileByLine is a function to read file in iterations
func ParseFileByLine(filename string) <-chan string {
	out := make(chan string)

	go func() {
		defer close(out)

		// if filename is a real file, parse it
		if utils.IsFileExists(filename) {
			f, err := os.Open(filename)
			if err != nil {
				return
			}
			defer f.Close()

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					continue
				}
				out <- line
			}
			if err := scanner.Err(); err != nil {
				logger.Debugf("error while reading file %s: %v", filename, err)
			}
		} else {
			// if filename is not a file, send it as a line
			out <- filename
		}
	}()

	return out
}
