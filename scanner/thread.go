package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

func SendTargets(ctx context.Context, targets chan *modules.Target, defaultPort int, filename string) {
	defer close(targets)
	for line := range utils.ParseFileByLine(filename) {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		target, err := ParseTarget(line, defaultPort)
		if err != nil {
			logger.Debugf("can't parse line %s as host or host:port, ignoring", line)
			continue
		}
		select {
		case targets <- target:
		case <-ctx.Done():
			return
		}
	}
}

// SendCredentials sends credential pairs to the credentials channel.
// Exits when the done channel is closed (threads stopped early) or ctx is cancelled.
func SendCredentials(ctx context.Context, credentials chan *modules.Credential, usernames, passwords []string, done <-chan struct{}) {
	defer close(credentials)
	for _, pwd := range passwords {
		for _, user := range usernames {
			select {
			case credentials <- &modules.Credential{Username: user, Password: pwd}:
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

// jsonResult is the schema for JSONL output.
type jsonResult struct {
	Target    string `json:"target"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Timestamp int64  `json:"timestamp"`
}

// GetResults drains the results channel and writes each success to the log and/or output file.
// In JSON mode it emits JSONL; otherwise plain text. wg is Done when channel fully drained.
func GetResults(results chan *Result, outputFile *os.File, wg *sync.WaitGroup, successes *atomic.Int64, jsonMode bool) {
	defer wg.Done()
	for {
		result, ok := <-results
		if !ok {
			return
		}

		successes.Add(1)

		if jsonMode {
			jr := jsonResult{
				Target:    result.OriginalTarget,
				Port:      result.Port,
				Protocol:  result.Command,
				Username:  result.Username,
				Password:  result.Password,
				Timestamp: result.Timestamp.Unix(),
			}
			line, err := json.Marshal(jr)
			if err != nil {
				logger.Debugf("json marshal error: %v", err)
				continue
			}
			lineStr := string(line)
			if outputFile != nil {
				_, _ = outputFile.WriteString(lineStr + "\n")
			} else {
				logger.Success(lineStr)
			}
		} else {
			successString := fmt.Sprintf("[%s] %s:%d [%s] [%s]", result.Command, result.IP, result.Port, result.Username, result.Password)
			logger.Success(successString)
			if outputFile != nil {
				_, _ = outputFile.WriteString(successString + "\n")
			}
		}
	}
}
