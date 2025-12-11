package scanner

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/vflame6/bruter/logger"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

func ParseTarget(target string, defaultPort int) (*Target, error) {
	var ip net.IP
	var err error

	testTarget := strings.Split(target, ":")

	if len(testTarget) == 2 {
		ip, err = LookupAddr(testTarget[0])
		if err != nil {
			return nil, err
		}

		port, err := strconv.Atoi(testTarget[1])
		if err != nil {
			return nil, err
		}
		if !(port >= 1 && port <= 65535) {
			return nil, errors.New("invalid port number, format 1-65535")
		}

		return &Target{IP: ip, Port: port, Encryption: false, Success: false, Retries: 0}, nil
	}
	if len(testTarget) == 1 {
		ip, err = LookupAddr(testTarget[0])
		if err != nil {
			return nil, err
		}
		return &Target{IP: ip, Port: defaultPort, Encryption: false, Success: false, Retries: 0}, nil
	}
	return nil, errors.New("target is not a valid IP, IP:PORT or filename")
}

func LookupAddr(addr string) (net.IP, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		ips, err := net.LookupHost(addr)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New(fmt.Sprintf("no IP addresses found on host %s", addr))
		}
		logger.Debugf("resolved %s to %s", addr, ips[0])
		ip = net.ParseIP(ips[0])
	}
	return ip, nil
}

// IsFileExists checks if a file exists at the given path.
func IsFileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	if err == nil {
		return true // File exists
	}
	if errors.Is(err, os.ErrNotExist) {
		return false // File does not exist
	}
	return false
}

func CountLinesInFile(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	buf := make([]byte, 32*1024)
	count := 0
	newline := []byte{'\n'}
	lastByteWasNewline := true // Assume empty file or starting fresh

	for {
		n, err := file.Read(buf)
		if n > 0 {
			count += bytes.Count(buf[:n], newline)
			lastByteWasNewline = buf[n-1] == '\n'
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}

	// If file is non-empty and doesn't end with newline, add 1
	if !lastByteWasNewline {
		count++
	}

	return count, nil
}
