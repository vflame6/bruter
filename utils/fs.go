package utils

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/vflame6/bruter/logger"
	"io"
	"os"
)

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

// ParseFileByLine is a function to read file in iterations
func ParseFileByLine(filename string) <-chan string {
	out := make(chan string)

	go func() {
		defer close(out)

		// if filename is a real file, parse it
		if IsFileExists(filename) {
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

// LoadLines reads all non-empty lines from a file into a slice.
// If filename is not a real file, it returns a single-element slice.
func LoadLines(filename string) []string {
	if !IsFileExists(filename) {
		return []string{filename}
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Debugf("error while reading file %s: %v", filename, err)
	}
	return lines
}
