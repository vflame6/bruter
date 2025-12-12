package utils

import (
	"bytes"
	"errors"
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
