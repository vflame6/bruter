package utils

import (
	"crypto/md5" //nolint:gosec
	"fmt"
	"strings"
)

// MD5Hex returns the lowercase hex-encoded MD5 hash of s.
func MD5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec
	return fmt.Sprintf("%x", sum)
}

func ContainsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
