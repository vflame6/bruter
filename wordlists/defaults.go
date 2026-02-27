// Package wordlists provides built-in default username and password lists
// for use with the --defaults flag.
//
// Wordlists are embedded from .txt files at compile time via go:embed.
// To update, edit usernames.txt and passwords.txt directly.
package wordlists

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"strings"
)

//go:embed usernames.txt
var usernamesRaw string

//go:embed passwords.txt
var passwordsRaw string

//go:embed ssh_badkeys.txt
var sshBadKeysRaw string

// DefaultUsernames contains common service usernames.
// Source: https://github.com/vflame6/wordlists/blob/main/usernames/top-usernames-shortlist.txt
var DefaultUsernames = parseLines(usernamesRaw)

// DefaultPasswords contains the 200 most used passwords (2023).
// Source: https://github.com/vflame6/wordlists/blob/main/passwords/2023-200_most_used_passwords.txt
var DefaultPasswords = parseLines(passwordsRaw)

// DefaultSSHKeys contains known-bad SSH private keys (Vagrant, F5, ExaGrid, etc.)
// parsed from PEM blocks in ssh_badkeys.txt.
// Source: https://github.com/rapid7/ssh-badkeys
var DefaultSSHKeys = parsePEMKeys(sshBadKeysRaw)

func parsePEMKeys(raw string) []string {
	data := []byte(raw)
	var keys []string
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		// Validate it's a usable private key
		pemBytes := pem.EncodeToMemory(block)
		if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			keys = append(keys, string(pemBytes))
		} else if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			keys = append(keys, string(pemBytes))
		} else if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			keys = append(keys, string(pemBytes))
		} else {
			// Include even if we can't parse (DSA keys, etc.) — ssh library handles them
			keys = append(keys, string(pemBytes))
		}
		data = rest
	}
	return keys
}

func parseLines(raw string) []string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
