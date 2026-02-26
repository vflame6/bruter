// Package wordlists provides built-in default username and password lists
// for use with the --defaults flag.
//
// Wordlists are embedded from .txt files at compile time via go:embed.
// To update, edit usernames.txt and passwords.txt directly.
package wordlists

import (
	_ "embed"
	"strings"
)

//go:embed usernames.txt
var usernamesRaw string

//go:embed passwords.txt
var passwordsRaw string

// DefaultUsernames contains common service usernames.
// Source: https://github.com/vflame6/wordlists/blob/main/usernames/top-usernames-shortlist.txt
var DefaultUsernames = parseLines(usernamesRaw)

// DefaultPasswords contains the 200 most used passwords (2023).
// Source: https://github.com/vflame6/wordlists/blob/main/passwords/2023-200_most_used_passwords.txt
var DefaultPasswords = parseLines(passwordsRaw)

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
