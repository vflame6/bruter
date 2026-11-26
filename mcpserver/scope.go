// Package mcpserver exposes bruter over the Model Context Protocol so an agent
// can drive it, without letting that agent choose its own targets.
//
// Credential testing is only legitimate inside an authorized engagement, and a
// model deciding for itself what to attack is not an authorization decision.
// The tools that put traffic on the wire are therefore gated on a scope file
// the operator writes before starting the server: if there is no scope file,
// those tools are never registered, and the agent sees only the read-only ones.
package mcpserver

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Scope is the set of hosts an MCP client is allowed to touch. It is built
// once, before the server starts, and never changes at runtime.
type Scope struct {
	nets    []*net.IPNet
	ips     []net.IP
	hosts   map[string]struct{}
	entries []string
}

// LoadScope reads a scope file: one IP, CIDR block or hostname per line, with
// blank lines and # comments ignored.
func LoadScope(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open scope file: %w", err)
	}
	defer func() { _ = f.Close() }()

	scope := &Scope{hosts: make(map[string]struct{})}

	lineNo := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := scope.add(line); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, lineNo, err)
		}
		scope.entries = append(scope.entries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read scope file: %w", err)
	}

	if len(scope.entries) == 0 {
		return nil, errors.New("scope file is empty: it must list at least one host or CIDR block")
	}
	return scope, nil
}

func (s *Scope) add(entry string) error {
	if strings.Contains(entry, "/") {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("%q is not a valid CIDR block: %w", entry, err)
		}
		s.nets = append(s.nets, network)
		return nil
	}

	// A bare host:port entry is almost certainly a mistake: scope is about
	// hosts, and silently ignoring the port would widen it.
	if host, _, err := net.SplitHostPort(entry); err == nil && host != "" {
		return fmt.Errorf("%q includes a port; list scope by host or CIDR block only", entry)
	}

	if ip := net.ParseIP(entry); ip != nil {
		s.ips = append(s.ips, ip)
		return nil
	}

	// "10.0.0.1-10.0.0.50" is a legal hostname as far as DNS grammar goes, so
	// it would otherwise be stored as a name that matches nothing and quietly
	// shrink the scope to empty.
	if lo, hi, found := strings.Cut(entry, "-"); found {
		if net.ParseIP(strings.TrimSpace(lo)) != nil && net.ParseIP(strings.TrimSpace(hi)) != nil {
			return fmt.Errorf("%q looks like an address range; write ranges as CIDR blocks, e.g. 10.0.0.0/24", entry)
		}
	}

	if !plausibleHostname(entry) {
		return fmt.Errorf("%q is neither an IP, a CIDR block nor a hostname", entry)
	}

	// No real top-level domain is all digits, so this is a mistyped address
	// rather than a host the operator meant to name.
	labels := strings.Split(entry, ".")
	if last := labels[len(labels)-1]; allDigits(last) {
		return fmt.Errorf("%q is not a valid IP address or hostname", entry)
	}

	s.hosts[strings.ToLower(entry)] = struct{}{}
	return nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Allows reports whether a target is in scope. The target may be given as
// host or host:port.
//
// Hostnames must match an entry exactly; bruter deliberately does not resolve
// them first, because a scope decision that depends on whatever DNS answers at
// the time is not a scope decision.
func (s *Scope) Allows(target string) bool {
	if s == nil {
		return false
	}

	host, ok := scopeHost(target)
	if !ok {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		for _, allowed := range s.ips {
			if allowed.Equal(ip) {
				return true
			}
		}
		for _, network := range s.nets {
			if network.Contains(ip) {
				return true
			}
		}
		return false
	}

	_, listed := s.hosts[strings.ToLower(host)]
	return listed
}

// scopeHost extracts the host from a target and rejects anything that is not
// exactly one host, optionally followed by one numeric port.
//
// The strictness is load-bearing rather than tidiness. net.SplitHostPort does
// not validate the port, so "10.0.0.5:22,10.9.9.9" parses as host 10.0.0.5
// with port "22,10.9.9.9". The scanner's target reader splits on commas and
// also treats a value naming an existing file as a target list, so a target
// that passed the scope check on its first host could smuggle in a second one.
func scopeHost(target string) (string, bool) {
	host := strings.TrimSpace(target)
	if host == "" {
		return "", false
	}

	// Separators the target reader would act on, and path characters.
	if strings.ContainsAny(host, ",/\\ \t\r\n") {
		return "", false
	}

	if h, p, err := net.SplitHostPort(host); err == nil {
		port, convErr := strconv.Atoi(p)
		if convErr != nil || port < 1 || port > 65535 {
			return "", false
		}
		host = h
	}

	host = strings.Trim(host, "[]")
	if host == "" {
		return "", false
	}
	return host, true
}

// Reject returns the subset of targets that are out of scope.
func (s *Scope) Reject(targets []string) []string {
	var out []string
	for _, target := range targets {
		if !s.Allows(target) {
			out = append(out, target)
		}
	}
	return out
}

// Entries lists the scope file's contents, so an agent can see what it is
// allowed to touch instead of guessing.
func (s *Scope) Entries() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.entries))
	copy(out, s.entries)
	return out
}

// plausibleHostname keeps obvious junk out of the scope file. It is a sanity
// check on operator input, not a validator of the DNS grammar.
func plausibleHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z',
				r >= 'A' && r <= 'Z',
				r >= '0' && r <= '9',
				r == '-', r == '_':
			default:
				return false
			}
		}
	}
	return true
}
