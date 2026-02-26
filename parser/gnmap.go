package parser

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// portEntry matches individual port entries in GNMAP Host lines:
//   22/open/tcp//ssh///
// Groups: 1=port, 2=state, 3=proto, 4=service
var portEntry = regexp.MustCompile(`(\d+)/([^/]*)/([^/]*)//?([^/]*)`)

// ParseGNMAP parses an nmap greppable output file (-oG) and returns
// discovered targets with open ports and recognized services.
func ParseGNMAP(path string) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("gnmap: %w", err)
	}
	defer f.Close()

	var targets []Target

	scanner := bufio.NewScanner(f)
	// Increase buffer for very long lines (nmap can produce huge Host lines)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// Only process Host lines with "Ports:" section
		if !strings.HasPrefix(line, "Host:") || !strings.Contains(line, "Ports:") {
			continue
		}

		// Extract host IP/hostname: "Host: 192.168.1.1 (hostname)\t..."
		host := extractGNMAPHost(line)
		if host == "" {
			continue
		}

		// Extract ports section: everything after "Ports: " until next tab-delimited section
		portsIdx := strings.Index(line, "Ports:")
		if portsIdx < 0 {
			continue
		}
		portsSection := line[portsIdx+len("Ports:"):]
		// Trim at next section (tab-delimited)
		if tabIdx := strings.Index(portsSection, "\t"); tabIdx >= 0 {
			portsSection = portsSection[:tabIdx]
		}

		// Parse each comma-separated port entry
		for _, entry := range strings.Split(portsSection, ",") {
			entry = strings.TrimSpace(entry)
			matches := portEntry.FindStringSubmatch(entry)
			if matches == nil {
				continue
			}

			port, err := strconv.Atoi(matches[1])
			if err != nil || port < 1 || port > 65535 {
				continue
			}

			state := matches[2]
			if state != "open" {
				continue
			}

			service := strings.TrimSpace(matches[4])

			service = strings.ToLower(service)
			if service == "" || service == "unknown" {
				continue
			}

			// Handle GNMAP "ssl|<service>" notation (e.g. "ssl|http")
			if strings.HasPrefix(service, "ssl|") {
				base := strings.TrimPrefix(service, "ssl|")
				// Try SSL variant first (e.g. "https"), then base
				if mod, ok := MapService(base + "s"); ok {
					targets = append(targets, Target{Host: host, Port: port, Service: mod})
					continue
				}
				service = base
			}

			mod, ok := MapService(service)
			if !ok {
				continue
			}

			targets = append(targets, Target{
				Host:    host,
				Port:    port,
				Service: mod,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("gnmap scan: %w", err)
	}

	return targets, nil
}

// extractGNMAPHost extracts the IP address from a GNMAP Host line.
// Format: "Host: 192.168.1.1 (hostname)\tPorts: ..."
func extractGNMAPHost(line string) string {
	// Skip "Host: "
	rest := strings.TrimPrefix(line, "Host:")
	rest = strings.TrimSpace(rest)

	// First token is the IP
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
