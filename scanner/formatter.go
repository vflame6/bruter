package scanner

import (
	"errors"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
	"net"
	"strconv"
)

// ParseTarget parses a target string into a Target struct.
// Supported formats:
//   - IPv4:         "1.2.3.4"
//   - IPv4:port:    "1.2.3.4:22"
//   - IPv6:         "::1" or "2001:db8::1"
//   - IPv6:port:    "[::1]:22"
//   - hostname:     "example.com"
//   - hostname:port "example.com:8080"
func ParseTarget(target string, defaultPort int) (*modules.Target, error) {
	var ip net.IP
	var port int
	var err error

	// Try host:port format first — net.SplitHostPort handles IPv4:port and [IPv6]:port
	host, portStr, splitErr := net.SplitHostPort(target)
	if splitErr == nil {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		if port < 1 || port > 65535 {
			return nil, errors.New("invalid port number, format 1-65535")
		}
		ip, err = utils.LookupAddr(host)
		if err != nil {
			return nil, err
		}
	} else {
		// No port supplied — bare IPv4, bare IPv6, or hostname
		port = defaultPort
		ip, err = utils.LookupAddr(target)
		if err != nil {
			return nil, err
		}
	}

	return &modules.Target{IP: ip, Port: port, Encryption: true, Success: false, Retries: 0}, nil
}
