package utils

import (
	"fmt"
	"net"
	"sync"

	"github.com/vflame6/bruter/logger"
)

// dnsCache caches hostname → resolved IP to avoid repeated DNS lookups.
var dnsCache sync.Map // map[string]net.IP

func LookupAddr(addr string) (net.IP, error) {
	ip := net.ParseIP(addr)
	if ip != nil {
		return ip, nil
	}

	// Check cache first
	if cached, ok := dnsCache.Load(addr); ok {
		return cached.(net.IP), nil
	}

	ips, err := net.LookupHost(addr)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found on host %s", addr)
	}
	logger.Debugf("resolved %s to %s", addr, ips[0])
	ip = net.ParseIP(ips[0])

	// Store in cache
	dnsCache.Store(addr, ip)

	return ip, nil
}
