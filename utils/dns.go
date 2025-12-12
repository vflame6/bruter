package utils

import (
	"errors"
	"fmt"
	"github.com/vflame6/bruter/logger"
	"net"
)

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
