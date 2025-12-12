package scanner

import (
	"errors"
	"github.com/vflame6/bruter/utils"
	"net"
	"strconv"
	"strings"
)

func ParseTarget(target string, defaultPort int) (*Target, error) {
	var ip net.IP
	var err error

	testTarget := strings.Split(target, ":")

	if len(testTarget) == 2 {
		ip, err = utils.LookupAddr(testTarget[0])
		if err != nil {
			return nil, err
		}

		port, err := strconv.Atoi(testTarget[1])
		if err != nil {
			return nil, err
		}
		if !(port >= 1 && port <= 65535) {
			return nil, errors.New("invalid port number, format 1-65535")
		}

		return &Target{IP: ip, Port: port, Encryption: false, Success: false, Retries: 0}, nil
	}
	if len(testTarget) == 1 {
		ip, err = utils.LookupAddr(testTarget[0])
		if err != nil {
			return nil, err
		}
		return &Target{IP: ip, Port: defaultPort, Encryption: false, Success: false, Retries: 0}, nil
	}
	return nil, errors.New("target is not a valid IP, IP:PORT or filename")
}
