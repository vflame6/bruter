package scanner

import (
	"context"
	"errors"
	"github.com/vflame6/bruter/logger"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type ProxyAwareDialer struct {
	dialer  proxy.Dialer
	timeout time.Duration
}

func NewProxyAwareDialer(proxyHost, proxyAuth string, timeout time.Duration) (*ProxyAwareDialer, error) {
	var dialer proxy.Dialer

	// check if proxy host is specified
	if proxyHost != "" {
		logger.Debugf("trying to set up proxy: %s", proxyHost)

		var auth *proxy.Auth

		if proxyAuth != "" {
			testProxyUsernamePassword := strings.Split(proxyAuth, ":")
			if len(testProxyUsernamePassword) != 2 {
				return nil, errors.New("invalid proxy auth string, try USERNAME:PASSWORD")
			}
			auth = &proxy.Auth{
				User:     testProxyUsernamePassword[0],
				Password: testProxyUsernamePassword[1],
			}
		}

		d, err := proxy.SOCKS5("tcp", proxyHost, auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, err
		}
		dialer = d
	} else {
		// No proxy — use standard net.Dialer wrapped to satisfy proxy.Dialer interface
		dialer = &net.Dialer{Timeout: timeout}
	}

	return &ProxyAwareDialer{dialer: dialer, timeout: timeout}, nil
}

func (p *ProxyAwareDialer) Dial(network, addr string) (net.Conn, error) {
	return p.dialer.Dial(network, addr)
}

func (p *ProxyAwareDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if cd, ok := p.dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	// fallback: ignore context (shouldn't happen with net.Dialer or SOCKS5)
	return p.dialer.Dial(network, addr)
}

func (p *ProxyAwareDialer) Timeout() time.Duration {
	return p.timeout
}
