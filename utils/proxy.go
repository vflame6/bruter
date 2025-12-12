package utils

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vflame6/bruter/logger"
	"golang.org/x/net/proxy"
)

type ProxyAwareDialer struct {
	dialer     proxy.Dialer
	timeout    time.Duration
	HTTPClient *http.Client
}

func NewProxyAwareDialer(proxyHost, proxyAuth string, timeout time.Duration) (*ProxyAwareDialer, error) {
	var dialer proxy.Dialer

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
		dialer = &net.Dialer{Timeout: timeout}
	}

	d := &ProxyAwareDialer{
		dialer:  dialer,
		timeout: timeout,
	}

	tr := &http.Transport{
		DialContext:     d.DialContext,
		TLSClientConfig: GetTLSConfig(),
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}

	d.HTTPClient = httpClient

	return d, nil
}

func (p *ProxyAwareDialer) Dial(network, addr string) (net.Conn, error) {
	return p.dialer.Dial(network, addr)
}

func (p *ProxyAwareDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if cd, ok := p.dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	return p.dialer.Dial(network, addr)
}

// DialTimeout dials with a specific timeout (implements pq.Dialer interface)
func (p *ProxyAwareDialer) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	// Use the provided timeout or fall back to default
	if timeout == 0 {
		timeout = p.timeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return p.DialContext(ctx, network, addr)
}

// DialTLS establishes a TLS connection through the proxy
func (p *ProxyAwareDialer) DialTLS(network, addr string, config *tls.Config) (net.Conn, error) {
	conn, err := p.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = GetTLSConfig()
	}

	tlsConn := tls.Client(conn, config)

	if err := tlsConn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// DialTLSContext establishes a TLS connection with context support
func (p *ProxyAwareDialer) DialTLSContext(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
	conn, err := p.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = GetTLSConfig()
	}

	if config.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		config = config.Clone()
		config.ServerName = host
	}

	tlsConn := tls.Client(conn, config)

	// Use context deadline if available, otherwise use timeout
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(p.timeout)
	}

	if err := tlsConn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (p *ProxyAwareDialer) Timeout() time.Duration {
	return p.timeout
}

// TLSDialerWrapper wraps ProxyAwareDialer to use TLS for all connections
type TLSDialerWrapper struct {
	Dialer *ProxyAwareDialer
}

func (w *TLSDialerWrapper) Dial(network, addr string) (net.Conn, error) {
	return w.Dialer.DialTLS(network, addr, nil)
}

func (w *TLSDialerWrapper) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	return w.Dialer.DialTLS(network, addr, nil)
}
