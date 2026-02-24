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

// CustomTransport wraps http.Transport and adds a default User-Agent header.
type CustomTransport struct {
	Transport http.RoundTripper
	UserAgent string
}

// RoundTrip implements the http.RoundTripper interface.
// It is needed to make the HTTP requests look like browsers.
func (t *CustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Set the User-Agent header on the request.
	req.Header.Set("User-Agent", t.UserAgent)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	// Use the underlying transport to perform the actual request.
	return t.Transport.RoundTrip(req)
}

type ProxyAwareDialer struct {
	dialer     proxy.Dialer
	timeout    time.Duration
	HTTPClient *http.Client
}

// NewProxyAwareDialer creates a dialer with optional SOCKS5 proxy and optional local address binding.
// localAddr binds outgoing connections to a specific interface IP (nil = OS default).
func NewProxyAwareDialer(proxyHost, proxyAuth string, timeout time.Duration, userAgent string, localAddr net.IP) (*ProxyAwareDialer, error) {
	var dialer proxy.Dialer

	// Build the base net.Dialer, optionally binding to a local interface address
	baseDialer := &net.Dialer{Timeout: timeout}
	if localAddr != nil {
		baseDialer.LocalAddr = &net.TCPAddr{IP: localAddr}
	}

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

		d, err := proxy.SOCKS5("tcp", proxyHost, auth, baseDialer)
		if err != nil {
			return nil, err
		}
		dialer = d
	} else {
		dialer = baseDialer
	}

	d := &ProxyAwareDialer{
		dialer:  dialer,
		timeout: timeout,
	}

	tr := &CustomTransport{
		Transport: &http.Transport{
			DialContext:     d.DialContext,
			TLSClientConfig: GetTLSConfig(),
		},
		UserAgent: userAgent,
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
	return w.Dialer.DialTLS(network, addr, GetTLSConfig())
}

func (w *TLSDialerWrapper) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	return w.Dialer.DialTLS(network, addr, GetTLSConfig())
}
