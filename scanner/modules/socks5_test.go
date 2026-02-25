package modules

import (
	"context"
	"net"
	"testing"
	"time"
)

// mockSOCKS5Server starts a SOCKS5 server that speaks RFC 1928/1929.
// authStatus: 0x00 = auth success, anything else = auth failure.
func mockSOCKS5Server(t *testing.T, authStatus byte) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Read method selection: [VER, NMETHODS, METHOD...]
		buf := make([]byte, 3)
		if _, err := readFull(conn, buf); err != nil {
			return
		}
		// Reply: choose Username/Password method (0x02)
		_, _ = conn.Write([]byte{0x05, 0x02})

		// Read sub-negotiation: [0x01, ulen, user..., plen, pass...]
		header := make([]byte, 2)
		if _, err := readFull(conn, header); err != nil {
			return
		}
		ulen := int(header[1])
		userBuf := make([]byte, ulen)
		if _, err := readFull(conn, userBuf); err != nil {
			return
		}
		plenBuf := make([]byte, 1)
		if _, err := readFull(conn, plenBuf); err != nil {
			return
		}
		passBuf := make([]byte, int(plenBuf[0]))
		if _, err := readFull(conn, passBuf); err != nil {
			return
		}
		// Send auth result
		_, _ = conn.Write([]byte{0x01, authStatus})
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// mockSOCKS5NoAcceptable simulates a server that rejects all auth methods.
func mockSOCKS5NoAcceptable(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 3)
		_, _ = readFull(conn, buf)
		_, _ = conn.Write([]byte{0x05, 0xFF}) // no acceptable method
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestSOCKS5Handler_AuthSuccess(t *testing.T) {
	host, port := mockSOCKS5Server(t, 0x00)
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := SOCKS5Handler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "admin", Password: "admin"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for auth success")
	}
}

func TestSOCKS5Handler_AuthFailure(t *testing.T) {
	host, port := mockSOCKS5Server(t, 0x01)
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := SOCKS5Handler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "admin", Password: "wrong"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for auth failure")
	}
}

func TestSOCKS5Handler_NoAcceptableMethod(t *testing.T) {
	host, port := mockSOCKS5NoAcceptable(t)
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := SOCKS5Handler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "admin", Password: "admin"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when server rejects all methods")
	}
}

func TestSOCKS5Handler_DialFailure(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 19977, OriginalTarget: "127.0.0.1"}
	_, err := SOCKS5Handler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "admin", Password: "admin"})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}
