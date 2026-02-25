package modules

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestCobaltStrikeHandler_DialFailure verifies that a connection refused
// is returned as an error (not misclassified as auth success or failure).
func TestCobaltStrikeHandler_DialFailure(t *testing.T) {
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           19971,
		OriginalTarget: "127.0.0.1",
		Encryption:     true,
	}
	ok, err := CobaltStrikeHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "", Password: "password"})

	if err == nil {
		t.Error("expected connection error, got nil")
	}
	if ok {
		t.Error("ok should be false on dial failure")
	}
}

// TestCobaltStrikeHandler_ImmediateClose verifies that a server that closes
// the connection immediately (wrong password) returns (false, nil).
func TestCobaltStrikeHandler_ImmediateClose(t *testing.T) {
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
		// Read and immediately close (simulates wrong password).
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}()

	addr := ln.Addr().(*net.TCPAddr)
	// CobaltStrike requires TLS — but we can test the logic with a plain TCP
	// mock that simulates the "connection closed = wrong password" path.
	// Since the TLS handshake will fail against a plain TCP server, we expect
	// either a TLS error (returned as err from DialTLSContext) or (false, nil).
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           addr.Port,
		OriginalTarget: "127.0.0.1",
		Encryption:     true,
	}
	ok, _ := CobaltStrikeHandler(context.Background(), newTestDialer(t), 2*time.Second,
		target, &Credential{Username: "", Password: "password"})

	// Key invariant: auth never returns ok=true against a plain TCP listener.
	if ok {
		t.Error("ok should be false when server closes connection")
	}
}
