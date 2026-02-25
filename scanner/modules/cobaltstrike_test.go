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

// TestCobaltStrikeHandler_WrongPassword simulates a server that closes the
// connection after receiving the packet — meaning wrong password.
// Since the handler requires TLS, a plain TCP listener causes the TLS handshake
// to fail (returned as err from DialTLSContext), which is the correct failure path.
func TestCobaltStrikeHandler_WrongPassword(t *testing.T) {
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
		// Read the 261-byte packet and close — simulates wrong password.
		buf := make([]byte, 261)
		_, _ = readFull(conn, buf)
		_ = conn.Close()
	}()

	addr := ln.Addr().(*net.TCPAddr)
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           addr.Port,
		OriginalTarget: "127.0.0.1",
		Encryption:     true,
	}
	ok, _ := CobaltStrikeHandler(context.Background(), newTestDialer(t), 2*time.Second,
		target, &Credential{Username: "", Password: "wrongpassword"})

	// Key invariant: never returns ok=true against a plain TCP listener.
	if ok {
		t.Error("ok should be false when server closes connection (wrong password)")
	}
}
