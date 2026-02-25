package modules

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestSMBHandler_DialFailure verifies that a connection refused error is returned
// as an error (not misclassified as authentication success or failure).
func TestSMBHandler_DialFailure(t *testing.T) {
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           19990,
		OriginalTarget: "127.0.0.1",
		Encryption:     false,
	}
	ok, err := SMBHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "Administrator", Password: ""})

	if err == nil {
		t.Error("expected connection error, got nil")
	}
	if ok {
		t.Error("ok should be false on dial failure")
	}
}

// TestSMBHandler_ImmediateClose verifies that a server that closes the connection
// before completing the SMB handshake is not treated as auth success.
func TestSMBHandler_ImmediateClose(t *testing.T) {
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
		_ = conn.Close()
	}()

	addr := ln.Addr().(*net.TCPAddr)
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           addr.Port,
		OriginalTarget: "127.0.0.1",
		Encryption:     false,
	}
	ok, err := SMBHandler(context.Background(), newTestDialer(t), 2*time.Second,
		target, &Credential{Username: "Administrator", Password: ""})

	if ok {
		t.Error("ok should be false when server closes connection immediately")
	}
	_ = err // protocol error expected; key invariant is ok=false
}
