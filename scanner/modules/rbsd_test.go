package modules

import (
	"context"
	"net"
	"testing"
	"time"
)

// mockRBSDServer accepts one connection, reads a fixed number of bytes,
// and replies with a single response byte.
func mockRBSDServer(t *testing.T, respByte byte) (string, int) {
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

		// Drain the incoming request.
		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			// rexec/rlogin/rsh all send a payload ending in \x00.
			if buf[n-1] == 0x00 {
				break
			}
		}
		_, _ = conn.Write([]byte{respByte})
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// --- rexec ---

func TestRexecHandler_Success(t *testing.T) {
	host, port := mockRBSDServer(t, 0x00)
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := RexecHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "root", Password: "root"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for rexec 0x00 response")
	}
}

func TestRexecHandler_Failure(t *testing.T) {
	host, port := mockRBSDServer(t, 0x01)
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := RexecHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "root", Password: "wrong"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for rexec non-zero response")
	}
}

func TestRexecHandler_DialFailure(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 19975, OriginalTarget: "127.0.0.1"}
	_, err := RexecHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "root", Password: "root"})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}

// --- rlogin ---

func TestRloginHandler_Success(t *testing.T) {
	host, port := mockRBSDServer(t, 0x00)
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := RloginHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "root", Password: ""})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for rlogin 0x00 response")
	}
}

func TestRloginHandler_Failure(t *testing.T) {
	host, port := mockRBSDServer(t, 0x01)
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := RloginHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "root", Password: ""})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for rlogin non-zero response")
	}
}

func TestRloginHandler_DialFailure(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 19974, OriginalTarget: "127.0.0.1"}
	_, err := RloginHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "root", Password: ""})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}

// --- rsh ---

func TestRshHandler_Success(t *testing.T) {
	host, port := mockRBSDServer(t, 0x00)
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := RshHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "root", Password: ""})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for rsh 0x00 response")
	}
}

func TestRshHandler_Failure(t *testing.T) {
	host, port := mockRBSDServer(t, 0x01)
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := RshHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "root", Password: ""})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for rsh non-zero response")
	}
}

func TestRshHandler_DialFailure(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 19973, OriginalTarget: "127.0.0.1"}
	_, err := RshHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "root", Password: ""})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}
