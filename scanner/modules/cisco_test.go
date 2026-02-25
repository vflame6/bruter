package modules

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// mockCiscoServer starts a minimal Cisco IOS Telnet server.
// onAuth is the response sent after password is submitted.
func mockCiscoServer(t *testing.T, onAuth string) (string, int) {
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

		_, _ = fmt.Fprintf(conn, "\r\nUsername: ")

		buf := make([]byte, 256)
		conn.Read(buf) //nolint:errcheck

		_, _ = fmt.Fprintf(conn, "Password: ")

		conn.Read(buf) //nolint:errcheck

		_, _ = fmt.Fprintf(conn, "%s", onAuth)
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestCiscoHandler_Success(t *testing.T) {
	host, port := mockCiscoServer(t, "Router>")
	target := &Target{
		IP:             net.ParseIP(host),
		Port:           port,
		OriginalTarget: host,
		Encryption:     false,
	}
	ok, err := CiscoHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "cisco", Password: "cisco"})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for user-mode prompt")
	}
}

func TestCiscoHandler_PrivMode(t *testing.T) {
	host, port := mockCiscoServer(t, "Router#")
	target := &Target{
		IP:             net.ParseIP(host),
		Port:           port,
		OriginalTarget: host,
		Encryption:     false,
	}
	ok, err := CiscoHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "cisco", Password: "cisco"})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for privileged-mode prompt")
	}
}

func TestCiscoHandler_Failure(t *testing.T) {
	host, port := mockCiscoServer(t, "\r\n% Login invalid\r\n\r\nUsername: ")
	target := &Target{
		IP:             net.ParseIP(host),
		Port:           port,
		OriginalTarget: host,
		Encryption:     false,
	}
	ok, err := CiscoHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "cisco", Password: "wrong"})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for invalid login response")
	}
}

func TestCiscoHandler_DialFailure(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 19988, OriginalTarget: "127.0.0.1"}
	_, err := CiscoHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "cisco", Password: "cisco"})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}
