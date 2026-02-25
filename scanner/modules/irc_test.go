package modules

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// mockIRCServer starts a minimal IRC server for one connection.
// It responds with the given numeric after receiving the registration sequence.
func mockIRCServer(t *testing.T, responseNumeric string) (string, int) {
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

		buf := make([]byte, 512)
		// Read PASS + NICK + USER (may arrive in one read or several).
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			data := string(buf[:n])
			if containsAll(data, "PASS", "NICK", "USER") {
				break
			}
		}
		_, _ = fmt.Fprintf(conn, ":%s\r\n", responseNumeric)
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// containsAll returns true if s contains all substrings.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !containsStr(s, sub) {
			return false
		}
	}
	return true
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findStr(s, sub))
}

func findStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestIRCHandler_Welcome(t *testing.T) {
	host, port := mockIRCServer(t, "irc.example.com 001 bruter :Welcome to the IRC Network bruter")
	target := &Target{
		IP:             net.ParseIP(host),
		Port:           port,
		OriginalTarget: host,
		Encryption:     false,
	}
	ok, err := IRCHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "bruter", Password: "correct"})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true when server sends 001 RPL_WELCOME")
	}
}

func TestIRCHandler_PasswordMismatch(t *testing.T) {
	host, port := mockIRCServer(t, "irc.example.com 464 bruter :Password incorrect")
	target := &Target{
		IP:             net.ParseIP(host),
		Port:           port,
		OriginalTarget: host,
		Encryption:     false,
	}
	ok, err := IRCHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "bruter", Password: "wrong"})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when server sends 464 ERR_PASSWDMISMATCH")
	}
}

func TestIRCHandler_DialFailure(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 19978, OriginalTarget: "127.0.0.1"}
	_, err := IRCHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "bruter", Password: "password"})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}
