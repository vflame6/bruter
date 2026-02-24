package modules

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vflame6/bruter/utils"
)

// mockIMAPServer starts a minimal IMAP server for one connection.
func mockIMAPServer(t *testing.T, loginResp string) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr := ln.Addr().(*net.TCPAddr)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		_, _ = fmt.Fprintf(conn, "* OK IMAP4rev1 ready\r\n")

		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			line := string(buf[:n])
			if strings.Contains(line, "LOGIN") {
				tag := strings.SplitN(line, " ", 2)[0]
				_, _ = fmt.Fprintf(conn, "%s %s\r\n", tag, loginResp)
				return
			}
		}
	}()

	return "127.0.0.1", addr.Port
}

func imapDialer(t *testing.T) *utils.ProxyAwareDialer {
	t.Helper()
	d, err := utils.NewProxyAwareDialer("", "", 3*time.Second, "test/1.0", nil)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	return d
}

func TestIMAPHandler(t *testing.T) {
	tests := []struct {
		name      string
		loginResp string
		wantOk    bool
	}{
		{"valid credentials", "OK LOGIN completed", true},
		{"invalid credentials NO", "NO LOGIN failed", false},
		{"invalid credentials BAD", "BAD invalid command", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := mockIMAPServer(t, tt.loginResp)
			target := &Target{
				IP:             net.ParseIP(host),
				Port:           port,
				OriginalTarget: host,
				Encryption:     false,
			}
			ok, err := IMAPHandler(context.Background(), imapDialer(t), 3*time.Second,
				target, &Credential{Username: "u", Password: "p"})

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tt.wantOk {
				t.Errorf("ok = %v, want %v", ok, tt.wantOk)
			}
		})
	}
}

func TestIMAPHandler_DialFailure(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 19997, OriginalTarget: "127.0.0.1"}
	_, err := IMAPHandler(context.Background(), imapDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "u", Password: "p"})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}
