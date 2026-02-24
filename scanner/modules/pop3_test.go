package modules

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/vflame6/bruter/utils"
)

// mockPOP3Server starts a minimal POP3 server that handles one connection.
func mockPOP3Server(t *testing.T, passResp string) (host string, port int) {
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

		_, _ = fmt.Fprintf(conn, "+OK POP3 ready\r\n")

		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			line := string(buf[:n])
			switch {
			case len(line) >= 4 && line[:4] == "USER":
				_, _ = fmt.Fprintf(conn, "+OK send PASS\r\n")
			case len(line) >= 4 && line[:4] == "PASS":
				_, _ = fmt.Fprintf(conn, "%s\r\n", passResp)
				return
			case len(line) >= 4 && line[:4] == "QUIT":
				_, _ = fmt.Fprintf(conn, "+OK bye\r\n")
				return
			}
		}
	}()

	return "127.0.0.1", addr.Port
}

func pop3Dialer(t *testing.T) *utils.ProxyAwareDialer {
	t.Helper()
	d, err := utils.NewProxyAwareDialer("", "", 3*time.Second, "test/1.0", nil)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	return d
}

func TestPOP3Handler(t *testing.T) {
	tests := []struct {
		name     string
		passResp string
		wantOk   bool
	}{
		{"valid credentials", "+OK logged in", true},
		{"invalid credentials", "-ERR invalid password", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := mockPOP3Server(t, tt.passResp)
			target := &Target{
				IP:             net.ParseIP(host),
				Port:           port,
				OriginalTarget: host,
				Encryption:     false,
			}
			ok, err := POP3Handler(context.Background(), pop3Dialer(t), 3*time.Second,
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

func TestPOP3Handler_DialFailure(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 19998, OriginalTarget: "127.0.0.1"}
	_, err := POP3Handler(context.Background(), pop3Dialer(t), 500*time.Millisecond,
		target, &Credential{Username: "u", Password: "p"})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}
