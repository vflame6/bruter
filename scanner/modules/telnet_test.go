package modules

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// mockTelnetServer starts a minimal Telnet server that runs one auth exchange.
// onAuth returns the response after password is sent.
func mockTelnetServer(t *testing.T, onAuth string) (string, int) {
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
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		_, _ = fmt.Fprintf(conn, "login: ")

		buf := make([]byte, 256)
		// read username line
		n, _ := conn.Read(buf)
		_ = string(buf[:n])

		_, _ = fmt.Fprintf(conn, "password: ")

		// read password line
		conn.Read(buf) //nolint:errcheck

		_, _ = fmt.Fprintf(conn, "%s", onAuth)
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestTelnetHandler_Success(t *testing.T) {
	host, port := mockTelnetServer(t, "user@host:~$ ")
	target := &Target{
		IP:             net.ParseIP(host),
		Port:           port,
		OriginalTarget: host,
		Encryption:     false,
	}
	ok, err := TelnetHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "admin", Password: "admin"})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for shell prompt response")
	}
}

func TestTelnetHandler_Failure(t *testing.T) {
	host, port := mockTelnetServer(t, "Login incorrect\r\nlogin: ")
	target := &Target{
		IP:             net.ParseIP(host),
		Port:           port,
		OriginalTarget: host,
		Encryption:     false,
	}
	ok, err := TelnetHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "admin", Password: "wrong"})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for failed login response")
	}
}

func TestTelnetHandler_DialFailure(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 19989, OriginalTarget: "127.0.0.1"}
	_, err := TelnetHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "admin", Password: "admin"})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}

func TestStripIAC(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "no IAC bytes",
			input: []byte("login: "),
			want:  "login: ",
		},
		{
			name:  "IAC sequence stripped",
			input: []byte{0xFF, 0xFD, 0x01, 'l', 'o', 'g', 'i', 'n', ':', ' '},
			want:  "login: ",
		},
		{
			name:  "multiple IAC sequences",
			input: []byte{0xFF, 0xFB, 0x03, 0xFF, 0xFD, 0x18, 'o', 'k'},
			want:  "ok",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(stripIAC(tt.input))
			if got != tt.want {
				t.Errorf("stripIAC(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
