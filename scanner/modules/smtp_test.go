package modules

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/vflame6/bruter/utils"
)

// mockSMTPServer starts a minimal SMTP server that handles one connection.
// respAuth is the AUTH response: "235 OK" for success, "535 failed" for failure.
func mockSMTPServer(t *testing.T, respAuth string) (host string, port int) {
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

		// Greeting
		_, _ = fmt.Fprintf(conn, "220 mock SMTP ready\r\n")

		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			line := string(buf[:n])

			switch {
			case len(line) >= 4 && line[:4] == "EHLO":
				_, _ = fmt.Fprintf(conn, "250-mock\r\n250 AUTH PLAIN LOGIN\r\n")
			case len(line) >= 4 && line[:4] == "HELO":
				_, _ = fmt.Fprintf(conn, "250 mock\r\n")
			case len(line) >= 4 && line[:4] == "AUTH":
				_, _ = fmt.Fprintf(conn, "%s\r\n", respAuth)
				return
			case len(line) >= 4 && line[:4] == "QUIT":
				_, _ = fmt.Fprintf(conn, "221 bye\r\n")
				return
			}
		}
	}()

	return "127.0.0.1", addr.Port
}

func smtpDialer(t *testing.T) *utils.ProxyAwareDialer {
	t.Helper()
	d, err := utils.NewProxyAwareDialer("", "", 3*time.Second, "test/1.0", nil)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	return d
}

func TestSMTPHandler(t *testing.T) {
	tests := []struct {
		name       string
		authResp   string
		wantOk     bool
		wantErrNil bool
	}{
		{
			name:       "valid credentials",
			authResp:   "235 2.7.0 Authentication successful",
			wantOk:     true,
			wantErrNil: true,
		},
		{
			name:       "invalid credentials 535",
			authResp:   "535 5.7.8 Authentication credentials invalid",
			wantOk:     false,
			wantErrNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := mockSMTPServer(t, tt.authResp)
			target := &Target{
				IP:             net.ParseIP(host),
				Port:           port,
				OriginalTarget: host,
				Encryption:     false,
			}
			cred := &Credential{Username: "user", Password: "pass"}

			ok, err := SMTPHandler(context.Background(), smtpDialer(t), 3*time.Second, target, cred)

			if tt.wantErrNil && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tt.wantOk {
				t.Errorf("ok = %v, want %v (err=%v)", ok, tt.wantOk, err)
			}
		})
	}
}

func TestSMTPHandler_DialFailure_ReturnsConnectionError(t *testing.T) {
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           19999, // nothing listening
		OriginalTarget: "127.0.0.1",
		Encryption:     false,
	}
	_, err := SMTPHandler(context.Background(), smtpDialer(t), 500*time.Millisecond, target,
		&Credential{Username: "u", Password: "p"})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}
