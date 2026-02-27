package modules

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func winrmTarget(t *testing.T, addr string) (*Target, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	return &Target{IP: net.ParseIP(h), Port: port}, port
}

func newWinRMServer(t *testing.T, validUser, validPass string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wsman" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(validUser+":"+validPass))
		if auth == expected {
			w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<IdentifyResponse/>`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
}

func TestWinRMHandler_Success(t *testing.T) {
	srv := newWinRMServer(t, "admin", "secret")
	defer srv.Close()

	target, _ := winrmTarget(t, srv.Listener.Addr().String())
	dialer := newTestDialer(t)
	cred := &Credential{Username: "admin", Password: "secret"}

	ok, err := WinRMHandler(context.Background(), dialer, time.Second*5, target, cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected successful auth")
	}
}

func TestWinRMHandler_Failure(t *testing.T) {
	srv := newWinRMServer(t, "admin", "secret")
	defer srv.Close()

	target, _ := winrmTarget(t, srv.Listener.Addr().String())
	dialer := newTestDialer(t)
	cred := &Credential{Username: "admin", Password: "wrong"}

	ok, err := WinRMHandler(context.Background(), dialer, time.Second*5, target, cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected failed auth")
	}
}

func TestWinRMHandler_SOAPBody(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	target, _ := winrmTarget(t, srv.Listener.Addr().String())
	dialer := newTestDialer(t)
	cred := &Credential{Username: "a", Password: "b"}

	_, _ = WinRMHandler(context.Background(), dialer, time.Second*5, target, cred)

	if !strings.Contains(gotBody, "Identify") {
		t.Fatalf("expected SOAP Identify body, got: %s", gotBody)
	}
}
