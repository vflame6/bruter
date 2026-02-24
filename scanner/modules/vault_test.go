package modules

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/vflame6/bruter/utils"
)

// startMockVault spins up a test server that records Host headers.
func startMockVault(t *testing.T, statusCode int, body string) (*httptest.Server, *string) {
	t.Helper()
	capturedHost := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*capturedHost = r.Host
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, capturedHost
}

func newTestDialer(t *testing.T) *utils.ProxyAwareDialer {
	t.Helper()
	d, err := utils.NewProxyAwareDialer("", "", 5*time.Second, "bruter-test/1.0", nil)
	if err != nil {
		t.Fatalf("NewProxyAwareDialer: %v", err)
	}
	return d
}

func successBody() string {
	b, _ := json.Marshal(map[string]any{"auth": map[string]any{"client_token": "tok"}})
	return string(b)
}

func parseTestServer(t *testing.T, srv *httptest.Server) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi port: %v", err)
	}
	return host, port
}

func TestVaultHandler_DomainTarget_SetsHostHeader(t *testing.T) {
	srv, capturedHost := startMockVault(t, 200, successBody())
	srvHost, srvPort := parseTestServer(t, srv)

	target := &Target{
		IP:             net.ParseIP(srvHost),
		Port:           srvPort,
		OriginalTarget: "vault.example.com",
		Encryption:     false,
	}
	_, _ = VaultHandler(context.Background(), newTestDialer(t), 5*time.Second, target,
		&Credential{Username: "admin", Password: "secret"})

	if *capturedHost != "vault.example.com" {
		t.Errorf("Host = %q, want %q", *capturedHost, "vault.example.com")
	}
}

func TestVaultHandler_DomainWithPort_SetsHostWithoutPort(t *testing.T) {
	srv, capturedHost := startMockVault(t, 200, successBody())
	srvHost, srvPort := parseTestServer(t, srv)

	target := &Target{
		IP:             net.ParseIP(srvHost),
		Port:           srvPort,
		OriginalTarget: "vault.example.com:8200",
		Encryption:     false,
	}
	_, _ = VaultHandler(context.Background(), newTestDialer(t), 5*time.Second, target,
		&Credential{Username: "admin", Password: "secret"})

	if *capturedHost != "vault.example.com" {
		t.Errorf("Host = %q, want %q (port stripped)", *capturedHost, "vault.example.com")
	}
}

func TestVaultHandler_IPTarget_DoesNotOverrideHost(t *testing.T) {
	srv, capturedHost := startMockVault(t, 200, successBody())
	srvHost, srvPort := parseTestServer(t, srv)

	target := &Target{
		IP:             net.ParseIP(srvHost),
		Port:           srvPort,
		OriginalTarget: srvHost, // bare IP — should not override
		Encryption:     false,
	}
	_, _ = VaultHandler(context.Background(), newTestDialer(t), 5*time.Second, target,
		&Credential{Username: "admin", Password: "secret"})

	// When OriginalTarget is an IP, we don't override — Go sets Host to IP:port by default
	if *capturedHost == "vault.example.com" {
		t.Error("Host should not be overridden to a domain when OriginalTarget is an IP")
	}
}
