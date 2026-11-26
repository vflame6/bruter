package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vflame6/bruter/scanner/modules"
)

// connect starts the server on an in-memory transport and returns a connected
// client session.
func connect(t *testing.T, scope *Scope) *mcp.ClientSession {
	t.Helper()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	server := mcp.NewServer(&mcp.Implementation{Name: "bruter", Version: "test"},
		&mcp.ServerOptions{Instructions: instructions})
	registerReadOnlyTools(server, scope)
	if scope != nil {
		registerActiveTools(server, scope)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })

	return clientSession
}

func toolNames(t *testing.T, session *mcp.ClientSession) []string {
	t.Helper()
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

// callText returns a tool call's text payload and whether the call was an error.
func callText(t *testing.T, session *mcp.ClientSession, name string, args any) (string, bool) {
	t.Helper()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}

	var text strings.Builder
	for _, content := range result.Content {
		if tc, ok := content.(*mcp.TextContent); ok {
			text.WriteString(tc.Text)
		}
	}
	return text.String(), result.IsError
}

func testScope(t *testing.T, body string) *Scope {
	t.Helper()
	scope, err := LoadScope(writeScope(t, body))
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	return scope
}

func TestWithoutScopeOnlyReadOnlyToolsExist(t *testing.T) {
	// The operator not configuring a scope is the operator not authorizing
	// anything, so the tools that put traffic on the wire must not exist at
	// all — an agent cannot be talked into calling a tool it cannot see.
	session := connect(t, nil)

	got := toolNames(t, session)
	want := []string{"check_scope", "list_services", "parse_scan"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("tools = %v, want %v", got, want)
	}
}

func TestWithScopeActiveToolsAppear(t *testing.T) {
	session := connect(t, testScope(t, "10.10.20.0/24\n"))

	got := toolNames(t, session)
	want := []string{"check_scope", "list_services", "parse_scan", "run_module", "spray"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("tools = %v, want %v", got, want)
	}
}

func TestListServicesMatchesRegistry(t *testing.T) {
	session := connect(t, nil)

	text, isErr := callText(t, session, "list_services", map[string]any{})
	if isErr {
		t.Fatalf("list_services failed: %s", text)
	}

	var out listServicesOutput
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("parse output %q: %v", text, err)
	}
	if len(out.Services) != len(modules.Modules) {
		t.Fatalf("reported %d services, registry has %d", len(out.Services), len(modules.Modules))
	}
	for _, svc := range out.Services {
		mod, ok := modules.Modules[svc.Name]
		if !ok {
			t.Errorf("reported unknown service %q", svc.Name)
			continue
		}
		if svc.DefaultPort != mod.DefaultPort {
			t.Errorf("%s default port = %d, want %d", svc.Name, svc.DefaultPort, mod.DefaultPort)
		}
	}
}

func TestCheckScopeSeparatesAllowedFromRejected(t *testing.T) {
	session := connect(t, testScope(t, "10.10.20.0/24\ndc01.corp.local\n"))

	text, isErr := callText(t, session, "check_scope", map[string]any{
		"targets": []string{"10.10.20.5", "dc01.corp.local", "8.8.8.8"},
	})
	if isErr {
		t.Fatalf("check_scope failed: %s", text)
	}

	var out checkScopeOutput
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("parse output %q: %v", text, err)
	}
	if !out.ScopeConfigured {
		t.Error("scope_configured = false with a scope loaded")
	}
	if len(out.Allowed) != 2 {
		t.Errorf("allowed = %v, want the two in-scope targets", out.Allowed)
	}
	if len(out.Rejected) != 1 || out.Rejected[0] != "8.8.8.8" {
		t.Errorf("rejected = %v, want [8.8.8.8]", out.Rejected)
	}
}

func TestRunModuleRefusesOutOfScopeTargets(t *testing.T) {
	session := connect(t, testScope(t, "10.10.20.0/24\n"))

	text, isErr := callText(t, session, "run_module", map[string]any{
		"service":   "ssh",
		"targets":   []string{"10.10.20.5", "8.8.8.8"},
		"usernames": []string{"root"},
		"passwords": []string{"toor"},
	})
	if !isErr {
		t.Fatalf("an out-of-scope target was accepted: %s", text)
	}
	if !strings.Contains(text, "8.8.8.8") {
		t.Errorf("error does not name the offending target: %s", text)
	}
	// A partial run would teach an agent that over-asking is free.
	if !strings.Contains(text, "Nothing was tested") {
		t.Errorf("error does not state that nothing ran: %s", text)
	}
}

func TestRunModuleRejectsUnknownService(t *testing.T) {
	session := connect(t, testScope(t, "10.10.20.0/24\n"))

	text, isErr := callText(t, session, "run_module", map[string]any{
		"service":   "not-a-protocol",
		"targets":   []string{"10.10.20.5"},
		"usernames": []string{"root"},
		"passwords": []string{"toor"},
	})
	if !isErr {
		t.Fatalf("an unknown service was accepted: %s", text)
	}
	if !strings.Contains(text, "list_services") {
		t.Errorf("error should point at list_services: %s", text)
	}
}

func TestRunModuleRequiresCredentials(t *testing.T) {
	session := connect(t, testScope(t, "10.10.20.0/24\n"))

	text, isErr := callText(t, session, "run_module", map[string]any{
		"service": "ssh",
		"targets": []string{"10.10.20.5"},
	})
	if !isErr {
		t.Fatalf("a run with no credentials was accepted: %s", text)
	}
}

func TestSprayRequiresDelay(t *testing.T) {
	session := connect(t, testScope(t, "10.10.20.0/24\n"))

	text, isErr := callText(t, session, "spray", map[string]any{
		"service":   "smb",
		"targets":   []string{"10.10.20.5"},
		"usernames": []string{"alice"},
		"passwords": []string{"Autumn2026"},
	})
	if !isErr {
		t.Fatalf("a spray with no round delay was accepted: %s", text)
	}
	if !strings.Contains(text, "delay_seconds") {
		t.Errorf("error does not name delay_seconds: %s", text)
	}
}

func TestSprayRejectsJitterLargerThanDelay(t *testing.T) {
	session := connect(t, testScope(t, "10.10.20.0/24\n"))

	text, isErr := callText(t, session, "spray", map[string]any{
		"service":        "smb",
		"targets":        []string{"10.10.20.5"},
		"usernames":      []string{"alice"},
		"passwords":      []string{"Autumn2026"},
		"delay_seconds":  60,
		"jitter_seconds": 120,
	})
	if !isErr {
		t.Fatalf("jitter larger than the delay was accepted: %s", text)
	}
}

func TestParseScanFlagsOutOfScopeFindings(t *testing.T) {
	// A scan file routinely covers more than the engagement scope. The tool
	// must say which findings are actually testable rather than hiding them.
	scan := filepath.Join(t.TempDir(), "scan.gnmap")
	body := "# Nmap 7.95 scan initiated\n" +
		"Host: 10.10.20.14 ()\tPorts: 445/open/tcp//microsoft-ds///, 88/open/tcp//kerberos-sec///\n" +
		"Host: 8.8.8.8 ()\tPorts: 22/open/tcp//ssh///\n"
	if err := os.WriteFile(scan, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	session := connect(t, testScope(t, "10.10.20.0/24\n"))

	text, isErr := callText(t, session, "parse_scan", map[string]any{"path": scan})
	if isErr {
		t.Fatalf("parse_scan failed: %s", text)
	}

	var out parseScanOutput
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("parse output %q: %v", text, err)
	}
	if out.Format != "nmap-gnmap" {
		t.Errorf("format = %q, want nmap-gnmap", out.Format)
	}

	var inScope, outOfScope int
	for _, target := range out.Targets {
		if target.InScope {
			inScope++
			continue
		}
		outOfScope++
		if target.Host != "8.8.8.8" {
			t.Errorf("unexpected out-of-scope host %s", target.Host)
		}
	}
	if inScope != 2 {
		t.Errorf("in-scope targets = %d, want 2 (smb and kerberos on 10.10.20.14)", inScope)
	}
	if outOfScope != 1 {
		t.Errorf("out-of-scope targets = %d, want 1", outOfScope)
	}
}

func TestParseScanRequiresPath(t *testing.T) {
	session := connect(t, nil)
	if text, isErr := callText(t, session, "parse_scan", map[string]any{"path": "  "}); !isErr {
		t.Fatalf("an empty path was accepted: %s", text)
	}
}

func TestInstructionsStateTheScopeRule(t *testing.T) {
	// The instructions are the only thing a model reads before choosing a
	// tool, so the scope rule and the lockout warning have to be in them.
	for _, want := range []string{"scope", "check_scope", "lockout"} {
		if !strings.Contains(strings.ToLower(instructions), want) {
			t.Errorf("server instructions never mention %q", want)
		}
	}
}

// --- review follow-ups ---

func TestSprayRequiresAnAccountCap(t *testing.T) {
	// A lockout-safe tool that defaults to unlimited attempts per account is
	// not lockout-safe.
	session := connect(t, testScope(t, "10.10.20.0/24\n"))

	text, isErr := callText(t, session, "spray", map[string]any{
		"service":       "smb",
		"targets":       []string{"10.10.20.5"},
		"usernames":     []string{"alice"},
		"passwords":     []string{"Autumn2026"},
		"delay_seconds": 60,
	})
	if !isErr {
		t.Fatalf("a spray with no per-account cap was accepted: %s", text)
	}
	if !strings.Contains(text, "max_attempts_per_user") {
		t.Errorf("error does not name the missing field: %s", text)
	}
}

func TestSprayCapIsSharedAcrossCalls(t *testing.T) {
	// The budget must belong to the server, not the call, or an agent can
	// reset every account's allowance by calling spray again.
	session := connect(t, testScope(t, "10.10.20.0/24\n"))

	args := func(cap int) map[string]any {
		return map[string]any{
			"service":               "smb",
			"targets":               []string{"10.10.20.5"},
			"usernames":             []string{"alice"},
			"passwords":             []string{"Autumn2026"},
			"delay_seconds":         1,
			"max_attempts_per_user": cap,
			"max_runtime_seconds":   5,
			"timeout_seconds":       1,
		}
	}

	// First call fixes the shared cap. 10.10.20.5 does not exist, so the run
	// itself just finds nothing; what matters is that the budget is created.
	if text, isErr := callText(t, session, "spray", args(3)); isErr {
		t.Fatalf("first spray failed: %s", text)
	}

	// A second call asking for a different cap must be refused rather than
	// silently replacing the shared budget.
	text, isErr := callText(t, session, "spray", args(10))
	if !isErr {
		t.Fatalf("a second spray silently changed the shared cap: %s", text)
	}
	if !strings.Contains(text, "shared across this session") {
		t.Errorf("error does not explain the shared budget: %s", text)
	}

	// Reusing the original value is fine.
	if text, isErr := callText(t, session, "spray", args(3)); isErr {
		t.Fatalf("reusing the established cap was refused: %s", text)
	}
}
