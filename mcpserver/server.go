package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vflame6/bruter/parser"
	"github.com/vflame6/bruter/scanner"
	"github.com/vflame6/bruter/scanner/modules"
)

// Run-length guards. An agent that asks for a six-hour spray should be told
// no rather than silently holding the session open.
const (
	defaultMaxRuntime = 5 * time.Minute
	hardMaxRuntime    = time.Hour
)

// instructions is sent to the client on connect.
const instructions = `bruter tests credentials against 54+ network protocols and can read nmap,
Nessus and Nexpose scan output.

Only the hosts in the operator's scope file may be tested. Call check_scope
before run_module or spray; targets outside the scope are refused. If
run_module and spray are not listed, the operator started this server without a
scope file and no credential testing is available in this session.

Every attempt made through these tools is a real authentication attempt against
a real service. On Active Directory, each failed attempt increments the account
lockout counter: use spray with max_attempts_per_user rather than run_module.`

// Serve runs the MCP server over the given streams until the client
// disconnects or ctx is cancelled.
//
// in and out must be the real stdio streams, captured before anything else is
// allowed to write to them: the protocol shares the stream with nothing.
func Serve(ctx context.Context, version string, scope *Scope, in io.ReadCloser, out io.WriteCloser) error {
	server := mcp.NewServer(&mcp.Implementation{
		Name:        "bruter",
		Title:       "bruter network credential testing",
		Description: "Network services bruteforce tool with scan-file import",
		Version:     version,
		WebsiteURL:  "https://github.com/vflame6/bruter",
	}, &mcp.ServerOptions{
		Instructions: instructions,
	})

	registerReadOnlyTools(server, scope)
	if scope != nil {
		registerActiveTools(server, scope)
	}

	session, err := server.Connect(ctx, &mcp.IOTransport{Reader: in, Writer: out}, nil)
	if err != nil {
		return fmt.Errorf("mcp connect: %w", err)
	}
	return session.Wait()
}

func readOnly() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}
}

func destructive() *mcp.ToolAnnotations {
	yes := true
	return &mcp.ToolAnnotations{DestructiveHint: &yes, OpenWorldHint: &yes}
}

// --- read-only tools ---

type listServicesInput struct{}

type serviceInfo struct {
	Name        string `json:"name"`
	DefaultPort int    `json:"default_port"`
}

type listServicesOutput struct {
	Services []serviceInfo `json:"services"`
}

type checkScopeInput struct {
	Targets []string `json:"targets" jsonschema:"targets to check, each given as host or host:port"`
}

type checkScopeOutput struct {
	ScopeConfigured bool     `json:"scope_configured"`
	Scope           []string `json:"scope"`
	Allowed         []string `json:"allowed"`
	Rejected        []string `json:"rejected"`
}

type parseScanInput struct {
	Path string `json:"path" jsonschema:"path to an nmap GNMAP or XML file, a Nessus .nessus file, or a Nexpose XML export"`
}

type parsedTarget struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	InScope bool   `json:"in_scope"`
}

type parseScanOutput struct {
	Format  string         `json:"format"`
	Targets []parsedTarget `json:"targets"`
}

func registerReadOnlyTools(server *mcp.Server, scope *Scope) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_services",
		Description: "List every protocol module bruter can run, with its default port.",
		Annotations: readOnly(),
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ listServicesInput) (*mcp.CallToolResult, listServicesOutput, error) {
		names := make([]string, 0, len(modules.Modules))
		for name := range modules.Modules {
			names = append(names, name)
		}
		sort.Strings(names)

		services := make([]serviceInfo, 0, len(names))
		for _, name := range names {
			services = append(services, serviceInfo{Name: name, DefaultPort: modules.Modules[name].DefaultPort})
		}
		return nil, listServicesOutput{Services: services}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "check_scope",
		Description: "Report which of the given targets the operator has authorized. " +
			"Call this before any credential testing; out-of-scope targets are refused.",
		Annotations: readOnly(),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in checkScopeInput) (*mcp.CallToolResult, checkScopeOutput, error) {
		out := checkScopeOutput{
			ScopeConfigured: scope != nil,
			Scope:           scope.Entries(),
		}
		for _, target := range in.Targets {
			if scope.Allows(target) {
				out.Allowed = append(out.Allowed, target)
				continue
			}
			out.Rejected = append(out.Rejected, target)
		}
		return nil, out, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "parse_scan",
		Description: "Parse an nmap, Nessus or Nexpose scan file and return the services bruter " +
			"can test, each flagged with whether it is in scope.",
		Annotations: readOnly(),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in parseScanInput) (*mcp.CallToolResult, parseScanOutput, error) {
		if strings.TrimSpace(in.Path) == "" {
			return nil, parseScanOutput{}, fmt.Errorf("path is required")
		}

		format, err := parser.DetectFormat(in.Path)
		if err != nil {
			return nil, parseScanOutput{}, fmt.Errorf("read %s: %w", in.Path, err)
		}

		targets, err := parser.ParseFile(in.Path, parser.FormatUnknown)
		if err != nil {
			return nil, parseScanOutput{}, err
		}

		out := parseScanOutput{Format: formatName(format)}
		for _, t := range targets {
			out.Targets = append(out.Targets, parsedTarget{
				Host:    t.Host,
				Port:    t.Port,
				Service: t.Service,
				InScope: scope.Allows(t.Host),
			})
		}
		return nil, out, nil
	})
}

func formatName(f parser.Format) string {
	switch f {
	case parser.FormatGNMAP:
		return "nmap-gnmap"
	case parser.FormatXML:
		return "nmap-xml"
	case parser.FormatNessus:
		return "nessus"
	case parser.FormatNexpose:
		return "nexpose"
	default:
		return "unknown"
	}
}

// --- active tools ---

type runModuleInput struct {
	Service       string   `json:"service" jsonschema:"module to run, e.g. ssh or smb; call list_services for the full set"`
	Targets       []string `json:"targets" jsonschema:"hosts to test, each host or host:port; all must be in scope"`
	Usernames     []string `json:"usernames,omitempty" jsonschema:"usernames to try"`
	Passwords     []string `json:"passwords,omitempty" jsonschema:"passwords to try"`
	UseDefaults   bool     `json:"use_defaults,omitempty" jsonschema:"use the built-in username and password wordlists"`
	Domain        string   `json:"domain,omitempty" jsonschema:"Active Directory or Kerberos realm; required by the kerberos modules"`
	Threads       int      `json:"threads,omitempty" jsonschema:"parallel attempts per host, default 5"`
	TimeoutSecs   int      `json:"timeout_seconds,omitempty" jsonschema:"per-connection timeout in seconds, default 10"`
	StopOnSuccess bool     `json:"stop_on_success,omitempty" jsonschema:"stop testing a host once valid credentials are found"`
	MaxRuntime    int      `json:"max_runtime_seconds,omitempty" jsonschema:"give up after this long, default 300, maximum 3600"`
}

type sprayInput struct {
	Service            string   `json:"service" jsonschema:"module to spray, e.g. kerberos, smb or ldap"`
	Targets            []string `json:"targets" jsonschema:"hosts to test, each host or host:port; all must be in scope"`
	Usernames          []string `json:"usernames" jsonschema:"accounts to spray"`
	Passwords          []string `json:"passwords" jsonschema:"passwords to try, one per round"`
	Domain             string   `json:"domain,omitempty" jsonschema:"Active Directory or Kerberos realm; required by the kerberos modules"`
	DelaySecs          int      `json:"delay_seconds" jsonschema:"pause between rounds in seconds; required, and should match the domain lockout observation window"`
	JitterSecs         int      `json:"jitter_seconds,omitempty" jsonschema:"random variation either way on the round delay, must not exceed it"`
	MaxAttemptsPerUser int      `json:"max_attempts_per_user" jsonschema:"required; stop after this many attempts per account across the whole session, counting every host. Set it below the domain lockout threshold"`
	TimeoutSecs        int      `json:"timeout_seconds,omitempty" jsonschema:"per-connection timeout in seconds, default 10"`
	MaxRuntime         int      `json:"max_runtime_seconds,omitempty" jsonschema:"give up after this long, default 300, maximum 3600"`
}

type credentialHit struct {
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type runOutput struct {
	Service     string          `json:"service"`
	Targets     int             `json:"targets"`
	Attempts    int64           `json:"attempts"`
	Found       []credentialHit `json:"found"`
	TimedOut    bool            `json:"timed_out"`
	Rounds      int             `json:"rounds,omitempty"`
	Explanation string          `json:"explanation,omitempty"`
}

func registerActiveTools(server *mcp.Server, scope *Scope) {
	// One budget for the life of the server. Building it per call would let an
	// agent reset every account's allowance just by calling spray again.
	var (
		budgetMu sync.Mutex
		budget   *scanner.AccountBudget
	)
	sharedBudget := func(max int) (*scanner.AccountBudget, error) {
		budgetMu.Lock()
		defer budgetMu.Unlock()
		if budget == nil {
			budget = scanner.NewAccountBudget(max)
			return budget, nil
		}
		if budget.Max() != max {
			return nil, fmt.Errorf(
				"max_attempts_per_user is shared across this session and was set to %d; "+
					"reuse that value or restart the server to change it", budget.Max())
		}
		return budget, nil
	}

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_module",
		Description: "Test credentials against one protocol on in-scope hosts. Every attempt is a " +
			"real authentication attempt. Against Active Directory accounts use spray instead, " +
			"because this tool has no per-account limit.",
		Annotations: destructive(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in runModuleInput) (*mcp.CallToolResult, runOutput, error) {
		opts, cleanup, err := baseOptions(in.Service, in.Usernames, in.Passwords, in.UseDefaults, in.Domain, in.TimeoutSecs)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			return nil, runOutput{}, err
		}
		if err := checkTargets(scope, in.Targets); err != nil {
			return nil, runOutput{}, err
		}

		opts.Threads = positiveOr(in.Threads, 5)
		opts.StopOnSuccess = in.StopOnSuccess

		return execute(ctx, opts, in.Targets, in.MaxRuntime, false)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "spray",
		Description: "Lockout-safe password spraying: try one password against every account and host, " +
			"then sleep before the next. Use this against Active Directory, with " +
			"max_attempts_per_user set below the domain lockout threshold.",
		Annotations: destructive(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sprayInput) (*mcp.CallToolResult, runOutput, error) {
		opts, cleanup, err := baseOptions(in.Service, in.Usernames, in.Passwords, false, in.Domain, in.TimeoutSecs)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			return nil, runOutput{}, err
		}
		if err := checkTargets(scope, in.Targets); err != nil {
			return nil, runOutput{}, err
		}
		if len(in.Usernames) == 0 || len(in.Passwords) == 0 {
			return nil, runOutput{}, fmt.Errorf("spray needs both usernames and passwords")
		}
		if in.DelaySecs <= 0 {
			return nil, runOutput{}, fmt.Errorf("delay_seconds is required and must be positive: it is the pause between rounds")
		}
		if in.JitterSecs > in.DelaySecs {
			return nil, runOutput{}, fmt.Errorf("jitter_seconds (%d) cannot exceed delay_seconds (%d)", in.JitterSecs, in.DelaySecs)
		}
		// Unlimited attempts per account is exactly what this tool exists to
		// prevent, so it is not an acceptable default here.
		if in.MaxAttemptsPerUser <= 0 {
			return nil, runOutput{}, fmt.Errorf(
				"max_attempts_per_user is required and must be positive; set it below the domain lockout threshold")
		}

		accounts, err := sharedBudget(in.MaxAttemptsPerUser)
		if err != nil {
			return nil, runOutput{}, err
		}

		opts.Spray = true
		opts.Order = scanner.OrderPassword
		opts.Threads = 1
		opts.Delay = time.Duration(in.DelaySecs) * time.Second
		opts.Jitter = time.Duration(in.JitterSecs) * time.Second
		opts.MaxAttemptsPerUser = in.MaxAttemptsPerUser
		opts.AccountBudget = accounts

		return execute(ctx, opts, in.Targets, in.MaxRuntime, true)
	})
}

// checkTargets refuses the whole call if any target is outside the operator's
// scope. Running the in-scope subset and quietly dropping the rest would teach
// an agent that asking for more than it is allowed costs nothing.
func checkTargets(scope *Scope, targets []string) error {
	if len(targets) == 0 {
		return fmt.Errorf("targets is required")
	}
	if rejected := scope.Reject(targets); len(rejected) > 0 {
		return fmt.Errorf("refused: %s are not in the operator's scope (%s). Nothing was tested",
			strings.Join(rejected, ", "), strings.Join(scope.Entries(), ", "))
	}
	return nil
}

// baseOptions builds the scanner options shared by both active tools. The
// returned cleanup removes the temporary wordlist and output files and is
// always safe to call.
func baseOptions(service string, usernames, passwords []string, useDefaults bool, domain string, timeoutSecs int) (*scanner.Options, func(), error) {
	if _, ok := modules.Modules[service]; !ok {
		return nil, nil, fmt.Errorf("unknown service %q; call list_services", service)
	}

	dir, err := os.MkdirTemp("", "bruter-mcp-")
	if err != nil {
		return nil, nil, fmt.Errorf("create working directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	opts := &scanner.Options{
		Command:            service,
		Defaults:           useDefaults,
		Domain:             domain,
		ConcurrentServices: 1,
		Parallel:           1,
		Threads:            1,
		Timeout:            time.Duration(positiveOr(timeoutSecs, 10)) * time.Second,
		Retries:            30,
		Order:              scanner.OrderPassword,
		NoStats:            true,
		JSON:               true,
		OutputFileName:     filepath.Join(dir, "results.jsonl"),
	}

	if len(usernames) > 0 {
		path, err := writeWordlist(dir, "usernames.txt", usernames)
		if err != nil {
			return nil, cleanup, err
		}
		opts.Usernames = path
	}
	if len(passwords) > 0 {
		path, err := writeWordlist(dir, "passwords.txt", passwords)
		if err != nil {
			return nil, cleanup, err
		}
		opts.Passwords = path
	}

	if opts.Usernames == "" && opts.Passwords == "" && !useDefaults {
		return nil, cleanup, fmt.Errorf("give usernames and passwords, or set use_defaults")
	}
	return opts, cleanup, nil
}

// execute runs one scan and reports what it found.
func execute(ctx context.Context, opts *scanner.Options, targets []string, maxRuntime int, spray bool) (*mcp.CallToolResult, runOutput, error) {
	limit := time.Duration(positiveOr(maxRuntime, int(defaultMaxRuntime.Seconds()))) * time.Second
	if limit > hardMaxRuntime {
		limit = hardMaxRuntime
	}

	runCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	// Targets go to the scanner as a file, one per line, never as a joined
	// string. The scanner's target reader splits on commas, so joining would
	// let a single scope-checked value expand back into several targets.
	targetFile, err := writeWordlist(filepath.Dir(opts.OutputFileName), "targets.txt", targets)
	if err != nil {
		return nil, runOutput{}, err
	}

	s, err := scanner.NewScanner(opts)
	if err != nil {
		return nil, runOutput{}, err
	}

	if spray {
		err = s.RunSpray(runCtx, opts.Command, targetFile)
	} else {
		err = s.Run(runCtx, opts.Command, targetFile)
	}
	s.Stop()
	if err != nil {
		return nil, runOutput{}, err
	}

	found, readErr := readHits(opts.OutputFileName)
	if readErr != nil {
		return nil, runOutput{}, readErr
	}

	out := runOutput{
		Service:  opts.Command,
		Targets:  len(targets),
		Attempts: s.Attempts.Load(),
		Found:    found,
		TimedOut: runCtx.Err() != nil,
	}
	if out.TimedOut {
		out.Explanation = fmt.Sprintf("stopped after %s; results so far are complete but the credential set was not exhausted", limit)
	}
	if out.Found == nil {
		out.Found = []credentialHit{}
	}
	return nil, out, nil
}

// readHits parses the JSONL the scanner wrote. A missing file means the run
// produced no results, which is the common case.
func readHits(path string) ([]credentialHit, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read results: %w", err)
	}

	var hits []credentialHit
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record struct {
			Target   string `json:"target"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("parse result %q: %w", line, err)
		}
		hits = append(hits, credentialHit{
			Target:   record.Target,
			Port:     record.Port,
			Service:  record.Protocol,
			Username: record.Username,
			Password: record.Password,
		})
	}
	return hits, nil
}

func writeWordlist(dir, name string, lines []string) (string, error) {
	path := filepath.Join(dir, name)
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", name, err)
	}
	return path, nil
}

func positiveOr(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}
