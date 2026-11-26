package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/mcpserver"
	"github.com/vflame6/bruter/scanner"
	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
)

// AUTHOR of the program
const AUTHOR = "Maksim Radaev (@vflame6)"

// VERSION should be linked to actual tag
var VERSION = "dev"

// BANNER format string. It is used in PrintBanner function with VERSION
const BANNER = "\n    __               __           \n   / /_  _______  __/ /____  _____\n  / __ \\/ ___/ / / / __/ _ \\/ ___/\n / /_/ / /  / /_/ / /_/  __/ /    \n/_.___/_/   \\__,_/\\__/\\___/_/      %s\n                                  \nMade by %s\n\n"

// program commands, flags and arguments
var (
	app = kingpin.New("bruter", "bruter is a network services bruteforce tool.")

	// targets
	targetFlag = app.Flag("target", "Target host or file with targets. Format host or host:port, one per line").Short('t').String()

	// scan input (nmap, nessus, nexpose — auto-detected)
	nmapFlag = app.Flag("input-file", "Scan output file (nmap GNMAP/XML, Nessus .nessus, Nexpose XML — auto-detected). Use with 'all' command.").Short('n').String()

	// wordlist flags
	usernameFlag   = app.Flag("username", "Username or file with usernames").Short('u').String()
	passwordFlag   = app.Flag("password", "Password or file with passwords").Short('p').String()
	comboFlag      = app.Flag("combo", "Combo wordlist file with user:pass pairs, one per line").String()
	defaultsFlag   = app.Flag("defaults", "Use built-in default username and password wordlists (user-specified -u/-p take priority)").Default("false").Bool()
	vulnsFlag      = app.Flag("vulns", "Run auth vulnerability checks and protocol default credentials only (no wordlist brute-force)").Default("false").Bool()
	userAsPassFlag = app.Flag("user-as-pass", "Try username as password for each user").Default("false").Bool()
	blankFlag      = app.Flag("blank", "Try blank/empty password for each user").Default("false").Bool()
	reversedFlag   = app.Flag("reversed", "Try reversed username as password for each user").Default("false").Bool()

	// optimization flags
	concurrentServicesFlag = app.Flag("concurrent-services", "Number of services to scan on host in parallel ('all' only)").Short('N').Default("4").Int()
	parallelFlag           = app.Flag("concurrent-hosts", "Number of hosts in parallel").Short('C').Default("32").Int()
	threadsFlag            = app.Flag("concurrent-threads", "Number of parallel threads per service").Short('c').Default("5").Int()
	noStatsFlag            = app.Flag("no-stats", "Disable progress bar for better performance").Default("false").Bool()
	delayFlag              = app.Flag("delay", "Delay between each attempt. Will always use single thread if set").Short('d').Default("0s").Duration()
	timeoutFlag            = app.Flag("timeout", "Connection timeout in seconds").Default("10s").Duration()
	stopOnSuccessFlag      = app.Flag("stop-on-success", "Stop bruteforcing current host when first valid credentials found (-f per host, -F global)").Short('f').Default("false").Bool()
	globalStopFlag         = app.Flag("stop-on-success-global", "Stop the entire run on first successful login across all hosts").Short('F').Default("false").Bool()
	retryFlag              = app.Flag("max-retries", "Number of connection errors to stop bruteforce the host. Specify 0 to disable this behavior").Default("30").Int()

	// spraying flags
	sprayFlag              = app.Flag("spray", "Lockout-safe spraying: try one credential group against every user and host, then sleep --delay before the next").Default("false").Bool()
	orderFlag              = app.Flag("order", "Credential ordering: 'password' tries one password across all users (default), 'user' tries all passwords for one user").Short('O').Default("password").Enum("password", "user")
	jitterFlag             = app.Flag("jitter", "Random variation of up to this much, either way, applied to --delay between spray rounds").Default("0s").Duration()
	maxAttemptsPerUserFlag = app.Flag("max-attempts-per-user", "Cap authentication attempts per username across the whole run; aborts once every account reaches it. 0 to disable").Default("0").Int()

	// directory flags
	domainFlag = app.Flag("domain", "Active Directory or Kerberos realm for modules that need one (kerberos, kerberos-enum). Usernames written as user@REALM override it").Default("").String()

	// mcp flag
	mcpScopeFlag = app.Flag("mcp-scope", "File listing the hosts and CIDR blocks an MCP client may test, one per line. Without it the server exposes read-only tools only").Default("").String()

	// checkpoint flag
	resumeFlag = app.Flag("resume", "Checkpoint file for attempted credentials. Reused on the next run to skip what was already tried").Default("").String()

	// connection flags
	proxyFlag     = app.Flag("proxy", "SOCKS-proxy address to use for connection in format IP:PORT").Default("").String()
	proxyAuthFlag = app.Flag("proxy-auth", "Proxy username and password in format username:password").Default("").String()
	ifaceFlag     = app.Flag("iface", "Network interface to bind outgoing connections to (e.g. eth0)").Short('I').Default("").String()

	// http flags
	userAgentFlag = app.Flag("user-agent", "User-Agent for HTTP connections").Default("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36").String()

	// service filter
	serviceFilterFlag = app.Flag("service", "Filter services in 'all' mode (comma-separated, e.g. ftp,ssh,smb)").Short('s').Default("").String()
	listServicesFlag  = app.Flag("list-services", "List all supported services and exit").Short('L').Default("false").Bool()

	// output options
	quietFlag   = app.Flag("quiet", "Enable quiet mode, print results only").Short('q').Default("false").Bool()
	debugFlag   = app.Flag("debug", "Enable debug mode, print all logs").Short('D').Default("false").Bool()
	verboseFlag = app.Flag("verbose", "Enable verbose mode, log every attempt with timestamp").Short('v').Default("false").Bool()
	jsonFlag    = app.Flag("json", "Output results as JSONL (one JSON object per line)").Short('j').Default("false").Bool()
	outputFlag  = app.Flag("output", "Filename to write output in raw format").Short('o').Default("").String()

	// available modules (alphabetical)
	allCommand           = app.Command("all", "Auto-detect modules from scan file (requires -n)")
	amqpCommand          = app.Command("amqp", "AMQP module (port 5672)")
	asteriskCommand      = app.Command("asterisk", "Asterisk Manager Interface module (port 5038)")
	cassandraCommand     = app.Command("cassandra", "Apache Cassandra CQL module (port 9042)")
	ciscoCommand         = app.Command("cisco", "Cisco IOS Telnet module (port 23)")
	ciscoEnableCommand   = app.Command("cisco-enable", "Cisco IOS enable-mode password module (port 23)")
	clickhouseCommand    = app.Command("clickhouse", "ClickHouse native protocol module (port 9000)")
	cobaltStrikeCommand  = app.Command("cobaltstrike", "Cobalt Strike team server module (port 50050)")
	couchdbCommand       = app.Command("couchdb", "Apache CouchDB module (port 5984)")
	elasticsearchCommand = app.Command("elasticsearch", "Elasticsearch module (port 9200)")
	etcdCommand          = app.Command("etcd", "etcd module (port 2379)")
	firebirdCommand      = app.Command("firebird", "Firebird SQL module (port 3050)")
	ftpCommand           = app.Command("ftp", "FTP module (port 21)")
	httpBasicCommand     = app.Command("http-basic", "HTTP Basic Auth module (port 80 / 443 TLS)")
	httpFormCommand      = app.Command("http-form", "HTTP form POST module (port 80 / 443 TLS)")
	httpProxyCommand     = app.Command("http-proxy", "HTTP proxy authentication module (port 8080)")
	imapCommand          = app.Command("imap", "IMAP module (port 143 / 993 TLS)")
	influxdbCommand      = app.Command("influxdb", "InfluxDB module (port 8086)")
	ircCommand           = app.Command("irc", "IRC server password module (port 6667)")
	kerberosCommand      = app.Command("kerberos", "Kerberos pre-authentication module, the usual AD spray channel (port 88, needs --domain)")
	kerberosEnumCommand  = app.Command("kerberos-enum", "Kerberos user enumeration and AS-REP roastable account discovery, submits no password (port 88, needs --domain)")
	ldapCommand          = app.Command("ldap", "LDAP module (port 389 / 636 TLS)")
	mcpCommand           = app.Command("mcp", "Run as a Model Context Protocol server on stdio for use by an AI agent (see --mcp-scope)")
	memcachedCommand     = app.Command("memcached", "Memcached SASL auth module (port 11211)")
	mongoCommand         = app.Command("mongo", "MongoDB module (port 27017)")
	mssqlCommand         = app.Command("mssql", "Microsoft SQL Server module (port 1433)")
	mysqlCommand         = app.Command("mysql", "MySQL module (port 3306)")
	neo4jCommand         = app.Command("neo4j", "Neo4j Bolt protocol module (port 7687)")
	nntpCommand          = app.Command("nntp", "NNTP AUTHINFO module (port 119 / 563 TLS)")
	oracleCommand        = app.Command("oracle", "Oracle Database module (port 1521)")
	pop3Command          = app.Command("pop3", "POP3 module (port 110 / 995 TLS)")
	postgresCommand      = app.Command("postgres", "PostgreSQL module (port 5432)")
	radminCommand        = app.Command("radmin", "Radmin 2.x module (port 4899)")
	rdpCommand           = app.Command("rdp", "RDP NLA/CredSSP module (port 3389)")
	redisCommand         = app.Command("redis", "Redis module (port 6379)")
	rexecCommand         = app.Command("rexec", "BSD rexec module (port 512)")
	rloginCommand        = app.Command("rlogin", "BSD rlogin module (port 513)")
	rpcapCommand         = app.Command("rpcap", "RPCAP remote packet capture module (port 2002)")
	rshCommand           = app.Command("rsh", "BSD rsh module (port 514)")
	rtspCommand          = app.Command("rtsp", "RTSP Basic/Digest Auth module (port 554)")
	s7Command            = app.Command("s7", "Siemens S7 PLC password module (port 102)")
	sipCommand           = app.Command("sip", "SIP Digest authentication module (port 5060)")
	smbCommand           = app.Command("smb", "SMB module (port 445)")
	smppCommand          = app.Command("smpp", "SMPP module (port 2775)")
	smtpCommand          = app.Command("smtp", "SMTP AUTH module (port 25 / 465 TLS / 587 STARTTLS)")
	smtpEnumCommand      = app.Command("smtp-enum", "SMTP user enumeration via VRFY/RCPT (port 25)")
	snmpCommand          = app.Command("snmp", "SNMP v1/v2c community string module (port 161 UDP)")
	socks5Command        = app.Command("socks5", "SOCKS5 username/password authentication module (port 1080)")
	sshCommand           = app.Command("ssh", "SSH module (port 22)")
	sshkeyCommand        = app.Command("sshkey", "SSH public key authentication module (port 22)")
	svnCommand           = app.Command("svn", "Subversion HTTP/WebDAV module (port 3690)")
	teamSpeakCommand     = app.Command("teamspeak", "TeamSpeak 3 ServerQuery module (port 10011)")
	telnetCommand        = app.Command("telnet", "Telnet module (port 23 / TLS)")
	vaultCommand         = app.Command("vault", "HashiCorp Vault userpass module (port 8200)")
	vmauthdCommand       = app.Command("vmauthd", "VMware vmauthd module (port 902)")
	vncCommand           = app.Command("vnc", "VNC module (port 5900)")
	winrmCommand         = app.Command("winrm", "WinRM Basic Auth module (port 5985 / 5986 TLS)")
	xmppCommand          = app.Command("xmpp", "XMPP SASL authentication module (port 5222)")

	_ = []any{
		listServicesFlag,
		allCommand, amqpCommand, asteriskCommand, cassandraCommand, ciscoCommand, ciscoEnableCommand,
		clickhouseCommand, cobaltStrikeCommand, couchdbCommand, elasticsearchCommand, etcdCommand,
		firebirdCommand, ftpCommand, httpBasicCommand, httpFormCommand, httpProxyCommand, imapCommand,
		influxdbCommand, ircCommand, kerberosCommand, kerberosEnumCommand, ldapCommand,
		mcpCommand, memcachedCommand, mongoCommand, mssqlCommand,
		mysqlCommand, neo4jCommand, nntpCommand, oracleCommand, pop3Command, postgresCommand,
		radminCommand, rdpCommand, redisCommand, rexecCommand, rloginCommand, rpcapCommand,
		rshCommand, rtspCommand, s7Command, sipCommand, smbCommand, smppCommand, smtpCommand,
		smtpEnumCommand, snmpCommand, socks5Command, sshCommand, sshkeyCommand, svnCommand,
		teamSpeakCommand, telnetCommand, vaultCommand, vmauthdCommand, vncCommand, winrmCommand,
		xmppCommand,
	}
)

// CustomUsageTemplate is a template for kingpin's help menu
const CustomUsageTemplate = `{{define "FormatCommand" -}}
{{if .FlagSummary}} {{.FlagSummary}}{{end -}}
{{range .Args}}{{if not .Hidden}} {{if not .Required}}[{{end}}{{if .PlaceHolder}}{{.PlaceHolder}}{{else}}<{{.Name}}>{{end}}{{if .Value|IsCumulative}}...{{end}}{{if not .Required}}]{{end}}{{end}}{{end -}}
{{end -}}

{{define "FormatCommandList" -}}
{{range . -}}
{{if not .Hidden -}}
{{if ne .Name "help"}}{{.Name}} {{end -}}
{{end -}}
{{template "FormatCommandList" .Commands -}}
{{end -}}
{{end -}}

{{define "FormatUsage" -}}
{{template "FormatCommand" .}}{{if .Commands}} <command> [<args> ...]{{end}}
{{if .Help}}
{{.Help|Wrap 0 -}}
{{end -}}

{{end -}}

{{if .Context.SelectedCommand -}}
usage: {{.App.Name}} {{.Context.SelectedCommand}}{{template "FormatUsage" .Context.SelectedCommand}}
{{else -}}
usage: {{.App.Name}}{{template "FormatUsage" .App}}
{{end -}}
{{if .Context.Flags -}}
Flags:
{{.Context.Flags|FlagsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{if .Context.Args -}}
Args:
{{.Context.Args|ArgsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{if .Context.SelectedCommand -}}
{{if .Context.SelectedCommand.Commands -}}
Commands: {{template "FormatCommandList" .Context.SelectedCommand.Commands}}
{{end -}}
{{else if .App.Commands -}}
Commands: {{template "FormatCommandList" .App.Commands}}
{{end -}}
`

func init() {
	if VERSION == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			VERSION = info.Main.Version
		}
	}
}

// PrintBanner is a function to print program banner
func PrintBanner() {
	fmt.Printf(BANNER, VERSION, AUTHOR)
}

// ParseArgs is a function to parse program arguments
func ParseArgs() string {
	// Parse into context first
	ctx, err := app.ParseContext(os.Args[1:])
	if err != nil {
		app.FatalUsage(err.Error())
	}

	// Check if --version, --help, or --list-services was requested
	if ctx.SelectedCommand == nil {
		// Check for flags that work without a command
		for _, elem := range ctx.Elements {
			if flag, ok := elem.Clause.(*kingpin.FlagClause); ok {
				switch flag.Model().Name {
				case "version", "help", "completion-script-zsh", "completion-script-bash":
					// Let kingpin handle --version, --help and --completion-script-*
					if _, err := app.Parse(os.Args[1:]); err != nil {
						app.FatalUsage(err.Error())
					}
					os.Exit(0)
				case "list-services":
					printServices()
					os.Exit(0)
				}
			}
		}

		// No command and no --version/--help/--list-services, show usage
		app.Usage(os.Args[1:])
		os.Exit(0)
	}

	// Now do the full parse which validates required flags
	return kingpin.MustParse(app.Parse(os.Args[1:]))
}

// everyUsernameCarriesRealm reports whether each supplied username already
// names its own realm, as "user@REALM" or "REALM\user". It is used to decide
// whether --domain is required, so an empty list counts as "no".
func everyUsernameCarriesRealm(usernameArg, comboArg string) bool {
	var names []string
	if usernameArg != "" {
		names = append(names, utils.LoadLines(usernameArg)...)
	}
	if comboArg != "" {
		for _, line := range utils.LoadLines(comboArg) {
			user, _, found := strings.Cut(line, ":")
			if found {
				names = append(names, user)
			}
		}
	}
	if len(names) == 0 {
		return false
	}

	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		at := strings.LastIndex(name, "@")
		slash := strings.Index(name, `\`)
		if (at <= 0 || at == len(name)-1) && (slash <= 0 || slash == len(name)-1) {
			return false
		}
	}
	return true
}

// runMCPServer serves the Model Context Protocol on stdio.
//
// The protocol has sole use of stdout, so the real streams are captured first
// and os.Stdout is then pointed at stderr: the scanner's dashboard and any
// other direct printing would otherwise be injected into the JSON-RPC stream
// and break the session.
func runMCPServer() error {
	stdin, stdout := os.Stdin, os.Stdout
	os.Stdout = os.Stderr

	if err := logger.Init(true, *debugFlag); err != nil {
		return fmt.Errorf("initialize logger: %w", err)
	}
	logger.SetOutput(os.Stderr)

	var scope *mcpserver.Scope
	if *mcpScopeFlag != "" {
		loaded, err := mcpserver.LoadScope(*mcpScopeFlag)
		if err != nil {
			return err
		}
		scope = loaded
		logger.Infof("mcp server scope: %s", strings.Join(scope.Entries(), ", "))
	} else {
		logger.Infof("mcp server started without --mcp-scope: credential testing tools are disabled, only read-only tools are exposed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	if err := mcpserver.Serve(ctx, VERSION, scope, stdin, stdout); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// printServices prints all supported modules with their default ports.
func printServices() {
	names := make([]string, 0, len(modules.Modules))
	for name := range modules.Modules {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Printf("%-20s %s\n", "SERVICE", "DEFAULT PORT")
	fmt.Printf("%-20s %s\n", "-------", "------------")
	for _, name := range names {
		mod := modules.Modules[name]
		fmt.Printf("%-20s %d\n", name, mod.DefaultPort)
	}
	fmt.Printf("\n%d services available\n", len(names))
}

func main() {
	// kingpin settings
	app.Version(VERSION)
	app.Author(AUTHOR)
	app.HelpFlag.Short('h')
	app.UsageTemplate(CustomUsageTemplate)

	// parse program arguments
	command := ParseArgs()

	// MCP mode owns stdio, so it has to be handled before anything can print.
	if command == "mcp" {
		if err := runMCPServer(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Detect stdin pipe — but only use it when no explicit target/nmap flag is given.
	// This prevents stdin from hijacking the run when CLI args are provided
	// (e.g. when invoked from automation tools that pipe stdin).
	stdinMode := utils.HasStdin()

	// all command requires -n flag or stdin
	nmapMode := command == "all"
	if nmapMode && *nmapFlag == "" && !stdinMode {
		fmt.Fprintln(os.Stderr, "error: 'all' command requires --input-file/-n scan file or piped stdin, try --help")
		os.Exit(1)
	}

	// -s only valid with "all" command
	if *serviceFilterFlag != "" && !nmapMode {
		fmt.Fprintln(os.Stderr, "error: --service/-s can only be used with 'all' command, try --help")
		os.Exit(1)
	}

	// If explicit --target is provided, CLI wins over stdin
	if *targetFlag != "" {
		stdinMode = false
	}

	// In "all" mode, --nmap flag wins over stdin
	if nmapMode && *nmapFlag != "" {
		stdinMode = false
	}

	// Validate: in normal mode, --target is required (unless stdin)
	if !nmapMode && !stdinMode && *targetFlag == "" {
		fmt.Fprintln(os.Stderr, "error: required flag --target not provided, try --help")
		os.Exit(1)
	}

	// Enumeration modules ignore the password field, so requiring -p would only
	// make people invent one.
	enumOnly := modules.Modules[command].EnumOnly

	// Validate: credentials are required in both modes (unless --combo, --defaults, --vulns, or credential mutation flags are provided)
	hasCredMutation := *userAsPassFlag || *blankFlag || *reversedFlag
	if enumOnly && *usernameFlag == "" && *comboFlag == "" && !*defaultsFlag {
		fmt.Fprintf(os.Stderr, "error: %s enumerates accounts and needs --username or --defaults\n", command)
		os.Exit(1)
	}
	if !enumOnly && *comboFlag == "" && !*defaultsFlag && !*vulnsFlag && !hasCredMutation && (*usernameFlag == "" || *passwordFlag == "") {
		fmt.Fprintln(os.Stderr, "error: provide --username and --password, --combo, --defaults, --vulns, or credential flags (--user-as-pass/--blank/--reversed), try --help")
		os.Exit(1)
	}
	// Credential mutations require usernames
	if hasCredMutation && *usernameFlag == "" && !*defaultsFlag {
		fmt.Fprintln(os.Stderr, "error: --user-as-pass/--blank/--reversed require --username or --defaults, try --help")
		os.Exit(1)
	}

	// Kerberos needs a realm. Without one every attempt would fail identically
	// and trip --max-retries, which reads like the KDC banned us. Usernames
	// that already carry their own realm are fine, which is why this checks
	// the wordlist rather than just the flag.
	needsDomain := command == "kerberos" || command == "kerberos-enum"
	if needsDomain && *domainFlag == "" && !nmapMode && !stdinMode {
		if *defaultsFlag || !everyUsernameCarriesRealm(*usernameFlag, *comboFlag) {
			fmt.Fprintln(os.Stderr, "error: the kerberos modules need a realm: pass --domain corp.local, or write every username as user@REALM")
			os.Exit(1)
		}
	}

	// Validate spraying options
	if *sprayFlag && (nmapMode || stdinMode) {
		fmt.Fprintln(os.Stderr, "error: --spray needs a single module command (e.g. 'bruter smb --spray'), not 'all' or piped input")
		os.Exit(1)
	}
	if *sprayFlag && *vulnsFlag {
		fmt.Fprintln(os.Stderr, "error: --spray cannot be combined with --vulns; the vulnerability pass authenticates outside the spray schedule, which defeats the per-account limits. Run it separately")
		os.Exit(1)
	}
	if *sprayFlag && *delayFlag == 0 {
		fmt.Fprintln(os.Stderr, "error: --spray requires --delay to set the pause between rounds (e.g. -d 30m)")
		os.Exit(1)
	}
	if *jitterFlag > 0 && *delayFlag == 0 {
		fmt.Fprintln(os.Stderr, "error: --jitter has nothing to vary without --delay")
		os.Exit(1)
	}
	if *maxAttemptsPerUserFlag > 0 && !*sprayFlag {
		fmt.Fprintln(os.Stderr, "error: --max-attempts-per-user only applies to --spray runs")
		os.Exit(1)
	}

	// instantiate logger
	if err := logger.Init(*quietFlag, *debugFlag); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	if *verboseFlag {
		logger.SetVerbose(true)
	}

	// print program banner
	if !*quietFlag {
		PrintBanner()
	}

	// pass scanner options
	options := scanner.Options{
		Usernames:  *usernameFlag,
		Passwords:  *passwordFlag,
		Defaults:   *defaultsFlag,
		Vulns:      *vulnsFlag || *defaultsFlag,
		UserAsPass: *userAsPassFlag,
		Blank:      *blankFlag,
		Reversed:   *reversedFlag,

		Combo:               *comboFlag,
		ConcurrentServices:  *concurrentServicesFlag,
		Parallel:            *parallelFlag,
		Threads:             *threadsFlag,
		Timeout:             *timeoutFlag,
		Delay:               *delayFlag,
		StopOnSuccess:       *stopOnSuccessFlag,
		GlobalStop:          *globalStopFlag,
		Retries:             *retryFlag,
		Proxy:               *proxyFlag,
		ProxyAuthentication: *proxyAuthFlag,
		UserAgent:           *userAgentFlag,
		OutputFileName:      *outputFlag,
		Verbose:             *verboseFlag,
		JSON:                *jsonFlag,
		Iface:               *ifaceFlag,
		NoStats:             *noStatsFlag,
		ServiceFilter:       *serviceFilterFlag,

		Spray:              *sprayFlag,
		Order:              *orderFlag,
		Jitter:             *jitterFlag,
		MaxAttemptsPerUser: *maxAttemptsPerUserFlag,

		Domain:     *domainFlag,
		ResumeFile: *resumeFlag,
	}
	// try to create scanner
	s, err := scanner.NewScanner(&options)
	if err != nil {
		logger.Fatal(err)
	}

	// set up context with signal-based cancellation (Ctrl+C / SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Infof("Received %s. Stopping the work...", sig)
		cancel()
	}()
	defer cancel()

	switch {
	case stdinMode:
		// stdin mode: read targets from pipe and auto-route to modules
		err = s.RunStdinWithResults(ctx, os.Stdin)
		if err != nil {
			logger.Fatal(err)
		}
	case nmapMode:
		// nmap mode: parse nmap output and run matching modules
		err = s.RunNmapWithResults(ctx, *nmapFlag)
		if err != nil {
			logger.Fatal(err)
		}
	case *sprayFlag:
		// spray mode: every target resolved up front, one credential round at a time
		err = s.RunSpray(ctx, command, *targetFlag)
		if err != nil {
			logger.Fatal(err)
		}

		s.Stop()
		if !*quietFlag {
			logger.Infof("finished spraying %s module", command)
		}
	default:
		// normal mode: run selected module against targets
		err = s.Run(ctx, command, *targetFlag)
		if err != nil {
			logger.Fatal(err)
		}

		// finish the execution
		s.Stop()
		// show which module is done its execution
		if !*quietFlag {
			logger.Infof("finished execution of %s module", command)
		}
	}
}
