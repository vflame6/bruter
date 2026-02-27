package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/scanner"
	"github.com/vflame6/bruter/utils"
)

// AUTHOR of the program
const AUTHOR = "Maksim Radaev (@vflame6)"

// VERSION should be linked to actual tag
const VERSION = "v1.0.0"

// BANNER format string. It is used in PrintBanner function with VERSION
const BANNER = "    __               __           \n   / /_  _______  __/ /____  _____\n  / __ \\/ ___/ / / / __/ _ \\/ ___/\n / /_/ / /  / /_/ / /_/  __/ /    \n/_.___/_/   \\__,_/\\__/\\___/_/      %s\n                                  \nMade by %s\n\n"

// program commands, flags and arguments
var (
	app = kingpin.New("bruter", "bruter is a network services bruteforce tool.")

	// targets
	targetFlag = app.Flag("target", "Target host or file with targets. Format host or host:port, one per line").Short('t').String()

	// scan input (nmap, nessus, nexpose — auto-detected)
	nmapFlag = app.Flag("nmap", "Scan output file (nmap GNMAP/XML, Nessus .nessus, Nexpose XML — auto-detected). Use with 'all' command.").Short('n').String()

	// wordlist flags
	usernameFlag = app.Flag("username", "Username or file with usernames").Short('u').String()
	passwordFlag = app.Flag("password", "Password or file with passwords").Short('p').String()
	comboFlag    = app.Flag("combo", "Combo wordlist file with user:pass pairs, one per line").String()
	defaultsFlag = app.Flag("defaults", "Use built-in default username and password wordlists (user-specified -u/-p take priority)").Default("false").Bool()

	// optimization flags
	parallelFlag      = app.Flag("concurrent-hosts", "Number of targets in parallel").Short('C').Default("32").Int()
	threadsFlag       = app.Flag("concurrent-threads", "Number of parallel threads per target").Short('c').Default("10").Int()
	delayFlag         = app.Flag("delay", "Delay between each attempt. Will always use single thread if set").Short('d').Default("0s").Duration()
	timeoutFlag       = app.Flag("timeout", "Connection timeout in seconds").Default("5s").Duration()
	stopOnSuccessFlag = app.Flag("stop-on-success", "Stop bruteforcing current host when first valid credentials found (-f per host, -F global)").Short('f').Default("false").Bool()
	globalStopFlag    = app.Flag("stop-on-success-global", "Stop the entire run on first successful login across all hosts").Short('F').Default("false").Bool()
	retryFlag         = app.Flag("max-retries", "Number of connection errors to stop bruteforce the host. Specify 0 to disable this behavior").Default("30").Int()

	// connection flags
	proxyFlag     = app.Flag("proxy", "SOCKS-proxy address to use for connection in format IP:PORT").Default("").String()
	proxyAuthFlag = app.Flag("proxy-auth", "Proxy username and password in format username:password").Default("").String()
	ifaceFlag     = app.Flag("iface", "Network interface to bind outgoing connections to (e.g. eth0)").Short('I').Default("").String()

	// http flags
	userAgentFlag = app.Flag("user-agent", "User-Agent for HTTP connections").Default("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36").String()

	// output options
	quietFlag   = app.Flag("quiet", "Enable quiet mode, print results only").Short('q').Default("false").Bool()
	debugFlag   = app.Flag("debug", "Enable debug mode, print all logs").Short('D').Default("false").Bool()
	verboseFlag = app.Flag("verbose", "Enable verbose mode, log every attempt with timestamp").Short('v').Default("false").Bool()
	jsonFlag    = app.Flag("json", "Output results as JSONL (one JSON object per line)").Short('j').Default("false").Bool()
	outputFlag  = app.Flag("output", "Filename to write output in raw format").Short('o').Default("").String()

	// available modules
	// sort alphabetically

	// amqp
	allCommand      = app.Command("all", "Auto-detect modules from scan file (requires -n)")
	amqpCommand     = app.Command("amqp", "AMQP module")
	asteriskCommand = app.Command("asterisk", "Asterisk Manager Interface module (port 5038)")
	// clickhouse
	clickhouseCommand = app.Command("clickhouse", "ClickHouse module (native)")
	// etcd
	etcdCommand = app.Command("etcd", "etcd module")
	// ftp
	ftpCommand = app.Command("ftp", "FTP module")
	// http-basic
	httpBasicCommand = app.Command("http-basic", "HTTP Basic Auth module (port 80 / 443 TLS)")
	// imap
	imapCommand = app.Command("imap", "IMAP module (port 143 / 993 TLS)")
	ircCommand  = app.Command("irc", "IRC server password module (port 6667)")
	// cisco / telnet
	ciscoCommand        = app.Command("cisco", "Cisco IOS Telnet module (port 23)")
	ciscoEnableCommand  = app.Command("cisco-enable", "Cisco IOS enable-mode password module (port 23)")
	cobaltStrikeCommand = app.Command("cobaltstrike", "Cobalt Strike team server module (port 50050)")
	teamSpeakCommand    = app.Command("teamspeak", "TeamSpeak 3 ServerQuery module (port 10011)")
	telnetCommand       = app.Command("telnet", "Telnet module (port 23 / TLS)")
	// ldap
	ldapCommand  = app.Command("ldap", "LDAP module (port 389 / 636 TLS)")
	ldapsCommand = app.Command("ldaps", "LDAPS module (port 636 TLS)")
	// mongodb
	mongoCommand = app.Command("mongo", "MongoDB module")
	// mssql
	mssqlCommand = app.Command("mssql", "Microsoft SQL Server module (port 1433)")
	// mysql
	mysqlCommand = app.Command("mysql", "MySQL module (port 3306)")
	// pop3
	pop3Command = app.Command("pop3", "POP3 module (port 110 / 995 TLS)")
	// postgres
	postgresCommand = app.Command("postgres", "PostgreSQL module")
	// redis
	redisCommand  = app.Command("redis", "Redis module")
	rexecCommand  = app.Command("rexec", "BSD rexec module (port 512)")
	rloginCommand = app.Command("rlogin", "BSD rlogin module (port 513)")
	rshCommand    = app.Command("rsh", "BSD rsh module (port 514)")
	rtspCommand   = app.Command("rtsp", "RTSP Basic Auth module (port 554)")
	// smpp
	smbCommand    = app.Command("smb", "SMB module (port 445)")
	socks5Command = app.Command("socks5", "SOCKS5 username/password authentication module (port 1080)")
	snmpCommand   = app.Command("snmp", "SNMP v1/v2c community string module (port 161 UDP)")
	smppCommand   = app.Command("smpp", "SMPP module")
	// smtp
	smtpCommand = app.Command("smtp", "SMTP AUTH module (port 25 / 465 TLS / 587 STARTTLS)")
	// ssh
	sshCommand    = app.Command("ssh", "SSH module")
	sshkeyCommand = app.Command("sshkey", "SSH public key authentication module (port 22)")
	// vault
	vaultCommand = app.Command("vault", "HashiCorp Vault module (http)")
	vncCommand   = app.Command("vnc", "VNC module (port 5900)")
	xmppCommand  = app.Command("xmpp", "XMPP SASL authentication module (port 5222)")
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

	// Check if --version was requested
	if ctx.SelectedCommand == nil {
		// Check for --version or --help flags
		for _, elem := range ctx.Elements {
			if flag, ok := elem.Clause.(*kingpin.FlagClause); ok {
				if flag.Model().Name == "version" ||
					flag.Model().Name == "help" ||
					flag.Model().Name == "completion-script-zsh" ||
					flag.Model().Name == "completion-script-bash" {
					// Let kingpin handle --version, --help and --completion-script-*
					app.Parse(os.Args[1:])
					os.Exit(0)
				}
			}
		}

		// No command and no --version/--help, show usage
		app.Usage(os.Args[1:])
		os.Exit(0)
	}

	// Now do the full parse which validates required flags
	return kingpin.MustParse(app.Parse(os.Args[1:]))
}

func main() {
	// kingpin settings
	app.Version(VERSION)
	app.Author(AUTHOR)
	app.HelpFlag.Short('h')
	app.UsageTemplate(CustomUsageTemplate)

	// parse program arguments
	command := ParseArgs()

	// Detect stdin pipe
	stdinMode := utils.HasStdin()

	// all command requires -n flag or stdin
	nmapMode := command == "all"
	if nmapMode && *nmapFlag == "" && !stdinMode {
		fmt.Fprintln(os.Stderr, "error: 'all' command requires --nmap/-n scan file or piped stdin, try --help")
		os.Exit(1)
	}

	// Validate: in normal mode, --target is required (unless stdin)
	if !nmapMode && !stdinMode && *targetFlag == "" {
		fmt.Fprintln(os.Stderr, "error: required flag --target not provided, try --help")
		os.Exit(1)
	}

	// Validate: credentials are required in both modes (unless --combo or --defaults is provided)
	if *comboFlag == "" && !*defaultsFlag && (*usernameFlag == "" || *passwordFlag == "") {
		fmt.Fprintln(os.Stderr, "error: provide --username and --password, --combo, or --defaults, try --help")
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
		Usernames:           *usernameFlag,
		Passwords:           *passwordFlag,
		Defaults:            *defaultsFlag,
		Combo:               *comboFlag,
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
	}
	// try to create scanner
	s, err := scanner.NewScanner(&options)
	if err != nil {
		logger.Fatal(err)
	}

	// set up context with signal-based cancellation (Ctrl+C / SIGTERM)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if stdinMode {
		// stdin mode: read targets from pipe and auto-route to modules
		err = s.RunStdinWithResults(ctx, os.Stdin)
		if err != nil {
			logger.Fatal(err)
		}
	} else if nmapMode {
		// nmap mode: parse nmap output and run matching modules
		err = s.RunNmapWithResults(ctx, *nmapFlag)
		if err != nil {
			logger.Fatal(err)
		}
	} else {
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
