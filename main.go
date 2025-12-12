package main

import (
	"fmt"
	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/scanner"
	"os"
)

// AUTHOR of the program
const AUTHOR = "vflame6"

// VERSION should be linked to actual tag
const VERSION = "v0.0.9"

// BANNER format string. It is used in PrintBanner function with VERSION
const BANNER = "    __               __           \n   / /_  _______  __/ /____  _____\n  / __ \\/ ___/ / / / __/ _ \\/ ___/\n / /_/ / /  / /_/ / /_/  __/ /    \n/_.___/_/   \\__,_/\\__/\\___/_/      %s\n                                  \n"

// program commands, flags and arguments
var (
	app       = kingpin.New("bruter", "bruter is a network services bruteforce tool.")
	quietFlag = app.Flag("quiet", "Enable quiet mode, print results only").Short('q').Default("false").Bool()
	debugFlag = app.Flag("debug", "Enable debug mode, print all logs").Short('D').Default("false").Bool()

	// file output flags
	outputFlag = app.Flag("output", "Filename to write output in raw format").Short('o').Default("").String()

	// optimization flags
	parallelFlag      = app.Flag("concurrent-hosts", "Number of targets in parallel").Short('C').Default("32").Int()
	threadsFlag       = app.Flag("concurrent-threads", "Number of parallel threads per target").Short('c').Default("10").Int()
	delayFlag         = app.Flag("delay", "Delay in millisecond between each attempt. Will always use single thread if set").Short('d').Default("0").Int()
	timeoutFlag       = app.Flag("timeout", "Connection timeout in seconds").Default("5").Int()
	stopOnSuccessFlag = app.Flag("stop-on-success", "Stop bruteforce the host on first success").Default("false").Bool()
	retryFlag         = app.Flag("max-retries", "Number of connection errors to stop bruteforce the host. Specify 0 to disable this behavior").Default("30").Int()

	// connection flags
	proxyFlag     = app.Flag("proxy", "SOCKS-proxy address to use for connection in format IP:PORT").Default("").String()
	proxyAuthFlag = app.Flag("proxy-auth", "Proxy username and password in format username:password").Default("").String()

	// targets
	targetFlag = app.Flag("target", "Target host or file with targets. Format host or host:port, one per line").Short('t').Required().String()

	// wordlist flags
	usernameFlag = app.Flag("username", "Username or file with usernames").Short('u').Required().String()
	passwordFlag = app.Flag("password", "Password or file with passwords").Short('p').Required().String()

	// available modules
	// sort alphabetically

	// amqp
	amqpCommand = app.Command("amqp", "AMQP module")
	// clickhouse
	clickhouseCommand = app.Command("clickhouse", "ClickHouse module")
	// etcd
	etcdCommand = app.Command("etcd", "etcd module")
	// ftp
	ftpCommand = app.Command("ftp", "FTP module")
	// mongodb
	mongoCommand = app.Command("mongo", "MongoDB module")
	// postgres
	postgresCommand = app.Command("postgres", "PostgreSQL module")
	// redis
	redisCommand = app.Command("redis", "Redis module")
	// smpp
	smppCommand = app.Command("smpp", "SMPP module")
	// ssh
	sshCommand = app.Command("ssh", "SSH module")
	// vault
	vaultCommand = app.Command("vault", "HashiCorp Vault userpass module")
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
	fmt.Printf(BANNER, VERSION)
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

	// instantiate logger
	if err := logger.Init(*quietFlag, *debugFlag); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	// print program banner
	if !*quietFlag {
		PrintBanner()
	}

	// show which module is executed
	if !*quietFlag {
		logger.Infof("executing %s module", command)
	}

	// try to create scanner
	s, err := scanner.NewScanner(
		*timeoutFlag,
		*outputFlag,
		*parallelFlag,
		*threadsFlag,
		*delayFlag,
		*stopOnSuccessFlag,
		*retryFlag,
		*proxyFlag,
		*proxyAuthFlag,
		*usernameFlag,
		*passwordFlag,
	)
	if err != nil {
		logger.Fatal(err)
	}

	// pass the selected command
	err = s.Run(command, *targetFlag)
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
