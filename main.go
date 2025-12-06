package main

import (
	"fmt"
	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/scanner"
	"os"
)

var (
	// Banner string
	Banner = "    __               __           \n   / /_  _______  __/ /____  _____\n  / __ \\/ ___/ / / / __/ _ \\/ ___/\n / /_/ / /  / /_/ / /_/  __/ /    \n/_.___/_/   \\__,_/\\__/\\___/_/     \n                                  "

	app       = kingpin.New("bruter", "bruter is a network services bruteforce tool.")
	quietFlag = app.Flag("quiet", "Enable quiet mode, print results only").Short('q').Default("false").Bool()
	debugFlag = app.Flag("debug", "Enable debug mode, print all logs").Short('D').Default("false").Bool()

	// file output flags
	outputFlag = app.Flag("output", "Filename to write output in raw format").Short('o').Default("").String()

	// optimization flags
	parallelFlag      = app.Flag("parallelism", "Number of targets in parallel").Short('T').Default("32").Int()
	threadsFlag       = app.Flag("threads", "Number of threads per target").Short('t').Default("10").Int()
	delayFlag         = app.Flag("delay", "Delay in millisecond between each attempt. Will always use single thread if set").Short('d').Default("0").Int()
	timeoutFlag       = app.Flag("timeout", "Connection timeout in seconds").Default("5").Int()
	stopOnSuccessFlag = app.Flag("stop-on-success", "Stop bruteforcing host on first success").Default("false").Bool()
	retryFlag         = app.Flag("max-retries", "Number of connection errors to stop bruteforcing host. Specify 0 to disable this behavior").Default("30").Int()

	// wordlist flags
	usernameFlag = app.Flag("username", "Username or file with usernames").Short('u').Required().String()
	passwordFlag = app.Flag("password", "Password or file with passwords").Short('p').Required().String()

	// available modules
	// sort alphabetically

	// clickhouse
	// default port 9000
	clickhouseCommand   = app.Command("clickhouse", "ClickHouse module")
	clickhouseTargetArg = clickhouseCommand.Arg("target", "Target host or file with targets. Format host or host:port, one per line").Required().String()

	// ftp
	// default port 21
	ftpCommand   = app.Command("ftp", "FTP module")
	ftpTargetArg = ftpCommand.Arg("target", "Target host or file with targets. Format host or host:port, one per line").Required().String()

	// mongodb
	// default port 27017
	mongoCommand   = app.Command("mongo", "MongoDB module")
	mongoTargetArg = mongoCommand.Arg("target", "Target host or file with targets. Format host or host:port, one per line").Required().String()

	// smpp
	// default port 2775
	smppCommand   = app.Command("smpp", "SMPP module")
	smppTargetArg = smppCommand.Arg("target", "Target host or file with targets. Format host or host:port, one per line").Required().String()
)

// PrintBanner is a function to print program banner
func PrintBanner() {
	fmt.Println(Banner)
}

func main() {
	// VERSION should be linked to actual tag
	VERSION := "0.0.5"

	// kingpin settings
	app.Version(VERSION)
	app.Author("vflame6")
	app.HelpFlag.Short('h')
	app.UsageTemplate(CustomUsageTemplate)

	// Parse into context first (doesn't validate required flags yet)
	ctx, err := app.ParseContext(os.Args[1:])
	if err != nil {
		app.FatalUsage(err.Error())
	}

	// Check if no command was selected
	if ctx.SelectedCommand == nil {
		app.Usage(os.Args[1:])
		os.Exit(0)
	}

	// parse options
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

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

	s, err := scanner.NewScanner(
		*timeoutFlag,
		*outputFlag,
		*parallelFlag,
		*threadsFlag,
		*delayFlag,
		*stopOnSuccessFlag,
		*retryFlag,
		*usernameFlag,
		*passwordFlag,
	)
	if err != nil {
		logger.Fatal(err)
	}

	if command == clickhouseCommand.FullCommand() {
		err = s.Run(command, *clickhouseTargetArg)
	}
	if command == ftpCommand.FullCommand() {
		err = s.Run(command, *ftpTargetArg)
	}
	if command == mongoCommand.FullCommand() {
		err = s.Run(command, *mongoTargetArg)
	}
	if command == smppCommand.FullCommand() {
		err = s.Run(command, *smppTargetArg)
	}
	if err != nil {
		logger.Fatal(err)
	}
	s.Stop()

	// show which module is done its execution
	if !*quietFlag {
		logger.Infof("finished execution of %s module", command)
	}
}

var CustomUsageTemplate = `{{define "FormatCommand" -}}
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
