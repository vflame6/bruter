<h1 align="center">
  bruter
</h1>

<h4 align="center">Active network services bruteforce tool.</h4>

<p align="center">
<a href="https://goreportcard.com/report/github.com/vflame6/bruter" target="_blank"><img src="https://goreportcard.com/badge/github.com/vflame6/bruter"></a>
<a href="https://github.com/vflame6/bruter/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/vflame6/bruter/releases"><img src="https://img.shields.io/github/release/vflame6/bruter"></a>
<a href="https://t.me/vflame6"><img src="https://img.shields.io/badge/Follow-@vflame6-33a3e1?style=flat&logo=telegram"></a>
</p>

Created by Maksim Radaev/[@vflame6](https://github.com/vflame6)

---

`bruter` is a network services bruteforce tool. It supports several services and can be improved to support more.

## Features

![bruter](static/bruter_demo.png)

Available modules: `amqp` ,`asterisk` ,`clickhouse` ,`etcd` ,`ftp` ,`http-basic` ,`imap` ,`irc` ,`cisco` ,`cisco-enable` ,`cobaltstrike` ,`teamspeak` ,`telnet` ,`ldap` ,`ldaps` ,`mongo` ,`mssql` ,`mysql` ,`pop3` ,`postgres` ,`redis` ,`rexec` ,`rlogin` ,`rsh` ,`rtsp` ,`smb` ,`socks5` ,`snmp` ,`smpp` ,`smtp` ,`ssh` ,`sshkey` ,`vault` ,`vnc` ,`xmpp`

Available features:

- Customizable parallelism and per-host threading
- Stop the bruteforce target on multiple connection errors
- SOCKS5 proxy support

## Usage

```shell
bruter -h
```

Here is a help menu for the tool:

```yaml
usage: bruter [<flags>] <command> [<args> ...]

  bruter is a network services bruteforce tool.

Flags:
  -h, --[no-]help              Show context-sensitive help (also try --help-long
  and --help-man).
  -t, --target=TARGET          Target host or file with targets. Format host or
  host:port, one per line
  -n, --nmap=NMAP              Nmap output file (GNMAP or XML, auto-detected).
  Runs matching modules automatically.
  -u, --username=USERNAME      Username or file with usernames
  -p, --password=PASSWORD      Password or file with passwords
  --combo=COMBO            Combo wordlist file with user:pass pairs,
  one per line
  -C, --concurrent-hosts=32    Number of targets in parallel
  -c, --concurrent-threads=10  Number of parallel threads per target
  -d, --delay=0s               Delay between each attempt. Will always use
  single thread if set
  --timeout=5s             Connection timeout in seconds
  -f, --[no-]stop-on-success   Stop bruteforcing current host when first valid
  credentials found (-f per host, -F global)
  -F, --[no-]stop-on-success-global
  Stop the entire run on first successful login
  across all hosts
  --max-retries=30         Number of connection errors to stop bruteforce
  the host. Specify 0 to disable this behavior
  --proxy=""               SOCKS-proxy address to use for connection in
  format IP:PORT
  --proxy-auth=""          Proxy username and password in format
  username:password
  -I, --iface=""               Network interface to bind outgoing connections to
  (e.g. eth0)
  --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
  User-Agent for HTTP connections
  -q, --[no-]quiet             Enable quiet mode, print results only
  -D, --[no-]debug             Enable debug mode, print all logs
  -v, --[no-]verbose           Enable verbose mode, log every attempt with
  timestamp
  -j, --[no-]json              Output results as JSONL (one JSON object per
  line)
  -o, --output=""              Filename to write output in raw format
  --[no-]version           Show application version.

Commands: amqp asterisk clickhouse etcd ftp http-basic imap irc cisco cisco-enable cobaltstrike teamspeak telnet ldap ldaps mongo mssql mysql pop3 postgres redis rexec rlogin rsh rtsp smb socks5 snmp smpp smtp ssh sshkey vault vnc xmpp
```

Targets are specified in format `IP` or `IP:PORT`. If `PORT` is not specified, the tool uses the default one (for example: `9000` for ClickHouse). 

You can also specify a file to parse. The format for targets file is shown below:  

```
192.168.0.11
192.168.0.12:12345
192.168.0.13:54321
```

The tool performs a check for default credentials (hardcoded) for applicable services. It also determines if an encryption is used on the service for later use.

## Installation

`bruter` requires **go1.25** to install successfully.

```shell
go install -v github.com/vflame6/bruter@latest
```

Compiled versions are available on [Release Binaries](https://github.com/vflame6/bruter/releases) page.

To Build:

```
go build -o bruter main.go
```

Build with Docker:

```shell
docker build -t bruter . 
```

## Contributing

Feel free to open an issue if something does not work, or if you have any issues. New ideas to improve the tool are much appreciated.
