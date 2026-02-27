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

`bruter` is a fast, concurrent network services bruteforce tool written in Go. It supports 36 protocols, scan file auto-detection, and flexible wordlist options — built for pentesters who need reliable credential testing at scale.

## Features

![bruter](static/bruter_demo.png)

- **36 modules** — SSH, RDP-adjacent, databases, mail, web, and more
- **Scan file auto-detection** — feed nmap (GNMAP/XML), Nessus, or Nexpose output directly
- **Built-in default wordlists** — 17 usernames + 200 passwords with `--defaults`
- **Combo wordlists** — `user:pass` format with `--combo`
- **Parallel execution** — configurable per-host threading and concurrent hosts
- **Smart probing** — auto-detects TLS and tests default credentials before brute
- **SOCKS5 proxy support** — with optional proxy authentication
- **Interface binding** — bind to a specific network interface with `-I`
- **Stop-on-success** — per-host (`-f`) or global (`-F`)
- **JSONL output** — machine-readable results with `-j`
- **Live progress** — real-time status line with speed, ETA, and success count

### Available Modules

| Category | Modules |
|----------|---------|
| **Remote Access** | `ssh`, `sshkey`, `rdp`, `winrm`, `telnet`, `rexec`, `rlogin`, `rsh`, `vnc` |
| **Databases** | `mysql`, `mssql`, `postgres`, `mongo`, `redis`, `clickhouse`, `etcd` |
| **Mail** | `smtp`, `imap`, `pop3` |
| **Web / HTTP** | `http-basic`, `vault` |
| **Directory** | `ldap`, `ldaps` |
| **File Sharing** | `ftp`, `smb` |
| **Messaging** | `irc`, `xmpp`, `smpp`, `amqp` |
| **Network** | `socks5`, `snmp`, `rtsp` |
| **VoIP** | `asterisk`, `teamspeak` |
| **Cisco** | `cisco`, `cisco-enable` |
| **Other** | `cobaltstrike` |

## Installation

`bruter` requires **Go 1.25+** to install successfully.

```shell
go install -v github.com/vflame6/bruter@latest
```

Pre-compiled binaries are available on the [Releases](https://github.com/vflame6/bruter/releases) page.

Build from source:

```shell
git clone https://github.com/vflame6/bruter.git
cd bruter
go build -o bruter main.go
```

Build with Docker:

```shell
docker build -t bruter .
docker run --rm bruter ssh -t 10.0.0.1 -u admin -p passwords.txt
```

## Usage

```
bruter [flags] <module> [module-flags]
```

### Quick Examples

**Brute-force SSH with a password list:**

```shell
bruter ssh -t 192.168.1.10 -u root -p /usr/share/wordlists/passwords.txt
```

**Multiple targets from a file:**

```shell
bruter ssh -t targets.txt -u users.txt -p passwords.txt -C 50 -c 5
```

**Use built-in default wordlists:**

```shell
bruter mysql -t 10.0.0.5:3306 --defaults
```

**Auto-detect from nmap scan:**

```shell
nmap -sV -oG scan.gnmap 10.0.0.0/24
bruter all -n scan.gnmap --defaults
```

**Auto-detect from Nessus/Nexpose:**

```shell
bruter all -n scan.nessus -u admin -p passwords.txt
bruter all -n nexpose-report.xml --defaults
```

**Combo wordlist (user:pass pairs):**

```shell
bruter ssh -t 10.0.0.1 --combo creds.txt
```

**JSONL output for piping:**

```shell
bruter ftp -t targets.txt --defaults -j | jq '.host'
```

**Stop on first success per host, save results:**

```shell
bruter smb -t targets.txt -u users.txt -p passwords.txt -f -o results.txt
```

**Through a SOCKS5 proxy:**

```shell
bruter ssh -t 10.0.0.1 -u root -p passwords.txt --proxy 127.0.0.1:1080
```

**Bind to a specific interface:**

```shell
bruter ssh -t 10.0.0.1 -u root -p passwords.txt -I eth0
```

### Full Flag Reference

```
Flags:
  -t, --target=TARGET                Target host or file (format: host or host:port)
  -n, --nmap=NMAP                    Scan file (nmap GNMAP/XML, Nessus, Nexpose — auto-detected)
  -u, --username=USERNAME            Username or file with usernames
  -p, --password=PASSWORD            Password or file with passwords
      --combo=COMBO                  Combo wordlist (user:pass per line)
      --defaults                     Use built-in default wordlists
  -C, --concurrent-hosts=32          Parallel targets
  -c, --concurrent-threads=10        Threads per target
  -d, --delay=0s                     Delay between attempts (forces single thread)
      --timeout=5s                   Connection timeout
  -f, --stop-on-success              Stop current host on first valid creds
  -F, --stop-on-success-global       Stop entire run on first valid creds
      --max-retries=30               Connection errors before skipping host (0=disable)
      --proxy=IP:PORT                SOCKS5 proxy
      --proxy-auth=user:pass         Proxy credentials
  -I, --iface=IFACE                  Bind to network interface
      --user-agent=UA                User-Agent for HTTP modules
  -q, --quiet                        Print results only
  -D, --debug                        Debug logging
  -v, --verbose                      Log every attempt
  -j, --json                         JSONL output
  -o, --output=FILE                  Write results to file
```

### Target Format

Targets use `host` or `host:port` format. If port is omitted, the module default is used.

```
192.168.0.11
192.168.0.12:2222
10.0.0.0/24
```

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request. New module ideas, bug reports, and feature requests are all appreciated.
