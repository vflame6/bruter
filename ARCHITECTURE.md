# ARCHITECTURE.md — bruter

Read this file before making any code changes. Update it after every change.

---

## What bruter Is

A concurrent network services brute-force tool for pentesters. Written in Go. 36 protocol modules, scan file auto-detection, flexible wordlists, SOCKS5 proxy support. Designed to be fast, simple, and composable with nmap/Nessus/Nexpose pipelines.

**Author:** Maksim Radaev (@vflame6)  
**Repo:** github.com/vflame6/bruter  
**Go version:** 1.25+  
**CLI framework:** kingpin/v2

---

## Package Map

```
main.go                  — CLI flag definitions, argument parsing, entry point
scanner/
  scanner.go             — Scanner struct, Options, Run() (single-module mode), credential loading, probing
  thread.go              — SendTargets, SendCredentials, GetResults, JSONL formatting
  nmap.go                — RunNmap/RunNmapWithResults (scan file → grouped module runs)
  stdin.go               — RunStdin/RunStdinWithResults (piped JSON/plain text → grouped module runs)
  formatter.go           — ParseTarget (host:port → Target struct)
  progress.go            — Live status line on stderr (attempts/s, ETA, success count)
  modules/
    modules.go           — Module registry (map[string]Module), Target, Credential, ModuleHandler type
    ssh.go               — SSHHandler (password auth only), classifySSHError
    sshkey.go            — SSHKeyHandler (public key auth — file path or raw PEM)
    <protocol>.go        — One file per protocol (ftp, rdp, smb, ldap, mysql, etc.)
parser/
  parser.go              — Target struct, serviceMap (nmap service → bruter module), MapService
  detect.go              — DetectFormat (sniff file header → GNMAP/XML/Nessus/Nexpose)
  gnmap.go               — ParseGNMAP
  xml.go                 — ParseXML
  nessus.go              — ParseNessus
  nexpose.go             — ParseNexpose
  stdin.go               — ParseStdin (JSON lines or plain host:port), portServiceMap fallback
wordlists/
  defaults.go            — go:embed for usernames.txt, passwords.txt, ssh_badkeys.txt. Parse functions.
  usernames.txt          — 17 common usernames
  passwords.txt          — 200 most-used passwords (2023)
  ssh_badkeys.txt        — 9 known-bad PEM private keys (rapid7/ssh-badkeys)
utils/
  proxy.go               — ProxyAwareDialer (SOCKS5, TLS, interface binding, HTTP client)
  fs.go                  — IsFileExists, CountLinesInFile, ParseFileByLine, LoadLines
  net.go                 — ReadFull
  dns.go                 — LookupAddr (DNS resolution)
  tls.go                 — GetTLSConfig (insecure, all cipher suites)
  stdin.go               — HasStdin (pipe detection)
  string.go              — ContainsAny, MD5Hex
  iface.go               — GetInterfaceIPv4
logger/
  logger.go              — Leveled logger (FATAL/INFO/DEBUG/SUCCESS/VERBOSE), progress bar integration
```

---

## Three Execution Modes

1. **Single module** — `bruter ssh -t targets.txt -u root -p passwords.txt`  
   Entry: `scanner.Run()`. One module, one target set, one credential set.

2. **Scan file** — `bruter all -n scan.gnmap --defaults`  
   Entry: `scanner.RunNmap()`. Parses scan file, groups targets by service, runs matching modules sequentially.

3. **Stdin pipeline** — `fingerprintx ... | bruter all --defaults`  
   Entry: `scanner.RunStdin()`. Reads JSON lines (fingerprintx/naabu format) or plain `host:port` from stdin.

All three converge on the same `ParallelHandler` → `ThreadHandler` → `ModuleHandler` execution chain.

---

## Credential System — THIS IS CRITICAL

The credential system is simple. Do not overcomplicate it.

### Three sources of credentials

| Source | Flag | Loaded into | Notes |
|--------|------|-------------|-------|
| Explicit files | `-u file -p file` | `UsernameList`, `PasswordList` | User-specified wordlists |
| Built-in defaults | `--defaults` | `UsernameList`, `PasswordList` | Embedded via go:embed |
| Combo file | `--combo file` | `ComboList` | Pre-paired `user:pass` lines |

### How --defaults works

`--defaults` means: **add the built-in default wordlists to the credential pool.**

- `-u` alone → user's usernames only
- `--defaults` alone → built-in usernames only
- `-u` + `--defaults` → user's usernames + built-in usernames (combined)
- Same logic for `-p` / passwords

**Special case: `sshkey` module.** When `--defaults` is set and no `-p` is provided, PasswordList loads `wordlists.DefaultSSHKeys` (9 known-bad PEM keys from rapid7/ssh-badkeys) instead of `DefaultPasswords`. Combined with DefaultUsernames, this tests all bad keys against default usernames. No special flags needed — bad keys are just another default wordlist.

### Module separation: ssh vs sshkey

**`ssh` is password-only.** It never touches SSH keys. `--defaults` on ssh loads default usernames + default passwords. Period.

**`sshkey` is key-only.** It handles all key-based authentication. `--defaults` on sshkey loads default usernames + default bad keys.

There is no `--badkeys` flag. There is no combined handler. The user is expected to understand the difference between password and key authentication and choose the right module.

Known-bad SSH keys are tied to specific default usernames in the real world (root, vagrant, mateidu, sync, cluster) because the public key is placed in a specific user's `~/.ssh/authorized_keys` by firmware/software. The DefaultUsernames list covers these.

### Credential execution order

`SendCredentials()` sends combo pairs first, then the username×password matrix:
1. All `ComboList` entries
2. Then `PasswordList[i]` × `UsernameList[j]` cross-product

### Flag composition rules

```
# Explicit wordlists — user provides everything
bruter ssh -u root -p wordlist.txt -t target

# Defaults — built-in usernames AND passwords
bruter ssh --defaults -t target

# Mixed — user-specified usernames + default usernames, default passwords
bruter ssh -u root --defaults -t target
# → UsernameList = ["root"] + DefaultUsernames, PasswordList = DefaultPasswords

# Combined — user's wordlists + defaults
bruter ssh -u users.txt -p passwords.txt --defaults -t target
# → UsernameList = users.txt + DefaultUsernames, PasswordList = passwords.txt + DefaultPasswords

# Combo — pre-paired credentials
bruter ssh --combo creds.txt -t target

# Key-based brute force with bad keys
bruter sshkey --defaults -t target
# → UsernameList = DefaultUsernames, PasswordList = DefaultSSHKeys (9 bad PEM keys)

# Key-based with specific user and key file
bruter sshkey -u root -p /path/to/key -t target
```

---

## Module System

Each module is registered in `modules.Modules` map:

```go
var Modules = map[string]Module{
    "ssh": {22, SSHHandler, "root", "123456"},
    ...
}
```

`Module` struct:
- `DefaultPort` — used when target has no explicit port
- `Handler` — `ModuleHandler` function signature
- `DefaultUsername` / `DefaultPassword` — used by probe() to test default creds before brute-forcing

### ModuleHandler signature

```go
type ModuleHandler func(ctx context.Context, dialer *ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error)
```

Returns:
- `(true, nil)` — authentication succeeded
- `(false, nil)` — authentication failed (wrong creds)
- `(false, err)` — connection error (triggers retry counter)

### Adding a new module

1. Create `scanner/modules/<protocol>.go` with a `<Protocol>Handler` function
2. Register in `modules.Modules` map in `modules.go`
3. Add kingpin command in `main.go`
4. Add nmap service mapping in `parser/parser.go` `serviceMap`
5. Add port mapping in `parser/stdin.go` `portServiceMap`
6. Update README

---

## Execution Flow (single-module mode)

```
main.go: ParseArgs() → validate flags → NewScanner(options)
  ↓
scanner.Run(ctx, command, targets):
  1. Look up module in Modules map
  2. Load credentials (UsernameList, PasswordList, ComboList)
  3. Print config dashboard
  5. Start progress display
  6. go SendTargets() → Targets channel
  7. N × go ParallelHandler():
       for target in Targets:
         probe(target) — TLS check + default creds
         go SendCredentials() → credentials channel
         M × go ThreadHandler():
           for cred in credentials:
             handler(target, cred) → success/fail/error
             if success → Results channel
  8. GetResults() drains Results → stdout/file (plain text or JSONL)
  9. Stop() → close output file
```

### Probing

Before brute-forcing each target, `probe()`:
1. Tests with encryption (TLS) + module's default credentials
2. If TLS fails, retries plaintext
3. If default creds work → result emitted, optionally skip brute-force

### Stop conditions

- `-f` (StopOnSuccess): stop bruting current host after first valid cred
- `-F` (GlobalStop): stop entire scan after first valid cred across all hosts
- `--max-retries=N`: skip host after N consecutive connection errors (ban detection)
- Ctrl+C / SIGTERM: graceful shutdown via context cancellation

---

## Scan File Pipeline

```
nmap/Nessus/Nexpose output → parser.ParseFile() → []parser.Target
  ↓
Group by service name → map[string][]Target
  ↓
For each service group:
  Look up bruter module → run ParallelHandler with those targets
```

Service mapping: `parser.serviceMap` maps nmap service names → bruter module names.

**http-basic is excluded from automatic mapping** — too many false positives. Must be run manually.

### Stdin pipeline (fingerprintx/naabu)

Same grouping logic but reads from stdin. Accepts:
- JSON lines: `{"host":"1.2.3.4","port":22,"service":"ssh"}`
- Plain text: `1.2.3.4:22` (port-based service guess via `portServiceMap`)

---

## Networking

All connections go through `ProxyAwareDialer`:
- Optional SOCKS5 proxy (`--proxy`)
- Optional interface binding (`-I eth0`)
- TLS support with `DialTLS` / `DialAutoContext` (insecure config, all ciphers)
- HTTP client with custom User-Agent for HTTP-based modules

Modules that need TLS use `target.Encryption` flag (set during probe).

---

## Output

Two formats:
- **Plain text** (default): `[module] ip:port [username] [password]`
- **JSONL** (`-j`): `{"target":"host:port","port":22,"protocol":"ssh","username":"root","password":"123456","timestamp":1234567890}`

Output goes to stdout (or file with `-o`). Progress goes to stderr.

---

## Key Design Decisions

1. **Probe before brute** — test default creds and TLS support on every target before sending the full wordlist. Avoids wasting time on unreachable hosts.

2. **http-basic manual-only** — HTTP basic auth produces too many false positives in scan mode. Excluded from `serviceMap` and `portServiceMap`. Run explicitly.

3. **Wordlists embedded via go:embed** — no external file dependencies. `--defaults` just works. Bad SSH keys are part of the embedded wordlists.

4. **ComboList before matrix** — SendCredentials sends pre-paired combos first, then username×password cross-product.

5. **Progress on stderr, results on stdout** — enables piping results to jq/other tools while still showing progress.

6. **ssh and sshkey are strictly separated** — ssh does password auth only, sshkey does key auth only. No mixed mode, no combined handler. The user chooses the right module.

---

## Gotchas

- `LoadLines()` in utils/fs.go: if the argument is NOT a file path, returns it as a single-element slice. This is how `-u root` works — "root" isn't a file, so it becomes `["root"]`.
- `ParseFileByLine()` has the same behavior — non-file strings are sent as a single line to the channel.
- Module `DefaultPassword` for sshkey is "/path/to/key" — this is a placeholder, not a real default. The probe will fail harmlessly.
- nmap.go and stdin.go load credentials independently of scanner.Run(). Usernames are loaded once; passwords are selected per-module inside the loop (sshkey gets DefaultSSHKeys, everything else gets DefaultPasswords). This matches the single-module flow in scanner.Run().
- `classifySSHError` detects when SSH server doesn't support password auth and returns `ErrSSHMethodNotAllowed`, which stops bruting that host.

---

## Testing

- Unit tests exist for: `scanner/` (thread, formatter, nmap, progress), `utils/`, `wordlists/`, `parser/`
- No module-level tests (removed in PR #15 — they required live services)
- `TestNmapSummary_Valid` has a pre-existing assertion mismatch (expects 4 targets, gets 3)
- Build check: `go build ./...`
- Full tests: `go test ./... -count=1`

---

## File Inventory (62 Go files, 13 test files)

Core: `main.go` + 6 scanner files + 36 module files + 7 parser files + 2 wordlist files + 9 util files + 1 logger file

---

*Last updated: 2026-03-06 by Erra*
