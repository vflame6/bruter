---
name: bruter
description: Use when testing network service credentials during an authorized engagement - brute-forcing or password-spraying SSH, SMB, RDP, Kerberos, databases and 50+ other protocols, importing nmap/Nessus/Nexpose scans, or finding unauthenticated services. Covers the bruter CLI and its MCP server.
---

# bruter

`bruter` tests credentials against 56 network protocols from one static binary,
and can read an nmap, Nessus or Nexpose scan file directly.

## Before anything else

Credential testing is only legitimate inside an authorized engagement. Before
putting traffic on the wire, confirm with your human partner:

1. **The target list.** Specific hosts or CIDR blocks they have authorization for.
2. **The lockout policy**, if Active Directory accounts are in play. You need
   the threshold and the observation window to pick safe spray settings.

Do not infer scope from a scan file, a hostname, or a previous task. A scan
file tells you what exists, not what you are allowed to touch. If scope is
unclear, ask.

## Via MCP (preferred when available)

The operator starts the server:

```shell
bruter mcp --mcp-scope engagement-scope.txt
```

`engagement-scope.txt` lists one IP, CIDR block or hostname per line. Tools:

| Tool | What it does |
|------|--------------|
| `list_services` | Every module and its default port |
| `parse_scan` | Parse a scan file; each finding flagged `in_scope` |
| `check_scope` | Which targets are authorized |
| `run_module` | Test credentials against one protocol |
| `spray` | Lockout-safe spraying, one password per round |

Rules:

- `spray` requires `max_attempts_per_user`. The budget is shared across the
  whole server session, so calling `spray` again does not give accounts a fresh
  allowance, and asking for a different value is refused.
- Call `check_scope` before `run_module` or `spray`. Out-of-scope targets are
  refused and **nothing** runs — not even the in-scope part of the request.
- If `run_module` and `spray` are missing from the tool list, the operator
  started the server without a scope file. Say so and stop; do not look for
  another way to run the scan.
- Against AD accounts use `spray`, never `run_module`. `run_module` has no
  per-account limit.

## Via the CLI

Pick a module and give it targets plus wordlists:

```shell
bruter ssh -t 10.10.20.0/24 -u users.txt -p passwords.txt
bruter mysql -t 10.10.20.31:3306 --defaults
```

Drive it from a scan instead of naming services yourself:

```shell
bruter all -n scan.gnmap --defaults -s ssh,ftp,rdp
```

Find unauthenticated and default-credential services without firing a single
wordlist attempt — a good, quiet first pass:

```shell
bruter all -n scan.xml --vulns
```

Add `-j` for JSONL on stdout and `-o results.txt` to keep a copy.

## Password spraying against Active Directory

This is the one workflow where getting the flags wrong does damage: locking out
a few hundred accounts is an outage you caused.

```shell
bruter kerberos -t dc01.corp.local --domain corp.local \
    -u users.txt -p seasons.txt \
    --spray --delay 35m --jitter 5m --max-attempts-per-user 3
```

- `--spray` tries one password against every user **and every host**, then
  sleeps. One attempt per account per host per round — so three domain
  controllers cost each account three attempts per round, because the lockout
  counter is on the directory, not the host. Spray one host if you only need to
  know whether a password is valid.
- `--delay` must exceed the domain's lockout observation window, so each round
  starts with the counters reset. 30+ minutes is typical; ask, do not guess.
- `--jitter` randomizes the pause. Must not exceed `--delay`.
- `--max-attempts-per-user` caps attempts per account across the whole run and
  aborts once every account hits it. Set it **below** the lockout threshold,
  leaving the user room to log in normally.
- `--order user` exists but empties one account's budget at a time. Do not use
  it against a live directory.

Long runs die. Add `--resume state.ck` and the same command picks up where it
stopped instead of re-spending lockout budget on work already done.

## Kerberos

```shell
# Which accounts exist? Submits no password, so it costs no lockout budget.
bruter kerberos-enum -t dc01.corp.local --domain corp.local -u users.txt

# Password validation via AS-REQ pre-authentication.
bruter kerberos -t dc01.corp.local --domain corp.local -u users.txt -p pw.txt --spray --delay 35m
```

`-p` is optional for `kerberos-enum` and `smtp-enum`: they ignore the password.

Run `kerberos-enum` first: it is free in lockout terms, it tells you which
names are real before you spend attempts on them, and it flags accounts with
pre-authentication disabled, which are AS-REP roastable.

Both modules need a realm, from `--domain` or usernames written as
`user@REALM`.

## Reading the output

A successful login is reported as `host:port username:password`. With `-j` each
hit is one JSON object. `--vulns` findings name the check that fired
(`null-session`, `anonymous-bind`, `no-auth`, …).

Treat recovered credentials as sensitive: report them to your human partner,
do not paste them into anything that leaves the engagement, and do not reuse
them against hosts outside scope.

## Flags worth knowing

| Flag | Why |
|------|-----|
| `-C` / `-c` | Concurrent hosts / threads per host. Lower them on fragile targets |
| `--max-retries` | Give up on a host after this many connection errors (default 30) |
| `-f` / `-F` | Stop on first success, per host / globally |
| `--timeout` | Per-connection timeout, default 10s |
| `--proxy` | SOCKS5, with `--proxy-auth` |
| `-I` | Bind to an interface, e.g. a VPN tun |
| `-L` | List every module and port |

`bruter -h` is the full reference.
