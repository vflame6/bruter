# Security Review

### SEC-1: Credentials not zeroed after use (MEDIUM)
Credential structs (`Credential.Username`, `Credential.Password`) are Go strings — immutable and garbage-collected. They can't be securely wiped from memory. This is a Go language limitation, not a bruter bug, but worth noting. For a pentest tool, this is acceptable. A paranoid approach would use `[]byte` and zero after use.

### SEC-2: InsecureSkipVerify used everywhere (ACCEPTABLE)
`TLSConfig` has `InsecureSkipVerify: true`. For a brute-force tool targeting arbitrary services, this is correct — you're testing auth, not cert validity. The `MinVersion: tls.VersionTLS10` is also appropriate for compatibility with older targets.

### SEC-3: Proxy auth split on first ":" only (LOW)
`proxy.go` splits proxy auth with `strings.Split(proxyAuth, ":")` and checks `len == 2`. If a password contains ":", this breaks. Should use `strings.SplitN(proxyAuth, ":", 2)`.

### SEC-4: No input validation on port ranges from CLI (LOW)
`ParseTarget` validates ports 1-65535, but the CLI flags `--concurrent-hosts` and `--concurrent-threads` don't validate for reasonable upper bounds. Passing `--concurrent-hosts 1000000` would try to create 1M goroutines. Should cap at a reasonable maximum (e.g., 10000).

### SEC-5: 15 modules don't use context for cancellation (HIGH)
These modules ignore the `ctx` parameter:
- asterisk, cisco, cisco-enable, irc, ldap, rexec, rlogin, rsh, rtsp, snmp, socks5, teamspeak, telnet, vnc, xmpp

This means Ctrl+C / SIGTERM won't immediately stop these modules' in-flight operations. They rely on socket timeouts to eventually stop. For a pentest tool this is acceptable but not ideal. Modules using `Dial` instead of `DialContext` can't be cancelled mid-connection.

### SEC-6: SNMP uses UDP — no proxy support silently ignored (LOW)
The SNMP module accepts but ignores the proxy dialer. The comment says so, but there's no user-visible warning. Should log an info message if proxy is configured.

### SEC-7: SSH key file path validation (LOW)
`sshkey` module reads a file path from the password field. There's no path traversal protection, but since this is a local CLI tool run by the operator, this is acceptable.

### SEC-8: Timeout on all network operations (GOOD ✅)
All raw TCP modules set `conn.SetDeadline()`. Modules using client libraries rely on library timeouts. Good coverage — no unbounded network operations found.
