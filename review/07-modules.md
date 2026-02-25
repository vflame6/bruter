# Module Quality Review

## General Patterns

All 35 modules follow a consistent pattern:
1. Build address string
2. Dial (TLS or plaintext based on `target.Encryption`)
3. Authenticate
4. Return `(true, nil)` on success, `(false, nil)` on auth failure, `(false, error)` on connection error

This consistency is excellent.

## Per-Module Findings

### MOD-1: SMTP dupBranchBody (MEDIUM)
`smtp.go:60` — both branches of `if ok, _ := client.Extension("AUTH"); ok` have the same body (flagged by golangci-lint). The PLAIN and LOGIN fallback logic needs review; currently the code may attempt both methods identically.

### MOD-2: LDAP module doesn't use ctx (MEDIUM)
The go-ldap library supports `DialURL` with TLS config but the module uses the basic `Dial` function. Should use the context-aware connection methods.

### MOD-3: XMPP module doesn't use dialer (LOW)
`XMPPHandler` ignores the `dialer` parameter entirely — it uses the go-xmpp library's internal dialer. This means proxy support doesn't work for XMPP. Should document this limitation or find a way to inject the dialer.

### MOD-4: SNMP module ignores dialer (ACCEPTABLE)
UDP-based, can't use SOCKS proxy. Documented in code comment. Should warn user if proxy is configured.

### MOD-5: Etcd module creates gRPC client per attempt (LOW)
Each auth attempt creates a full etcd client with gRPC connection. Heavy overhead. Could reuse the transport.

### MOD-6: MongoDB module uses URI-based auth (GOOD ✅)
Clean implementation using the official driver's URI connection string.

### MOD-7: Redis module (GOOD ✅)
Clean implementation with context support.

### MOD-8: HTTP Basic module (GOOD ✅)
Properly handles Host header for virtual hosts, uses context, drains response body.

### MOD-9: SSH module (GOOD ✅)
Comprehensive — supports insecure algorithms for old servers, detects unsupported auth methods.

### MOD-10: VNC uses archived library (HIGH)
See DEP-1. The `mitchellh/go-vnc` library is from 2015.

### MOD-11: CobaltStrike module correctness (MEDIUM)
Need to verify the CobaltStrike handshake against known implementations. The protocol is undocumented and changes between versions.

### MOD-12: Telnet/Cisco prompt detection (LOW)
`readUntilPrompt` matches against fixed strings like `"$"`, `"#"`, `">"`. These could false-positive on banner text. Not a critical issue for a brute-forcer but could cause false positives.
