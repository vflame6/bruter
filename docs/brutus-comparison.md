# Competitive Analysis: bruter vs Brutus (Praetorian)

**Date:** 2026-02-26
**Source:** https://github.com/praetorian-inc/brutus

## Overview

Brutus is a Go-based multi-protocol credential testing tool by Praetorian (offensive security firm). It positions itself as a modern Hydra replacement with zero external dependencies and pipeline-first design.

## Protocol Coverage Comparison

### Brutus has (24 protocols):
ssh, ftp, rdp, mysql, postgresql, mssql, redis, smb, ldap, snmp, telnet, vnc, winrm, http (basic), imap, pop3, smtp, mongodb, cassandra, couchdb, elasticsearch, influxdb, neo4j, browser (headless Chrome for web forms)

### bruter has (38 modules):
ssh, sshkey, ftp, mysql, postgres, mssql, redis, smb, ldap, ldaps, snmp, telnet, telnets, vnc, http-basic, imap, pop3, smtp, mongo, amqp, asterisk, cisco, cisco-enable, clickhouse, cobaltstrike, etcd, irc, rexec, rlogin, rsh, rtsp, smpp, socks5, teamspeak, vault, xmpp, smb

### bruter has but Brutus doesn't (14):
- **amqp** — RabbitMQ
- **asterisk** — VoIP PBX
- **cisco / cisco-enable** — Cisco devices
- **clickhouse** — analytics DB
- **cobaltstrike** — C2 teamserver
- **etcd** — key-value store
- **irc** — IRC servers
- **rexec / rlogin / rsh** — legacy BSD r-services
- **rtsp** — IP cameras/streaming
- **smpp** — SMS gateway
- **socks5** — SOCKS proxy auth
- **teamspeak** — voice server
- **vault** — HashiCorp Vault
- **xmpp** — Jabber/XMPP

### Brutus has but bruter doesn't (8):
- **rdp** — Remote Desktop Protocol (with sticky keys detection!)
- **winrm** — Windows Remote Management
- **cassandra** — distributed DB
- **couchdb** — document DB
- **elasticsearch** — search engine
- **influxdb** — time-series DB
- **neo4j** — graph DB
- **browser** — headless Chrome for web form auth (AI-assisted)

## Key Feature Gaps (bruter lacks)

### 1. JSON stdin pipeline (HIGH priority)
Brutus reads fingerprintx/naabu JSON from stdin:
```bash
naabu -host 10.0.0.0/24 | fingerprintx --json | brutus --json
```
bruter has `--nmap` for nmap input but no JSON stdin pipeline. This is the #1 integration gap.
**→ Task #118 already exists**

### 2. Embedded SSH bad keys (MEDIUM priority)
Brutus auto-tests known bad SSH keys (Vagrant, F5 BIG-IP, ExaGrid, etc.) against every SSH target. Zero config.
bruter has `sshkey` module but requires manual key files.
**→ Task #119 already exists**

### 3. RDP module (MEDIUM priority)
Full RDP auth testing + NLA detection + sticky keys backdoor scanning. This is a unique differentiator. Complex to implement (RDP protocol is heavy).
**→ Worth creating a task**

### 4. WinRM module (LOW-MEDIUM priority)
Useful for Windows environments. Go library available (masterzen/winrm).
**→ Worth creating a task**

### 5. Library-first design (LOW priority for now)
Brutus can be imported as a Go library. bruter is CLI-only. Nice for tool builders but not urgent.

### 6. Browser-based auth (LOW priority)
Headless Chrome + AI vision for web login forms. Impressive but niche — most web bruting uses specialized tools.

## bruter's Advantages Over Brutus

1. **More niche protocols** — bruter covers 14 protocols Brutus doesn't (IoT, VoIP, legacy, gaming, C2)
2. **Nmap input parsing** — GNMAP and XML auto-detection
3. **Proxy support** — SOCKS5/HTTP proxy with auth
4. **Progress bar** — live speed/ETA display
5. **Combo wordlists** — user:pass pair files
6. **TLS auto-detection** — transparent encrypt/no-encrypt fallback per target
7. **Configuration dashboard** — startup config summary (just added)

## Recommendations (Priority Order)

| # | Feature | Priority | Effort | Task |
|---|---------|----------|--------|------|
| 1 | JSON stdin pipeline (fingerprintx/naabu compat) | HIGH | Medium | #118 |
| 2 | Embedded SSH bad keys | MEDIUM | Low | #119 |
| 3 | RDP module | MEDIUM | High | NEW |
| 4 | WinRM module | LOW-MED | Medium | NEW |
| 5 | Additional DBs (cassandra, couchdb, elasticsearch, influxdb, neo4j) | LOW | Medium each | NEW |

## Conclusion

bruter and Brutus target the same space but with different strengths. bruter has broader protocol coverage (38 vs 24), especially for niche/IoT/legacy services. Brutus has better pipeline integration and some unique features (RDP sticky keys, browser auth, SSH bad keys).

The highest-value improvements for bruter are: (1) JSON stdin pipeline for fingerprintx/naabu compatibility, and (2) embedded SSH bad keys. These close the main usability gap without massive effort.
