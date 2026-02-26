# Research: Legacy SSL v2/v3 Support in Bruter

**Date:** 2026-02-26  
**Task:** #114  
**Reference:** hydra `-O` flag (old SSL mode)

## Current State

- `utils/tls.go` sets `MinVersion: tls.VersionTLS10`
- Go's `crypto/tls` has `VersionSSL30 = 0x0300` but it's **deprecated and non-functional** since Go 1.14 (golang/go#32716)
- SSLv2 was **never supported** by Go's crypto/tls
- Setting `MinVersion: tls.VersionSSL30` silently uses TLS 1.0 as the minimum

## What hydra's `-O` flag does

Hydra uses OpenSSL (linked via C). The `-O` flag forces SSLv3-compatible handshake for targets that don't support TLS 1.0+. This is relevant for:
- Very old embedded devices (pre-2014 firmware)
- Legacy ICS/SCADA systems
- Old network appliances stuck on SSLv3

In practice, SSLv2/v3-only targets are extremely rare in 2026 — POODLE (2014) forced most upgrades.

## Options Explored

### Option A: CGo + OpenSSL bindings
Libraries: `pexip/go-openssl`, `spacemonkeygo/openssl`

**Pros:**
- Full SSLv2/v3 support via system OpenSSL
- Feature parity with hydra

**Cons:**
- Breaks cross-compilation (CGo required)
- Build dependency on `libssl-dev` / OpenSSL headers
- bruter currently is pure Go — zero CGo deps
- Increases binary size and build complexity significantly
- OpenSSL 3.x disables SSLv2 by default anyway (need legacy provider)

### Option B: Fork/patch Go's crypto/tls
**Cons:**
- Massive maintenance burden
- SSLv3 code was deliberately removed for security
- Not worth the effort for a niche use case

### Option C: Raw TCP + manual SSL handshake
**Cons:**
- Would need to implement SSLv3 record protocol from scratch
- Enormous effort, error-prone, no real benefit

### Option D: Do nothing (recommended)

**Rationale:**
1. SSLv2 is dead. SSLv3 is effectively dead (POODLE, 2014). RFC 7568 prohibits SSLv3.
2. bruter's TLS 1.0 minimum already covers 99.9%+ of real-world targets
3. Adding CGo would break the pure-Go cross-compilation story — a significant architectural cost
4. The probe() fallback (TLS → plaintext) already handles most legacy scenarios
5. hydra's `-O` flag exists because hydra is C-linked to OpenSSL — it gets SSLv3 "for free"

## Recommendation

**Close this task as won't-fix.** Document the limitation in README or `--help`:

> bruter supports TLS 1.0 through TLS 1.3. SSLv2/v3 are not supported as they are
> cryptographically broken (POODLE, RFC 7568). For the rare SSLv3-only target,
> use hydra with `-O` flag.

If demand arises in the future, the cleanest path would be an optional build tag (`-tags openssl`) that swaps `utils.GetTLSConfig()` for an OpenSSL-backed dialer — but this should not be default.

## Implementation

Added this note to the codebase. No code changes needed.
