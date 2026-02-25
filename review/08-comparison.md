# Comparison with Reference Projects

## BruteSpray (x90skysn3k/brutespray)

| Feature | Bruter | BruteSpray |
|---|---|---|
| Language | Go | Go (rewritten from Python) |
| Protocol modules | 35 | ~20 |
| Nmap GNMAP/XML input | ❌ | ✅ |
| Nessus input | ❌ | ✅ |
| Nexpose input | ❌ | ✅ |
| Combo wordlist (-C) | ❌ | ✅ |
| SOCKS proxy | ✅ | ✅ |
| Interface binding | ✅ | ❌ |
| JSONL output | ✅ | ❌ |
| Global stop on first success | ✅ | ❌ |
| Verbose per-attempt logging | ✅ | ❌ |
| Progress bar | ❌ | ❌ |
| TLS auto-detection | ✅ | Partial |
| IPv6 support | ✅ | Partial |
| Domain/Host header | ✅ | ❌ |

### Key Takeaways

**Bruter advantages:**
- More modules (35 vs ~20)
- Better networking (interface binding, TLS fallback, IPv6)
- JSONL output for automation
- Global stop flag
- Verbose logging

**BruteSpray advantages:**
- Nmap/Nessus/Nexpose input parsing (huge for workflow integration)
- Combo wordlists
- Output directory organization
- More established user base

**Recommendation:** Adding nmap GNMAP/XML parsing would make bruter a clear BruteSpray replacement. This is the single highest-value feature to add.

## Other Go Brute-Force Tools

- **gobrute** (various small projects) — typically single-protocol, not comparable
- **legba** — Rust-based, not Go, but similar scope with 50+ modules
- **hydra** — C-based, the classic. 50+ modules but single-threaded per-target

Bruter is well-positioned in the Go ecosystem — it has more modules than any other Go brute-force tool found.
