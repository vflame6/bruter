# Architecture Review

## Scanner → ParallelHandler → ThreadHandler Pipeline

The current architecture is a two-level fan-out:
1. `Scanner.Run()` spawns `Parallel` goroutines (one per concurrent host)
2. Each `ParallelHandler` spawns `Threads` goroutines per target

This is a solid pattern for brute-forcing. The channel-based pipeline (`Targets → ParallelHandler → credentials → ThreadHandler → Results`) is idiomatic Go.

### Issues

#### ARCH-1: Default credential check embedded in ParallelHandler (HIGH)
The ParallelHandler does a default credential check AND TLS fallback detection before spawning ThreadHandlers. This logic is complex (50+ lines) and conflates two concerns: protocol detection and brute-forcing. Should be extracted into a separate `probe` step.

#### ARCH-2: CLI flag parsing uses global variables (MEDIUM)
All 40+ flags are package-level `var` declarations in `main.go`. This makes testing impossible and creates tight coupling. The `Options` struct in scanner is good, but the bridge from globals to struct is fragile.

#### ARCH-3: Kingpin CLI library is in "contributions only" mode (LOW)
Kingpin v2 works but is no longer actively maintained. The author (alecthomas) has moved on. For a tool this size, `cobra` or `kong` (also by alecthomas, the spiritual successor to kingpin) would be better long-term choices. Not urgent — kingpin v2 is stable.

#### ARCH-4: Module registration is a static map (LOW)
`modules.Modules` is a `map[string]Module` initialized at package level. This works fine for 35 modules but doesn't support plugin-style extensibility. A `Register()` pattern with `init()` functions would be more Go-idiomatic and allow optional modules (e.g., skip modules with heavy deps).

#### ARCH-5: No progress reporting (MEDIUM)
There's no way to see progress during a long scan (how many targets done, credentials tried per target, ETA). BruteSpray has a progress bar. This is a significant UX gap for penetration testers running large scans.

#### ARCH-6: No nmap/nessus input parsing (MEDIUM)
BruteSpray's killer feature is reading nmap/nessus output directly. Bruter requires manual target lists. Adding scan parser support would significantly increase utility.

#### ARCH-7: No combo wordlist support (LOW)
BruteSpray supports `-C user:pass` combo files. Bruter requires separate username and password inputs.

#### ARCH-8: Credential iteration order is password-outer, username-inner (LOW)
`SendCredentials` iterates passwords in the outer loop, usernames in the inner. This means it tries all users with password1, then all users with password2. This is good for avoiding lockouts (different from user-first order). Could be configurable.
