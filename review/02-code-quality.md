# Code Quality Review

## DRY Violations

### QUAL-1: Repeated addr construction in every module (HIGH)
Every single module starts with:
```go
addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))
```
This is in 32 out of 35 modules. Should be a method on `Target`:
```go
func (t *Target) Addr() string { return net.JoinHostPort(t.IP.String(), strconv.Itoa(t.Port)) }
```

### QUAL-2: Repeated TLS/plaintext dial pattern (MEDIUM)
Many modules (telnet, imap, pop3, irc, etc.) have:
```go
if target.Encryption {
    conn, err = dialer.DialTLS(...)
} else {
    conn, err = dialer.Dial(...)
}
```
Could be a helper: `dialer.DialAuto(ctx, target)` that checks `target.Encryption`.

### QUAL-3: Repeated deadline setting (LOW)
After dialing, many modules do `conn.SetDeadline(time.Now().Add(timeout))`. Could be set by the dial helper.

## Naming & Go Idioms

### QUAL-4: Exported constants AUTHOR, VERSION, BANNER (LOW)
These should be unexported (`author`, `version`, `banner`) since they're only used in `main`.

### QUAL-5: BufferMultiplier naming (LOW)
`BufferMultiplier` is exported but only used within the `scanner` package. Should be `bufferMultiplier`.

### QUAL-6: `Options.Verbose` is `bool` but also `*bool` from flag (LOW)
The `Options.Verbose` field is `bool`, but the flag produces `*bool`. The indirection is handled in `main.go` but the inconsistency is worth noting.

## Unused / Dead Code

### QUAL-7: `Options.Command` is set but never read externally (LOW)
`s.Opts.Command` is set in `Run()` but it's only read from `Result.Command` which is set separately. Minor redundancy.

## Comments / Documentation

### QUAL-8: Module handlers lack godoc on return semantics (MEDIUM)
The `ModuleHandler` type documents `(bool, error)` return values, but individual handlers don't consistently document what `(false, nil)` vs `(false, error)` means. Some modules return `(false, error)` for connection failures, others return `(false, nil)`. The convention should be documented:
- `(true, nil)` = authenticated
- `(false, nil)` = connected but wrong credentials
- `(false, error)` = connection/protocol error

## Logger Issues

### QUAL-9: `os.Exit(1)` in Fatal bypasses deferred mutex unlock (HIGH)
`golangci-lint` flagged this. `Fatal()` and `Fatalf()` lock the mutex, then call `os.Exit(1)` which skips all defers including `mu.Unlock()`. In practice this is fine (process exits), but it's technically a bug and could cause issues if the logger is used in tests. Fix: unlock before exit, or use `log.Fatal` pattern.

### QUAL-10: fmt.Fprintln return values unchecked (LOW)
All 6 `fmt.Fprintf`/`fmt.Fprintln` calls in logger ignore errors. Acceptable for stdout/stderr logging, but `golangci-lint` flags them. Adding `//nolint:errcheck` comments or using `_ =` would be cleaner.
