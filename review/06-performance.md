# Performance Review

### PERF-1: DNS resolution per-target, no caching (MEDIUM)
`LookupAddr` in `utils/dns.go` calls `net.LookupHost` for every hostname target. If the same hostname appears multiple times (different ports), it's resolved each time. Add a simple `sync.Map` cache.

### PERF-2: Credential file re-read for every target (HIGH)
`SendCredentials` calls `utils.ParseFileByLine(passwords)` and `utils.ParseFileByLine(usernames)` for every target in `ParallelHandler`. For large wordlists, this means re-reading and re-parsing the files from disk for each target. Should load credentials into memory once and iterate from a slice.

### PERF-3: No connection pooling (LOW)
Each credential attempt opens a new TCP connection. For some protocols (HTTP, LDAP, SMTP), connection reuse would significantly reduce overhead. However, many auth protocols close connections on failure, so pooling isn't always possible. Module-specific optimization opportunity.

### PERF-4: Byte-at-a-time reading in telnet (LOW)
`readUntilPrompt` reads one byte at a time via `reader.Read(rawBuf)` where `rawBuf` is 1 byte. The `bufio.Reader` buffer helps, but the `stripIAC` + `strings.Contains` on every byte is wasteful. Could read larger chunks.

### PERF-5: String allocations in hot path (LOW)
`net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))` allocates a new string every call. Since this is called once per credential attempt per module, caching `addr` on the Target struct would help.

### PERF-6: Output file not buffered (LOW)
Results written to `--output` file use `outputFile.WriteString()` directly. For high-throughput scans with many results, a `bufio.Writer` would reduce syscalls.

### PERF-7: Channel buffer sizing (LOW)
`BufferMultiplier = 4` means channels are `parallel * 4` and `threads * 4`. This is reasonable. No evidence of channel contention from the code analysis.
