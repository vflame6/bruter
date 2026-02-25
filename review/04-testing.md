# Testing Review

## Coverage Summary

| Package | Coverage | Assessment |
|---|---|---|
| main | 0% | No tests at all |
| logger | 71.1% | Good — tests both modes |
| scanner | 26.9% | Low — complex logic untested |
| scanner/modules | 58.0% | Decent — but tests are mock-based |
| utils | 43.1% | Moderate |

### TEST-1: Scanner package has only 26.9% coverage (HIGH)
The most critical logic (ParallelHandler, ThreadHandler, global stop, retry logic, credential sending) has minimal test coverage. The `scanner_test.go` and `thread_test.go` exist but don't cover:
- Context cancellation behavior
- GlobalStop propagation
- Retry limit enforcement
- StopOnSuccess per-target behavior
- Race conditions between threads (the `-race` flag passes, but that only catches actual races in existing tests)

### TEST-2: Module tests are unit-level only (MEDIUM)
Module tests create mock servers (good!) but only test happy paths and basic auth failures. Missing:
- Timeout behavior
- Connection reset handling
- Malformed protocol responses
- TLS vs plaintext fallback

### TEST-3: No integration tests (MEDIUM)
No end-to-end tests that run the actual scanner pipeline with a real module against a test server. This would catch bugs in the ParallelHandler → ThreadHandler → Results pipeline.

### TEST-4: ParseTarget fuzz testing opportunity (LOW)
`ParseTarget` handles various formats (IPv4, IPv6, hostname, with/without port). This is an ideal candidate for `go test -fuzz`:
```go
func FuzzParseTarget(f *testing.F) {
    f.Add("192.168.1.1:22")
    f.Add("[::1]:22")
    f.Add("example.com")
    f.Fuzz(func(t *testing.T, input string) {
        ParseTarget(input, 22) // should never panic
    })
}
```

### TEST-5: No benchmarks (LOW)
No `Benchmark*` tests for hot paths (credential generation, result formatting, module handlers). Would help identify performance regressions.

### TEST-6: Main package untestable (MEDIUM)
`main.go` has all logic in global scope with `os.Exit` calls. The `ParseArgs` function can't be tested without running a subprocess. Refactoring into a `cmd` package with injectable dependencies would help.
