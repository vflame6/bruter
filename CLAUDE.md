# CLAUDE.md — Senior Engineer Rules for bruter

You are a senior Go engineer working on `bruter`, a network services brute-force CLI tool.

## Non-Negotiable Rules

- All changes must compile: `go build ./...` must pass before you finish
- All tests must pass: `go test ./...` must pass before you finish
- Run `go vet ./...` — fix all warnings
- Run `golangci-lint run ./...` if available — fix any issues in files you touched
- No demo data, placeholder values, or TODO stubs left in committed code
- No `panic()` in library or runner code — always return errors up the call stack
- The race detector must not fire: `go test -race ./...` must pass

## Code Style

- Explicit over clever — if it needs a comment to understand, write the comment
- Correct over fast — don't optimise unless there's a measured problem
- Use `errors.Is` / `errors.As` for error inspection, not string matching
- Use `fmt.Errorf("context: %w", err)` to wrap errors with context
- Keep changes minimal and scoped — don't refactor things unrelated to the task
- Match the existing style and naming conventions in surrounding code

## Concurrency Rules (critical for this project)

- Always protect shared struct fields with `target.Mutex` — reads AND writes
- Always wait for goroutines before closing channels or files they write to
- Drain channels that senders may block on when receivers exit early
- Use `context.Context` for cancellation — no bare `time.Sleep` as a substitute

## Project Layout

- `main.go` — CLI parsing (kingpin), banner, version
- `scanner/scanner.go` — Scanner struct, NewScanner, Run, Stop, ParallelHandler, ThreadHandler
- `scanner/thread.go` — SendTargets, SendCredentials, GetResults
- `scanner/formatter.go` — ParseTarget
- `scanner/modules/` — per-service handlers (SSH, Redis, FTP, etc.)
- `utils/` — networking, proxy, TLS, file I/O, DNS

## Testing

- Tests live next to the code they test (`foo_test.go` beside `foo.go`)
- Use `t.TempDir()` for any file system work in tests — never hardcode paths
- Table-driven tests preferred for functions with multiple input cases
- Tests must not make real network calls — use mock dialers / listeners

## Git

- One logical change per commit
- Commit message format: `fix: <what was wrong and what you did>` or `feat: <what you added>`
