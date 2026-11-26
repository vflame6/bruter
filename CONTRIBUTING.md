# Contributing to bruter

Thanks for helping out. New protocol modules, scan-format parsers and bug fixes
are all welcome.

`bruter` is a tool for authorized security testing. Contributions are expected
to serve that purpose: testing systems you own or have written permission to
test. Pull requests whose only purpose is evading detection or attacking third
parties will be closed.

---

## Development setup

Go **1.26 or newer** is required. The floor comes from the dependency graph —
`golang.org/x/crypto`, `golang.org/x/net`, `google.golang.org/grpc` and the
OpenTelemetry packages all declare `go 1.26.0` — so it cannot be lowered
without pinning older crypto libraries.

```shell
git clone https://github.com/vflame6/bruter.git
cd bruter
go build -o bruter .
```

Run the same checks CI runs before you open a pull request:

```shell
gofmt -l .                  # must print nothing
go vet ./...
go test ./...
golangci-lint run ./...     # config in .golangci.yml
```

CI additionally runs `go test -race ./...`, a 60s fuzz pass over the target
parser, `govulncheck`, and `goreleaser check`. It builds and tests on Linux,
macOS and Windows against the Go floor and current stable.

## Repository layout

| Path | What lives there |
|------|------------------|
| `main.go` | CLI definition (kingpin flags and one command per module) |
| `scanner/` | Scheduling, concurrency, progress, result formatting |
| `scanner/spray.go` | `--spray` scheduling and the per-account attempt budget |
| `scanner/state.go` | `--resume` checkpointing |
| `scanner/modules/` | One file per protocol, plus the `Modules` registry |
| `parser/` | nmap GNMAP/XML, Nessus and Nexpose scan importers |
| `mcpserver/` | `bruter mcp`: MCP tools and the scope allowlist that gates them |
| `utils/` | Dialers, proxy/TLS helpers, DNS, file and string helpers |
| `wordlists/` | Embedded default wordlists (`--defaults`) |
| `skills/bruter/` | Agent skill published for `npx skills add` |
| `tests/` | Docker-based integration scripts, one per module |

---

## Adding a module

A module is one function plus one registry entry. Everything else —
concurrency, retries, proxying, interface binding, progress, output formats —
is handled by the scanner.

### 1. Write the handler

Create `scanner/modules/<name>.go` with a function matching `ModuleHandler`:

```go
func ModuleHandler(
    ctx context.Context,
    dialer *utils.ProxyAwareDialer,
    timeout time.Duration,
    target *Target,
    credential *Credential,
) (bool, error)
```

Always dial through the supplied `dialer` (never `net.Dial` directly) so
`--proxy`, `--iface` and `--timeout` keep working. `scanner/modules/socks5.go`
is a good short reference; `ftp.go` shows TLS auto-detection.

```go
package modules

import (
    "context"
    "time"

    "github.com/vflame6/bruter/utils"
)

// ExampleHandler is an implementation of ModuleHandler for the Example protocol.
func ExampleHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
    conn, err := dialer.DialContext(ctx, "tcp", target.Addr())
    if err != nil {
        return false, err
    }
    defer func() { _ = conn.Close() }()

    _ = conn.SetDeadline(time.Now().Add(timeout))

    // ... speak the protocol, send credential.Username / credential.Password ...

    return authenticated, nil
}
```

**The return contract is the one thing worth getting right:**

| Return | Meaning | Scanner behaviour |
|--------|---------|-------------------|
| `true, nil` | Credentials are valid | Recorded as a hit; honours `-f` / `-F` |
| `false, nil` | Credentials are wrong | Moves to the next pair |
| `_, err` | Transport or protocol failure | Increments the host's error count; the host is abandoned at `--max-retries` |

Returning an error for a rejected password is the most common mistake: it burns
the retry budget and makes `bruter` give up on a perfectly reachable host after
30 wrong guesses.

Other expectations:

- Respect `ctx` cancellation — the handler must return promptly on Ctrl+C.
- Set a deadline from `timeout` on every connection.
- One connection per attempt, closed with `defer`; no package-level state.
- Handlers run concurrently on the same `*Target`. Use `target.SetExtra` /
  `target.GetExtra` for data discovered during probing, never a bare field.
- For protocols that may or may not be wrapped in TLS, use
  `dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)`.

If your module needs a run option that the handler signature does not carry —
the Kerberos modules need a realm, for instance — add it to `scanner.Options`,
attach it in `Scanner.annotateTarget`, and read it in the handler with
`target.GetExtra`. Do not reach for a package-level variable: `all` mode runs
many modules concurrently off copies of the scanner.

### 2. Register it

Add an entry to `Modules` in `scanner/modules/modules.go`:

```go
"example": {
    DefaultPort: 1234, Handler: ExampleHandler,
    DefaultUsername: "admin", DefaultPassword: "admin",
},
```

`DefaultUsername` / `DefaultPassword` are what the help text and the single-pair
smoke path use. Two optional fields add more value than a wordlist ever will:

```go
"example": {
    DefaultPort: 1234, Handler: ExampleHandler,
    DefaultUsername: "admin", DefaultPassword: "admin",

    // --vulns: auth bypasses, reported as findings rather than guesses.
    VulnChecks: []VulnCheck{
        {Name: "no-auth", Handler: ExampleNoAuthHandler, Creds: []Credential{{}}},
    },

    // Vendor defaults tried before the wordlist.
    DefaultCreds: []Credential{
        {Username: "admin", Password: "example"},
    },
},
```

### 3. Wire up the CLI

In `main.go`, add the command next to its alphabetical neighbours and add the
variable to the `_ = []any{...}` slice below the declarations (kingpin registers
on construction; the slice keeps the unused variable alive):

```go
exampleCommand = app.Command("example", "Example protocol module (port 1234)")
```

### 4. Teach the scan importers about it

So that `bruter all -n scan.xml` picks the service up:

- `parser/parser.go` — add every nmap service name that maps to your module to
  `serviceMap` (include TLS variants, e.g. `example` and `examples`).
- `parser/nessus.go` — if Nessus uses a different `svc_name`, normalize it in
  `mapNessusService`.
- `parser/stdin.go` — add the default port to `portServiceMap` for piped
  `fingerprintx` / `naabu` JSON that carries no service name.

### 5. Update the tests

- `scanner/modules/modules_test.go` holds an explicit list of registered
  service names. Add yours.
- `parser/golden_test.go` asserts every `serviceMap` value resolves to a real
  module, so a typo here fails the build rather than silently dropping targets.
- If you extended a sample scan in `parser/testdata/`, regenerate the expected
  output and **read the diff** before committing it:

  ```shell
  go test ./parser -update
  git diff parser/testdata/golden
  ```

### 6. Add an integration script

`tests/<name>.sh`, following the existing pattern: start the service in Docker,
run the module against it, tear the container down.

```shell
#!/bin/bash
docker run -d -p 127.0.0.1:1234:1234 --name example-server some/image
sleep 5
go run . example -t 127.0.0.1:1234 -u tests/usernames.txt -p tests/passwords.txt -D
docker rm -f example-server
```

These are not run by CI (they need live services) but they are how a reviewer
verifies the module actually works. Say in the pull request which script you
ran and what it found.

### 7. Add it to the README

New modules go in the module tables. Protocols that are unusual for a
credential testing tool go in the first table, the rest in the second.

---

## Pull requests

- One logical change per pull request.
- `gofmt -l .` prints nothing; `go vet`, `go test ./...` and `golangci-lint run`
  are clean.
- Describe how you tested it. For a module, that means the service you ran it
  against.
- Protocol quirks and magic byte sequences deserve a comment with a reference
  (RFC number, vendor doc). Future readers will not re-derive them.

## Releases

Maintainers only. Pushing a tag runs `.github/workflows/release.yml`, which
builds 8 platform archives, `.deb` / `.rpm` / `.apk` / Arch packages, and
updates the Homebrew tap.

### Homebrew tap

There is no setup and no extra repository: **this repo is the tap.** Each
release commits the generated `Casks/bruter.rb` to `main` here, using the
workflow's own `GITHUB_TOKEN`, so no personal access token is involved.

That file is generated. Do not edit it by hand; change the `homebrew_casks`
block in `.goreleaser.yaml` instead.

The trade-off is on the user's side. Homebrew's short form

```shell
brew tap vflame6/tap        # expands to github.com/vflame6/homebrew-tap
```

always prepends `homebrew-` to the repository name, so reaching a tap that is
not named that way means giving the URL once:

```shell
brew tap vflame6/bruter https://github.com/vflame6/bruter
brew trust vflame6/bruter
brew install bruter
```

`brew trust` is unavoidable: Homebrew will not load a formula or a cask from a
non-official tap without it, whatever the tap is named.

Moving to a one-command `brew install vflame6/tap/bruter` would mean creating
a `vflame6/homebrew-tap` repository and a PAT with `contents: write` on it,
because `GITHUB_TOKEN` cannot push to a second repository.

The tap ships a cask rather than a formula, which is what GoReleaser supports
now that `brews` is deprecated. Homebrew installs casks on macOS only; Linux
users are served by the `.deb`, `.rpm`, `.apk` and Arch packages.
