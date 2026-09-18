# Compilation

Riven is pure Go (no cgo) and builds with Go 1.26 or newer.

## Build

```
go build -o riven ./
```

Or with the helper scripts (they embed the version and bump the build number):

```
./build.sh            # Linux/macOS
./build.sh -native    # just this machine
.\build.ps1           # Windows PowerShell
build.cmd             # Windows CMD (forwards to build.ps1)
```

Binaries are named `riven_<VERSION>.<BUILD>-<OS>-<ARCH>[.exe]`.

## Build Scripts

All three scripts accept the same flags. Run the one for your OS:

| Platform | Command |
|---|---|
| Linux / macOS | `./build.sh [flags]` |
| Windows (PowerShell) | `.\build.ps1 [flags]` |
| Windows (CMD) | `build.cmd [flags]` (forwards to `build.ps1`) |

| Flag | Effect |
|---|---|
| `-windows` / `-linux` / `-darwin` | Select platform(s); combine freely |
| `-amd64` / `-arm64` | Select architecture(s); combine freely |
| `-all` | Build every platform/arch combination |
| `-deb` / `-rpm` | Package linux builds as .deb/.rpm (combine with `-linux`) |
| `-test` | Run unit tests + fuzz seed corpus |
| `-testall` | Run the full suite: unit, fuzz, integration, e2e, smoke |
| `-integration` | Run integration tests (tag: `integration`) |
| `-teste2e` | Run end-to-end tests (tag: `e2e`) |
| `-testsmoke` | Run smoke tests (tag: `smoke`) |
| `-testscripts` | Run the build script tests (tag: `scripts`) |
| `-coverage` | Run tests with a coverage report |
| `-clean` | Remove build artifacts |

Example: `./build.sh -linux -arm64 -deb` builds linux/arm64 and packages it as `.deb`.

> [!NOTE]
> With no flags, all three scripts build windows/amd64 + linux/amd64. Darwin is
> always opt-in (`-darwin` or `-all`). All builds use `CGO_ENABLED=0` (pure Go).

## Cross-compilation

```
./build.sh -all                 # linux + windows + darwin, amd64 + arm64
./build.sh -linux -arm64
./build.sh -windows
./build.sh -native              # just this machine
.\build.ps1 -all
```

Output goes to `build/<os>/`. All builds use `CGO_ENABLED=0 -trimpath` and strip
symbols (`-s -w`).

## Linux packages

`-deb` and `-rpm` package the linux builds; combine them with `-linux` or `-all`:

```
./build.sh -linux -deb -rpm     # both architectures, both formats
./build.sh -linux -arm64 -deb   # just the arm64 .deb
.\build.ps1 -linux -deb -rpm    # same from Windows
```

The packages land next to the binaries in `build/linux/` and install it as
`/usr/bin/riven`. Packaging uses [nfpm](https://github.com/goreleaser/nfpm); if
it is not on `PATH` the scripts run `go install` for it on the spot. nfpm is pure
Go, so a `.deb` or `.rpm` can be built from any of the three platforms. Every
release and beta ships all four (amd64 and arm64, deb and rpm).

## Versioning

- `version/version_base.txt` holds the base semantic version (e.g. `1.0.0`).
- `version/build_number.txt` holds the number the next build takes. A build uses
  it and writes the one after, and a release does the same -- so the number a
  release ships is the one that was in the file when it started, and no two
  releases can carry the same version.
- The version, short git commit, and build number are injected via `-ldflags -X`
  into `internal/app`. Override the base with `VERSION=1.2.3 ./build.sh`, or pin
  the build number with `BUILD_NUMBER=42 ./build.sh`.

## Tests

```
./build.sh -test           # unit + fuzz seed corpus
./build.sh -integration    # library matrix (tag: integration)
./build.sh -teste2e        # drives the built binary (tag: e2e)
./build.sh -testsmoke      # build-and-run sanity (tag: smoke)
./build.sh -testscripts    # the build scripts themselves (tag: scripts)
./build.sh -testall
.\build.ps1 -testall
```

See [testing.md](testing.md) for details.

## Dependencies

All dependencies are pure Go, so `CGO_ENABLED=0` builds work on every target:

- `golang.org/x/crypto` -- Argon2id, ChaCha20-Poly1305, Twofish, BLAKE2b, HKDF
- `golang.org/x/sys` -- memory locking and process hardening
- `golang.org/x/term` -- masked password entry
- `golang.org/x/text` -- Unicode normalization and legacy decoding of passwords
- `github.com/makiuchi-d/gozxing` -- QR encoding and decoding

Recipient key mechanisms come from the standard library: `crypto/hpke` (RFC 9180),
`crypto/mlkem` and `crypto/ecdh`. `crypto/hpke` is why Go 1.26 is the minimum.
`internal/shamir/` is vendored third-party source under MPL-2.0, deliberately left
unformatted and unmodified; `gofmt` checks skip it, and a CI job fails if it drifts
from upstream (see `internal/shamir/UPSTREAM`).

## Install

```
go install github.com/secu-tools/riven@latest
```
