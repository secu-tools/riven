# Testing

Five tiers. Unit and fuzz tests live next to the code in `internal/`; the rest
live under `tests/` behind build tags.

```
go test ./... -count=1                             # unit and fuzz seeds
go test -tags integration ./tests/integration/     # library, in process
go test -tags e2e ./tests/e2e/                     # the compiled binary
go test -tags smoke ./tests/smoke/                 # binary starts and answers
go test -tags scripts ./tests/scripts/             # the build scripts, against a copy
./build.sh -testall                                # all five, as the release does
```

## What the tiers cover

- **Unit** (`internal/*/`) -- each package against its own contract: the pipeline
  in every mode, the byte format against [format.md](format.md), padding, the
  transport encodings, key types, the CLI surface, and the stealth properties
  (no constant offsets, uniform bytes, nothing recognisable in a piece).
- **Integration** (`tests/integration/`) -- the library end to end across a matrix
  of content shapes, sizes, thresholds, transports, modes and recording choices,
  including every K-sized subset.
- **End to end** (`tests/e2e/`) -- the compiled binary, driven as a user drives it:
  every algorithm and key type, the export formats and mixed input, text and
  standard input, keygen, completion scripts, the `-y` output contract, and the
  failure paths.
- **Smoke** (`tests/smoke/`) -- the binary starts, answers, and exits correctly.
- **Build scripts** (`tests/scripts/`) -- build.sh and build.ps1, run against a
  copy of the tree: the build number convention, a failed compile, a failed
  package, finding or failing to install nfpm, and `-native` building only this
  host.

Every defect found during development has a regression test naming the original
behaviour (`*/regression_test.go`). Keyless mode is checked from both directions:
a keyless set must open with nothing supplied and must not open when a password is
offered; a password-sealed set must not open without one.

## Fuzzing

Parsers must never panic on hostile input. Targets cover `wire`, `format`,
`cascade`, `core`, `qrcode` and `pieceio`.

```
go test -run "^Fuzz" -count=1 ./internal/...                 # seed corpus only
go test ./internal/format -fuzz "^FuzzDecode" -fuzztime=60s   # active fuzzing
```

## Notes

- Tests use a low-cost Argon2id configuration; production defaults are far
  stronger.
- `go vet ./...` and `gofmt -l .` are expected to be clean, except for the
  vendored `internal/shamir/`, which is left byte-for-byte as upstream.
- Some tests skip where the platform cannot host them, and say so when they do:
  file mode checks on Windows, where access follows inherited ACLs instead;
  creating a symlink or a file name containing a terminal escape, which not every
  filesystem allows; and the completion tests that run a shell, when `bash` is
  not on `PATH`. The other three shells are checked by inspecting the generated
  script, since they cannot be assumed present.
