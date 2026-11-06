# Riven

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI](https://github.com/secu-tools/riven/actions/workflows/ci.yml/badge.svg)](https://github.com/secu-tools/riven/actions/workflows/ci.yml)
[![Build](https://github.com/secu-tools/riven/actions/workflows/build.yml/badge.svg)](https://github.com/secu-tools/riven/actions/workflows/build.yml)
[![CodeQL](https://github.com/secu-tools/riven/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/secu-tools/riven/actions/workflows/github-code-scanning/codeql)
[![Dependency Graph](https://github.com/secu-tools/riven/actions/workflows/dependabot/update-graph/badge.svg)](https://github.com/secu-tools/riven/actions/workflows/dependabot/update-graph)

> [!WARNING]
> **Testing phase, not a final release.** Every effort is made to keep your data
> recoverable, but that can only be promised for the *same build*: a later
> version, or a different build of the same version, may not open pieces written
> today.
>
> Every piece records the program version and commit hash that wrote it, and
> `riven info PIECE` prints them, so you can find the matching binary or check
> out that commit and build it. Those fields sit inside the sealed metadata, so
> `info` can only read them while the piece still opens with your password or key --
> **run it once now and keep the output**, rather than counting on it after
> something has gone wrong. Keeping a copy of the binary you split with is the
> one measure that always works.
>
> Keep an independent backup of anything important, test your recovery before you
> rely on it, and re-split after upgrading. More testing is welcome.

Split a file into several pieces so that any **K of N** of them, plus the
correct password(s), rebuild the original -- and fewer than K reveal nothing.
Pieces are cascade-encrypted, quantum-resistant, and indistinguishable from
random data.

- **Shamir secret sharing** -- choose how many pieces exist (N) and how many are
  needed (K). Below K, a piece tells you nothing about the content.
- **[Two methods](docs/usage.md#method)** -- `full` (the default, and the safer)
  makes each piece a share of the whole file, so fewer than K reveal nothing,
  and that is mathematically proven. `compact` makes each piece about 1/K of the
  file, for large files and QR codes; below K it relies on the encryption
  (AES-256 and ChaCha20) holding.
- **[Layers](docs/usage.md#layers)** -- protect the content with one password,
  or stack several layers, each keyed by a password or by someone's public key,
  so two people must cooperate. Or use [no password at
  all](docs/usage.md#split-only-with-no-password) and let the threshold be the
  only protection.
- **[Files or text](docs/usage.md#what-to-split)** -- split a file, a string, or
  whatever another program pipes in; recover it to a file or straight to
  standard output for the next command. The file's name travels inside the
  encrypted metadata, so a reconstruction restores it.
- **[Post-quantum](docs/usage.md#keygen)** -- 256-bit symmetric keys with
  Argon2id, plus recipient key layers built on the standard library's HPKE (RFC
  9180): X-Wing (ML-KEM-768 with X25519) by default, or ML-KEM-768/1024, X25519,
  P-256, P-384. Usable alongside passwords or on their own, so a recipient needs
  only their private key.
- **[Six transport formats](docs/usage.md#export-formats)** -- a binary file,
  base64 for messengers, base32 for copying by hand, BIP-39 words for writing
  out by hand, a QR code image, or a printable recovery sheet. Formats can be
  mixed when reconstructing, and the text formats carry a checksum so a typo is
  reported as such.
- **Stealth** -- a piece has no header, magic bytes, or extension signature; it
  looks like random noise unless you have the password or key that opens it
  (or, for `--info public` and `none`, the tool; see [what one piece
  shows](docs/usage.md#what-one-piece-shows)).
  [Padding](docs/usage.md#piece-size) rounds every piece up to a size class, so
  its length gives only a range.
- **[Wizard](docs/usage.md#the-wizard)** -- run `riven <file>` and answer a few
  questions (Enter takes the default). Everything the wizard asks can also be
  passed as a flag, so any workflow can be fully automated.
- **[Tab completion](docs/usage.md#completion)** --
  `riven completion bash|zsh|fish|powershell`, generated from the parser's own
  flag tables so it cannot fall behind.

## Install

```
go install github.com/secu-tools/riven@latest
```

Or take a binary from the [releases page](https://github.com/secu-tools/riven/releases)
-- Linux, Windows and macOS, amd64 and arm64. Linux also gets `.deb` and `.rpm`
packages, which install the binary as `/usr/bin/riven`:

```
sudo dpkg -i riven_<version>-linux-amd64.deb
sudo rpm -i riven_<version>-linux-amd64.rpm
```

Or build from source (Go 1.26+):

```
go build -o riven ./       # or: ./build.sh -native / .\build.ps1 -native
```

## Quick start

Split a file. The wizard asks a handful of questions; press Enter for defaults:

```
riven secret.pdf
```

Reconstruct from any K pieces:

```
riven combine secret.pdf.1 secret.pdf.3 secret.pdf.5
```

Split a string instead of a file, and get it back exactly:

```
riven split --text "123456" -n 3 -k 2 --password-env PW --out ./pieces -y
CODE=$(riven combine pieces/secret.1 pieces/secret.2 --password-env PW -y)
```

Split with no password at all, so any K pieces are enough on their own:

```
riven split secret.pdf -n 5 -k 3 --keyless -y
riven combine secret.pdf.1 secret.pdf.3 secret.pdf.4 -y > recovered.pdf
```

Inspect a single piece (needs the first layer's password, or its key with
`--identity`, unless the set was split with `--info public`):

```
riven info secret.pdf.2
```

Riven splits one file. To split a directory, pack it into an archive first
([why compressing pays](docs/usage.md#splitting-a-directory)):

```
tar -czf wallet.tar.gz ./wallet
riven split wallet.tar.gz -n 5 -k 3 --password-env PW -o ./pieces -y
```

`combine`, `verify` and `info` all take a folder in place of the pieces: files in
it that are not pieces are ignored, and one piece exported in several formats is
counted once.

```
riven combine ./pieces --password-env PW -y > recovered.tar.gz
```

Generate a post-quantum recipient key pair:

```
riven keygen
```

Pieces in different formats can be combined together, since the format is read
from the content:

```
riven combine piece.1 piece.2.png piece.3.txt
```

Turn on tab completion:

```
source <(riven completion bash)        # or zsh, fish, powershell
```

## Scripting

Every question has a flag, and `-y` never prompts: it uses defaults and fails
instead of asking. Passwords come from environment variables so they never touch
disk or appear in the process list.

```
export RIVEN_PW1=... RIVEN_PW2=...

riven split secret.pdf -n 5 -k 3 \
  --algo chacha20-poly1305,aes-256-gcm \
  --password-env RIVEN_PW1 --password-env RIVEN_PW2 \
  --format all --out ./pieces -y

riven combine pieces/secret.pdf.1 pieces/secret.pdf.2.png pieces/secret.pdf.3.txt \
  --password-env RIVEN_PW1 --password-env RIVEN_PW2 --out recovered.pdf -y
```

See [docs/usage.md](docs/usage.md) for all flags.

## How the pieces are protected

The input is cascade-encrypted, the ciphertext is split into N shares, and each
share is sealed in an authenticated envelope. Rebuilding needs **K pieces AND
every password** (AND every recipient private key, if any were used). A single
piece shows at most its own details -- which piece it is, how many are needed,
whether it is intact -- never the content.

Two consequences worth knowing before you start:

- **A leaked password alone is worthless.** Without K pieces there is nothing the
  password can decrypt. K pieces without the password are equally useless.
- **Each piece is about the size of the whole input**, not `size / N`, so N
  pieces cost roughly N times the original. A 1 GB file into 5 pieces writes five
  ~1 GB files. That is what makes fewer than K pieces reveal nothing.
  `--method compact` trades that for pieces of about 1/K of the input; the
  [method](docs/usage.md#method) section says what it gives up.

## Security notes

- Choose strong passwords, or let Riven generate them (`--generate`, or press
  Enter at the prompt). A generated password is shown once and stored nowhere
  else: it is the **only** way to recover your data
  ([passwords](docs/usage.md#passwords)).
- Store pieces and passwords separately. Losing more than N-K pieces, or any
  password, makes the data unrecoverable by design.
- Plan for the memory: a split holds the shares at once, so it needs roughly
  `(N+2)` times the input, or about 3 times with `--method compact`
  ([large inputs](docs/usage.md#large-inputs)).
- Passwords are held in locked memory that stays out of swap, and are wiped on
  exit, on Ctrl-C, and on panic. Keys, plaintext and shares are zeroed as soon as
  they are done with, but are not pinned: they can be gigabytes. Core dumps are
  disabled.
- What a leaked piece or a leaked password is worth, and what is not covered:
  [docs/faq.md](docs/faq.md#security) and [SECURITY.md](SECURITY.md).

## Documentation

- [docs/usage.md](docs/usage.md) -- commands, every flag, and what each choice
  trades
- [docs/faq.md](docs/faq.md) -- short answers: size, formats, what a leaked piece
  is worth
- [SECURITY.md](SECURITY.md) -- what Riven claims, what it does not, and how to
  report a break
- [docs/format.md](docs/format.md) -- byte-level piece format
- [docs/compilation.md](docs/compilation.md) -- building and cross-compiling
- [docs/testing.md](docs/testing.md) -- running the test suites
- [docs/sample-sheet.html](docs/sample-sheet.html) -- a real printable recovery sheet

## License

MIT -- see [LICENSE](LICENSE). One vendored component
(`internal/shamir/`) is MPL-2.0; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
