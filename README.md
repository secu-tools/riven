# Riven

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](go.mod)

> [!WARNING]
> **Testing phase, not a final release.** Every effort is made to keep your data
> recoverable, but that can only be promised for the *same build*: a later
> version, or a different build of the same version, may not open pieces written
> today.
>
> Every piece records the program version and commit hash that wrote it, and
> `riven info PIECE` prints them, so you can find the matching binary or check
> out that commit and build it. Those fields sit inside the sealed metadata, so
> `info` can only read them while the piece still opens with your password --
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
- **Layers** -- protect the content with one password, or stack several layers,
  each keyed by a password or by someone's public key, so two people must
  cooperate. Or use no password at all and let the threshold be the only
  protection.
- **Files or text** -- split a file, a string, or whatever another program pipes
  in; recover it to a file or straight to standard output for the next command.
  The file's name travels inside the encrypted metadata, so a reconstruction
  restores it.
- **Post-quantum** -- 256-bit symmetric keys with Argon2id, plus recipient key
  layers built on the standard library's HPKE (RFC 9180): X-Wing (ML-KEM-768 with
  X25519) by default, or ML-KEM-768/1024, X25519, P-256, P-384. Usable alongside
  passwords or on their own, so a recipient needs only their private key.
- **Six transport formats** -- a binary file, base64 for messengers, base32 for
  copying by hand, BIP-39 words for writing out by hand, a QR code image, or a
  printable recovery sheet. Formats can be mixed when reconstructing, and the text
  formats carry a checksum so a typo is reported as such.
- **Stealth** -- a piece has no header, magic bytes, or extension signature; it
  looks like random noise unless you have the password. Padding rounds every
  piece up to a size class, so its length gives only a range.
- **Wizard** -- run `riven <file>` and answer a few questions (Enter takes the
  default). Everything the wizard asks can also be passed as a flag, so any
  workflow can be fully automated.
- **Tab completion** -- `riven completion bash|zsh|fish|powershell`, generated
  from the parser's own flag tables so it cannot fall behind.

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
go build -o riven ./       # or: make build / ./build.sh / .\build.ps1
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

Inspect a single piece (needs the password):

```
riven info secret.pdf.2
```

Riven splits one file. To split a directory, pack it into an archive yourself
first, with whatever compression you prefer -- every piece is a full copy of the
input, so a smaller archive means N smaller pieces:

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

Turn on tab completion:

```
source <(riven completion bash)        # or zsh, fish, powershell
```

## Export formats

Each piece can be written as any combination of:

| Format | File | Size | Use |
|--------|------|------|-----|
| binary | `secret.pdf.1` | 1.0x | default; smallest |
| base64 | `secret.pdf.1.txt` | 1.4x | paste into a messenger, or print |
| base32 | `secret.pdf.1.b32.txt` | 2.0x | copy by hand; one case, grouped in fours |
| words | `secret.pdf.1.words.txt` | 4.7x | write out by hand as BIP-39 words; up to 4096 bytes per piece |
| qr | `secret.pdf.1.png` | n/a | scan from paper; holds up to 2952 bytes per piece |
| sheet | `secret.pdf.1.html` | n/a | print: QR code, text and instructions on a page |

`words` is by far the largest form and exists only for a small secret that has to
be transcribed by a person; use `base32` for anything else. The export menu marks
a format the pieces are too large for, and states what each one costs -- the word
count, or the number of printed pages -- before you pick it.

QR error correction is chosen automatically: the strongest level that still
fits, so small pieces tolerate ~30% damage and only near-capacity pieces drop to
the weakest level (which Riven warns about, since it matters when printing).

When reconstructing, the input format is detected from the content, so pieces can
be mixed freely:

```
riven combine piece.1 piece.2.png piece.3.txt
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
piece with the password shows only its own metadata -- which piece it is, how
many are needed, whether it is intact -- never the content.

Two consequences worth knowing before you start:

- **A leaked password alone is worthless.** Without K pieces there is nothing to
  decrypt, at any computational cost, now or against a quantum attacker. K pieces
  without the password are equally useless.
- **Each piece is about the size of the whole input**, not `size / N`, so N
  pieces cost roughly N times the original. A 1 GB file into 5 pieces writes five
  ~1 GB files. That is what makes fewer than K pieces reveal nothing.

Every piece of a set is the same size, and splitting the same input again gives
that size again. `--pad` sets how coarse the size class is: 5 percent by default,
up to 500 for a vaguer answer, or `none` for exact sizes.

Each piece records the algorithms, the Argon2id cost and the input file's name by
default, so the password is all you need and `combine` offers the original name
back. It is offered rather than used unasked, because the name came from whoever
wrote the pieces. Withhold any of them (`--record-algo false`, `--record-kdf false`,
`--record-name false`) and the first two become a second secret to supply with
`--algo` or `--kdf`.

`--keyless` uses no password: any K pieces rebuild the file, fewer than K reveal
nothing about the content.

Its metadata is readable, by design. There is no password to ask for, so
`riven info` on a single piece tells you what it is: which set it belongs to,
which piece it is, how many more you need, and the original file name. That is
the point -- a keyless piece found later is identifiable rather than an anonymous
blob of noise. The payload hash is readable for the same reason, so someone who
can already guess the file exactly can confirm the guess.

A keyless set is also unauthenticated: substituted pieces rebuild without
complaint. This is not a gap that can be closed. Authentication needs a secret
the attacker does not have, and keyless means you hold none -- a key built into
Riven would be in the source and in every binary, so it would authenticate
nothing. One password layer gives both encryption and authentication; that is
the fix when you need it.

Layers stack in any order, each keyed by a password or a recipient key:

```
riven split board.pdf -n 4 -k 2 --password-env PW --recipient alice.pub --recipient bob.pub -y
```

That needs the password and both private keys.

## Security notes

- Choose strong passwords, or let Riven generate them (`--generate`, or press
  Enter at the prompt). Generated passwords are shown once, and under `-y` are
  printed to standard output one per line -- they are the **only** way to recover
  your data, and are stored nowhere else.
- Passwords may be in any language: a password is read as UTF-8 and normalized
  (NFC) before use, so the same characters open the pieces however they are typed.
- Store pieces and passwords separately. Losing more than N-K pieces, or any
  password, makes the data unrecoverable by design.
- Plan for the storage: N pieces take about N times the size of the original.
- Plan for the memory too: a split holds the shares at once, so it needs roughly
  `(N+3)` times the input size. See
  [docs/usage.md](docs/usage.md#large-inputs) for what to do about a large file.
- Passwords are held in locked memory that stays out of swap, and are wiped on
  exit, on Ctrl-C, and on panic. Keys, plaintext and shares are zeroed as soon as
  they are done with, but are not pinned: they can be gigabytes. Core dumps are
  disabled.
- A single leaked piece is worth nothing: below K it reveals nothing about the
  content, which is a property of Shamir secret sharing rather than of this tool.
  More in [docs/faq.md](docs/faq.md#security).

## Documentation

- [docs/faq.md](docs/faq.md) -- size, formats, what a leaked piece is worth
- [docs/usage.md](docs/usage.md) -- commands and every flag
- [docs/format.md](docs/format.md) -- byte-level piece format
- [docs/compilation.md](docs/compilation.md) -- building and cross-compiling
- [docs/testing.md](docs/testing.md) -- running the test suites
- [docs/sample-sheet.html](docs/sample-sheet.html) -- a real printable recovery sheet

## License

MIT -- see [LICENSE](LICENSE). One vendored component
(`internal/shamir/`) is MPL-2.0; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
