# Usage

Riven has six commands: `split`, `combine`, `verify`, `info`, `keygen`, and
`completion`. With no command and a file argument, `riven <file>` runs the split
wizard. With no arguments on a terminal it shows a menu.

Every wizard question is skipped when the answer is supplied on the command line,
and every flag has a matching wizard question. `-y` (`--yes`) takes defaults for
anything still unanswered and never prompts: if a required value is missing it
fails with a message naming the flag to use.

Messages fold to the width of the window. On a terminal, errors, warnings and
finished steps are coloured; the words say the same without it. Colour is left
out when the output goes to a file or a pipe, when `NO_COLOR` is set, when
`TERM=dumb`, and with `--no-color`.

## What to split

The data can come from three places:

```
riven split FILE               # a file
riven split -                  # standard input (needs -y)
riven split --text "123456"    # a string given on the command line
riven split --text-env NAME    # a string taken from an environment variable
```

`--text` is visible in the process list, so prefer `--text-env` or standard input
for anything sensitive. Pieces take the input file's name; text and standard input
default to `secret`, which `--name BASE` overrides.

### Splitting a directory

Riven splits one file. To split a directory, pack it into an archive yourself
first:

```
tar -czf wallet.tar.gz ./wallet     # or zip, 7z, whatever you already use
riven split wallet.tar.gz -n 5 -k 3 --password-env PW -o ./pieces -y
```

The archive format and the compression are yours to choose. Compress if you can:
every piece is as large as the input (1/K of it with `--method compact`), so
halving the archive halves all N of them, and the memory a split needs with it
(see [Large inputs](#large-inputs)).

## How a split is protected

Riven offers three ways to protect a split. Pick one:

| Mode | What you need to rebuild the file | Use it when |
|------|-----------------------------------|-------------|
| password (default) | K pieces and the password | the normal case |
| layers | K pieces plus every password and recipient key you chose | several people or factors must take part |
| `--keyless` | K pieces, nothing else | the threshold alone is the protection |

In all three, fewer than K pieces reveal nothing about the content.

### Layers

A split can be wrapped in several layers, applied outermost first. Each layer is
keyed either by a password or by a recipient's public key, and **all** of them are
needed to rebuild the file. The order of the `--password-env` and `--recipient`
flags is the order of the layers:

```
riven split board.pdf -n 4 -k 2 \
  --password-env CHAIR_PW \
  --recipient alice.pub \
  --recipient bob.pub \
  --password-env SECRETARY_PW -y
```

That produces four layers: a password, Alice's key, Bob's key, another password.
Alice and Bob must both take part, and both passwords are needed too. Two
recipients on their own, with no password, is the way to require two people to
cooperate and nothing else:

```
riven split deal.pdf -n 3 -k 2 --recipient alice.pub --recipient bob.pub -y
riven combine deal.pdf.1 deal.pdf.2 --identity alice.key --identity bob.key -y
```

`--algo` names the algorithm per layer, positionally. Unnamed layers take
AES-256-GCM, XChaCha20-Poly1305 and Twofish-256-GCM in turn, three different
designs, skipping one that shares a design with the layer above. Neighbouring
layers may not share an algorithm, so a weakness in one does not carry through
the cascade.

```
--algo chacha20-poly1305,aes-256-gcm,xchacha20-poly1305,twofish-256-gcm
```

### Split only, with no password

`--keyless` writes pieces with no encryption and no password. Any K pieces rebuild
the file; fewer reveal nothing. K must be at least 2. The trade-offs:

- **Anyone who gathers K pieces succeeds.** The threshold is the only lock.
- **A piece says what it is.** With no password to ask for, `riven info` on one
  piece shows which set it belongs to, which piece it is, how many more are needed
  and the original file name, so a piece found later is identifiable rather than
  an anonymous blob of noise. `--info none` hides that. Either way the content and
  its exact length stay unreadable, and one piece cannot even confirm a guess of
  the content.
- **Nothing authenticates the set.** Substituted pieces rebuild without complaint.
  That cannot be fixed without a secret: a key built into Riven would be in the
  source and in every binary, so it would authenticate nothing. One password layer
  gives both encryption and authentication.

### Method

Many secret-sharing tools encrypt the file, split only the key, and put the whole
encrypted file in every piece, so one piece holds everything an attacker needs
except the key. Riven spreads the encrypted file itself over the pieces, in one of
two ways, chosen with `--method`:

| | `full` (default) | `compact` |
|---|---|---|
| Each piece holds | a share of the whole encrypted file | a share of the keys, and 1/K of the encrypted file |
| Piece size | the whole file | about 1/K of the file |
| Fewer than K pieces | reveal nothing: mathematically proven | reveal nothing while AES-256 and ChaCha20 stay unbroken |
| K pieces | as strong as your passwords and keys | the same |

`full` is the safer method. Fewer than K of its pieces hold no ciphertext at all,
only shares that fit every possible content equally well, so no computer and no
future attack, quantum ones included, can read anything from them. Use it whenever
the file is small enough, which is most secrets.

`compact` trades that proof for size. Use it for large files, or to fit a QR code:
a 3-of-5 set of a 6,000 byte file gives pieces of about 2,350 bytes instead of
6,300.
The content is sealed under two fresh random keys with different ciphers,
AES-256-GCM then XChaCha20-Poly1305, and an all-or-nothing transform, then cut
into N fragments, any K of which rebuild it; only the keys are Shamir-shared. A
partial set has neither the keys nor the whole of the sealed data, so reading it
would take breaking both ciphers.

Both methods work with or without a password: your password and key layers, if
any, still go on underneath.

### What one piece shows

`--info` decides who can read a piece's details: which piece it is, how many are
needed, the layers and the file name. The Argon2id cost stays readable, because
a password is stretched before anything opens; only `--record-kdf false` or
`none` keeps it off a piece.

| `--info` | Details readable by | One stolen piece can be used to try passwords |
|---|---|---|
| `protected` (default) | whoever holds the first layer's password or private key | the first layer's, if it is a password |
| `strict` | whoever holds every password and private key the set takes | only all of them at once, and only with every key |
| `public` (default with `--keyless`) | anyone with Riven | no |
| `none` | nobody: `info` shows only the set id | no |

`protected` asks for one secret, the one the first `--password-env` or
`--recipient` names, so its holder can tell what a piece is without the others.
`strict` asks for everything rebuilding asks for. Details sealed to a private key
cost each piece one more encapsulated key (see [keygen](#keygen)).

Where one piece can be used to try passwords, each guess costs one Argon2id
derivation, and a correct one gives the details, not the content, which still
needs K pieces and the other layers. A generated password makes this moot.

`public` helps recovery: a piece found later says what it is and which build
wrote it. `none` gives nothing away, so `verify` cannot say how many pieces a
short set still needs, and recovery sheets leave out the piece number, the counts
and the file name. It needs `-k 2` or more: at `-k 1` every piece is the whole
set.

### What each piece records

Each piece records the algorithms, the Argon2id cost and the input file's name by
default, so the password is all you need and `combine` offers the original name
back. It is offered rather than used unasked, because the name came from whoever
wrote the pieces (see [Where the recovered file is
written](#where-the-recovered-file-is-written)). Withhold any of them with
`--record-algo false`, `--record-kdf false` or `--record-name false`; the first
two then have to be supplied with `--algo` or `--kdf` when combining. That adds
little secrecy: there are only 256 possible costs, and the default algorithms are
the first an attacker would try.

## split

```
riven split FILE [options]
riven FILE                     # same thing via the wizard
```

| Flag | Meaning | Default |
|------|---------|---------|
| `-n, --parts N` | total pieces to create | 5 |
| `-k, --threshold K` | pieces required to reconstruct (1..N) | 3 |
| `--password-env NAME` | add a password layer, read from environment `NAME` | one password layer |
| `--recipient FILE` | add a recipient layer using that public key | none |
| `--algo a,b,c` | algorithm per layer, in order | chosen automatically |
| `--keyless` | no encryption and no password (see [Split only](#split-only-with-no-password)) | off |
| `--method full\|compact` | how the content is spread over the pieces (see [Method](#method)) | `full` |
| `--info protected\|strict\|public\|none` | who can read a piece's details (see [What one piece shows](#what-one-piece-shows)) | `protected`, or `public` with `--keyless` |
| `-f, --format LIST` | `binary`, `base64`, `base32`, `qr`, `sheet`, `words`, `all`, or a comma-separated subset | `binary` |
| `--qr-scale N` | QR module size in pixels | 8 |
| `--kdf SPEC` | Argon2id cost: a preset name or `m=<MiB>,t=<passes>,p=<lanes>` | `recommended` |
| `--record-algo true\|false` | write the algorithms into each piece (see [What each piece records](#what-each-piece-records)) | `true` |
| `--record-kdf true\|false` | write the Argon2id cost into each piece | `true` |
| `--identity FILE` | your private key, so the split can be fully verified | none |
| `--pad PCT` | class width in whole percent; `0` or `none` drops the size class (see [Piece size](#piece-size)) | `1` |
| `--verify true\|false` | re-read the pieces and rebuild the original before reporting success (`-v` alone turns it on, `--no-verify` off) | `true` |
| `--generate` | generate strong password(s) instead of prompting | off |
| `-t, --text STRING` | split this string instead of a file | none |
| `--text-env NAME` | split the contents of an environment variable | none |
| `--record-name true\|false` | write the input file's name into each piece | `true` |
| `--name BASE` | base name for the piece files (not the content) | input file name, or `secret` |
| `-o, --out DIR` | output directory for pieces | the input file's directory |
| `-y, --yes` | non-interactive; defaults, no prompts | off |

Pieces are written as `FILE.1`, `FILE.2`, ..., zero-padded to the width of N
(`FILE.01` from ten pieces up), plus the extension for each format (see [Export
formats](#export-formats)).
If files with those names already exist, Riven asks before replacing them, since
they are probably an earlier set; under `-y` they are replaced.

By default Riven re-reads K pieces and reconstructs to confirm the split is
recoverable before reporting success; `--no-verify` skips this.

### The wizard

The wizard asks only what matters for a normal split: how many pieces, how many are
needed, a password, the export format, and where to write. Everything else sits
behind one question:

```
Security:
  1) recommended: encrypt with one password (aes-256-gcm)
  2) advanced: several layers, each a password or a recipient key
  3) no encryption: split only, no password, any K pieces rebuild the file
```

Option 2 then asks, for each layer, whether it is keyed by a password or a
recipient key, which algorithm to use, and where the password or key comes from. It
can generate a key pair on the spot if you do not have one. After the layers it
asks the method, what one piece shows, what to record, the Argon2id cost, and the
size padding. Passing any of those as a flag skips the matching question. The
recommended option asks none of them and uses the defaults. When a password is
already given with `--password-env`, option 3 is not offered, since it would
drop that password.

## combine

```
riven combine PIECE... [options]
riven combine DIR [options]
```

| Flag | Meaning |
|------|---------|
| `--password-env NAME` | read a password from environment `NAME`; repeat once per password layer, in order |
| `--identity FILE` | your recipient private key; repeat once per recipient layer, in any order |
| `--algo a,b,c` | algorithms, required for sets split with `--record-algo false` |
| `--kdf SPEC` | Argon2id cost, required for sets split with `--record-kdf false` |
| `-o, --out FILE` | where to write the recovered data; `-` means standard output |
| `-y, --yes` | non-interactive |

The input format is detected from the content, so binary pieces, base64 text, and
QR images can be mixed in one command.

A directory may be given instead of the pieces. The files directly inside it are
read (it does not descend into subdirectories), anything that is not a piece is
ignored, and a piece exported in several formats is counted once. That last part
matters: opening a piece costs a full key derivation, so a folder written with
`--format all` would otherwise cost six times what it should.

```
riven combine ./pieces --password-env PW --out recovered.pdf -y
```

Keyless sets need no password and are opened without asking for anything. A set
split with `--info public` or `--info none` opens without a password too, then
asks for exactly as many as its layers need; under `-y` it names
`--password-env` instead. So does a set whose details are sealed to a recipient
key alone, once `--identity` has opened it. At the prompt, the first password
alone opens a protected set, and the rest are then asked for. Private keys can be
given in any order: Riven works out which layer each one belongs to.

A damaged piece is skipped with a warning when enough intact pieces remain, so a
spare piece is worth keeping.

When a set omitted its algorithms or cost, an interactive run asks for them, once
each, at the point the set turns out to need them; with `-y` it fails and names
the flag instead. Each piece is opened once whatever is asked. A run with no
`--password-env` tries every piece without a password first and asks only if some
piece needs one; when some pieces open without a password and others do not, it
says so, and Enter alone means the set has none.

### Where the recovered file is written

`combine` has to put the rebuilt data somewhere:

```
riven combine p.1 p.2 -o recovered.pdf     # into a file you name
riven combine p.1 p.2 -o -                 # to standard output
riven combine p.1 p.2 -y                   # to standard output (the -y default)
riven combine p.1 p.2                      # the recorded file name, or it asks
```

Unless `--out` says otherwise, an interactive run writes to the name the pieces
recorded, and asks before replacing an existing file. Pieces split with
`--record-name false`, or from text or standard input, carry no name, and it asks
for one. Under `-y` the result always goes to standard output whatever was
recorded, so the scripting contract does not change.

Only you can read the recovered file, even when it replaces a file others could
read. On Windows it takes the folder's permissions instead. If recovery fails,
nothing is written and an existing file is left as it was.

When it goes to standard output, the bytes are written exactly as they were, with
nothing added and no trailing newline, and every message goes to standard error
instead. That is what makes the result usable by the next program:

```
export RIVEN_PW=...
CODE=$(riven combine code.1 code.2 --password-env RIVEN_PW -y)
riven combine key.1 key.2 --password-env RIVEN_PW -y | gpg --import
```

## verify

```
riven verify PIECE... [options]
riven verify DIR [options]
```

Answers one question: will these pieces rebuild the file? It reads every piece,
groups them by set, and where a set has enough distinct pieces it rebuilds in
memory and checks the result against the recorded hash. Nothing is written.

It takes the same password, `--algo`, `--kdf` and `--identity` flags as `combine`.

```
riven verify pieces/* --password-env RIVEN_PW
riven verify ./pieces  --password-env RIVEN_PW    # the folder, on any shell
```

A set that is short of the threshold is reported with the number still needed,
which is the point of running it. A set split with `--info none` hides that
number, so it is only reported as short. A piece that is damaged, or that belongs
to another set, is named.

## info

```
riven info PIECE... [options]
riven info DIR [options]
```

Takes the same password, `--algo`, `--kdf`, and `--identity` flags as `combine`.
Opens each piece and prints the transport form it detected, the set id, which piece
it is and how many are needed, whether it is intact, the method, the recorded
file name if there is one, the layers (when recorded), and the Argon2id cost.
Passing several pieces also groups them by set. No content is revealed.

A `protected` piece needs its first layer's password or `--identity` key, and a
`strict` one every password and key its set takes. One split with `--info public`
needs none of them. One split with `--info none` shows its set id and nothing
else, with or without them.

## keygen

```
riven keygen [TYPE] [--pub FILE] [--priv FILE] [-o DIR] [-y]
```

Writes a recipient key pair of the given type. Share the `.pub` with senders; keep
the `.key` secret. Use `--recipient <pub>` when splitting and `--identity <key>`
when combining or inspecting.

`--pub` and `--priv` name exact paths. `-o` sets the directory for whichever of
the two riven names itself, and is refused when both are given explicitly.

The type is the argument after the command:

```
riven keygen                 # x-wing, the default, into the current directory
riven keygen -o ./keys       # riven-key.pub and riven-key.key under ./keys
riven keygen x25519 --pub alice.pub --priv alice.key -y
```

| Type | Post-quantum | Public key | Added to every piece | When the details are sealed to it too |
|------|--------------|------------|----------------------|---------------------------------------|
| `x-wing` (default) | yes, plus classical | 1216 bytes | 1120 bytes | 2240 bytes |
| `ml-kem-768` | yes | 1184 bytes | 1088 bytes | 2176 bytes |
| `ml-kem-1024` | yes | 1568 bytes | 1568 bytes | 3136 bytes |
| `x25519` | no | 32 bytes | 32 bytes | 64 bytes |
| `p256` | no | 65 bytes | 65 bytes | 130 bytes |
| `p384` | no | 97 bytes | 97 bytes | 194 bytes |

`x-wing` (ML-KEM-768 with X25519) holds as long as either of them does. Use it
unless you have a reason not to. The `ml-kem-*` types are post-quantum only;
`x25519`, `p256` and `p384` are not post-quantum and exist for existing keys and
small pieces.

Size matters because the encapsulated key rides in **every** piece, and twice
when the envelope that keeps the details is sealed to the key as well: under the
default `--info protected` when the key is the first layer, and under
`--info strict`. Largest content that still fits one QR code, measured with
`--pad none`, no recorded file name (a recorded name takes its length off these),
and the key as the only layer, so carried twice. The compact columns are for 2 of
3; a higher threshold fits about K times the content, less the overhead:

| Type | `full`, weakest (L) | `full`, strongest (H) | `compact`, L | `compact`, H |
|------|---------------------|-----------------------|--------------|--------------|
| `x25519` | 2655 B | 975 B | 5141 B | 1781 B |
| `p256` | 2589 B | 909 B | 5042 B | 1682 B |
| `p384` | 2525 B | 845 B | 4946 B | 1586 B |
| `ml-kem-768` | 543 B | does not fit | 1973 B | does not fit |
| `x-wing` | 479 B | does not fit | 1877 B | does not fit |
| `ml-kem-1024` | does not fit | does not fit | 533 B | does not fit |

Carrying the key once, under `--info public` or `none` or behind a password as
the first layer, adds its size back in the `full` columns and about twice that in
the `compact` ones. A post-quantum recipient set can still go on paper, but only
with weak error correction, a small payload, and `--method compact` or the key
carried once; `x25519` is the comfortable choice for print. Padding applies on
top of these figures.

Splitting and combining need no type flag: each key file names its type in its
label, and key lengths are distinct per type, so a mislabelled file is refused.
When the details are not sealed to it, a key of the wrong type reports the size
the data actually needs; a piece whose details are sealed to it just does not
open.

## Passwords

- Interactive entry is masked with `*`, and new passwords must be confirmed.
- Press Enter at a split's password prompt to generate a strong random one.
- For automation, `--password-env NAME` is the only source. Environment variables
  leave no copy on disk and, unlike command-line arguments, do not appear in the
  process list. Repeat the flag once per password layer, in outer-to-inner order.
- Layers must each use a different password.
- Passwords may be in any language. A password is treated as UTF-8 and normalized
  (Unicode NFC) before use, so it opens the pieces even when it is later typed in a
  different Unicode form; input that is not UTF-8 is decoded from GB18030. Use
  UTF-8 where you can, and the same characters will always work.

### Generated passwords

A generated password is the only way to recover the data, so it is never written
next to the pieces.

| Run | Where the password goes |
|-----|-------------------------|
| interactive | shown on screen in a marked block |
| `-y` | printed to standard output, one per line, in layer order |

Under `-y` the passwords are the only thing on standard output, so a script can
capture them directly:

```
mapfile -t PW < <(riven split vault.db -n 3 -k 2 \
                    --algo chacha20-poly1305,aes-256-gcm --out ./pieces -y)
# PW[0] is the first layer's password, PW[1] the second.
```

Capture them at the time. They are stored nowhere else.

## Piece size

Every piece of a set is written at the same size, and splitting the same input again
gives that same size. The size is not the content length: each piece is rounded up to
the next size class, so it tells an observer only which class the content falls in.

`--pad` sets the class width in percent, which is also the worst-case storage cost:

| `--pad` | What a piece size tells an observer | Cost |
|---------|-------------------------------------|------|
| `1` (default) | the content is within 1 percent of the piece size | up to 1 percent |
| `2` | within 2 percent | up to 2 percent |
| `5` | within 5 percent | up to 5 percent |
| `10` | within 10 percent | up to 10 percent |
| `100` | somewhere in a range of one doubling | up to twice the size |
| `500` | somewhere in a range of six times | up to six times the size |
| `none` | the exact content length | none |

The smallest class is 256 bytes, so anything that fits in it, a short password or a
PIN, comes out at exactly 256 bytes whatever its length. `none` drops that too.

Every piece also carries 32 random bytes on top of the content, whatever
`--pad` says. They are what keeps a single piece from confirming a guess of the
content.

The wizard asks for a percent under the advanced security option (0 to 100, where
0 drops the size class); the recommended option uses the default. The flag accepts
up to 500. Padding works the same with or without a password.

## Large inputs

Riven works on any size of input that fits in memory, and the requirement is not
the file size. Shamir gives every share the full length of the payload, so N shares
of an X byte input are N*X bytes on their own. A split needs roughly

```
full:     (N + 2) * input size
compact:  (2 + 2/K) * input size (3 times at -k 2, 4 at -k 1)
```

The content is encrypted straight into what is shared or dispersed, so it is
never held twice. For the full method that is the input, the encrypted payload
and the N shares, with one piece being written once the payload is gone: a 1 GiB
file into 5 pieces needs about 7 GiB. The compact method holds the input and the
sealed data, then works out each piece's fragment only when that piece is
written, so the piece count does not add to it: the same file needs about 3 GiB
at any N. Above 64 MiB the split prints the figure before it starts.

Pieces are written and released one at a time rather than all being held, so the
export format count does not add to this, and neither does the piece count beyond
its share. `combine` needs the K pieces it was given plus one copy of the result.

The N*X floor of the full method is a property of Shamir sharing, not of this
implementation. Both methods work in memory, so files far past available memory
are out of reach for the current piece format. Raising that ceiling needs a
chunked format, where the payload is sharded and sealed a block at a time; that
is a format change and is not implemented.

Practical guidance:

- Under about a tenth of free memory, divided by N: no thought needed.
- Larger than that: compress first (`tar -czf`, `zstd`), which shrinks the input
  and therefore every share, or use `--method compact`.
- Much larger: split an encrypted container, or split the key to one, rather than
  the data. A key is a few dozen bytes at any file size, and that also puts QR,
  `sheet` and `words` back within reach.

## Export formats

`--format` accepts a comma-separated list, or `all`.

| Format | File | Size | Use |
|--------|------|------|-----|
| `binary` | `s.1` | 1.0x | default; the smallest form |
| `base64` | `s.1.txt` | 1.4x | paste into a messenger or an email |
| `base32` | `s.1.b32.txt` | 2.0x | copy by hand: one case, grouped in fours |
| `words` | `s.1.words.txt` | 4.7x | write out by hand; at most 4096 bytes per piece |
| `qr` | `s.1.png` | n/a | scan from paper; at most 2952 bytes per piece |
| `sheet` | `s.1.html` | n/a | print: QR code, text and instructions; at most 16 pages per piece |

Aliases: `bin`/`raw`, `b64`/`text`, `b32`, `qrcode`/`png`, `paper`/`print`/`html`,
`bip39`/`mnemonic`.

The wizard asks the same thing and accepts either numbers or names, mixed:
`2,3`, `base64,qr`, `base32,4`, or `all`. With each entry it states what that
choice costs for the pieces at hand: a format the pieces are too large for is
marked `NOT AVAILABLE` with the size and the limit, and `words` gives the word
count per piece. A note too long to sit beside its entry takes the line under
it, and the listing is folded to the width of the terminal. The same limits are
enforced for `--format`, before any file is written.

The three text formats carry a checksum, so a mistyped character is reported as a
damaged file rather than as a wrong password. It sits inside the encoded text, so
the file is still one run of characters with no line that identifies it.

### words

`words` writes the piece as BIP-39 English words. It is by far the largest form:
**about 4.7 times the size of the binary piece**, roughly 2.4 times even the
base32 text. A 500 byte piece is 367 words.

It exists for one job: a small secret that has to be written on paper by hand and
read back by a person, where a word list is much harder to get wrong than a run of
letters. Numbering, punctuation, line breaks and case are ignored when reading it
back, so a transcription can be laid out however suits.

Pieces over 4096 bytes are refused, and the error says to use `base32` instead.
For anything but a small secret, `base32` carries the same data in less than half
the characters.

### qr

A QR code holds at most 2952 bytes, so QR export works only for small inputs. The
error correction level is picked per piece: the strongest that fits. Pieces of one
set are the same size, so they normally share a level; the summary reports what
each piece actually got rather than assuming.

### Scanning and photographing

Riven reads a code back from a photograph, not just a clean scan: rotated, upside
down, small in a larger frame, taken at an angle, unevenly lit, blurred, or saved
as a low-quality JPEG. It rectifies the image from the code's own finder patterns
before decoding, so a steep angle is not a problem in itself.

Size is what decides how forgiving it is. Up to about 400 bytes per piece, even a
poor photograph reads. Larger symbols have smaller modules, so a very steep angle
stops working and the shot needs to be flatter and sharper; the split summary
warns when the pieces are over 400 bytes. If a set has to survive being
photographed casually, keep the pieces small: a smaller file, `--method compact`
with a higher K, or an `x25519` recipient key rather than a post-quantum one.

QR export is all or nothing: if any piece is too large, nothing is written and the
error names the piece and the overshoot. A set where only some pieces have a QR
code could not be scanned back.

### QR and size padding

Padding still applies when exporting to QR, so a piece whose natural size fits can
be rounded past 2952 bytes and refused. The input length alone decides this, so an
input that fails will always fail.

`--pad none` gives the smallest pieces and clears the limit whenever the natural
size fits. With a wider class than the default, a narrower one such as `--pad 1`
may be enough. The error says which to try. The cost of `none` is that the piece
length then follows the content length.

When the content is simply too large, `--method compact` makes each piece about
1/K of it, which the error also suggests.

### sheet

A recovery sheet is the one format that explains itself: it names the tool, says
how many pieces are needed, and carries the piece as a QR code and as base32 text
with instructions for reading either one back. That is deliberate, so someone who
finds the page knows what to do with it. It prints the original file name only
when the pieces record it (`--record-name false` leaves it off). Do not print one
if the pieces themselves have to stay unattributable.
[sample-sheet.html](sample-sheet.html) is a real one.

It degrades rather than failing as pieces grow:

| Piece size | What you get |
|------------|--------------|
| up to 2952 bytes | QR code plus text |
| larger | text only, with the missing code explained on the page |
| over about 880 bytes, more than one page | a warning to keep the pages together and in order |
| over 16 pages, about 14 KB | refused: use `base32` or `binary` |

The split reports the page count when a piece runs to more than one page, since
losing one page of a piece loses the piece.

## completion

```
riven completion [bash|zsh|fish|powershell]
```

Prints a completion script on standard output. With no shell named it is taken
from `$SHELL`, or from `$PSModulePath` on Windows.

```
source <(riven completion bash)                                  # this session
riven completion bash > ~/.local/share/bash-completion/completions/riven
riven completion zsh  > "${fpath[1]}/_riven"
riven completion fish > ~/.config/fish/completions/riven.fish
riven completion powershell | Out-String | Invoke-Expression      # add to $PROFILE
```

It completes commands, every flag, and the values of the flags that have a fixed
set: export formats, algorithms, Argon2 presets, padding widths, `true`/`false`,
recipient key types, and shell names. `--password-env` and `--text-env` complete
from the environment variables that are actually set.

Everything else completes as a file path, including absolute ones such as
`/root/piece1.data`, so a piece or an output directory is completed the way any
other path is in that shell. The scripts are generated from the parser's own flag
tables, so they cannot fall behind the flags Riven accepts.

One limitation, in PowerShell only: it does not call a native completer for a word
that is just `-` or `--`, so type at least one letter after the dashes
(`riven --f<TAB>`) for flag names.

## Argon2id cost

`--kdf` accepts a preset name or an explicit specification:

| Preset | Cost |
|--------|------|
| `recommended` | 64 MiB, 3 passes, 4 lanes (RFC 9106 second recommended option) |
| `paranoid` | 256 MiB, 4 passes, 4 lanes |
| `max` | 1 GiB, 4 passes, 4 lanes |

Custom: `m=<MiB>,t=<passes>,p=<lanes>`, for example `--kdf m=256,t=4,p=4`. Any
subset of the keys may be given; the rest come from `recommended`. Memory must be
one of 8/16/32/64/128/256/512/1024 MiB, passes 1-8, and lanes 1/2/4/8. These limits
exist so the cost fits in the one byte a piece can record without becoming a
fingerprint (see [format.md](format.md#4-cost-byte)).

A key is derived per piece, so the cost scales with N, though the derivations run
in parallel. `recommended` is well under a second per piece; `max` a few seconds.

## Examples

Single password, 3-of-5:

```
riven split notes.txt -n 5 -k 3 --password-env PW -y
```

Two password layers with generated passwords, in every format:

```
riven split vault.db -n 4 -k 2 --algo chacha20-poly1305,twofish-256-gcm \
  --generate --format all -y
```

Split only, no password, any 2 of 3:

```
riven split key.bin -n 3 -k 2 --keyless -y
riven combine key.bin.1 key.bin.2 -y > key.bin
```

Two people must cooperate, no password:

```
riven split deal.pdf -n 3 -k 2 --recipient alice.pub --recipient bob.pub -y
riven combine deal.pdf.1 deal.pdf.2 --identity alice.key --identity bob.key -y > deal.pdf
```

Withhold the algorithms and cost, then supply them to reconstruct:

```
riven split m.bin -n 3 -k 2 --algo aes-256-gcm --password-env PW \
  --record-algo false --record-kdf false --kdf m=256,t=4,p=4 -y

riven combine m.bin.1 m.bin.2 --password-env PW \
  --algo aes-256-gcm --kdf m=256,t=4,p=4 -o m.bin -y
```

Split a string and use it in a script:

```
riven split --text "123456" -n 3 -k 2 --password-env PW --out ./pieces -y
CODE=$(riven combine pieces/secret.1 pieces/secret.2 --password-env PW -y)
```

Split what another program produces, without it touching disk:

```
pass show mykey | riven split - -n 3 -k 2 --password-env PW --name mykey -y
```
