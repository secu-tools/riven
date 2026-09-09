# FAQ

Short answers; click a question to expand it. Depth is in [usage.md](usage.md)
and [format.md](format.md).

## Security

<details>
<summary><b>If one piece leaks, is my data exposed?</b></summary>

No. Below the threshold K, a piece reveals nothing about the content: not a
partial file, not a hint, nothing. That is Shamir secret sharing, not a property
of this tool, and it is information-theoretic rather than computational. Look up
Shamir secret sharing if you want the mathematics.

That covers the content. A `--keyless` piece also carries readable metadata by
design -- file name, set, piece number, length, and the payload hash -- so a
stray piece can be identified without a password. Any password layer seals that
too.

</details>

<details>
<summary><b>How many pieces does an attacker need?</b></summary>

K, the threshold you chose. K-1 pieces are worth exactly as much as zero. On top
of that they still need every password and recipient private key, unless the split
was made with `--keyless`.

</details>

<details>
<summary><b>If my password leaks, is my data exposed?</b></summary>

No, not on its own. Without K pieces there is nothing to decrypt, at any
computational cost. The reverse holds too: K pieces without the password are
useless.

</details>

<details>
<summary><b>Can someone tell a file is a Riven piece?</b></summary>

Not from the file. A piece has no header, no magic bytes and no fixed byte at any
offset: it is a random salt, a masked cost byte, a random nonce and AEAD
ciphertext. Two exceptions, both deliberate:

- A `--keyless` piece is identifiable to anyone holding this tool, and its
  metadata is readable, because the envelope key for those is public. Nothing
  authenticates such a set either, so it can be replaced undetectably.
- A recovery sheet names the tool on the page, which is the point of it.

</details>

<details>
<summary><b>What does the piece size reveal?</b></summary>

A range, not a length. Every piece is rounded up to a size class `--pad` percent
wide (5 by default), so the size says only which class the content falls in. With
`--pad none` the size follows the content length exactly. A split with no password
is not padded at all, because its metadata is readable and the length would leak
either way.

</details>

<details>
<summary><b>Is the file name visible?</b></summary>

No. It lives inside the encrypted manifest, so it is readable only by someone who
can already open the piece. Only the name is kept, never the path, permissions or
timestamps. `--record-name false` leaves it out.

</details>

<details>
<summary><b>Is it post-quantum?</b></summary>

Yes. Below the threshold the guarantee is information-theoretic, so quantum
compute does not help. Above it, 256-bit AEADs and Argon2id leave about 128-bit
security against Grover. Recipient key layers default to `x-wing` (ML-KEM-768 with
X25519), which holds if either component holds.

</details>

<details>
<summary><b>What is not covered?</b></summary>

A compromised machine while Riven runs, weak passwords you chose yourself, losing
more than N-K pieces, and `--text` (visible in the process list). The full list is
in [SECURITY.md](../SECURITY.md).

</details>

## Size

<details>
<summary><b>How big is each piece?</b></summary>

About the size of the whole input, not `size / N`. Five pieces of a 1 GB file are
five ~1 GB files. Shamir gives every share the full payload length; that is what
makes fewer than K pieces reveal nothing.

</details>

<details>
<summary><b>How much does each format add on top of that?</b></summary>

| Format | Size | Limit |
|--------|------|-------|
| binary | 1.0x | none |
| base64 | 1.4x | none |
| base32 | 2.0x | none |
| words | 4.7x | 4096 bytes per piece |
| qr | n/a | 2952 bytes per piece |
| sheet | n/a | about 17 KB per piece, 16 printed pages |

Padding adds up to `--pad` percent on top (5 by default).

</details>

<details>
<summary><b>How much memory does a split need?</b></summary>

Roughly `(N + 3)` times the input: the input, the encrypted payload, the N shares,
and one piece being written. A 1 GB file into 5 pieces needs about 8 GB. Above
64 MiB the split prints the figure before it starts. Pieces are written and
released one at a time, so the number of export formats does not add to this.

</details>

<details>
<summary><b>Can I split a 1 TB file?</b></summary>

Not directly: the N shares must be in memory at once, so a 1 TB file into 5 pieces
would need about 8 TB of RAM. Split the key instead of the data. Encrypt the file
with any container (age, gpg, LUKS, 7z), then split the key. A key is a few dozen
bytes at any file size, which also puts QR, sheets and words back within reach.

</details>

<details>
<summary><b>Does Riven compress?</b></summary>

No. Compress before splitting if you want it. It matters more here than in most
tools: every piece is a full copy, so halving the input halves all N pieces and
the memory the split needs.

</details>

## Formats

<details>
<summary><b>Which format should I use?</b></summary>

`binary` unless you have a reason. `base64` to paste into a messenger. `base32` to
copy by hand or scan back with OCR. `qr` to scan from paper. `sheet` to print
something a stranger could act on. `words` only for a small secret written out by
hand.

</details>

<details>
<summary><b>Can I mix formats when rebuilding?</b></summary>

Yes. The format is detected from the content, never the file name, so a binary
piece, a photographed QR code and a retyped base32 file combine in one command.

</details>

<details>
<summary><b>Why does QR stop at 2952 bytes?</b></summary>

That is the QR standard's byte-mode maximum at the weakest error correction level.
Riven picks the strongest level that fits, so smaller pieces get more damage
tolerance. Codes over about 400 bytes have small enough modules that a casual
photograph starts to fail; the split says so.

</details>

<details>
<summary><b>Why is "words" so much larger?</b></summary>

Eleven bits per word, and an average English word is about six characters. It
exists for a secret transcribed by a person, where a word list is far harder to
get wrong than a run of letters. Use `base32` for anything else: same data, less
than half the characters.

</details>

<details>
<summary><b>How many pages is a recovery sheet?</b></summary>

Roughly 780 piece bytes per page. One page up to about that, then it warns on the
page to keep the pages together, and refuses past 16 pages. A piece too large for
a QR code still gets a sheet, with the text alone.

</details>

<details>
<summary><b>Can I split a directory?</b></summary>

Pack it yourself first (`tar -czf archive.tar.gz DIR`), then split the archive.
That leaves the archive format and the compression to you.

</details>

## Damage and recovery

<details>
<summary><b>What happens if a piece is corrupted?</b></summary>

It fails to open, and the message says so: if another piece opened with the same
password, the failing one is damaged rather than wrongly keyed. Text formats also
carry a CRC-32 that catches a mistyped character before the piece is tried.

</details>

<details>
<summary><b>Can a corrupted piece be repaired?</b></summary>

Only inside a QR code, which has its own Reed-Solomon (about 7 to 30 percent of
the symbol, depending on the level). Nothing else repairs. That is deliberate: the
redundancy in this design is N versus K. With 3-of-5 you can lose two whole pieces,
which is stronger than any per-file recovery record would be, and a recovery record
would add structure that a piece is specifically built not to have.

</details>

<details>
<summary><b>What if I lose a piece?</b></summary>

You have `N - K` to spare. Beyond that the data is gone.

</details>

<details>
<summary><b>What if I forget the password?</b></summary>

The data is gone. There is no recovery path, by design.

</details>

<details>
<summary><b>Can I add pieces to an existing set later?</b></summary>

No. Split again with a larger N. Pieces from two splits are different sets and do
not combine.

</details>

<details>
<summary><b>How do I check my pieces still work?</b></summary>

`riven verify PIECE...` or `riven verify DIR`. It rebuilds in memory and checks
the result against the recorded hash, writing nothing. A set short of the
threshold is reported with the number still needed.

</details>

<details>
<summary><b>How many pieces should I make?</b></summary>

Enough that losing a location does not lose the data, and few enough that
gathering K is realistic. 3-of-5 is a reasonable default: any two pieces can be
lost, and any two holders working together still have nothing.

</details>
