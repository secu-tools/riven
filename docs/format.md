# Piece format

Byte-level specification of what Riven writes. It is the reference for anyone
implementing a reader, auditing the format, or recovering data without this tool.

Conventions used throughout:

- Integers are unsigned and big-endian. `u8`, `u16`, `u32`, `u64` give the width.
- `bytes(n)` is n raw bytes. `blob` is a `u32` length followed by that many bytes.
- Offsets are zero-based and inclusive-exclusive: `[0:16]` is the first 16 bytes.
- All sizes are bytes.

## 1. Structure

A piece file contains one sealed envelope. Inside it is a manifest, which carries
one Shamir share of the cascade payload:

```
piece file
  header (salt, cost byte, nonce)          in the clear, all high entropy
  XChaCha20-Poly1305(manifest) + tag
      manifest
        set metadata (version, set id, k, n, serial, flags, ...)
        share            one Shamir share of the payload
        padding          random bytes, to reach a size class

payload  (reassembled from k shares, never stored whole in one piece)
  cascade header (per-layer kind, algorithm, salt, nonce, encapsulated key)
  ciphertext     the input, wrapped once per layer
```

Nothing outside the header is in the clear. The header is a random salt, a masked
cost byte and a random nonce, so a piece has no fixed bytes at any offset.

## 2. Piece file

| Offset | Size | Field |
|--------|------|-------|
| `[0:16]` | 16 | salt, uniform random |
| `[16:17]` | 1 | masked Argon2id cost byte (section 4) |
| `[17:41]` | 24 | XChaCha20-Poly1305 nonce, uniform random |
| `[41:len-16]` | var | manifest ciphertext |
| `[len-16:len]` | 16 | Poly1305 tag |

Fixed header: 41 bytes. Minimum piece: 57 bytes (header plus tag, an empty
manifest). Total length:

```
piece = 41 + 83 + 2*layers + name + creator version + creator commit + share + padding + 16
      = 140 + 2*layers + name + creator version + creator commit + share + padding
```

The associated data covering the ciphertext is:

```
"riven-piece-v1" || salt || cost byte
```

so neither the salt nor the declared cost can be altered without the tag failing.

## 3. Manifest

The plaintext sealed by the envelope. Fields appear in this order.

| Size | Field | Notes |
|------|-------|-------|
| 2 | `u16` version | 1 |
| 16 | set id | random per split, identical across the pieces of one set |
| 1 | `u8` k | pieces required, 1..255 |
| 1 | `u8` n | pieces produced, k..255 |
| 1 | `u8` serial | this piece, 1..n |
| 1 | `u8` flags | section 3.1 |
| 8 | `u64` payload length | length of the cascade payload, not of the input file. Informational: reconstruction uses the share lengths |
| 32 | payload hash | BLAKE2b-256 of the payload; identical across the set |
| 1 | `u8` layer count | 0..255 |
| 2 per layer | layer descriptors | section 3.2 |
| blob | file name | section 3.3; empty when none was recorded |
| blob | creator version | section 3.4; may be empty, though the CLI always writes it |
| blob | creator commit | section 3.4; may be empty, though the CLI always writes it |
| blob | share | one Shamir share (section 6) |
| blob | padding | random bytes, length 0 or more (section 7) |

Fixed part: 2 + 16 + 4 + 8 + 32 + 1 + five `u32` length prefixes = 83 bytes.

### 3.1 Flags

| Bit | Value | Meaning when set |
|-----|-------|------------------|
| 0 | `0x01` | encrypted: the payload has one or more cascade layers |
| 1 | `0x02` | hybrid: at least one layer is keyed by a recipient key |
| 2 | `0x04` | the algorithm ids are recorded (section 3.2) |
| 3 | `0x08` | the cost byte holds real parameters rather than noise |
| 4 | `0x10` | keyless envelope: sealed with the public key of section 5.2 |

Bits 5 to 7 are reserved and written as zero.

### 3.2 Layer descriptors

Two bytes per layer, outermost first:

| Size | Field | Values |
|------|-------|--------|
| 1 | `u8` kind | 0 = password, 1 = recipient key |
| 1 | `u8` algorithm id | section 8, or 0 when not recorded |

With flag bit 2 clear, every algorithm id is written as 0 and the reader must be
given the list separately.

### 3.3 File name

The original file's name, at most 255 bytes, and nothing else about the file: no
path, no permissions, no timestamps. It is written only when the input was a file
and `--record-name` was not turned off; text and standard input record nothing.

It sits inside the sealed manifest, so it is readable only by someone who can
already open a piece. It does add its length to every piece, which padding then
rounds away in the usual case (section 7).

A reader must treat it as untrusted input: it comes from whoever wrote the piece.
Before it is used as a path, strip everything up to the last `/`, `\` or `:`,
strip trailing dots and spaces, and reject the result if it is empty, `.`, `..`,
contains a control character or any of `<>:"|?*`, or names a Windows device
(`con`, `nul`, `prn`, `aux`, `clock$`, `conin$`, `conout$`, `com0`..`com9`,
`lpt0`..`lpt9`, including the superscript digit forms Windows also resolves).

Reject two further classes, which are about how the name renders rather than what
it addresses: the C1 control block `U+0080`..`U+009F`, and the bidirectional
controls `U+200E`, `U+200F`, `U+202A`..`U+202E`, `U+2066`..`U+2069`, `U+061C`,
plus `U+00AD` and `U+FEFF`. A right-to-left override makes a name ending
`gpj.exe` display as `exe.jpg`. Ordinary international names are unaffected,
including the zero-width joiners Indic and Arabic scripts need.

Riven's own implementation is `core.SafeName`.

### 3.4 Creator version and commit

Two blobs, each at most 64 bytes: the program version and the commit hash of the
build that wrote the piece. They let `info` report which build produced a piece,
so a version mismatch can be diagnosed. A reader that does not need them may
ignore them.

## 4. Cost byte

One byte carries the Argon2id cost. Bit layout before masking:

| Bits | Field | Value |
|------|-------|-------|
| 7..5 | memory index | `8 << index` MiB: 8, 16, 32, 64, 128, 256, 512, 1024 |
| 4..2 | passes minus one | 1..8 passes |
| 1..0 | lanes index | 1, 2, 4, 8 |

Every one of the 256 values decodes to a valid configuration, so noise is
indistinguishable from a recorded cost. The byte stored on disk is masked:

```
stored = encoded XOR BLAKE2b-256("riven-kdf-mask-v1" || salt)[0]
```

With recording off (flag bit 3 clear) the stored byte is uniform random instead,
and the reader must be given the parameters.

## 5. Envelope key

32 bytes, used with XChaCha20-Poly1305.

### 5.1 Password envelope

```
seed = BLAKE2b-256("riven-pw-mix-v1" || for each password: u32 length || password)
key  = Argon2id(seed, salt, passes, memory, lanes, 32)
```

Passwords are mixed in layer order, outermost first. Length prefixing means
`{"ab","c"}` and `{"a","bc"}` cannot collide. Every password of the set is needed
to open any piece.

### 5.2 Keyless envelope

Used when the split has no password layer, which covers split-only sets and sets
addressed only to recipient keys:

```
key = BLAKE2b-256("riven-keyless-envelope-v1" || salt)
```

This key is public. Anyone holding this specification can open the envelope of
such a piece and read its manifest, including the payload length. The content
still needs k shares and, for a recipient set, the private keys.

## 6. Share

The payload is split with Shamir secret sharing over GF(2^8).

| Threshold | Share layout |
|-----------|--------------|
| k = 1 | the payload itself, no tag: every piece is a full copy |
| k >= 2, payload <= 524288 | `bytes(payload length) \|\| u8 x-coordinate` |
| k >= 2, payload > 524288 | one such share per 512 KiB chunk, concatenated |

Chunking exists so a large split can use every core. Chunks are 524288 bytes
except the last. The chunk count is not stored; it follows from the share length,
because a share of m chunks covering s payload bytes is `s + m` long with
`(m-1)*524288 < s <= m*524288`, which admits exactly one m:

```
m = ceil(shareLength / 524289)
```

Every share of a set has the same length. Each chunk is an independent sharing
with its own x-coordinates, so a reader must slice the shares chunk by chunk and
interpolate each chunk separately.

## 7. Padding

Padding hides the content length. A piece is rounded up to the next size class:
classes start at 256 bytes, and each is `--pad` percent wider than the one below
(5 by default, maximum 500):

```
size(0) = 256
size(i+1) = size(i) + max(1, size(i) * percent / 100)
```

The padding length is whatever brings the piece to the first class at or above its
natural length, so every piece of a set is the same size, and splitting the same
input again produces that size again.

Padding is omitted entirely when the envelope is keyless (section 5.2): the
padding length lives in the manifest, which is readable there, so it would hide
nothing.

## 8. Cascade payload

The payload is the input wrapped once per layer, innermost first, preceded by a
header describing the layers.

| Size | Field | Notes |
|------|-------|-------|
| 2 | `u16` version | 1 |
| 1 | `u8` layer count | 0..255 |
| per layer | descriptor | see below |
| rest | ciphertext | the outermost layer's output |

Each layer descriptor, outermost first:

| Size | Field | Notes |
|------|-------|-------|
| 1 | `u8` kind | 0 = password, 1 = recipient key |
| 1 | `u8` algorithm id | 0 when not recorded |
| blob | salt | 16 bytes for a password layer, empty for a recipient layer |
| blob | nonce | algorithm-dependent length, see the table below |
| blob | encapsulated key | empty for a password layer |

Reader limits: at most 255 layers, 64 bytes of salt, 64 bytes of nonce, and 4096
bytes of encapsulated key per layer.

Zero layers is a well-formed payload: the header is followed by the input
unchanged. That is the split-only case.

### 8.1 Algorithms

| id | name | key | nonce | tag |
|----|------|-----|-------|-----|
| 1 | `aes-256-gcm` | 32 | 12 | 16 |
| 2 | `chacha20-poly1305` | 32 | 12 | 16 |
| 3 | `xchacha20-poly1305` | 32 | 24 | 16 |
| 4 | `twofish-256-gcm` | 32 | 12 | 16 |
| 5 | `aes-256-ctr-hmac` | 32 | 16 | 32 |

Id 0 is reserved for "not recorded" and is never assigned. Ids are permanent: a
number is never reused for a different algorithm. Two neighbouring layers may not
use the same algorithm.

The envelope always uses XChaCha20-Poly1305, whatever the layers use.

### 8.2 Layer keys

Password layer:

```
key = Argon2id(password, layer salt, passes, memory, lanes, 32)
```

using the same cost as the envelope. The password for layer i is the i-th
password supplied, counting password layers only.

Recipient layer, using HPKE (RFC 9180) in export-only mode:

```
enc, ctx = HPKE.SetupBaseS(recipient public key, info)
info     = "riven-recipient-v1:" || key type name
secret   = ctx.Export("riven-layer-key-v1", 32)
key      = HKDF-SHA256(secret, salt = empty, info = "riven-kem-layer-v1", 32)
```

`enc` is the encapsulated key stored in the layer descriptor. Its length
identifies the key type:

| Key type | encapsulated key | public key | HPKE KEM |
|----------|------------------|------------|----------|
| `x-wing` | 1120 | 1216 | 0x647a |
| `ml-kem-768` | 1088 | 1184 | 0x0041 |
| `ml-kem-1024` | 1568 | 1568 | 0x0042 |
| `x25519` | 32 | 32 | 0x0020 |
| `p256` | 65 | 65 | 0x0010 |
| `p384` | 97 | 97 | 0x0011 |

The KDF is HKDF-SHA256 for every type except `ml-kem-1024` (SHA-512) and `p384`
(SHA-384).

### 8.3 Layer associated data

Each layer's AEAD covers 11 bytes of associated data:

```
"riven-casc" || u8 algorithm id
```

so a layer cannot be replayed under a different algorithm.

## 9. Transport encodings

A piece is stored in one of six forms. The form is detected from the content,
never from the file name, so they mix freely in one reconstruction.

| Form | Extension | Size | Content |
|------|-----------|------|---------|
| binary | none | 1.00x | the piece bytes exactly |
| base64 | `.txt` | 1.36x | standard base64 of `piece \|\| checksum`, wrapped at 76 columns |
| base32 | `.b32.txt` | 2.01x | RFC 4648 base32 of `piece \|\| checksum`, in groups of 4, 8 groups to a line |
| words | `.words.txt` | 4.70x | BIP-39 English words for `piece \|\| checksum`, 11 bits per word |
| qr | `.png` | n/a | PNG of a QR code carrying the piece bytes in byte mode |
| sheet | `.html` | n/a | printable page carrying the base32 text and, when it fits, the QR code |

The size column counts characters written per piece byte, including the checksum
and the separators, measured over 200 to 4096 byte pieces. It drifts a little with
the piece size, most for words: 4.87x at 200 bytes, 4.65x at 4096.

The three text forms append a four-byte CRC-32 (IEEE, big-endian) of the piece
before encoding:

```
encoded = base64, base32 or BIP-39 of ( piece || CRC32(piece) )
```

It sits inside the encoded blob rather than on a line of its own, so the file
remains one run of alphabet characters with nothing that identifies it. A reader
strips the last four bytes when the CRC matches; when it does not, the whole blob
is used and the reader reports that the text may be damaged. Binary and QR carry
no checksum of their own: a QR code has its own error correction, and both are
covered by the envelope tag.

Detection order:

1. If the bytes parse as a PNG, JPEG or GIF header, decode the QR payload.
2. If the bytes contain `id="piece-text"`, take the text of that element and read
   it as base32; this is a saved recovery sheet.
3. If every token is a word from the BIP-39 English list, and there are enough of
   them to hold a piece, decode as words.
4. If every byte is whitespace, a hyphen, or in the base32 alphabet, and the
   length after removing separators is a multiple of eight, decode as base32.
   Letters may be either case.
5. Otherwise, if every byte is whitespace or in the base64 alphabet, and the
   length after removing whitespace is a multiple of four, decode as base64.
6. Otherwise use the bytes as they are.

In steps 3 to 5 the result must be at least 57 bytes, so binary input is never
misread. Words are tried before base32 because their tokens are letters, which are
also valid base32 characters. Base32 is tried before base64 because every base32
character is also a base64 character but not the reverse. A piece is uniformly
random, so its base64 form falling entirely inside the 32-character base32
alphabet, or a raw piece falling entirely inside the base64 alphabet, is a one in
2^n event.

### Words

`piece || CRC32(piece)` is read eleven bits at a time, each group indexing the
standard BIP-39 English word list. This is BIP-39's encoding only: no entropy is
generated, no mnemonic checksum is appended, and the result is not a wallet seed
phrase.

The last group is padded with zero bits, so the word count does not determine the
byte count. Decoding tries both candidate lengths and keeps the one whose CRC-32
matches.

Reading is deliberately loose: tokens are split on any non-letter, case is folded,
and list numbering is ignored. Every token must be on the list; one that is not
fails detection rather than being guessed at.

Pieces over 4096 bytes are refused, which is 2982 words. The word list is embedded
verbatim; its source and SHA-256 are recorded in `internal/pieceio/bip39_words.go`.

### Recovery sheet

The sheet is the one form that identifies itself: it names the tool, states the
piece number and the threshold, and carries recovery instructions. It is a
self-contained HTML page with no external references, and the piece text sits in
`<pre id="piece-text">`, which is what makes a saved sheet readable as input.

A piece too large for a QR code still gets a sheet, with the text alone and the
missing code explained. Page count is estimated at 39 characters per line and 44
lines per page, roughly 780 piece bytes per page; a sheet running to more than one
page carries a warning to keep the pages together, and the print stylesheet keeps
the code, the instructions and the footer whole while letting the text block flow.
Pieces needing more than 16 pages are refused.

QR codes use byte mode at the strongest error correction level that fits: 1272
bytes at level H, 1662 at Q, 2330 at M, 2952 at L.

File names are `BASE.SERIAL` with the serial zero-padded to the width of n, plus
the extension above: `secret.pdf.1` for five pieces, `secret.pdf.01` for ten.

## 10. Reading a set

1. Read k pieces in any transport form and decode each to piece bytes.
2. For each piece, derive the envelope key (section 5) and open the envelope. The
   cost comes from the cost byte unless supplied separately.
3. Check every manifest reports the same version, set id, k, n and payload hash.
   Collect one share per distinct serial.
4. Interpolate the shares (section 6) to recover the payload. The padding is a
   separate field and is simply not used.
5. Check the payload against the payload hash. This is what detects a wrong or
   corrupt share, since interpolation below the threshold yields plausible bytes
   rather than an error.
6. Peel the cascade (section 8) from the outermost layer inward.

Fewer than k pieces cannot complete step 4, at any computational cost.

## 11. Key files

A recipient key pair is two text files. Each holds a label line, a base64 line,
and optional comments:

```
riven-x25519-public
y+Q7y3gjEVzC+t7S5Nlq0dBqausD2CaC9xh0h3/MtGA=
```

| Line | Content |
|------|---------|
| label | `riven-` + key type name + `-public` or `-private` |
| body | standard base64 of the serialized key |
| `#...` | ignored, as are blank lines |

The label decides the key type; the length is checked against it, so a
mislabelled file is refused rather than misread. Key type names are `x-wing`,
`ml-kem-768`, `ml-kem-1024`, `x25519`, `p256` and `p384`. Serialized lengths are
in section 8.2 for public keys; private keys are 32 bytes for `x-wing`, `x25519`
and `p256`, 48 for `p384`, and 64 for both `ml-kem-*` types.

Public key files are written with mode 0644, private with 0600.

## 12. Versioning

The manifest carries a `u16` version, currently 1; the cascade header carries its
own, currently 1. A reader refuses a version it does not know rather than
guessing. Algorithm ids and key type identifiers are permanent and never reused.

> [!WARNING]
> Riven is in beta and the format is not yet stable. While the version stays at
> 1 it may change without notice, and pieces written by one build are not
> guaranteed to open with another. Re-split anything important after upgrading.
