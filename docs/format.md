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
one Shamir share of what the set shares:

```
piece file
  header (salt, cost byte, [keys], nonce)  in the clear, all high entropy
  XChaCha20-Poly1305(manifest) + tag
      manifest
        set metadata (version, set id, k, n, serial, flags, ...)
        share            one Shamir share of the shared bytes
        fragment         compact method only: this piece's part of the sealed data
        details share    hidden details only: one Shamir share of the details

shared bytes  (reassembled from k shares, never stored whole in one piece)
  full method:     payload length, payload, fill
  compact method:  sealed length, the two keys that open the data, fill

payload
  cascade header (per-layer kind, algorithm, salt, nonce, encapsulated key)
  ciphertext     the input, wrapped once per layer

package  (compact method: dispersed, so each piece holds 1/k of it)
  the payload under two keyed layers and an all-or-nothing transform
```

The fill is random: the hash salt and the padding.

Nothing outside the header is in the clear. The header is a random salt, a masked
cost byte, for an envelope sealed to recipient keys their masked encapsulated
keys, and a random nonce, so a piece has no fixed bytes at any offset.

## 2. Piece file

| Offset | Size | Field |
|--------|------|-------|
| `[0:16]` | 16 | salt, uniform random |
| `[16:17]` | 1 | masked Argon2id cost byte (section 4) |
| `[17:17+e]` | e | masked encapsulated keys of a sealed envelope (section 5.3); e = 0 otherwise |
| `[17+e:41+e]` | 24 | XChaCha20-Poly1305 nonce, uniform random |
| `[41+e:len-16]` | var | manifest ciphertext |
| `[len-16:len]` | 16 | Poly1305 tag |

Header: 41 bytes, plus e for a sealed envelope. Minimum piece: 57 bytes (header
plus tag, an empty manifest). Total length:

```
piece = 41 + e + 79 + 2*layers + name + creator version + creator commit
           + share + fragment + details share + 16
      = 136 + e + 2*layers + name + creator version + creator commit
           + share + fragment + details share
```

The associated data covering the ciphertext is everything before the nonce:

```
"riven-piece-v1" || salt || cost byte || masked encapsulated keys
```

so neither the salt, the declared cost nor the encapsulated keys can be altered
without the tag failing.

## 3. Manifest

The plaintext sealed by the envelope. Fields appear in this order.

| Size | Field | Notes |
|------|-------|-------|
| 2 | `u16` version | 2 |
| 16 | set id | random per split, identical across the pieces of one set |
| 1 | `u8` k | pieces required, 1..255 |
| 1 | `u8` n | pieces produced, k..255 |
| 1 | `u8` serial | this piece, 1..n |
| 1 | `u8` flags | section 3.1 |
| 32 | payload hash | BLAKE2b-256 of the shared bytes (section 6); identical across the set |
| 1 | `u8` layer count | 0..255 |
| 2 per layer | layer descriptors | section 3.2 |
| blob | file name | section 3.3; empty when none was recorded |
| blob | creator version | section 3.4; may be empty, though the CLI always writes it |
| blob | creator commit | section 3.4; may be empty, though the CLI always writes it |
| blob | share | one Shamir share (section 6) |
| blob | fragment | compact method: this piece's fragment (section 6.3); empty otherwise |
| blob | details share | hidden details: one share of the details (section 3.5); empty otherwise |

Nothing follows the details share; a reader rejects a manifest with bytes left
over.

Fixed part: 2 + 16 + 4 + 32 + 1 + six `u32` length prefixes = 79 bytes.

With hidden details (flag bit 6), k, n, serial and the layer count are written as
zero, the name and creator blobs are empty, and flag bits 0 to 3 are clear. The
real values are in the details share. A reader rejects a manifest that hides its
details but shows any of them.

### 3.1 Flags

| Bit | Value | Meaning when set |
|-----|-------|------------------|
| 0 | `0x01` | encrypted: the payload has one or more cascade layers |
| 1 | `0x02` | hybrid: at least one layer is keyed by a recipient key |
| 2 | `0x04` | the algorithm ids are recorded (section 3.2) |
| 3 | `0x08` | the cost byte holds real parameters rather than noise |
| 4 | `0x10` | keyless envelope: sealed with the public key of section 5.2 |
| 5 | `0x20` | compact method: the piece carries a fragment (section 6.3) |
| 6 | `0x40` | hidden details: the details are shared (section 3.5) |
| 7 | `0x80` | sealed envelope: sealed to recipient keys (section 5.3) |

A reader rejects a piece that sets both bit 4 and bit 7.

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

### 3.5 Hidden details

A set written with `--info none` keeps its details out of every manifest and shares
them the way it shares the content, so they are readable only from k pieces:

```
details = u8 flags || u8 k || u8 n || u8 cost || u8 layer count || 2 per layer
          || blob name || blob creator version || blob creator commit
          || zero padding || hash
hash    = BLAKE2b-256("riven-details-v1" || everything before it)
```

`flags` holds bits 0 to 3 of section 3.1. `cost` is the cost byte of section 4,
unmasked, when bit 3 is set, and zero otherwise. The other fields are as in the
manifest. The zero padding brings the whole, hash included, to a multiple of 256
bytes: the length of a details share is the one thing a piece shows of them, and
unpadded it would give away the length of the name and the number of layers. A
reader rejects padding that is not zero.

The details are split with the set's threshold exactly as section 6.2 describes;
they always fit one chunk. A reader does not know k, so it interpolates with every
distinct details share it holds: more shares than k give the same answer, and
fewer give noise that the hash rejects. Hidden details need k of 2 or more: at
k = 1 a share is a plain copy, which would show the details to anyone.

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
and the reader must be given the parameters. It is also random when the details
are hidden; the cost is then in the details (section 3.5).

## 5. Envelope key

32 bytes, used with XChaCha20-Poly1305. Which secrets seal it depends on
`--info`:

| `--info` | Envelope |
|----------|----------|
| `protected` (default) | the first layer's secret alone: its password (section 5.1, with that one password), or its recipient key (section 5.3, with that one key and no password) |
| `strict` | every password and every recipient key: section 5.1 with every password when the set has no recipient key, section 5.3 otherwise |
| `public`, `none` | the public key of section 5.2, as for a split-only set |

Nothing on the piece says which was used; a reader tries them (section 10).

### 5.1 Password envelope

```
seed = BLAKE2b-256("riven-pw-mix-v1" || for each password: u32 length || password)
key  = Argon2id(seed, salt, passes, memory, lanes, 32)
```

Passwords are mixed in layer order, outermost first. Length prefixing means
`{"ab","c"}` and `{"a","bc"}` cannot collide. A strict envelope mixes every
password of the set, and a protected one the first layer's alone.

### 5.2 Keyless envelope

Used by split-only sets, and by any set written with `--info public` or
`--info none`. The passwords and keys then key only the cascade layers (section
8), so nothing on a single piece depends on them.

```
key = BLAKE2b-256("riven-keyless-envelope-v1" || salt)
```

This key is public. Anyone holding this specification can open the envelope of
such a piece and read its manifest. The content, and its length, still need k
shares and, for a recipient set, the private keys. A reader tries this key first,
since it costs one hash and any set may use it.

### 5.3 Sealed envelope

Used by a strict set with recipient keys, with or without passwords, and by a
protected set whose first layer is a recipient key, sealed to that key alone with
no password; flag bit 7 is set. Each piece carries a fresh HPKE encapsulation to
every distinct recipient public key the envelope is sealed to, made as for a
recipient layer (section 8.2):

```
enc_i, ctx_i = HPKE.SetupBaseS(recipient public key i, info)
info         = "riven-recipient-v1:" || key type name
secret_i     = ctx_i.Export("riven-layer-key-v1", 32)
```

The recipients are taken once each, in ascending byte order of their serialized
public keys (section 11), not in layer order: a reader holding the private keys
can put them in that order without knowing the layers, which the envelope hides.
The encapsulated keys are joined and masked:

```
encs   = enc_1 || ... || enc_m
masked = encs XOR ChaCha20(key = BLAKE2b-256("riven-enc-mask-v1" || salt),
                           nonce = 12 zero bytes)
```

`masked` is what the header holds after the cost byte. The mask is public; it
keeps fixed bytes, such as a P-256 point's leading `0x04`, off the piece. The
envelope key binds the passwords, every secret and the encapsulated keys:

```
pw  = the key of section 5.1 over every password of a strict set, or empty
key = BLAKE2b-256("riven-sealed-envelope-v1" || salt || u8 len(pw) || pw
                  || u8 m || secret_1 || ... || secret_m || encs)
```

So opening any piece takes every private key and every password the envelope is
sealed to. The piece does not say how many encapsulated keys it carries or of
which types. A reader puts the private keys it was given in the order above,
sizes each encapsulated key from its key type (section 8.2), and tries them all,
then fewer, until the tag verifies.

## 6. Share

### 6.1 What is shared

The full method shares the payload itself; the compact method shares only what
opens the dispersed data (section 6.3):

```
full:     shared = u64(payload length) || payload || fill
compact:  shared = u64(72) || u64(sealed length) || key1(32) || key2(32) || fill
```

The sealed length is the length of `outer` in section 6.3.

The fill is at least 32 random bytes, plus whatever padding adds (section 7). For
the compact method the padding goes in the dispersed data instead, so its fill is
32 bytes. The payload hash covers all of it, so fewer than k pieces can neither
check a guess of the content against the hash nor tell the content from the
fill, even when the envelope is public (section 5.2).

### 6.2 Shamir sharing

The shared bytes are split with Shamir secret sharing over GF(2^8), the byte
field AES uses: addition is XOR, multiplication is modulo `0x11B`. Each byte `s`
gets its own random polynomial of degree k-1:

```
f(x) = s + a1*x + ... + a(k-1)*x^(k-1)      a1..a(k-1) uniformly random
```

A share is `f(x)` for every byte at one x-coordinate. The x-coordinates are
distinct and never zero. A byte is recovered from k shares `(xi, yi)` with

```
s = sum over i of ( yi * product over j != i of ( xj / (xi + xj) ) )
```

Fewer than k shares still produce an answer, just a wrong one, so a reader
checks the payload hash (section 10).

| Threshold | Share layout |
|-----------|--------------|
| k = 1 | the shared bytes themselves, no tag: every piece is a full copy |
| k >= 2, shared <= 524288 bytes | `bytes(shared length) \|\| u8 x-coordinate` |
| k >= 2, shared > 524288 bytes | one such share per 512 KiB chunk, concatenated |

Chunking exists so a large split can use every core. Chunks are 524288 bytes
except the last. The chunk count is not stored; it follows from the share length,
because a share of m chunks covering s shared bytes is `s + m` long with
`(m-1)*524288 < s <= m*524288`, which admits exactly one m:

```
m = ceil(shareLength / 524289)
```

Every share of a set has the same length. Each chunk is an independent sharing
with its own x-coordinates, so a reader must slice the shares chunk by chunk and
interpolate each chunk separately.

### 6.3 Compact method: package and fragments

The payload is sealed under two fresh random keys, followed by random fill
(section 7), and put through an all-or-nothing transform:

```
inner = nonce1(12) || AES-256-GCM(key1, nonce1, payload, "riven-compact-v1" || 0x01)
outer = nonce2(24) || XChaCha20-Poly1305(key2, nonce2, inner, "riven-compact-v1" || 0x03)
c     = (outer || fill) XOR ChaCha20(key3, nonce = 12 zero bytes, counter = 0)
data  = c || (key3 XOR BLAKE2b-256("riven-aont-v1" || c))
```

The nonces, the fill and key3 are random for every split. key3 is not stored: a
reader recovers it from the whole of the data, and only from the whole of it.
ChaCha20 is the RFC 8439 cipher. `outer` is the payload plus 68 bytes, and the
data is at least the payload plus 100.

The transform is also what authenticates the fill. A byte changed anywhere in the
data, fill and tail included, changes the hash or the tail, so key3 comes out
wrong, all of `outer` decrypts to noise, and XChaCha20-Poly1305 refuses it.

The data is dispersed so that any k of the n fragments rebuild it. It is read in
groups of k bytes; group j holds the coefficients of

```
p_j(X) = d[j*k] + d[j*k+1]*X + ... + d[j*k+k-1]*X^(k-1)
```

over the field of section 6.2. A fragment is a coordinate x followed by p_j(x)
for every group in order:

```
fragment = u8 x || p_0(x) || p_1(x) || ...
```

The coordinates are distinct, non-zero and drawn at random, so a fragment does not
say which piece it is. A reader takes any k fragments with coordinates x_1..x_k
and, for every group, solves the system with matrix entries `V[r][t] = x_r^t`,
which has exactly one solution because the coordinates are distinct. The result
is the data: undo the transform with its last 32 bytes, then the first `sealed
length` bytes are `outer`.

## 7. Padding

Padding hides the content length. The fill (section 6.1) grows until the piece
reaches the next size class: classes start at 256 bytes, and each is `--pad`
percent wider than the one below (a whole number, 1 by default, maximum 500):

```
size(0) = 256
size(i+1) = size(i) + max(1, size(i) * percent / 100)
```

The piece is measured with the minimum 32 bytes of fill, and the fill then grows
to reach the first class at or above that size. So every piece of a set is the
same size, and splitting the same input again produces that size again. Where no
fill length gives a share of exactly the right size, at a 512 KiB chunk boundary
(section 6.2), the piece lands one byte short of the class. `--pad none` keeps the
minimum fill.

The fill is shared, so padding works the same for a keyless envelope.

For the compact method the shared bytes have a fixed length, so the padding goes
in the dispersed data instead: the fill between `outer` and the transform's tail,
sized so the piece reaches its class exactly. Each extra group of k bytes adds
one byte to every fragment. With hidden details the details share is part of the
piece and counts toward its length like any other field.

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

Every layer writes `ciphertext || tag`. `twofish-256-gcm` is standard GCM with
Twofish in place of AES. `aes-256-ctr-hmac` is encrypt-then-MAC, with the nonce
as the initial counter block and `ad` the layer associated data (section 8.3):

```
encKey || macKey = HKDF-SHA-512(layer key, salt = empty, info = "riven-aes-ctr-hmac-v1"), 64 bytes
ciphertext       = AES-256-CTR(encKey, nonce) XOR plaintext
tag              = HMAC-SHA-256(macKey, u64 len(ad) || ad || u64 len(nonce) || nonce || ciphertext)
```

Id 0 is reserved for "not recorded" and is never assigned. Ids are permanent: a
number is never reused for a different algorithm. Two neighbouring layers may not
use the same algorithm.

The envelope always uses XChaCha20-Poly1305, whatever the layers use.

### 8.2 Layer keys

Password layer:

```
key = Argon2id(password, layer salt, passes, memory, lanes, 32)
```

using the set's cost: the one that opened a password envelope, otherwise the
cost byte (section 4), or the cost in the details when they are hidden. The
password for layer i is the i-th password supplied, counting password layers
only.

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
missing code explained. Page count is estimated at 44 lines per page, each of 32
base32 characters, roughly 880 piece bytes per page. A sheet running to more than
one page carries a warning to keep the pages together, and the print stylesheet
keeps the code, the instructions and the footer whole while letting the text block
flow. Pieces needing more than 16 pages are refused.

QR codes use byte mode at the strongest error correction level that fits: 1272
bytes at level H, 1662 at Q, 2330 at M, 2952 at L.

File names are `BASE.SERIAL` with the serial zero-padded to the width of n, plus
the extension above: `secret.pdf.1` for five pieces, `secret.pdf.01` for ten.

## 10. Reading a set

1. Read k pieces in any transport form and decode each to piece bytes.
2. For each piece, open the envelope: with the keyless key (section 5.2); sealed
   to the private keys alone (section 5.3); with the password key of the first
   password alone, then of every password (section 5.1), at the cost from the
   cost byte unless supplied separately; and sealed to the private keys and every
   password (section 5.3).
3. Check every manifest reports the same version, set id, flags, k, n and payload
   hash. Collect one piece per distinct serial, or with hidden details per
   distinct details share.
4. With hidden details, interpolate the details shares (section 3.5) to learn k,
   the flags, the cost, the layers and the name.
5. Interpolate k shares (section 6.2) to recover the shared bytes. Check them
   against the payload hash, then read the length from the first 8 bytes and take
   that many bytes after it. The rest is fill, and a length that leaves less than
   32 bytes of it is rejected. The hash is what detects a wrong or corrupt share,
   since interpolation below the threshold yields plausible bytes rather than an
   error.
6. For the full method those bytes are the payload. For the compact method they
   are the sealed length and the keys: rebuild the data from k fragments (section
   6.3), recover key3 from all of it, undo the transform, and open the two layers
   of `outer` to get the payload. A damaged byte anywhere in the data shows here,
   as a layer that does not open.
7. Peel the cascade (section 8) from the outermost layer inward.

Fewer than k pieces cannot complete step 5, at any computational cost. For the
compact method they also hold fewer than k fragments, so the data is incomplete
and key3 is unknown, with the two keyed layers behind it: reading any part of it
would need those ciphers broken.

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

The manifest carries a `u16` version, currently 2; the cascade header carries its
own, currently 1. A reader refuses a version it does not know rather than
guessing, so version 1 pieces are not read. Algorithm ids and key type names are
permanent and never reused.

> [!WARNING]
> Riven is in beta and the format is not yet stable. It may change without
> notice, and pieces written by one build are not guaranteed to open with
> another. Re-split anything important after upgrading.
