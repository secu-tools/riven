// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package format encodes and decodes a single Riven piece.
//
// On-disk a piece is:
//
//	salt(16) || kdf(1) || nonce(24) || XChaCha20-Poly1305(key, nonce, manifest) || tag(16)
//
// Every byte is uniform random (salt, nonce), a masked cost byte, or AEAD
// ciphertext. Nothing is in the clear: version, metadata and share all live
// inside the sealed manifest.
//
// The kdf byte holds the Argon2id cost masked by a keystream derived from the
// salt. Every byte value decodes to a plausible cost, so a random byte is
// indistinguishable from a recorded one. Recording is optional; when it is off
// the byte is random and the caller supplies the cost.
package format

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/secu-tools/riven/internal/cascade"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/wire"
)

// Version is the manifest schema version. A reader refuses a version it does not
// know rather than guessing at the layout. Version 2 moved the content length and
// the padding into the shared bytes.
const Version uint16 = 2

// MinFill is the least random fill shared after the payload. The payload hash
// covers it, so the hash cannot be checked against a guess of the content by
// anyone holding fewer than k shares, and the fill pads the piece as well.
const MinFill = 32

// lengthLen is the size of the payload length that starts the shared bytes.
const lengthLen = 8

// MaxNameLen bounds the recorded file name. Every piece carries it, so it is kept
// short enough that recording a name never decides whether a piece fits a QR code.
const MaxNameLen = 255

// MaxCreatorLen bounds the recorded program version and commit hash. They are
// small, fixed-shape build identifiers, not user data.
const MaxCreatorLen = 64

const (
	saltLen  = kdf.SaltLen
	kdfLen   = kdf.ParamsLen
	nonceLen = chacha20poly1305.NonceSizeX // 24
	tagLen   = chacha20poly1305.Overhead   // 16
	setIDLen = 16
	hashLen  = 32

	headerLen = saltLen + kdfLen + nonceLen

	// MinPieceLen is the smallest possible valid piece (empty manifest).
	MinPieceLen = headerLen + tagLen

	// SetIDLen is exported for callers that generate set identifiers.
	SetIDLen = setIDLen
)

// Flags recorded in the manifest.
const (
	flagEncrypted    = 1 << 0 // has one or more cascade layers
	flagHybrid       = 1 << 1 // has a KEM layer
	flagAlgoRecorded = 1 << 2 // cascade algorithm ids are recorded
	flagKDFRecorded  = 1 << 3 // the kdf byte holds real parameters
	// flagKeyless marks an envelope sealed with the public keyless key rather
	// than a password. On its own that means only the threshold protects the
	// content; combined with flagHybrid it means the reader needs the recipient
	// private key instead of a password.
	flagKeyless = 1 << 4
)

// Manifest is the decrypted metadata plus Shamir share carried by one piece.
type Manifest struct {
	Version     uint16
	SetID       []byte
	K           int
	N           int
	Serial      int
	Encrypted   bool
	Hybrid      bool
	AlgoStored  bool
	KDFStored   bool
	Keyless     bool
	PayloadHash []byte
	Layers      []cascade.Descriptor
	Share       []byte

	// Name is the original file name, empty when it was not recorded. It is
	// untrusted: it comes from whoever wrote the piece. Callers that turn it into
	// a path must reduce it to a base name first.
	Name string

	// CreatorVersion and CreatorCommit identify the build that wrote the piece.
	// They are diagnostic only: they let a version mismatch be reported to the
	// user instead of failing with no explanation.
	CreatorVersion string
	CreatorCommit  string
}

// EncodeInput carries everything needed to write one piece.
type EncodeInput struct {
	SetID       []byte
	K           int
	N           int
	Serial      int
	Encrypted   bool
	Hybrid      bool
	RecordAlgo  bool
	RecordKDF   bool
	Keyless     bool // seal the envelope with the public keyless key, not a password
	PayloadHash []byte
	Layers      []cascade.Descriptor
	Share       []byte
	Name        string // original file name, empty to record none

	// CreatorVersion and CreatorCommit identify the build writing the piece. Set
	// by the caller from its own build info; not user-configurable.
	CreatorVersion string
	CreatorCommit  string

	Passwords [][]byte // envelope passwords (all cascade passwords, in order)
	Params    kdf.Params
}

// validate rejects an input that cannot describe a piece, before any randomness
// or key derivation is spent on it.
func (in EncodeInput) validate() error {
	if len(in.SetID) != setIDLen {
		return errors.New("format: set id must be 16 bytes")
	}
	if len(in.PayloadHash) != hashLen {
		return errors.New("format: payload hash must be 32 bytes")
	}
	if in.K < 1 || in.N < in.K || in.N > 255 || in.Serial < 1 || in.Serial > in.N {
		return errors.New("format: invalid k/n/serial")
	}
	if len(in.Name) > MaxNameLen {
		return fmt.Errorf("format: recorded name is %d bytes, the limit is %d", len(in.Name), MaxNameLen)
	}
	if len(in.CreatorVersion) > MaxCreatorLen || len(in.CreatorCommit) > MaxCreatorLen {
		return fmt.Errorf("format: creator version/commit exceed %d bytes", MaxCreatorLen)
	}
	if in.Keyless {
		if len(in.Passwords) > 0 {
			return errors.New("format: a keyless piece cannot have passwords")
		}
		return nil
	}
	if len(in.Passwords) == 0 {
		return errors.New("format: a password is required unless the piece is keyless")
	}
	return in.Params.Validate()
}

// costByte returns the masked Argon2id cost byte.
//
// The byte is masked either way, so a hidden configuration is a random byte that
// still decodes to a plausible value. A keyless piece derives no key from a
// password, so its byte carries nothing.
func (in EncodeInput) costByte(salt []byte) (byte, error) {
	if in.RecordKDF && !in.Keyless {
		enc, err := in.Params.Encode()
		if err != nil {
			return 0, err
		}
		return kdf.MaskParams(enc, salt), nil
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// flags packs the manifest flag byte.
func (in EncodeInput) flags() uint8 {
	var f uint8
	if in.Encrypted {
		f |= flagEncrypted
	}
	if in.Hybrid {
		f |= flagHybrid
	}
	if in.RecordAlgo {
		f |= flagAlgoRecorded
	}
	if in.RecordKDF && !in.Keyless {
		f |= flagKDFRecorded
	}
	if in.Keyless {
		f |= flagKeyless
	}
	return f
}

// Encode produces the on-disk bytes for one piece.
func Encode(in EncodeInput) ([]byte, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}

	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	kdfByte, err := in.costByte(salt)
	if err != nil {
		return nil, err
	}

	flags := in.flags()

	w := wire.NewWriter(len(in.Share) + 128)
	w.U16(Version)
	w.Raw(in.SetID)
	w.U8(uint8(in.K))
	w.U8(uint8(in.N))
	w.U8(uint8(in.Serial))
	w.U8(flags)
	w.Raw(in.PayloadHash)
	w.U8(uint8(len(in.Layers)))
	for _, d := range in.Layers {
		w.U8(uint8(d.Kind))
		if in.RecordAlgo {
			w.U8(d.SchemeID)
		} else {
			w.U8(0)
		}
	}
	w.Bytes([]byte(in.Name))
	w.Bytes([]byte(in.CreatorVersion))
	w.Bytes([]byte(in.CreatorCommit))
	w.Bytes(in.Share)
	body := w.Result()

	var key []byte
	if in.Keyless {
		key = keylessKey(salt)
	} else {
		key = envelopeKey(in.Passwords, salt, in.Params)
	}
	aead, err := chacha20poly1305.NewX(key)
	memory.Zero(key)
	if err != nil {
		memory.Zero(body)
		return nil, err
	}

	out := make([]byte, 0, headerLen+len(body)+tagLen)
	out = append(out, salt...)
	out = append(out, kdfByte)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, body, envelopeAD(salt, kdfByte))
	memory.Zero(body)
	return out, nil
}

// ErrWrongPassword indicates the piece did not open with the given password and
// cost parameters.
var ErrWrongPassword = errors.New("format: wrong password or parameters, or not a riven piece")

// fixedManifestLen is the manifest overhead that does not depend on the share,
// the name, the creator strings, or the number of layers: version(2) + set
// id(16) + k/n/serial/flags(4) + payload hash(32) + layer count(1) + four length
// prefixes(16): name, creator version, creator commit, share.
const fixedManifestLen = 2 + setIDLen + 4 + hashLen + 1 + 16

// PieceLen returns the exact encoded length of a piece, without encoding it. The
// padding is chosen to reach a target size, so that target has to be known before
// the piece is built. metaLen is the combined length of the name and creator
// version/commit strings. The package tests assert this against real encodings.
func PieceLen(shareLen, layerCount, metaLen int) int {
	return headerLen + fixedManifestLen + 2*layerCount + metaLen + shareLen + tagLen
}

// PeekParams reports the cost parameters a piece declares, without deriving a
// key. The value is unauthenticated: for a file of unknown origin it is simply
// whatever the bytes decode to, which is how callers can warn about an expensive
// open before committing to it. It returns false if the input is too short.
func PeekParams(piece []byte) (kdf.Params, bool) {
	if len(piece) < MinPieceLen {
		return kdf.Params{}, false
	}
	return kdf.DecodeParams(kdf.MaskParams(piece[saltLen], piece[:saltLen])), true
}

// Decode opens a piece and returns its manifest plus the cost parameters that
// worked. Supplying no passwords opens the piece as keyless, which needs no key
// derivation at all. Otherwise, when override is non-nil those parameters are
// used and otherwise they are read from the masked cost byte, and exactly one key
// derivation is performed.
func Decode(piece []byte, passwords [][]byte, override *kdf.Params) (*Manifest, kdf.Params, error) {
	if len(piece) < MinPieceLen {
		return nil, kdf.Params{}, ErrWrongPassword
	}
	salt := piece[:saltLen]
	kdfByte := piece[saltLen]
	nonce := piece[saltLen+kdfLen : headerLen]
	body := piece[headerLen:]

	var params kdf.Params
	var key []byte
	if len(passwords) == 0 {
		key = keylessKey(salt)
	} else {
		params = kdf.DecodeParams(kdf.MaskParams(kdfByte, salt))
		if override != nil {
			if err := override.Validate(); err != nil {
				return nil, kdf.Params{}, err
			}
			params = *override
		}
		key = envelopeKey(passwords, salt, params)
	}
	aead, err := chacha20poly1305.NewX(key)
	memory.Zero(key)
	if err != nil {
		return nil, kdf.Params{}, err
	}
	pt, err := aead.Open(nil, nonce, body, envelopeAD(salt, kdfByte))
	if err != nil {
		return nil, kdf.Params{}, ErrWrongPassword
	}
	m, perr := parseManifest(pt)
	memory.Zero(pt)
	if perr != nil {
		return nil, kdf.Params{}, perr
	}
	return m, params, nil
}

func parseManifest(pt []byte) (*Manifest, error) {
	r := wire.NewReader(pt)
	ver, err := r.U16()
	if err != nil {
		return nil, err
	}
	if ver != Version {
		return nil, fmt.Errorf("format: unsupported piece version %d (this build writes and reads version %d)", ver, Version)
	}
	setID, err := r.Raw(setIDLen)
	if err != nil {
		return nil, err
	}
	k, err := r.U8()
	if err != nil {
		return nil, err
	}
	n, err := r.U8()
	if err != nil {
		return nil, err
	}
	serial, err := r.U8()
	if err != nil {
		return nil, err
	}
	flags, err := r.U8()
	if err != nil {
		return nil, err
	}
	payloadHash, err := r.Raw(hashLen)
	if err != nil {
		return nil, err
	}
	layerCount, err := r.U8()
	if err != nil {
		return nil, err
	}
	algoStored := flags&flagAlgoRecorded != 0
	layers := make([]cascade.Descriptor, layerCount)
	for i := 0; i < int(layerCount); i++ {
		kind, err := r.U8()
		if err != nil {
			return nil, err
		}
		id, err := r.U8()
		if err != nil {
			return nil, err
		}
		layers[i] = cascade.Descriptor{
			Kind:     cascade.Kind(kind),
			SchemeID: id,
			Recorded: algoStored,
		}
	}
	name, err := r.Bytes(MaxNameLen)
	if err != nil {
		return nil, err
	}
	creatorVersionRaw, err := r.Bytes(MaxCreatorLen)
	if err != nil {
		return nil, err
	}
	creatorCommitRaw, err := r.Bytes(MaxCreatorLen)
	if err != nil {
		return nil, err
	}
	share, err := r.Bytes(0)
	if err != nil {
		return nil, err
	}
	if r.Remaining() != 0 {
		return nil, errors.New("format: unexpected bytes after the share")
	}

	if k < 1 || n < k || serial < 1 || serial > n {
		return nil, errors.New("format: invalid k/n/serial in manifest")
	}

	return &Manifest{
		Version:        ver,
		SetID:          setID,
		K:              int(k),
		N:              int(n),
		Serial:         int(serial),
		Encrypted:      flags&flagEncrypted != 0,
		Hybrid:         flags&flagHybrid != 0,
		AlgoStored:     algoStored,
		KDFStored:      flags&flagKDFRecorded != 0,
		Keyless:        flags&flagKeyless != 0,
		PayloadHash:    payloadHash,
		Layers:         layers,
		Share:          share,
		Name:           string(name),
		CreatorVersion: safeCreator(creatorVersionRaw),
		CreatorCommit:  safeCreator(creatorCommitRaw),
	}, nil
}

// envelopeKey derives the per-piece envelope key from all envelope passwords and
// the piece salt.
func envelopeKey(passwords [][]byte, salt []byte, p kdf.Params) []byte {
	seed := kdf.MixPasswords(passwords)
	key := p.Derive(seed, salt)
	memory.Zero(seed)
	return key
}

// keylessKey derives the envelope key for a piece that carries no password. The
// derivation is public and deliberately cheap: there is no secret to stretch, so
// a password hashing cost would only waste time. Confidentiality of the content
// comes entirely from the Shamir threshold, and anyone holding this tool can
// open the envelope of such a piece and read its metadata.
func keylessKey(salt []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("riven-keyless-envelope-v1"))
	h.Write(salt)
	return h.Sum(nil)
}

func envelopeAD(salt []byte, kdfByte byte) []byte {
	ad := make([]byte, 0, 14+len(salt)+1)
	ad = append(ad, "riven-piece-v1"...)
	ad = append(ad, salt...)
	ad = append(ad, kdfByte)
	return ad
}

// Hash returns the BLAKE2b-256 of b, used for payload identity and integrity.
func Hash(b []byte) []byte {
	h := blake2b.Sum256(b)
	return h[:]
}

// SharedLen returns the length of the shared bytes for a payload of payloadLen
// bytes followed by fill random bytes.
func SharedLen(payloadLen, fill int) int { return lengthLen + payloadLen + fill }

// WrapPayload returns what is shared for payload, and the hash every manifest of
// the set carries. The shared bytes are the payload length (8 bytes, big-endian),
// the payload, then fill random bytes, at least MinFill.
//
// The fill does two jobs. It pads, and because the length sits inside the shared
// bytes, fewer than k pieces cannot tell the payload from the fill even when the
// envelope is public. It also salts the hash, which would otherwise be a function
// of the content alone: a keyless piece would then let anyone confirm a guess of
// the content, reading a PIN or a short password straight off a single piece.
func WrapPayload(payload []byte, fill int) (shared, hash []byte, err error) {
	if fill < MinFill {
		return nil, nil, fmt.Errorf("format: fill of %d bytes is under the minimum %d", fill, MinFill)
	}
	shared = make([]byte, SharedLen(len(payload), fill))
	binary.BigEndian.PutUint64(shared, uint64(len(payload)))
	copy(shared[lengthLen:], payload)
	if _, err := rand.Read(shared[lengthLen+len(payload):]); err != nil {
		memory.Zero(shared)
		return nil, nil, err
	}
	return shared, Hash(shared), nil
}

// UnwrapPayload checks reconstructed shared bytes against the manifest's hash and
// returns the payload they carry, which aliases shared. It reports false when the
// hash does not match, which is how a wrong or corrupt share is detected, or when
// the recorded length leaves less than MinFill.
func UnwrapPayload(shared, hash []byte) ([]byte, bool) {
	if len(shared) < SharedLen(0, MinFill) || !bytes.Equal(Hash(shared), hash) {
		return nil, false
	}
	n := binary.BigEndian.Uint64(shared)
	if n > uint64(len(shared)-SharedLen(0, MinFill)) {
		return nil, false
	}
	return shared[lengthLen : lengthLen+int(n)], true
}

// safeCreator reduces a recorded build identifier to characters that are safe to
// print. The field comes from whoever wrote the piece, and a keyless piece can be
// written by anyone, so raw bytes would let a crafted file drive the reader's
// terminal with escape sequences. A version string and a commit hash are printable
// ASCII, so anything else is replaced rather than passed through.
func safeCreator(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		out[i] = c
	}
	return string(out)
}
