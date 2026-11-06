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

	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/wire"
)

// Version is the manifest schema version. A reader refuses a version it does not
// know rather than guessing at the layout.
const Version uint16 = 2

// MinFill is the least random fill shared after the payload. The payload hash
// covers it, so the hash cannot be checked against a guess of the content by
// anyone holding fewer than k shares, and the fill pads the piece as well.
const MinFill = 32

// PayloadAt is where the payload sits in the shared bytes: after its length, an
// 8-byte big-endian count.
const PayloadAt = 8

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
	// than a password. That is the case with no password at all, and also when a
	// password set chose to keep the password off its envelopes, so that one piece
	// cannot be used to test password guesses.
	flagKeyless = 1 << 4
	flagCompact = 1 << 5 // the set uses the compact method: the piece carries a fragment
	flagHidden  = 1 << 6 // the details are shared rather than written in the manifest
	// flagSealed marks an envelope sealed to recipient keys (section 5.3).
	// With it every bit of the byte has a meaning.
	flagSealed = 1 << 7

	// detailFlags are the flags that describe the set rather than the envelope.
	// A piece with hidden details keeps them in its shared details instead.
	detailFlags = flagEncrypted | flagHybrid | flagAlgoRecorded | flagKDFRecorded
)

// Manifest is the decrypted metadata plus Shamir share carried by one piece.
type Manifest struct {
	Version uint16
	SetID   []byte
	Serial  int // zero when the details are hidden

	// Details is what the piece says about its set, all zero when the details
	// are hidden. Params is the recorded cost, set only when KDFStored.
	Details

	Keyless      bool // the envelope opened with the public keyless key
	SealedToKeys bool // the envelope opened with the recipient keys
	// PasswordOpened says the envelope key was derived from a password, so the
	// cost that opened it is the set's. It is how the piece opened, not a field
	// the piece carries.
	PasswordOpened bool
	Compact        bool
	Hidden         bool
	PayloadHash    []byte

	// Share, Fragment and DetailsShare point into the opened manifest rather
	// than being copied out of it, since a share is as large as the input. Wipe
	// clears them.
	Share []byte

	// Fragment is this piece's part of the dispersed package, for a compact set;
	// empty otherwise.
	Fragment []byte

	// DetailsShare is this piece's share of the set's details, for a set that
	// hides them; empty otherwise. DecodeDetails reads what k of them rebuild.
	DetailsShare []byte

	plain []byte // the opened manifest the three above point into
}

// Wipe zeroes the opened manifest, which the share, the fragment and the details
// share point into, and drops all three. The other fields stay readable.
func (m *Manifest) Wipe() {
	memory.Zero(m.plain)
	m.plain, m.Share, m.Fragment, m.DetailsShare = nil, nil, nil, nil
}

// EncodeInput carries everything needed to write one piece.
type EncodeInput struct {
	// Details describes the set. Params is also the cost the envelope key is
	// derived with, and the cost is recorded only when a password is stretched.
	Details

	SetID       []byte
	Serial      int
	Keyless     bool // seal the envelope with the public keyless key, not a password
	PayloadHash []byte
	Share       []byte

	// Recipients, when set, seals the envelope to every one of these keys, once
	// each and in the order of their public key bytes, and to Passwords as well
	// when there are any (section 5.3).
	Recipients []*kem.PublicKey

	// Stretched says a password is stretched with Params somewhere in the set, so
	// the cost is worth recording. It is true whenever the envelope takes a
	// password, and also for a password set sealed with the keyless envelope.
	Stretched bool

	// Fragment is this piece's part of the dispersed package, for a compact set;
	// a piece that carries one is marked compact.
	Fragment []byte

	// DetailsShare, when set, is this piece's share of the set's details. The
	// manifest then leaves them out: k, n, serial, layers, name, creator, and the
	// flags that describe the set are all written as zero.
	DetailsShare []byte

	Passwords [][]byte // envelope passwords (all cascade passwords, in order)
}

// hidden reports whether the details are left out of the manifest.
func (in EncodeInput) hidden() bool { return len(in.DetailsShare) > 0 }

// stretched reports whether a password is stretched with Params: one of the
// set's layers says so, or the envelope itself takes a password.
func (in EncodeInput) stretched() bool { return in.Stretched || len(in.Passwords) > 0 }

// recordsCost reports whether the manifest says the cost is recorded: it was
// asked for, and a password is stretched with it.
func (in EncodeInput) recordsCost() bool { return in.KDFStored && in.stretched() }

// validate rejects an input that cannot describe a piece, before any randomness
// or key derivation is spent on it.
func (in EncodeInput) validate() error {
	if len(in.SetID) != setIDLen {
		return errors.New("format: set id must be 16 bytes")
	}
	if len(in.PayloadHash) != hashLen {
		return errors.New("format: payload hash must be 32 bytes")
	}
	if err := in.Details.validate(); err != nil {
		return err
	}
	if in.Serial < 1 || in.Serial > in.N {
		return errors.New("format: invalid k/n/serial")
	}
	if in.hidden() && !in.Keyless {
		return errors.New("format: hidden details need the keyless envelope")
	}
	if in.Keyless {
		if len(in.Passwords) > 0 || len(in.Recipients) > 0 {
			return errors.New("format: a keyless piece cannot have passwords or recipient keys")
		}
	} else if len(in.Passwords) == 0 && len(in.Recipients) == 0 {
		return errors.New("format: a password or a recipient key is required unless the piece is keyless")
	}
	if in.stretched() {
		return in.Params.Validate()
	}
	return nil
}

// costByte returns the masked Argon2id cost byte.
//
// The byte is masked either way, so a hidden configuration is a random byte that
// still decodes to a plausible value. A piece with no stretched password, or one
// whose details are hidden, carries nothing in it.
func (in EncodeInput) costByte(salt []byte) (byte, error) {
	if in.recordsCost() && !in.hidden() {
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

	// The header is everything before the nonce: the salt, the cost byte and, for
	// an envelope sealed to recipient keys, their masked encapsulations.
	header := append(append([]byte{}, salt...), kdfByte)
	var key []byte
	switch {
	case in.Keyless:
		key = keylessKey(salt)
	case len(in.Recipients) > 0:
		masked, k, err := sealTo(in.Recipients, in.Passwords, salt, in.Params)
		if err != nil {
			return nil, err
		}
		header, key = append(header, masked...), k
	default:
		key = envelopeKey(in.Passwords, salt, in.Params)
	}
	aead, err := chacha20poly1305.NewX(key)
	memory.Zero(key)
	if err != nil {
		return nil, err
	}

	body := in.manifest()
	out := make([]byte, 0, len(header)+nonceLen+len(body)+tagLen)
	out = append(out, header...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, body, envelopeAD(header))
	memory.Zero(body)
	return out, nil
}

// manifest writes the manifest of section 3. With hidden details, everything that
// describes the set is written as zero or empty, so a piece shows only that it
// belongs to a set and what it carries for it.
func (in EncodeInput) manifest() []byte {
	d, serial := in.Details, in.Serial
	d.KDFStored = in.recordsCost()
	flags := d.flags()
	if in.hidden() {
		d, serial, flags = Details{}, 0, flagHidden
	}
	if in.Keyless {
		flags |= flagKeyless
	}
	if len(in.Recipients) > 0 {
		flags |= flagSealed
	}
	if len(in.Fragment) > 0 {
		flags |= flagCompact
	}

	w := wire.NewWriter(len(in.Share) + len(in.Fragment) + len(in.DetailsShare) + 128)
	w.U16(Version)
	w.Raw(in.SetID)
	w.U8(uint8(d.K))
	w.U8(uint8(d.N))
	w.U8(uint8(serial))
	w.U8(flags)
	w.Raw(in.PayloadHash)
	d.writeMeta(w)
	w.Bytes(in.Share)
	w.Bytes(in.Fragment)
	w.Bytes(in.DetailsShare)
	return w.Result()
}

// ErrWrongPassword indicates the piece did not open with the given password and
// cost parameters.
var ErrWrongPassword = errors.New("format: wrong password, key or parameters, or not a riven piece")

// fixedManifestLen is the manifest overhead that does not depend on the share,
// the name, the creator strings, or the number of layers: version(2) + set
// id(16) + k/n/serial/flags(4) + payload hash(32) + layer count(1) + six length
// prefixes(24): name, creator version, creator commit, share, fragment, details.
const fixedManifestLen = 2 + setIDLen + 4 + hashLen + 1 + 24

// Shape is what decides a piece's length: the lengths of its variable fields.
// With hidden details the manifest carries no layers and no strings, so Layers
// and Meta are zero and Details is the length of the details share instead.
type Shape struct {
	Encaps   int // the encapsulated keys an envelope sealed to recipient keys carries
	Share    int
	Layers   int // layer descriptors written in the manifest
	Meta     int // name, creator version and creator commit together
	Fragment int
	Details  int
}

// PieceLen returns the exact encoded length of a piece of the given shape, without
// encoding it. The padding is chosen to reach a target size, so that target has to
// be known before the piece is built. The package tests assert this against real
// encodings.
func PieceLen(s Shape) int {
	return headerLen + s.Encaps + fixedManifestLen + 2*s.Layers + s.Meta + s.Share + s.Fragment + s.Details + tagLen
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
// apply to it, which are zero when none are known.
//
// The keyless envelope is tried first. It costs one hash, and a password set can
// use it too, so passwords being given does not mean the envelope takes them.
// When that fails and passwords were given, exactly one key derivation is
// performed, with override when it is non-nil and the recorded cost otherwise.
//
// For a keyless envelope the cost is the override, or the recorded cost byte
// when the manifest says it is real; for hidden details it comes from the
// details instead, which this function cannot read.
func Decode(piece []byte, passwords [][]byte, override *kdf.Params) (*Manifest, kdf.Params, error) {
	if err := checkDecode(piece, override); err != nil {
		return nil, kdf.Params{}, err
	}
	m, err := openAt(piece, 0, keylessKey(piece[:saltLen]))
	if err == nil {
		if !m.Keyless {
			m.Wipe()
			return nil, kdf.Params{}, errors.New("format: the piece opened with the keyless key but is not marked keyless")
		}
		params := m.Params
		if override != nil {
			params = *override
		}
		return m, params, nil
	}
	if !errors.Is(err, ErrWrongPassword) || len(passwords) == 0 {
		return nil, kdf.Params{}, err
	}
	return DecodePassword(piece, passwords, override)
}

// DecodePassword is Decode without the keyless attempt, for a piece of a set
// already known to seal its envelopes with passwords: it saves a full pass over
// the piece, and a keyless piece slipped in among them fails rather than opens.
func DecodePassword(piece []byte, passwords [][]byte, override *kdf.Params) (*Manifest, kdf.Params, error) {
	if len(passwords) == 0 {
		return nil, kdf.Params{}, ErrWrongPassword
	}
	if err := checkDecode(piece, override); err != nil {
		return nil, kdf.Params{}, err
	}
	params, _ := PeekParams(piece)
	if override != nil {
		params = *override
	}
	m, err := openAt(piece, 0, envelopeKey(passwords, piece[:saltLen], params))
	if err != nil {
		return nil, kdf.Params{}, err
	}
	if m.Keyless || m.SealedToKeys {
		m.Wipe()
		return nil, kdf.Params{}, errors.New("format: the piece opened with the password alone but is not marked so")
	}
	m.PasswordOpened = true
	return m, params, nil
}

// checkDecode rejects what no decode can use: a piece too short to be one, and
// an override that is not a valid cost.
func checkDecode(piece []byte, override *kdf.Params) error {
	if len(piece) < MinPieceLen {
		return ErrWrongPassword
	}
	if override != nil {
		return override.Validate()
	}
	return nil
}

// openAt opens the envelope with key, which it wipes, and parses the manifest.
// encLen is how many bytes of encapsulated keys sit between the cost byte and the
// nonce: none but for an envelope sealed to recipient keys. The manifest keeps
// the opened bytes, which its share points into.
func openAt(piece []byte, encLen int, key []byte) (*Manifest, error) {
	defer memory.Zero(key)
	header := saltLen + kdfLen + encLen
	if len(piece) < header+nonceLen+tagLen {
		return nil, ErrWrongPassword
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, piece[header:header+nonceLen], piece[header+nonceLen:], envelopeAD(piece[:header]))
	if err != nil {
		return nil, ErrWrongPassword
	}
	m, err := parseManifest(pt)
	if err != nil {
		memory.Zero(pt)
		return nil, err
	}
	if m.KDFStored {
		m.Params, _ = PeekParams(piece)
	}
	return m, nil
}

func parseManifest(pt []byte) (*Manifest, error) {
	r := newReader(pt)
	ver := r.u16()
	if r.err == nil && ver != Version {
		return nil, fmt.Errorf("format: unsupported piece version %d (this build writes and reads version %d)", ver, Version)
	}
	m := &Manifest{Version: ver, SetID: r.raw(setIDLen), plain: pt}
	k, n, serial, flags := r.u8(), r.u8(), r.u8(), r.u8()
	m.Details = Details{K: int(k), N: int(n)}
	m.setFlags(flags)
	m.Serial = int(serial)
	m.Keyless = flags&flagKeyless != 0
	m.SealedToKeys = flags&flagSealed != 0
	m.Compact = flags&flagCompact != 0
	m.Hidden = flags&flagHidden != 0
	m.PayloadHash = r.raw(hashLen)
	r.meta(&m.Details)
	m.Share, m.Fragment, m.DetailsShare = r.view(0), r.view(0), r.view(0)
	if r.err != nil {
		return nil, r.err
	}
	if r.Remaining() != 0 {
		return nil, errors.New("format: unexpected bytes after the details")
	}
	return m, m.check()
}

// check rejects a manifest whose fields contradict its flags.
func (m *Manifest) check() error {
	if m.Compact != (len(m.Fragment) > 0) {
		return errors.New("format: the fragment does not match the compact flag")
	}
	if m.SealedToKeys && m.Keyless {
		return errors.New("format: an envelope cannot be both keyless and sealed to keys")
	}
	if !m.Hidden {
		if len(m.DetailsShare) > 0 {
			return errors.New("format: details share in a manifest that shows its details")
		}
		if m.K < 1 || m.N < m.K || m.Serial < 1 || m.Serial > m.N {
			return errors.New("format: invalid k/n/serial in manifest")
		}
		return nil
	}
	if !m.Keyless || len(m.DetailsShare) == 0 {
		return errors.New("format: hidden details need the keyless envelope and a details share")
	}
	if m.Serial != 0 || !m.Details.empty() {
		return errors.New("format: a manifest with hidden details shows some of them")
	}
	return nil
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
// a password hashing cost would only waste time. Anyone holding this tool can
// open the envelope of such a piece and read what its manifest shows.
func keylessKey(salt []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("riven-keyless-envelope-v1"))
	h.Write(salt)
	return h.Sum(nil)
}

// envelopeAD binds the header, everything before the nonce, to the envelope.
func envelopeAD(header []byte) []byte {
	return append([]byte("riven-piece-v1"), header...)
}

// Hash returns the BLAKE2b-256 of b, used for payload identity and integrity.
func Hash(b []byte) []byte {
	h := blake2b.Sum256(b)
	return h[:]
}

// SharedLen returns the length of the shared bytes for a payload of payloadLen
// bytes followed by fill random bytes.
func SharedLen(payloadLen, fill int) int { return PayloadAt + payloadLen + fill }

// Wrap finishes shared bytes in place, around a payload of payloadLen bytes the
// caller wrote at shared[PayloadAt:]. It writes the length before the payload and
// random fill after it, at least MinFill bytes, and returns the hash every
// manifest of the set carries.
//
// The fill does two jobs. It pads, and because the length sits inside the shared
// bytes, fewer than k pieces cannot tell the payload from the fill even when the
// envelope is public. It also salts the hash, which would otherwise be a function
// of the content alone: a keyless piece would then let anyone confirm a guess of
// the content, reading a PIN or a short password straight off a single piece.
func Wrap(shared []byte, payloadLen int) (hash []byte, err error) {
	if fill := len(shared) - SharedLen(payloadLen, 0); payloadLen < 0 || fill < MinFill {
		return nil, fmt.Errorf("format: %d shared bytes leave under %d of fill after %d", len(shared), MinFill, payloadLen)
	}
	binary.BigEndian.PutUint64(shared, uint64(payloadLen))
	if _, err := rand.Read(shared[PayloadAt+payloadLen:]); err != nil {
		return nil, err
	}
	return Hash(shared), nil
}

// WrapPayload is Wrap for a payload held elsewhere: it returns new shared bytes
// with fill random bytes after the payload, and their hash.
func WrapPayload(payload []byte, fill int) (shared, hash []byte, err error) {
	shared = make([]byte, SharedLen(len(payload), fill))
	copy(shared[PayloadAt:], payload)
	if hash, err = Wrap(shared, len(payload)); err != nil {
		memory.Zero(shared)
		return nil, nil, err
	}
	return shared, hash, nil
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
	return shared[PayloadAt : PayloadAt+int(n)], true
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
