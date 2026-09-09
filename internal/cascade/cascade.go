// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package cascade applies zero or more independent AEAD layers to a payload.
// Layer 0 (the first entry) is the outermost shell and is peeled first on
// decrypt; each layer uses its own scheme, salt or KEM material, nonce, and key.
// A layer is keyed by a password (Argon2id) or by a secret encapsulated to a
// recipient public key. Zero layers still produces a well-formed payload.
//
// Recording the scheme identifiers is optional. When they are omitted the
// payload carries only the per-layer salts and nonces, and the caller must
// supply the algorithm list to decrypt.
package cascade

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/wire"
)

// Version is the cascade header schema version. A reader refuses a version it
// does not know rather than guessing at the layout.
const Version uint16 = 1

const (
	maxLayers   = 255
	maxSaltLen  = 64
	maxNonceLen = 64
	maxKEMCtLen = 4096

	// schemeHidden marks a layer whose algorithm was not recorded.
	schemeHidden uint8 = 0
)

// Kind distinguishes how a layer's key is derived.
type Kind uint8

const (
	// Password keys the layer from a password via Argon2id.
	Password Kind = 0
	// KEM keys the layer from a secret encapsulated to a recipient public key.
	KEM Kind = 1
)

// Layer describes one encryption step.
type Layer struct {
	Kind     Kind
	SchemeID uint8

	Password []byte // Password layers

	KEMSecret     []byte // KEM layers (encrypt side): the shared secret
	KEMCiphertext []byte // KEM layers: ciphertext stored in the header
}

// Descriptor is public metadata about a layer. SchemeID is zero and Recorded is
// false when the algorithm was not written into the payload. KEMCiphertextLen is
// the length of the stored encapsulated key, which identifies the recipient key
// type on a KEM layer.
type Descriptor struct {
	Kind             Kind
	SchemeID         uint8
	Recorded         bool
	KEMCiphertextLen int
}

// Decapsulator recovers a KEM shared secret from a stored ciphertext. Several may
// be supplied: a shared secret cannot be checked on its own, because a mechanism
// returns an unrelated secret rather than an error for a key that does not match,
// so each candidate is tried until one produces a layer that authenticates.
type Decapsulator func(ciphertext []byte) ([]byte, error)

// Encrypt wraps plaintext in the given layers and returns a self-describing
// payload (header followed by the outermost ciphertext). plaintext is not
// modified. When recordSchemes is false the algorithm identifiers are omitted.
func Encrypt(plaintext []byte, layers []Layer, params kdf.Params, recordSchemes bool) ([]byte, error) {
	if len(layers) > maxLayers {
		return nil, fmt.Errorf("cascade: too many layers (%d > %d)", len(layers), maxLayers)
	}

	type applied struct {
		kind     Kind
		schemeID uint8
		salt     []byte
		nonce    []byte
		kemCt    []byte
	}
	descs := make([]applied, len(layers))

	ct := append([]byte(nil), plaintext...)
	// Apply innermost (highest index) first so layer 0 ends up outermost.
	for i := len(layers) - 1; i >= 0; i-- {
		scheme, ok := ciphers.ByID(layers[i].SchemeID)
		if !ok {
			memory.Zero(ct)
			return nil, fmt.Errorf("cascade: unknown scheme id %d", layers[i].SchemeID)
		}
		nonce := make([]byte, scheme.NonceLen)
		if _, err := rand.Read(nonce); err != nil {
			memory.Zero(ct)
			return nil, err
		}

		var key, salt, kemCt []byte
		switch layers[i].Kind {
		case Password:
			salt = make([]byte, kdf.SaltLen)
			if _, err := rand.Read(salt); err != nil {
				memory.Zero(ct)
				return nil, err
			}
			key = params.Derive(layers[i].Password, salt)
		case KEM:
			var err error
			key, err = kemKey(layers[i].KEMSecret)
			if err != nil {
				memory.Zero(ct)
				return nil, err
			}
			kemCt = layers[i].KEMCiphertext
		default:
			memory.Zero(ct)
			return nil, fmt.Errorf("cascade: unknown layer kind %d", layers[i].Kind)
		}

		aead, err := scheme.New(key)
		memory.Zero(key)
		if err != nil {
			memory.Zero(ct)
			return nil, err
		}
		sealed := aead.Seal(nil, nonce, ct, layerAD(scheme.ID))
		memory.Zero(ct)
		ct = sealed

		stored := scheme.ID
		if !recordSchemes {
			stored = schemeHidden
		}
		descs[i] = applied{kind: layers[i].Kind, schemeID: stored, salt: salt, nonce: nonce, kemCt: kemCt}
	}

	w := wire.NewWriter(len(ct) + 64)
	w.U16(Version)
	w.U8(uint8(len(layers)))
	for _, d := range descs {
		w.U8(uint8(d.kind))
		w.U8(d.schemeID)
		w.Bytes(d.salt)
		w.Bytes(d.nonce)
		w.Bytes(d.kemCt)
	}
	w.Raw(ct)
	return w.Result(), nil
}

// Decrypt reverses Encrypt. Passwords for the Password layers are supplied in
// order via passwords; decap recovers shared secrets for KEM layers (nil when
// there are none). schemes supplies the per-layer algorithm ids for payloads
// that did not record them, and may be nil otherwise. The returned plaintext is
// caller-owned.
func Decrypt(payload []byte, passwords [][]byte, decaps []Decapsulator, params kdf.Params, schemes []uint8) ([]byte, error) {
	layers, ct, err := parse(payload)
	if err != nil {
		return nil, err
	}
	if err := checkPasswordCount(layers, passwords); err != nil {
		return nil, err
	}
	if err := checkSchemes(layers, schemes); err != nil {
		return nil, err
	}

	cur := ct
	pwIdx := 0
	for i, l := range layers {
		scheme, err := layerScheme(l, schemes, i)
		if err != nil {
			return nil, err
		}

		var pt []byte
		switch l.kind {
		case Password:
			pt, err = openPasswordLayer(l, scheme, cur, passwords[pwIdx], params)
			pwIdx++
		case KEM:
			pt, err = openKEMLayer(l, scheme, cur, decaps, i)
		default:
			err = fmt.Errorf("cascade: unknown layer kind %d", l.kind)
		}
		if err != nil {
			return nil, err
		}

		if i > 0 {
			memory.Zero(cur)
		}
		cur = pt
	}
	return cur, nil
}

// checkPasswordCount rejects a password list that does not match the payload,
// which is a clearer failure than an authentication error would be.
func checkPasswordCount(layers []layerDesc, passwords [][]byte) error {
	want := 0
	for _, l := range layers {
		if l.kind == Password {
			want++
		}
	}
	if len(passwords) != want {
		return fmt.Errorf("cascade: need %d passwords, got %d", want, len(passwords))
	}
	return nil
}

// layerScheme resolves the algorithm for one layer, taking it from the payload
// or, for a layer that did not record it, from the supplied list. The nonce
// length is checked here because it is the one cheap way to catch a wrong
// algorithm before spending a key derivation on it.
func layerScheme(l layerDesc, schemes []uint8, i int) (ciphers.Scheme, error) {
	id := l.schemeID
	if id == schemeHidden {
		id = schemes[i]
	}
	scheme, ok := ciphers.ByID(id)
	if !ok {
		return ciphers.Scheme{}, fmt.Errorf("cascade: unknown scheme id %d", id)
	}
	if len(l.nonce) != scheme.NonceLen {
		return ciphers.Scheme{}, fmt.Errorf("cascade: layer %d is not %s (nonce length mismatch)", i+1, scheme.Name)
	}
	return scheme, nil
}

// openPasswordLayer peels one Argon2id-keyed layer.
func openPasswordLayer(l layerDesc, scheme ciphers.Scheme, ct, password []byte, params kdf.Params) ([]byte, error) {
	key := params.Derive(password, l.salt)
	aead, err := scheme.New(key)
	memory.Zero(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, l.nonce, ct, layerAD(scheme.ID))
	if err != nil {
		return nil, ErrWrongPassword
	}
	return pt, nil
}

// openKEMLayer peels one recipient-keyed layer by trying each supplied key.
//
// A shared secret cannot be checked on its own: a mechanism returns an unrelated
// secret rather than an error for a key that does not match, so the AEAD tag is
// what decides. The last decapsulation error is kept and reported, because it
// explains a mismatched key type, which is the likely reason for supplying the
// wrong key file.
func openKEMLayer(l layerDesc, scheme ciphers.Scheme, ct []byte, decaps []Decapsulator, i int) ([]byte, error) {
	if len(decaps) == 0 {
		return nil, fmt.Errorf("%w: layer %d", ErrKeyRequired, i+1)
	}
	var lastDecapErr error
	for _, d := range decaps {
		ss, err := d(l.kemCt)
		if err != nil {
			lastDecapErr = err
			continue // wrong key type, or malformed ciphertext
		}
		key, err := kemKey(ss)
		memory.Zero(ss)
		if err != nil {
			return nil, err
		}
		aead, err := scheme.New(key)
		memory.Zero(key)
		if err != nil {
			return nil, err
		}
		if pt, err := aead.Open(nil, l.nonce, ct, layerAD(scheme.ID)); err == nil {
			return pt, nil
		}
	}
	if lastDecapErr != nil {
		return nil, fmt.Errorf("%w: layer %d: %v", ErrKeyRequired, i+1, lastDecapErr)
	}
	return nil, fmt.Errorf("%w: layer %d is keyed to a recipient key that was not supplied", ErrKeyRequired, i+1)
}

// ErrWrongPassword indicates a layer failed to authenticate (wrong password,
// key, or algorithm, wrong ordering, or corrupted payload).
var ErrWrongPassword = errors.New("cascade: decryption failed (wrong password, key, or algorithm)")

// ErrSchemesRequired indicates the payload did not record its algorithms and
// the caller did not supply them.
var ErrSchemesRequired = errors.New("cascade: algorithms were not recorded and none were supplied")

// ErrKeyRequired indicates a KEM layer could not be opened by any supplied
// recipient private key.
var ErrKeyRequired = errors.New("cascade: a recipient private key is required")

// checkSchemes verifies that supplied algorithm ids cover every hidden layer.
func checkSchemes(layers []layerDesc, schemes []uint8) error {
	hidden := 0
	for _, l := range layers {
		if l.schemeID == schemeHidden {
			hidden++
		}
	}
	if hidden == 0 {
		return nil
	}
	if len(schemes) == 0 {
		return ErrSchemesRequired
	}
	if len(schemes) != len(layers) {
		return fmt.Errorf("cascade: this payload has %d layers, got %d algorithms", len(layers), len(schemes))
	}
	return nil
}

// Descriptors returns per-layer public metadata for display, without decrypting.
func Descriptors(payload []byte) ([]Descriptor, error) {
	layers, _, err := parse(payload)
	if err != nil {
		return nil, err
	}
	out := make([]Descriptor, len(layers))
	for i, l := range layers {
		out[i] = Descriptor{
			Kind:             l.kind,
			SchemeID:         l.schemeID,
			Recorded:         l.schemeID != schemeHidden,
			KEMCiphertextLen: len(l.kemCt),
		}
	}
	return out, nil
}

type layerDesc struct {
	kind     Kind
	schemeID uint8
	salt     []byte
	nonce    []byte
	kemCt    []byte
}

func parse(payload []byte) ([]layerDesc, []byte, error) {
	r := wire.NewReader(payload)
	ver, err := r.U16()
	if err != nil {
		return nil, nil, err
	}
	if ver != Version {
		return nil, nil, fmt.Errorf("cascade: unsupported header version %d", ver)
	}
	n, err := r.U8()
	if err != nil {
		return nil, nil, err
	}
	layers := make([]layerDesc, n)
	for i := 0; i < int(n); i++ {
		kind, err := r.U8()
		if err != nil {
			return nil, nil, err
		}
		id, err := r.U8()
		if err != nil {
			return nil, nil, err
		}
		salt, err := r.Bytes(maxSaltLen)
		if err != nil {
			return nil, nil, err
		}
		nonce, err := r.Bytes(maxNonceLen)
		if err != nil {
			return nil, nil, err
		}
		kemCt, err := r.Bytes(maxKEMCtLen)
		if err != nil {
			return nil, nil, err
		}
		layers[i] = layerDesc{kind: Kind(kind), schemeID: id, salt: salt, nonce: nonce, kemCt: kemCt}
	}
	return layers, r.Rest(), nil
}

func kemKey(ss []byte) ([]byte, error) {
	if len(ss) == 0 {
		return nil, errors.New("cascade: empty KEM shared secret")
	}
	r := hkdf.New(sha256.New, ss, nil, []byte("riven-kem-layer-v1"))
	k := make([]byte, 32)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, err
	}
	return k, nil
}

func layerAD(schemeID uint8) []byte {
	return []byte{'r', 'i', 'v', 'e', 'n', '-', 'c', 'a', 's', 'c', schemeID}
}
