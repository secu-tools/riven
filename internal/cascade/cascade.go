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
	"crypto/cipher"
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
// false when the algorithm was not written into the payload.
type Descriptor struct {
	Kind     Kind
	SchemeID uint8
	Recorded bool
}

// Decapsulator recovers a KEM shared secret from a stored ciphertext. Several may
// be supplied: a shared secret cannot be checked on its own, because a mechanism
// returns an unrelated secret rather than an error for a key that does not match,
// so each candidate is tried until one produces a layer that authenticates.
type Decapsulator func(ciphertext []byte) ([]byte, error)

// Len returns the length of the payload EncryptTo writes from n bytes of
// plaintext under layers.
func Len(n int, layers []Layer) (int, error) {
	schemes, err := resolve(layers)
	if err != nil {
		return 0, err
	}
	hdr, ct := lengths(n, layers, schemes)
	return hdr + ct, nil
}

// EncryptTo is Encrypt writing the payload into dst, which must be exactly Len
// bytes, so a caller can have it land where it is used next. Every layer seals in
// place, so nothing else the size of the plaintext is allocated. On an error dst
// is wiped.
func EncryptTo(dst, plaintext []byte, layers []Layer, params kdf.Params, recordSchemes bool) error {
	schemes, err := resolve(layers)
	if err != nil {
		return err
	}
	hdr, ct := lengths(len(plaintext), layers, schemes)
	if len(dst) != hdr+ct {
		return fmt.Errorf("cascade: payload buffer is %d bytes, need %d", len(dst), hdr+ct)
	}
	fail := func(err error) error {
		memory.Zero(dst)
		return err
	}

	type applied struct {
		schemeID uint8
		salt     []byte
		nonce    []byte
	}
	descs := make([]applied, len(layers))

	// The body grows by a tag per layer into the room dst leaves after it. Apply
	// innermost (highest index) first so layer 0 ends up outermost.
	body := dst[hdr : hdr+len(plaintext)]
	copy(body, plaintext)
	for i := len(layers) - 1; i >= 0; i-- {
		nonce := make([]byte, schemes[i].NonceLen)
		if _, err := rand.Read(nonce); err != nil {
			return fail(err)
		}
		var salt []byte
		if layers[i].Kind == Password {
			salt = make([]byte, kdf.SaltLen)
			if _, err := rand.Read(salt); err != nil {
				return fail(err)
			}
		}
		aead, err := layerAEAD(layers[i], schemes[i], salt, params)
		if err != nil {
			return fail(err)
		}
		body = aead.Seal(body[:0], nonce, body, layerAD(schemes[i].ID))

		stored := schemes[i].ID
		if !recordSchemes {
			stored = schemeHidden
		}
		descs[i] = applied{schemeID: stored, salt: salt, nonce: nonce}
	}

	w := wire.NewWriter(hdr)
	w.U16(Version)
	w.U8(uint8(len(layers)))
	for i, d := range descs {
		w.U8(uint8(layers[i].Kind))
		w.U8(d.schemeID)
		w.Bytes(d.salt)
		w.Bytes(d.nonce)
		w.Bytes(kemCiphertext(layers[i]))
	}
	if len(w.Result()) != hdr {
		return fail(errors.New("cascade: header length does not match its layers"))
	}
	copy(dst, w.Result())
	return nil
}

// resolve looks up every layer's algorithm, rejecting what Encrypt cannot apply.
func resolve(layers []Layer) ([]ciphers.Scheme, error) {
	if len(layers) > maxLayers {
		return nil, fmt.Errorf("cascade: too many layers (%d > %d)", len(layers), maxLayers)
	}
	schemes := make([]ciphers.Scheme, len(layers))
	for i, l := range layers {
		scheme, ok := ciphers.ByID(l.SchemeID)
		if !ok {
			return nil, fmt.Errorf("cascade: unknown scheme id %d", l.SchemeID)
		}
		if l.Kind != Password && l.Kind != KEM {
			return nil, fmt.Errorf("cascade: unknown layer kind %d", l.Kind)
		}
		schemes[i] = scheme
	}
	return schemes, nil
}

// lengths returns the header length and the ciphertext length for n bytes of
// plaintext: per layer a kind, an id and three length-prefixed fields (salt,
// nonce, encapsulated key), and a tag on the ciphertext.
func lengths(n int, layers []Layer, schemes []ciphers.Scheme) (hdr, ct int) {
	hdr, ct = 2+1, n
	for i, l := range layers {
		hdr += 2 + 3*4 + schemes[i].NonceLen + len(kemCiphertext(l))
		if l.Kind == Password {
			hdr += kdf.SaltLen
		}
		ct += schemes[i].TagLen
	}
	return hdr, ct
}

// kemCiphertext is what the header stores as a layer's encapsulated key.
func kemCiphertext(l Layer) []byte {
	if l.Kind == KEM {
		return l.KEMCiphertext
	}
	return nil
}

// layerAEAD keys one layer for sealing, wiping the key once the AEAD holds it.
func layerAEAD(l Layer, scheme ciphers.Scheme, salt []byte, params kdf.Params) (cipher.AEAD, error) {
	var key []byte
	if l.Kind == Password {
		key = params.Derive(l.Password, salt)
	} else {
		k, err := kemKey(l.KEMSecret)
		if err != nil {
			return nil, err
		}
		key = k
	}
	aead, err := scheme.New(key)
	memory.Zero(key)
	return aead, err
}

// Decrypt reverses Encrypt in place: it overwrites payload and returns the
// plaintext as a sub-slice of it, so no copy the size of the content is made.
// Passwords for the Password layers are supplied in order via passwords; decap
// recovers shared secrets for KEM layers (nil when there are none). schemes
// supplies the per-layer algorithm ids for payloads that did not record them,
// and may be nil otherwise.
//
// After an error the payload is partly decrypted or wiped, since an AEAD clears
// what it fails to open, so a caller that may try again keeps its own copy.
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

	pwIdx := 0
	for i, l := range layers {
		scheme, err := layerScheme(l, schemes, i)
		if err != nil {
			return nil, err
		}
		switch l.kind {
		case Password:
			ct, err = openPasswordLayer(l, scheme, ct, passwords[pwIdx], params)
			pwIdx++
		case KEM:
			ct, err = openKEMLayer(l, scheme, ct, decaps, i)
		default:
			err = fmt.Errorf("cascade: unknown layer kind %d", l.kind)
		}
		if err != nil {
			return nil, err
		}
	}
	return ct, nil
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

// openPasswordLayer peels one Argon2id-keyed layer in place.
func openPasswordLayer(l layerDesc, scheme ciphers.Scheme, ct, password []byte, params kdf.Params) ([]byte, error) {
	key := params.Derive(password, l.salt)
	aead, err := scheme.New(key)
	memory.Zero(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(ct[:0], l.nonce, ct, layerAD(scheme.ID))
	if err != nil {
		return nil, ErrWrongPassword
	}
	return pt, nil
}

// openKEMLayer peels one recipient-keyed layer in place by trying each supplied
// key.
//
// A shared secret cannot be checked on its own: a mechanism returns an unrelated
// secret rather than an error for a key that does not match, so the AEAD tag is
// what decides. An AEAD clears what it fails to open, so with more than one key
// to try, each attempt opens into a scratch buffer and the one that works is
// copied back. The last decapsulation error is kept and reported, because it
// explains a mismatched key type, which is the likely reason for supplying the
// wrong key file.
func openKEMLayer(l layerDesc, scheme ciphers.Scheme, ct []byte, decaps []Decapsulator, i int) ([]byte, error) {
	if len(decaps) == 0 {
		return nil, fmt.Errorf("%w: layer %d", ErrKeyRequired, i+1)
	}
	dst := ct[:0]
	if len(decaps) > 1 {
		dst = make([]byte, 0, len(ct))
		defer memory.Zero(dst[:cap(dst)])
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
		if pt, err := aead.Open(dst, l.nonce, ct, layerAD(scheme.ID)); err == nil {
			return ct[:copy(ct, pt)], nil
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
	return layers, r.RestView(), nil
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
