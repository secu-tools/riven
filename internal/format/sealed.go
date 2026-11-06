// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package format

import (
	"bytes"
	"errors"
	"math/bits"
	"slices"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"

	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/memory"
)

// A protected set with recipient keys seals each piece's envelope to them, as
// docs/format.md section 5.3 lays out. Every piece carries a fresh encapsulation
// to each distinct recipient, and the envelope key is derived from all of the
// shared secrets, and from the passwords as well when the set has them. Reading
// a piece's details then needs everything the content needs.
//
// The encapsulations are in key order, by public key, not in layer order: the
// order of the layers is one of the details the envelope hides, and a reader
// holding the private keys can put them in key order without knowing it.

// maxSubsetKeys is how many private keys DecodeSealed will search the subsets
// of. More keys than the set needs is the unusual case, and the search doubles
// with each key, so past this only every key given together is tried.
const maxSubsetKeys = 8

// keyID orders recipient keys: by the public key's bytes, as its key file holds
// them.
func keyID(p *kem.PublicKey) []byte { return p.Bytes() }

// sealOrder puts recipient keys in key order, once each.
func sealOrder(rs []*kem.PublicKey) []*kem.PublicKey {
	out := slices.Clone(rs)
	slices.SortFunc(out, func(a, b *kem.PublicKey) int { return bytes.Compare(keyID(a), keyID(b)) })
	return slices.CompactFunc(out, func(a, b *kem.PublicKey) bool { return bytes.Equal(keyID(a), keyID(b)) })
}

// openOrder puts private keys in key order, once each.
func openOrder(keys []*kem.PrivateKey) []*kem.PrivateKey {
	type entry struct {
		id []byte
		k  *kem.PrivateKey
	}
	es := make([]entry, len(keys))
	for i, k := range keys {
		es[i] = entry{keyID(k.Public()), k}
	}
	slices.SortFunc(es, func(a, b entry) int { return bytes.Compare(a.id, b.id) })
	es = slices.CompactFunc(es, func(a, b entry) bool { return bytes.Equal(a.id, b.id) })
	out := make([]*kem.PrivateKey, len(es))
	for i, e := range es {
		out[i] = e.k
	}
	return out
}

// EncapsLen is how many bytes of encapsulated keys a piece sealed to these
// recipients carries, for Shape.Encaps.
func EncapsLen(recipients []*kem.PublicKey) int {
	n := 0
	for _, r := range sealOrder(recipients) {
		n += r.Scheme().CiphertextSize()
	}
	return n
}

// sealTo encapsulates to every recipient and derives the envelope key, from the
// passwords too when there are any. It returns the encapsulated keys masked for
// the header, and the key.
func sealTo(recipients []*kem.PublicKey, passwords [][]byte, salt []byte, p kdf.Params) (masked, key []byte, err error) {
	var encs []byte
	var secrets [][]byte
	defer func() { wipeAll(secrets) }()
	for _, r := range sealOrder(recipients) {
		ss, enc, err := r.Encapsulate()
		if err != nil {
			return nil, nil, err
		}
		secrets = append(secrets, ss)
		encs = append(encs, enc...)
	}
	var pwKey []byte
	if len(passwords) > 0 {
		pwKey = envelopeKey(passwords, salt, p)
		defer memory.Zero(pwKey)
	}
	return maskEncs(encs, salt), sealedKey(salt, pwKey, encs, secrets), nil
}

func wipeAll(bs [][]byte) {
	for _, b := range bs {
		memory.Zero(b)
	}
}

// maskEncs XORs the encapsulated keys with a keystream drawn from the salt. The
// salt is public, so this hides nothing from someone running riven; it is there
// so that no byte of a piece is fixed, as a P-256 point's leading 0x04 or an
// X25519 key's clear top bit otherwise would be. Masking twice unmasks.
func maskEncs(b, salt []byte) []byte {
	seed := blake2b.Sum256(append([]byte("riven-enc-mask-v1"), salt...))
	s, err := chacha20.NewUnauthenticatedCipher(seed[:], make([]byte, chacha20.NonceSize))
	if err != nil {
		panic(err) // the key and nonce lengths are fixed above
	}
	out := make([]byte, len(b))
	s.XORKeyStream(out, b)
	return out
}

// sealedKey derives the envelope key from the salt, the password key when there
// is one, every shared secret, and the encapsulated keys themselves, which binds
// the header to the key.
func sealedKey(salt, pwKey, encs []byte, secrets [][]byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("riven-sealed-envelope-v1"))
	h.Write(salt)
	h.Write([]byte{byte(len(pwKey))})
	h.Write(pwKey)
	h.Write([]byte{byte(len(secrets))})
	for _, s := range secrets {
		h.Write(s)
	}
	h.Write(encs)
	return h.Sum(nil)
}

// DecodeSealed opens a piece of a protected set, whose envelope takes the
// passwords, the recipient keys, or both. With passwords the password key is
// derived once, and serves both the password envelope, tried first, and the
// sealed one. The keys may be more than the set needs: every key given is tried
// together first, then, for up to maxSubsetKeys of them, fewer. A keyless piece,
// like a piece of another set, does not open here.
func DecodeSealed(piece []byte, passwords [][]byte, keys []*kem.PrivateKey, override *kdf.Params) (*Manifest, kdf.Params, error) {
	if err := checkDecode(piece, override); err != nil {
		return nil, kdf.Params{}, err
	}
	params, _ := PeekParams(piece)
	if override != nil {
		params = *override
	}
	var pwKey []byte
	if len(passwords) > 0 {
		pwKey = envelopeKey(passwords, piece[:saltLen], params)
		defer memory.Zero(pwKey)
		if m, err := openAt(piece, 0, bytes.Clone(pwKey)); err == nil {
			if m.Keyless || m.SealedToKeys {
				m.Wipe()
				return nil, kdf.Params{}, errors.New("format: the piece opened with the password alone but is not marked so")
			}
			m.PasswordOpened = true
			return m, params, nil
		}
	}
	m := eachSubset(openOrder(keys), func(sub []*kem.PrivateKey) *Manifest {
		m, _ := openSealed(piece, pwKey, sub)
		return m
	})
	if m == nil {
		return nil, kdf.Params{}, ErrWrongPassword
	}
	if m.Keyless || !m.SealedToKeys {
		m.Wipe()
		return nil, kdf.Params{}, errors.New("format: the piece opened with recipient keys but is not marked as sealed to them")
	}
	m.PasswordOpened = pwKey != nil
	// Opened with keys alone, the cost byte stretched nothing, and is only a
	// cost when the manifest says the set records one, as for keyless pieces.
	if pwKey == nil && override == nil {
		params = m.Params
	}
	return m, params, nil
}

// openSealed opens a piece whose header carries one encapsulation for each of
// keys, in that order.
func openSealed(piece, pwKey []byte, keys []*kem.PrivateKey) (*Manifest, error) {
	encLen := 0
	for _, k := range keys {
		encLen += k.Scheme().CiphertextSize()
	}
	if len(piece) < saltLen+kdfLen+encLen+nonceLen+tagLen {
		return nil, ErrWrongPassword
	}
	salt := piece[:saltLen]
	encs := maskEncs(piece[saltLen+kdfLen:saltLen+kdfLen+encLen], salt)
	secrets := make([][]byte, 0, len(keys))
	defer func() { wipeAll(secrets) }()
	off := 0
	for _, k := range keys {
		n := k.Scheme().CiphertextSize()
		ss, err := k.Decapsulate(encs[off : off+n])
		if err != nil {
			return nil, ErrWrongPassword
		}
		secrets = append(secrets, ss)
		off += n
	}
	return openAt(piece, encLen, sealedKey(salt, pwKey, encs, secrets))
}

// eachSubset calls try with keys, then, when there are few enough of them, with
// each smaller subset in turn, the largest first and each kept in order. It
// returns the first manifest try returns.
func eachSubset(keys []*kem.PrivateKey, try func([]*kem.PrivateKey) *Manifest) *Manifest {
	if len(keys) == 0 {
		return nil
	}
	if m := try(keys); m != nil || len(keys) > maxSubsetKeys {
		return m
	}
	full := 1<<len(keys) - 1
	for size := len(keys) - 1; size >= 1; size-- {
		for mask := full - 1; mask > 0; mask-- {
			if bits.OnesCount(uint(mask)) != size {
				continue
			}
			var sub []*kem.PrivateKey
			for i, k := range keys {
				if mask&(1<<i) != 0 {
					sub = append(sub, k)
				}
			}
			if m := try(sub); m != nil {
				return m
			}
		}
	}
	return nil
}
