// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package kem wraps the standard library HPKE (RFC 9180) key encapsulation
// mechanisms used for Riven's recipient layers.
//
// A recipient layer is keyed by a public key instead of a password: only the
// holder of the matching private key can recover it. The encapsulated key rides
// in every piece, so the scheme decides how much each piece grows, which matters
// most for QR export.
//
// X-Wing is the default: ML-KEM-768 with X25519, standing as long as either
// holds. The elliptic-curve schemes are for existing keys and small pieces; NIST
// IR 8547 proposes deprecating them after 2030, so they are compatibility
// options. See docs/usage.md for the sizes.
package kem

import (
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// SharedSecretSize is the length of the secret derived for a layer.
const SharedSecretSize = 32

// hpkeInfo binds an encapsulation to this application and scheme, so material
// produced for one scheme cannot be reinterpreted as another.
func hpkeInfo(name string) []byte { return []byte("riven-recipient-v1:" + name) }

// exporterContext labels the exported layer key within the HPKE context.
const exporterContext = "riven-layer-key-v1"

// Scheme identifies a supported KEM. The values are Riven's own and appear in
// key file labels; the underlying HPKE identifiers come from the RFC 9180
// registry.
type Scheme uint8

const (
	// XWing is ML-KEM-768 combined with X25519 (HPKE KEM 0x647a).
	XWing Scheme = iota
	// MLKEM768 is ML-KEM-768 alone (FIPS 203, HPKE KEM 0x0041).
	MLKEM768
	// MLKEM1024 is ML-KEM-1024 alone (FIPS 203, HPKE KEM 0x0042).
	MLKEM1024
	// X25519 is DHKEM(X25519, HKDF-SHA256) (HPKE KEM 0x0020).
	X25519
	// P256 is DHKEM(P-256, HKDF-SHA256) (HPKE KEM 0x0010).
	P256
	// P384 is DHKEM(P-384, HKDF-SHA384) (HPKE KEM 0x0011).
	P384
)

type schemeInfo struct {
	name        string
	summary     string
	kem         func() hpke.KEM
	kdf         func() hpke.KDF
	postQuantum bool
}

// registry holds one entry per scheme, in the order All returns them.
var registry = []schemeInfo{
	XWing: {
		name:        "x-wing",
		summary:     "ML-KEM-768 with X25519, secure while either one holds",
		kem:         hpke.MLKEM768X25519,
		kdf:         hpke.HKDFSHA256,
		postQuantum: true,
	},
	MLKEM768: {
		name:        "ml-kem-768",
		summary:     "post-quantum only, NIST category 3",
		kem:         hpke.MLKEM768,
		kdf:         hpke.HKDFSHA256,
		postQuantum: true,
	},
	MLKEM1024: {
		name:        "ml-kem-1024",
		summary:     "post-quantum only, NIST category 5, largest pieces",
		kem:         hpke.MLKEM1024,
		kdf:         hpke.HKDFSHA512,
		postQuantum: true,
	},
	X25519: {
		name:    "x25519",
		summary: "classical only, smallest pieces, not post-quantum",
		kem:     func() hpke.KEM { return hpke.DHKEM(ecdh.X25519()) },
		kdf:     hpke.HKDFSHA256,
	},
	P256: {
		name:    "p256",
		summary: "classical only, for existing NIST P-256 keys",
		kem:     func() hpke.KEM { return hpke.DHKEM(ecdh.P256()) },
		kdf:     hpke.HKDFSHA256,
	},
	P384: {
		name:    "p384",
		summary: "classical only, for existing NIST P-384 keys",
		kem:     func() hpke.KEM { return hpke.DHKEM(ecdh.P384()) },
		kdf:     hpke.HKDFSHA384,
	},
}

// Default returns the scheme used when the user does not choose one.
func Default() Scheme { return XWing }

// All returns every supported scheme, in the order they are offered.
func All() []Scheme {
	out := make([]Scheme, len(registry))
	for i := range registry {
		out[i] = Scheme(i)
	}
	return out
}

// Names returns the scheme names, for help text.
func Names() []string {
	out := make([]string, len(registry))
	for i := range registry {
		out[i] = registry[i].name
	}
	return out
}

func (s Scheme) info() (schemeInfo, bool) {
	if int(s) >= len(registry) {
		return schemeInfo{}, false
	}
	return registry[s], true
}

// Name returns the scheme name as it is written on the command line.
func (s Scheme) Name() string {
	if i, ok := s.info(); ok {
		return i.name
	}
	return fmt.Sprintf("unknown-%d", uint8(s))
}

// Summary is a one-line description for menus and help text.
func (s Scheme) Summary() string {
	if i, ok := s.info(); ok {
		return i.summary
	}
	return ""
}

// PostQuantum reports whether the scheme resists a quantum attacker.
func (s Scheme) PostQuantum() bool {
	i, ok := s.info()
	return ok && i.postQuantum
}

// String makes a scheme printable.
func (s Scheme) String() string { return s.Name() }

// kem returns the HPKE mechanism, or an error for an unknown scheme.
func (s Scheme) kem() (hpke.KEM, hpke.KDF, error) {
	i, ok := s.info()
	if !ok {
		return nil, nil, fmt.Errorf("kem: unknown scheme %d", uint8(s))
	}
	return i.kem(), i.kdf(), nil
}

// PublicKeySize is the serialized length of a public key for this scheme.
func (s Scheme) PublicKeySize() int { return s.sizes().pub }

// PrivateKeySize is the serialized length of a private key for this scheme.
func (s Scheme) PrivateKeySize() int { return s.sizes().priv }

// CiphertextSize is the length of the encapsulated key carried in every piece.
func (s Scheme) CiphertextSize() int { return s.sizes().ct }

type schemeSizes struct{ pub, priv, ct int }

// sizeCache holds the lengths measured once per scheme. They are fixed by the
// mechanism, but the standard library does not expose them as constants for
// every suite, so they are taken from a generated key on first use.
var (
	sizeMu    sync.Mutex
	sizeCache = map[Scheme]schemeSizes{}
)

func (s Scheme) sizes() schemeSizes {
	sizeMu.Lock()
	defer sizeMu.Unlock()
	if v, ok := sizeCache[s]; ok {
		return v
	}
	k, kdf, err := s.kem()
	if err != nil {
		return schemeSizes{}
	}
	priv, err := k.GenerateKey()
	if err != nil {
		return schemeSizes{}
	}
	privBytes, err := priv.Bytes()
	if err != nil {
		return schemeSizes{}
	}
	pub := priv.PublicKey()
	enc, _, err := hpke.NewSender(pub, kdf, hpke.ExportOnly(), hpkeInfo(s.Name()))
	if err != nil {
		return schemeSizes{}
	}
	v := schemeSizes{pub: len(pub.Bytes()), priv: len(privBytes), ct: len(enc)}
	sizeCache[s] = v
	return v
}

// Parse resolves a scheme name. Common spellings are accepted so a user does not
// have to remember the exact punctuation.
func Parse(s string) (Scheme, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.ReplaceAll(t, "_", "-")
	switch t {
	case "", "default", "x-wing", "xwing", "mlkem768x25519", "ml-kem-768-x25519":
		return XWing, nil
	case "ml-kem-768", "mlkem768", "mlkem-768", "768":
		return MLKEM768, nil
	case "ml-kem-1024", "mlkem1024", "mlkem-1024", "1024":
		return MLKEM1024, nil
	case "x25519", "curve25519":
		return X25519, nil
	case "p256", "p-256", "nistp256", "secp256r1":
		return P256, nil
	case "p384", "p-384", "nistp384", "secp384r1":
		return P384, nil
	}
	return 0, fmt.Errorf("kem: unknown recipient key type %q (use one of: %s)",
		s, strings.Join(Names(), ", "))
}

// PublicKey is a recipient's public key.
type PublicKey struct {
	s  Scheme
	pk hpke.PublicKey
}

// PrivateKey is a recipient's private key.
type PrivateKey struct {
	s  Scheme
	sk hpke.PrivateKey
}

// Generate creates a fresh key pair for the given scheme.
func Generate(s Scheme) (*PrivateKey, error) {
	k, _, err := s.kem()
	if err != nil {
		return nil, err
	}
	sk, err := k.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{s: s, sk: sk}, nil
}

// Scheme reports which mechanism this key belongs to.
func (k *PrivateKey) Scheme() Scheme { return k.s }

// Public returns the matching public key.
func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{s: k.s, pk: k.sk.PublicKey()}
}

// Bytes returns the serialized private key. Treat it as highly sensitive.
func (k *PrivateKey) Bytes() ([]byte, error) { return k.sk.Bytes() }

// Decapsulate recovers the shared secret for a layer. A ciphertext of the wrong
// length belongs to another scheme and is rejected here, which lets a caller
// holding several keys skip the ones that cannot match.
func (k *PrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if want := k.s.CiphertextSize(); len(ciphertext) != want {
		return nil, fmt.Errorf("kem: this layer carries a %d-byte encapsulated key, but a %s key expects %d bytes",
			len(ciphertext), k.s.Name(), want)
	}
	_, kdf, err := k.s.kem()
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(ciphertext, k.sk, kdf, hpke.ExportOnly(), hpkeInfo(k.s.Name()))
	if err != nil {
		return nil, err
	}
	return r.Export(exporterContext, SharedSecretSize)
}

// Scheme reports which mechanism this key belongs to.
func (p *PublicKey) Scheme() Scheme { return p.s }

// Bytes returns the serialized public key.
func (p *PublicKey) Bytes() []byte { return p.pk.Bytes() }

// Encapsulate produces a fresh shared secret and the encapsulated key that lets
// the holder of the private key recover it.
func (p *PublicKey) Encapsulate() (secret, ciphertext []byte, err error) {
	_, kdf, err := p.s.kem()
	if err != nil {
		return nil, nil, err
	}
	enc, sender, err := hpke.NewSender(p.pk, kdf, hpke.ExportOnly(), hpkeInfo(p.s.Name()))
	if err != nil {
		return nil, nil, err
	}
	ss, err := sender.Export(exporterContext, SharedSecretSize)
	if err != nil {
		return nil, nil, err
	}
	return ss, enc, nil
}

// PublicFromBytes parses a serialized public key of the given scheme.
func PublicFromBytes(b []byte, s Scheme) (*PublicKey, error) {
	k, _, err := s.kem()
	if err != nil {
		return nil, err
	}
	if want := s.PublicKeySize(); len(b) != want {
		return nil, fmt.Errorf("kem: a %s public key is %d bytes, got %d", s.Name(), want, len(b))
	}
	pk, err := k.NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("kem: invalid %s public key: %w", s.Name(), err)
	}
	return &PublicKey{s: s, pk: pk}, nil
}

// PrivateFromBytes parses a serialized private key of the given scheme.
func PrivateFromBytes(b []byte, s Scheme) (*PrivateKey, error) {
	k, _, err := s.kem()
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("kem: empty private key")
	}
	if want := s.PrivateKeySize(); len(b) != want {
		return nil, fmt.Errorf("kem: a %s private key is %d bytes, got %d", s.Name(), want, len(b))
	}
	sk, err := k.NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("kem: invalid %s private key: %w", s.Name(), err)
	}
	return &PrivateKey{s: s, sk: sk}, nil
}

// SchemeForPublicKeySize reports which schemes could have produced a public key
// of this length. Lengths happen to be distinct today, but a key file states its
// scheme rather than relying on that.
func SchemeForPublicKeySize(n int) []Scheme {
	var out []Scheme
	for _, s := range All() {
		if s.PublicKeySize() == n {
			out = append(out, s)
		}
	}
	return out
}

// SchemeForCiphertextSize reports which schemes produce an encapsulated key of
// this length. It names the key type a piece was sealed to, which is otherwise
// not recorded.
func SchemeForCiphertextSize(n int) []Scheme {
	var out []Scheme
	for _, s := range All() {
		if s.CiphertextSize() == n {
			out = append(out, s)
		}
	}
	return out
}
