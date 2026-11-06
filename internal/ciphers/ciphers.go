// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package ciphers is a registry of authenticated encryption schemes used for
// cascade layers. Every scheme is an AEAD with a 256-bit key (quantum-resistant
// under Grover to a 128-bit effective level). All primitives come from the Go
// standard library or golang.org/x/crypto; adding a vetted scheme is a single
// registry entry.
package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	//lint:ignore SA1019 frozen, not removed (golang/go#30141); kept as a third design for cascades, and pieces written with it must still open
	"golang.org/x/crypto/twofish"
)

// Scheme describes one authenticated encryption algorithm.
type Scheme struct {
	ID       uint8  // stable on-format identifier
	Name     string // stable human-readable name
	KeyLen   int    // key length in bytes
	NonceLen int    // nonce length in bytes
	TagLen   int    // bytes the AEAD adds, so a buffer can be sized before a key exists
	design   string // the cipher underneath, which one break would reach in every scheme sharing it
	newAEAD  func(key []byte) (cipher.AEAD, error)
}

// New constructs an AEAD from a key of exactly KeyLen bytes.
func (s Scheme) New(key []byte) (cipher.AEAD, error) {
	if len(key) != s.KeyLen {
		return nil, errors.New("ciphers: wrong key length for " + s.Name)
	}
	return s.newAEAD(key)
}

func gcmOf(newBlock func([]byte) (cipher.Block, error)) func([]byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		b, err := newBlock(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	}
}

func twofishBlock(key []byte) (cipher.Block, error) {
	c, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// registry is ordered by ID. IDs are permanent: never reuse or renumber one, or
// pieces already written stop decoding.
var registry = []Scheme{
	{ID: 1, Name: "aes-256-gcm", KeyLen: 32, NonceLen: 12, TagLen: 16, design: "aes", newAEAD: gcmOf(aes.NewCipher)},
	{ID: 2, Name: "chacha20-poly1305", KeyLen: 32, NonceLen: chacha20poly1305.NonceSize, TagLen: 16, design: "chacha20", newAEAD: chacha20poly1305.New},
	{ID: 3, Name: "xchacha20-poly1305", KeyLen: 32, NonceLen: chacha20poly1305.NonceSizeX, TagLen: 16, design: "chacha20", newAEAD: chacha20poly1305.NewX},
	{ID: 4, Name: "twofish-256-gcm", KeyLen: 32, NonceLen: 12, TagLen: 16, design: "twofish", newAEAD: gcmOf(twofishBlock)},
	{ID: 5, Name: "aes-256-ctr-hmac", KeyLen: 32, NonceLen: ctrHMACNonceSize, TagLen: ctrHMACTagSize, design: "aes", newAEAD: newAESCTRHMAC},
}

// suggested is the order layers that name no algorithm take one in, repeating.
// Each is a different design: AES is a substitution-permutation network, ChaCha20
// adds, rotates and XORs, and Twofish is a Feistel network with key-dependent
// S-boxes. A break in one then reaches one layer in three, never two that touch.
// Each must name an entry in registry.
var suggested = []string{"aes-256-gcm", "xchacha20-poly1305", "twofish-256-gcm"}

// ByID returns the scheme with the given identifier.
func ByID(id uint8) (Scheme, bool) {
	for _, s := range registry {
		if s.ID == id {
			return s, true
		}
	}
	return Scheme{}, false
}

// ByName returns the scheme with the given name.
func ByName(name string) (Scheme, bool) {
	for _, s := range registry {
		if s.Name == name {
			return s, true
		}
	}
	return Scheme{}, false
}

// All returns every registered scheme, ordered by ID. Callers derive menus,
// help text, and validation from this, so adding a registry entry is all that
// is needed to expose a new algorithm.
func All() []Scheme {
	out := make([]Scheme, len(registry))
	copy(out, registry)
	return out
}

// Names returns the scheme names sorted alphabetically.
func Names() []string {
	names := make([]string, 0, len(registry))
	for _, s := range registry {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

// Default returns the scheme of a first layer that names none.
func Default() Scheme {
	return suggestion(0)
}

// Suggested returns the scheme id for layer i, counting from zero, when it names
// none, under a layer using above (zero for the first layer). Layers take the
// suggestions in turn. When the layer above was chosen by hand and shares a
// design with this layer's turn, the next suggestion that does not is taken.
func Suggested(i int, above uint8) uint8 {
	a, _ := ByID(above)
	for j := range suggested {
		if s := suggestion(i + j); s.design != a.design {
			return s.ID
		}
	}
	panic("ciphers: every suggested scheme shares one design")
}

// suggestion returns the i-th suggestion, starting over after the last.
func suggestion(i int) Scheme {
	name := suggested[i%len(suggested)]
	s, ok := ByName(name)
	if !ok {
		panic("ciphers: suggested scheme " + name + " is not registered")
	}
	return s
}

// Name returns the display name for an id, or a placeholder if it is unknown.
func Name(id uint8) string {
	if s, ok := ByID(id); ok {
		return s.Name
	}
	return fmt.Sprintf("scheme-%d", id)
}

// Cascade returns the scheme ids n layers that name none get, outermost first.
func Cascade(n int) []uint8 {
	if n <= 0 {
		return nil
	}
	out := make([]uint8, n)
	var above uint8
	for i := range out {
		out[i] = Suggested(i, above)
		above = out[i]
	}
	return out
}

// ParseList resolves a comma-separated list of scheme names to ids.
func ParseList(spec string) ([]uint8, error) {
	var out []uint8
	for _, part := range strings.Split(spec, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		s, ok := ByName(part)
		if !ok {
			return nil, fmt.Errorf("unknown algorithm %q (available: %s)", part, strings.Join(Names(), ", "))
		}
		out = append(out, s.ID)
	}
	if len(out) == 0 {
		return nil, errors.New("no algorithms given")
	}
	return out, nil
}
