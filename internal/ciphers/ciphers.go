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
	"golang.org/x/crypto/twofish"
)

// Scheme describes one authenticated encryption algorithm.
type Scheme struct {
	ID       uint8  // stable on-format identifier
	Name     string // stable human-readable name
	KeyLen   int    // key length in bytes
	NonceLen int    // nonce length in bytes
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
	{ID: 1, Name: "aes-256-gcm", KeyLen: 32, NonceLen: 12, newAEAD: gcmOf(aes.NewCipher)},
	{ID: 2, Name: "chacha20-poly1305", KeyLen: 32, NonceLen: chacha20poly1305.NonceSize, newAEAD: chacha20poly1305.New},
	{ID: 3, Name: "xchacha20-poly1305", KeyLen: 32, NonceLen: chacha20poly1305.NonceSizeX, newAEAD: chacha20poly1305.NewX},
	{ID: 4, Name: "twofish-256-gcm", KeyLen: 32, NonceLen: 12, newAEAD: gcmOf(twofishBlock)},
	{ID: 5, Name: "aes-256-ctr-hmac", KeyLen: 32, NonceLen: ctrHMACNonceSize, newAEAD: newAESCTRHMAC},
}

// defaultName is the scheme used when the user does not choose one. It must
// name an entry in registry; Default panics at startup otherwise.
const defaultName = "chacha20-poly1305"

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

// Count returns the number of registered schemes.
func Count() int { return len(registry) }

// Names returns the scheme names sorted alphabetically.
func Names() []string {
	names := make([]string, 0, len(registry))
	for _, s := range registry {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

// Default returns the scheme used when none is chosen.
func Default() Scheme {
	s, ok := ByName(defaultName)
	if !ok {
		panic("ciphers: default scheme " + defaultName + " is not registered")
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

// Cascade returns n scheme ids for successive cascade layers, cycling through
// the registry starting at the default so adjacent layers always differ.
func Cascade(n int) []uint8 {
	if n <= 0 {
		return nil
	}
	all := All()
	start := 0
	for i, s := range all {
		if s.Name == defaultName {
			start = i
			break
		}
	}
	out := make([]uint8, n)
	for i := 0; i < n; i++ {
		out[i] = all[(start+i)%len(all)].ID
	}
	return out
}

// Nth returns the suggested scheme id for cascade layer i (zero-based).
func Nth(i int) uint8 {
	if i < 0 {
		i = 0
	}
	c := Cascade(i + 1)
	return c[i]
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
