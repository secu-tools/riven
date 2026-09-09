// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package cascade

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/secu-tools/riven/internal/kdf"
)

// TestPayloadMatchesTheSpecification parses a cascade payload using only what
// docs/format.md section 8 states.
func TestPayloadMatchesTheSpecification(t *testing.T) {
	params := kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}
	plaintext := []byte("cascade payload contents")
	payload, err := Encrypt(plaintext, []Layer{
		{Kind: Password, SchemeID: 2, Password: []byte("outer")},
		{Kind: KEM, SchemeID: 3, KEMSecret: bytes.Repeat([]byte{7}, 32), KEMCiphertext: bytes.Repeat([]byte{9}, 32)},
	}, params, true)
	if err != nil {
		t.Fatal(err)
	}

	pos := 0
	u8 := func() byte { v := payload[pos]; pos++; return v }
	blob := func() []byte {
		n := int(binary.BigEndian.Uint32(payload[pos:]))
		pos += 4
		v := payload[pos : pos+n]
		pos += n
		return v
	}

	if v := binary.BigEndian.Uint16(payload[pos:]); v != 1 {
		t.Fatalf("version is %d, the specification says 1", v)
	}
	pos += 2
	if n := u8(); n != 2 {
		t.Fatalf("layer count is %d, want 2", n)
	}

	// Layer 1: password, chacha20-poly1305 (id 2, 12-byte nonce), 16-byte salt,
	// no encapsulated key.
	if kind, algo := u8(), u8(); kind != 0 || algo != 2 {
		t.Fatalf("layer 1 is kind %d algorithm %d, want 0 and 2", kind, algo)
	}
	if salt := blob(); len(salt) != 16 {
		t.Fatalf("layer 1 salt is %d bytes, want 16", len(salt))
	}
	if nonce := blob(); len(nonce) != 12 {
		t.Fatalf("layer 1 nonce is %d bytes, want 12 for chacha20-poly1305", len(nonce))
	}
	if enc := blob(); len(enc) != 0 {
		t.Fatalf("layer 1 carries %d encapsulated bytes, want none", len(enc))
	}

	// Layer 2: recipient key, xchacha20-poly1305 (id 3, 24-byte nonce), no salt.
	if kind, algo := u8(), u8(); kind != 1 || algo != 3 {
		t.Fatalf("layer 2 is kind %d algorithm %d, want 1 and 3", kind, algo)
	}
	if salt := blob(); len(salt) != 0 {
		t.Fatalf("layer 2 carries %d salt bytes, want none", len(salt))
	}
	if nonce := blob(); len(nonce) != 24 {
		t.Fatalf("layer 2 nonce is %d bytes, want 24 for xchacha20-poly1305", len(nonce))
	}
	if enc := blob(); len(enc) != 32 {
		t.Fatalf("layer 2 encapsulated key is %d bytes, want 32", len(enc))
	}

	// The rest is the outermost ciphertext: plaintext plus one tag per layer.
	if got, want := len(payload)-pos, len(plaintext)+32; got != want {
		t.Fatalf("ciphertext is %d bytes, want %d", got, want)
	}

	// Section 8.1: id 0 means "not recorded".
	hidden, err := Encrypt(plaintext, []Layer{{Kind: Password, SchemeID: 2, Password: []byte("p")}}, params, false)
	if err != nil {
		t.Fatal(err)
	}
	if algo := hidden[4]; algo != 0 {
		t.Fatalf("an unrecorded algorithm is written as %d, want 0", algo)
	}
}

// TestLayerAssociatedData pins the 11-byte string of section 8.3.
func TestLayerAssociatedData(t *testing.T) {
	ad := layerAD(2)
	if len(ad) != 11 {
		t.Fatalf("associated data is %d bytes, want 11", len(ad))
	}
	if !bytes.Equal(ad[:10], []byte("riven-casc")) || ad[10] != 2 {
		t.Fatalf("associated data is %q", ad)
	}
}
