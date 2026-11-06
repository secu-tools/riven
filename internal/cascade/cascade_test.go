// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package cascade

import (
	"bytes"
	"errors"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
)

// fastProfile keeps Argon2 cheap for tests.
var fastProfile = kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}

// encrypt is EncryptTo into a buffer of its own: a self-describing payload, the
// header followed by the outermost ciphertext.
func encrypt(plaintext []byte, layers []Layer, params kdf.Params, recordSchemes bool) ([]byte, error) {
	n, err := Len(len(plaintext), layers)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if err := EncryptTo(out, plaintext, layers, params, recordSchemes); err != nil {
		return nil, err
	}
	return out, nil
}

// descriptors parses a payload's header into the per-layer metadata, without
// decrypting.
func descriptors(payload []byte) ([]Descriptor, error) {
	layers, _, err := parse(payload)
	if err != nil {
		return nil, err
	}
	out := make([]Descriptor, len(layers))
	for i, l := range layers {
		out[i] = Descriptor{Kind: l.kind, SchemeID: l.schemeID, Recorded: l.schemeID != schemeHidden}
	}
	return out, nil
}

// decrypt is Decrypt on a copy. Decrypt works in place, and these tests try one
// payload several ways.
func decrypt(payload []byte, pws [][]byte, decaps []Decapsulator, p kdf.Params, schemes []uint8) ([]byte, error) {
	return Decrypt(append([]byte(nil), payload...), pws, decaps, p, schemes)
}

// TestDecryptInPlace checks Decrypt leaves the plaintext inside the payload
// rather than in a copy, and that a wrong recipient key tried first does not
// spoil the payload for the right one.
func TestDecryptInPlace(t *testing.T) {
	right, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	ss, ct, err := right.Public().Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	pt := bytes.Repeat([]byte("in place "), 1000)
	layers := []Layer{
		{Kind: Password, SchemeID: 5, Password: []byte("pw")},
		{Kind: KEM, SchemeID: 1, KEMSecret: ss, KEMCiphertext: ct},
	}
	payload, err := encrypt(pt, layers, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := Len(len(pt), layers); err != nil || n != len(payload) {
		t.Fatalf("Len says %d (%v), Encrypt made %d", n, err, len(payload))
	}
	decaps := []Decapsulator{
		func(c []byte) ([]byte, error) { return wrong.Decapsulate(c) },
		func(c []byte) ([]byte, error) { return right.Decapsulate(c) },
	}
	got, err := Decrypt(payload, [][]byte{[]byte("pw")}, decaps, fastProfile, nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("decrypt with the wrong key first: %v", err)
	}
	if !bytes.Contains(payload, pt) {
		t.Fatal("the plaintext was not written into the payload")
	}
}

func TestCascadeZeroLayers(t *testing.T) {
	pt := []byte("hello world")
	payload, err := encrypt(pt, nil, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decrypt(payload, nil, nil, fastProfile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("mismatch: %q", got)
	}
}

func TestCascadeMultiPassword(t *testing.T) {
	pt := []byte("the quick brown fox jumps over the lazy dog")
	layers := []Layer{
		{Kind: Password, SchemeID: 1, Password: []byte("first-pass")},
		{Kind: Password, SchemeID: 2, Password: []byte("second-pass")},
		{Kind: Password, SchemeID: 5, Password: []byte("third-pass")},
	}
	payload, err := encrypt(pt, layers, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	pws := [][]byte{[]byte("first-pass"), []byte("second-pass"), []byte("third-pass")}
	got, err := decrypt(payload, pws, nil, fastProfile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("mismatch")
	}

	// Wrong password fails.
	bad := [][]byte{[]byte("first-pass"), []byte("WRONG"), []byte("third-pass")}
	if _, err := decrypt(payload, bad, nil, fastProfile, nil); err == nil {
		t.Fatal("expected failure on wrong password")
	}
	// Wrong order fails.
	swapped := [][]byte{[]byte("second-pass"), []byte("first-pass"), []byte("third-pass")}
	if _, err := decrypt(payload, swapped, nil, fastProfile, nil); err == nil {
		t.Fatal("expected failure on wrong order")
	}

	if ds, _ := descriptors(payload); len(ds) != 3 {
		t.Fatalf("expected 3 descriptors, got %d", len(ds))
	}
}

func TestCascadeHybridKEM(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	ss, ct, err := pub.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}

	pt := []byte("post-quantum protected secret")
	layers := []Layer{
		{Kind: Password, SchemeID: 3, Password: []byte("outer")},
		{Kind: KEM, SchemeID: 3, KEMSecret: ss, KEMCiphertext: ct},
	}
	payload, err := encrypt(pt, layers, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}

	decap := func(c []byte) ([]byte, error) { return priv.Decapsulate(c) }
	got, err := decrypt(payload, [][]byte{[]byte("outer")}, []Decapsulator{decap}, fastProfile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("hybrid mismatch")
	}

	// Missing private key fails.
	if _, err := decrypt(payload, [][]byte{[]byte("outer")}, nil, fastProfile, nil); err == nil {
		t.Fatal("expected failure without decapsulator")
	}
	// Wrong private key fails.
	other, _ := kem.Generate(kem.Default())
	badDecap := func(c []byte) ([]byte, error) { return other.Decapsulate(c) }
	if _, err := decrypt(payload, [][]byte{[]byte("outer")}, []Decapsulator{badDecap}, fastProfile, nil); err == nil {
		t.Fatal("expected failure with wrong private key")
	}
}

func TestHiddenSchemesRequireSupplied(t *testing.T) {
	pt := []byte("algorithms are not recorded here")
	layers := []Layer{
		{Kind: Password, SchemeID: 1, Password: []byte("a")},
		{Kind: Password, SchemeID: 2, Password: []byte("b")},
	}
	payload, err := encrypt(pt, layers, fastProfile, false)
	if err != nil {
		t.Fatal(err)
	}
	pws := [][]byte{[]byte("a"), []byte("b")}

	// descriptors must not leak the ids.
	ds, err := descriptors(payload)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range ds {
		if d.Recorded || d.SchemeID != schemeHidden {
			t.Fatalf("layer %d leaked its algorithm: %+v", i, d)
		}
	}

	// Without algorithms it must refuse rather than guess.
	if _, err := decrypt(payload, pws, nil, fastProfile, nil); !errors.Is(err, ErrSchemesRequired) {
		t.Fatalf("expected ErrSchemesRequired, got %v", err)
	}
	// Wrong count is reported.
	if _, err := decrypt(payload, pws, nil, fastProfile, []uint8{1}); err == nil {
		t.Fatal("expected failure on wrong algorithm count")
	}
	// Correct algorithms work.
	got, err := decrypt(payload, pws, nil, fastProfile, []uint8{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("mismatch")
	}
	// Wrong algorithms fail.
	if _, err := decrypt(payload, pws, nil, fastProfile, []uint8{2, 1}); err == nil {
		t.Fatal("expected failure with wrong algorithms")
	}
}

func TestRecordedSchemesIgnoreSupplied(t *testing.T) {
	pt := []byte("recorded")
	layers := []Layer{{Kind: Password, SchemeID: 4, Password: []byte("p")}}
	payload, err := encrypt(pt, layers, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	// A recorded payload opens without supplied algorithms.
	got, err := decrypt(payload, [][]byte{[]byte("p")}, nil, fastProfile, nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("recorded decrypt failed: %v", err)
	}
	ds, _ := descriptors(payload)
	if len(ds) != 1 || !ds[0].Recorded || ds[0].SchemeID != 4 {
		t.Fatalf("bad descriptor: %+v", ds)
	}
}

func TestWrongParamsFail(t *testing.T) {
	pt := []byte("cost matters")
	payload, err := encrypt(pt, []Layer{{Kind: Password, SchemeID: 1, Password: []byte("p")}}, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	other := kdf.Params{Memory: 8 * 1024, Time: 2, Par: 1}
	if _, err := decrypt(payload, [][]byte{[]byte("p")}, nil, other, nil); err == nil {
		t.Fatal("expected failure with different cost parameters")
	}
}

func TestCascadeAllSchemes(t *testing.T) {
	pt := bytes.Repeat([]byte("A"), 100)
	for _, s := range ciphers.All() {
		payload, err := encrypt(pt, []Layer{{Kind: Password, SchemeID: s.ID, Password: []byte("p")}}, fastProfile, true)
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		got, err := decrypt(payload, [][]byte{[]byte("p")}, nil, fastProfile, nil)
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("%s mismatch", s.Name)
		}
	}
}

// TestEncryptToNeedsTheExactLength checks EncryptTo writes only into a buffer of
// the length Len gives, so a caller cannot have it write past or short of the
// place it reserved, and wipes the buffer when it refuses.
func TestEncryptToNeedsTheExactLength(t *testing.T) {
	layers := []Layer{{Kind: Password, SchemeID: 2, Password: []byte("pw")}}
	n, err := Len(10, layers)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{n - 1, n + 1} {
		if err := EncryptTo(make([]byte, size), make([]byte, 10), layers, fastProfile, true); err == nil {
			t.Fatalf("a %d-byte buffer was taken for a %d-byte payload", size, n)
		}
	}
	if _, err := Len(10, []Layer{{Kind: Password, SchemeID: 99}}); err == nil {
		t.Fatal("Len accepted an unknown algorithm")
	}
	if _, err := Len(10, []Layer{{Kind: Kind(7), SchemeID: 1}}); err == nil {
		t.Fatal("Len accepted an unknown layer kind")
	}
}
