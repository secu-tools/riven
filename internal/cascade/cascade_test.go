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

func TestCascadeZeroLayers(t *testing.T) {
	pt := []byte("hello world")
	payload, err := Encrypt(pt, nil, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(payload, nil, nil, fastProfile, nil)
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
	payload, err := Encrypt(pt, layers, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	pws := [][]byte{[]byte("first-pass"), []byte("second-pass"), []byte("third-pass")}
	got, err := Decrypt(payload, pws, nil, fastProfile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("mismatch")
	}

	// Wrong password fails.
	bad := [][]byte{[]byte("first-pass"), []byte("WRONG"), []byte("third-pass")}
	if _, err := Decrypt(payload, bad, nil, fastProfile, nil); err == nil {
		t.Fatal("expected failure on wrong password")
	}
	// Wrong order fails.
	swapped := [][]byte{[]byte("second-pass"), []byte("first-pass"), []byte("third-pass")}
	if _, err := Decrypt(payload, swapped, nil, fastProfile, nil); err == nil {
		t.Fatal("expected failure on wrong order")
	}

	if ds, _ := Descriptors(payload); len(ds) != 3 {
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
	payload, err := Encrypt(pt, layers, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}

	decap := func(c []byte) ([]byte, error) { return priv.Decapsulate(c) }
	got, err := Decrypt(payload, [][]byte{[]byte("outer")}, []Decapsulator{decap}, fastProfile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("hybrid mismatch")
	}

	// Missing private key fails.
	if _, err := Decrypt(payload, [][]byte{[]byte("outer")}, nil, fastProfile, nil); err == nil {
		t.Fatal("expected failure without decapsulator")
	}
	// Wrong private key fails.
	other, _ := kem.Generate(kem.Default())
	badDecap := func(c []byte) ([]byte, error) { return other.Decapsulate(c) }
	if _, err := Decrypt(payload, [][]byte{[]byte("outer")}, []Decapsulator{badDecap}, fastProfile, nil); err == nil {
		t.Fatal("expected failure with wrong private key")
	}
}

func TestHiddenSchemesRequireSupplied(t *testing.T) {
	pt := []byte("algorithms are not recorded here")
	layers := []Layer{
		{Kind: Password, SchemeID: 1, Password: []byte("a")},
		{Kind: Password, SchemeID: 2, Password: []byte("b")},
	}
	payload, err := Encrypt(pt, layers, fastProfile, false)
	if err != nil {
		t.Fatal(err)
	}
	pws := [][]byte{[]byte("a"), []byte("b")}

	// Descriptors must not leak the ids.
	ds, err := Descriptors(payload)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range ds {
		if d.Recorded || d.SchemeID != schemeHidden {
			t.Fatalf("layer %d leaked its algorithm: %+v", i, d)
		}
	}

	// Without algorithms it must refuse rather than guess.
	if _, err := Decrypt(payload, pws, nil, fastProfile, nil); !errors.Is(err, ErrSchemesRequired) {
		t.Fatalf("expected ErrSchemesRequired, got %v", err)
	}
	// Wrong count is reported.
	if _, err := Decrypt(payload, pws, nil, fastProfile, []uint8{1}); err == nil {
		t.Fatal("expected failure on wrong algorithm count")
	}
	// Correct algorithms work.
	got, err := Decrypt(payload, pws, nil, fastProfile, []uint8{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("mismatch")
	}
	// Wrong algorithms fail.
	if _, err := Decrypt(payload, pws, nil, fastProfile, []uint8{2, 1}); err == nil {
		t.Fatal("expected failure with wrong algorithms")
	}
}

func TestRecordedSchemesIgnoreSupplied(t *testing.T) {
	pt := []byte("recorded")
	layers := []Layer{{Kind: Password, SchemeID: 4, Password: []byte("p")}}
	payload, err := Encrypt(pt, layers, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	// A recorded payload opens without supplied algorithms.
	got, err := Decrypt(payload, [][]byte{[]byte("p")}, nil, fastProfile, nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("recorded decrypt failed: %v", err)
	}
	ds, _ := Descriptors(payload)
	if len(ds) != 1 || !ds[0].Recorded || ds[0].SchemeID != 4 {
		t.Fatalf("bad descriptor: %+v", ds)
	}
}

func TestWrongParamsFail(t *testing.T) {
	pt := []byte("cost matters")
	payload, err := Encrypt(pt, []Layer{{Kind: Password, SchemeID: 1, Password: []byte("p")}}, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	other := kdf.Params{Memory: 8 * 1024, Time: 2, Par: 1}
	if _, err := Decrypt(payload, [][]byte{[]byte("p")}, nil, other, nil); err == nil {
		t.Fatal("expected failure with different cost parameters")
	}
}

func TestCascadeAllSchemes(t *testing.T) {
	pt := bytes.Repeat([]byte("A"), 100)
	for _, s := range ciphers.All() {
		payload, err := Encrypt(pt, []Layer{{Kind: Password, SchemeID: s.ID, Password: []byte("p")}}, fastProfile, true)
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		got, err := Decrypt(payload, [][]byte{[]byte("p")}, nil, fastProfile, nil)
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("%s mismatch", s.Name)
		}
	}
}
