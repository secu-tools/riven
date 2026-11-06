// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package format

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/secu-tools/riven/internal/cascade"
	"github.com/secu-tools/riven/internal/kem"
)

func genKey(t *testing.T, s kem.Scheme) *kem.PrivateKey {
	t.Helper()
	k, err := kem.Generate(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sealedInput is buildInput sealed to keys, with passwords only when given.
func sealedInput(share []byte, passwords [][]byte, keys ...*kem.PrivateKey) EncodeInput {
	in := buildInput(share)
	in.Passwords = passwords
	in.Layers = nil
	for _, k := range keys {
		in.Recipients = append(in.Recipients, k.Public())
		in.Layers = append(in.Layers, cascade.Descriptor{Kind: cascade.KEM, SchemeID: 1, Recorded: true})
	}
	return in
}

// TestSealedToKeysOnly checks a piece sealed to recipient keys alone opens with
// every one of them, in any order and alongside keys it does not need, and with
// nothing less: not the public key, not a password, and not some of the keys.
func TestSealedToKeysOnly(t *testing.T) {
	a, b := genKey(t, kem.X25519), genKey(t, kem.XWing)
	other := genKey(t, kem.X25519)
	share := []byte("a share sealed to two keys")
	piece, err := Encode(sealedInput(share, nil, a, b))
	if err != nil {
		t.Fatal(err)
	}

	for _, keys := range [][]*kem.PrivateKey{{a, b}, {b, a}, {other, b, a}, {a, other, b}} {
		m, _, err := DecodeSealed(piece, nil, keys, nil)
		if err != nil {
			t.Fatalf("%d keys: %v", len(keys), err)
		}
		if !m.SealedToKeys || m.Keyless || !bytes.Equal(m.Share, share) {
			t.Fatalf("bad manifest: %+v", m)
		}
	}
	for _, keys := range [][]*kem.PrivateKey{nil, {a}, {b}, {a, other}} {
		if _, _, err := DecodeSealed(piece, nil, keys, nil); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("%d keys opened a piece sealed to two: %v", len(keys), err)
		}
	}
	if _, _, err := Decode(piece, nil, nil); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("the public key opened a sealed piece: %v", err)
	}
	if _, _, err := DecodePassword(piece, [][]byte{[]byte("password")}, &fast); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("a password opened a piece sealed to keys alone: %v", err)
	}
}

// TestSealedToPasswordAndKey checks a set with both takes both: the key alone
// and the password alone each fail.
func TestSealedToPasswordAndKey(t *testing.T) {
	k := genKey(t, kem.X25519)
	pw := [][]byte{[]byte("password")}
	share := []byte("a share sealed to a password and a key")
	piece, err := Encode(sealedInput(share, pw, k))
	if err != nil {
		t.Fatal(err)
	}
	m, params, err := DecodeSealed(piece, pw, []*kem.PrivateKey{k}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Share, share) || params != fast {
		t.Fatalf("share or cost lost: %+v %+v", m, params)
	}
	if _, _, err := DecodeSealed(piece, nil, []*kem.PrivateKey{k}, nil); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("the key alone opened it: %v", err)
	}
	if _, _, err := DecodeSealed(piece, pw, nil, nil); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("the password alone opened it: %v", err)
	}
	if _, _, err := DecodeSealed(piece, [][]byte{[]byte("wrong")}, []*kem.PrivateKey{k}, nil); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("a wrong password opened it: %v", err)
	}
}

// TestDecodeSealedOpensAPasswordPiece checks a piece sealed with passwords alone
// opens through DecodeSealed too, whatever keys come with them.
func TestDecodeSealedOpensAPasswordPiece(t *testing.T) {
	piece, err := Encode(buildInput([]byte("share")))
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := DecodeSealed(piece, [][]byte{[]byte("password")}, []*kem.PrivateKey{genKey(t, kem.X25519)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.SealedToKeys {
		t.Fatal("a password piece reads as sealed to keys")
	}
}

// TestSealedRepeatedRecipient checks a key used for two layers is encapsulated
// to once, so its one private key opens the piece.
func TestSealedRepeatedRecipient(t *testing.T) {
	k := genKey(t, kem.X25519)
	in := sealedInput([]byte("share"), nil, k, k)
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeSealed(piece, nil, []*kem.PrivateKey{k}, nil); err != nil {
		t.Fatal(err)
	}
	want := PieceLen(Shape{Encaps: kem.X25519.CiphertextSize(), Share: len(in.Share), Layers: 2})
	if len(piece) != want {
		t.Fatalf("piece is %d bytes, PieceLen with one encapsulation says %d", len(piece), want)
	}
}

func TestSealedPieceLen(t *testing.T) {
	a, b := genKey(t, kem.P256), genKey(t, kem.MLKEM768)
	in := sealedInput(make([]byte, 100), [][]byte{[]byte("p")}, a, b)
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	encaps := kem.P256.CiphertextSize() + kem.MLKEM768.CiphertextSize()
	if want := PieceLen(Shape{Encaps: encaps, Share: 100, Layers: 2}); len(piece) != want {
		t.Fatalf("piece is %d bytes, PieceLen says %d", len(piece), want)
	}
}

// TestSealedHeaderIsBound checks a change anywhere in the encapsulations, which
// sit outside the AEAD, is caught.
func TestSealedHeaderIsBound(t *testing.T) {
	k := genKey(t, kem.X25519)
	piece, err := Encode(sealedInput([]byte("share"), nil, k))
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{saltLen + kdfLen, saltLen + kdfLen + kem.X25519.CiphertextSize() - 1} {
		bad := bytes.Clone(piece)
		bad[at] ^= 1
		if _, _, err := DecodeSealed(bad, nil, []*kem.PrivateKey{k}, nil); err == nil {
			t.Fatalf("a flipped bit at %d went unnoticed", at)
		}
	}
}

// TestSealedHeaderHasNoFixedBytes checks the encapsulations are masked: a P-256
// encapsulated key always starts 0x04, and a piece must not.
func TestSealedHeaderHasNoFixedBytes(t *testing.T) {
	k := genKey(t, kem.P256)
	seen := map[byte]bool{}
	for range 16 {
		piece, err := Encode(sealedInput([]byte("share"), nil, k))
		if err != nil {
			t.Fatal(err)
		}
		seen[piece[saltLen+kdfLen]] = true
	}
	if len(seen) < 2 {
		t.Fatal("the first byte of the encapsulated key is the same in every piece")
	}
}

func TestSealedRejectsKeyless(t *testing.T) {
	in := sealedInput([]byte("share"), nil, genKey(t, kem.X25519))
	in.Keyless = true
	if _, err := Encode(in); err == nil {
		t.Fatal("a keyless piece sealed to keys should be rejected")
	}
}

// TestEachSubsetOrder checks the subsets come largest first, each in key order,
// and that past maxSubsetKeys only the whole set is tried.
func TestEachSubsetOrder(t *testing.T) {
	keys := make([]*kem.PrivateKey, 3)
	for i := range keys {
		keys[i] = genKey(t, kem.X25519)
	}
	var sizes []int
	eachSubset(keys, func(sub []*kem.PrivateKey) *Manifest {
		sizes = append(sizes, len(sub))
		for i := 1; i < len(sub); i++ {
			if slices.Index(keys, sub[i]) < slices.Index(keys, sub[i-1]) {
				t.Fatal("a subset is out of order")
			}
		}
		return nil
	})
	if want := []int{3, 2, 2, 2, 1, 1, 1}; !slices.Equal(sizes, want) {
		t.Fatalf("sizes %v, want %v", sizes, want)
	}

	many := make([]*kem.PrivateKey, maxSubsetKeys+1)
	for i := range many {
		many[i] = keys[0]
	}
	tries := 0
	eachSubset(many, func([]*kem.PrivateKey) *Manifest { tries++; return nil })
	if tries != 1 {
		t.Fatalf("%d tries past maxSubsetKeys, want 1", tries)
	}
}

// FuzzDecodeSealed feeds arbitrary pieces to the sealed decoder, holding two
// keys of different types, with and without a password. The keys are made once,
// so the fuzzer spends its time on the header and the envelope, and the cost is
// fixed, as in FuzzDecode, so no input selects an expensive derivation. Whatever
// opens must have opened by a route its flags allow.
func FuzzDecodeSealed(f *testing.F) {
	a, err := kem.Generate(kem.X25519)
	if err != nil {
		f.Fatal(err)
	}
	b, err := kem.Generate(kem.XWing)
	if err != nil {
		f.Fatal(err)
	}
	keys := []*kem.PrivateKey{a, b}
	pw := []byte("password")
	for _, in := range []EncodeInput{
		sealedInput([]byte("seed share"), nil, a, b),
		sealedInput([]byte("seed share"), [][]byte{pw}, a),
		buildInput([]byte("seed share")),
	} {
		piece, err := Encode(in)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(piece, pw)
		f.Add(piece, []byte{})
	}
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, data, pw []byte) {
		var pws [][]byte
		if len(pw) > 0 {
			pws = [][]byte{pw}
		}
		m, _, err := DecodeSealed(data, pws, keys, &fast)
		if err != nil {
			return
		}
		defer m.Wipe()
		// Never keyless; opened with the password exactly when one was given;
		// without one, only by being sealed to the keys.
		if m.Keyless || m.PasswordOpened != (pws != nil) || !m.PasswordOpened && !m.SealedToKeys {
			t.Fatalf("opened by a route the flags do not allow: keyless %v, sealed %v, password %v",
				m.Keyless, m.SealedToKeys, m.PasswordOpened)
		}
	})
}
