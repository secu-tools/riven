// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package format

import (
	"bytes"
	"errors"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

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

// TestOneBufferServesEveryCall checks an OpenBuffer carries across separate
// calls, as a combine tries a piece first without a password, then with the
// first password, then with all of them: three attempts, one piece's worth.
func TestOneBufferServesEveryCall(t *testing.T) {
	in := buildInput(make([]byte, 4<<20))
	in.Passwords = [][]byte{[]byte("one"), []byte("two")}
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var ob OpenBuffer
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, _, err := ob.Decode(piece, nil, &fast); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("keyless: %v", err)
	}
	if _, _, err := ob.DecodePassword(piece, in.Passwords[:1], &fast); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("the first password alone: %v", err)
	}
	m, _, err := ob.DecodePassword(piece, in.Passwords, &fast)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	m.Wipe()
	// Two derivations at the test cost take 8 MiB each, and give it back.
	if got := after.TotalAlloc - before.TotalAlloc; got > uint64(2*len(piece))+uint64(2*fast.Memory)<<10 {
		t.Fatalf("three attempts on a %d-byte piece allocated %d bytes", len(piece), got)
	}
}

// TestTryingKeysReusesOneBuffer checks the ways tried on one piece share the
// memory they open into: a wrong key leaves it wiped for the next attempt, so a
// piece that opens at the third subset of keys costs one piece's worth, not
// three. Every subset here decapsulates, since any 32 bytes do for X25519, so
// each one that is wrong gets as far as a full open.
func TestTryingKeysReusesOneBuffer(t *testing.T) {
	a, b, other := genKey(t, kem.X25519), genKey(t, kem.X25519), genKey(t, kem.X25519)
	piece, err := Encode(sealedInput(make([]byte, 4<<20), nil, a, b))
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	m, _, err := DecodeSealed(piece, nil, []*kem.PrivateKey{a, other, b}, nil)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	m.Wipe()
	if got := after.TotalAlloc - before.TotalAlloc; got > uint64(2*len(piece)) {
		t.Fatalf("trying keys on a %d-byte piece allocated %d bytes", len(piece), got)
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
	piece, err := Encode(buildInput([]byte("shares")))
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
	in := sealedInput([]byte("shares"), nil, k, k)
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
	piece, err := Encode(sealedInput([]byte("shares"), nil, k))
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
		piece, err := Encode(sealedInput([]byte("shares"), nil, k))
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
	in := sealedInput([]byte("shares"), nil, genKey(t, kem.X25519))
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

// TestEncodeToSealsInPlace checks a piece sealed around a share and a fragment
// already where they go, in a buffer that held other bytes before, opens to them
// with every kind of envelope; and that EncodeTo refuses a buffer of the wrong
// length rather than writing past what the shape needs.
func TestEncodeToSealsInPlace(t *testing.T) {
	share, frag := bytes.Repeat([]byte("sh"), 500), bytes.Repeat([]byte("f"), 301)
	key := genKey(t, kem.X25519)
	pw := [][]byte{[]byte("password")}
	cases := map[string]struct {
		in   EncodeInput
		open func(piece []byte) (*Manifest, error)
	}{
		"password": {buildInput(share), func(p []byte) (*Manifest, error) {
			m, _, err := Decode(p, pw, nil)
			return m, err
		}},
		"recipient and password": {sealedInput(share, pw, key), func(p []byte) (*Manifest, error) {
			m, _, err := DecodeSealed(p, pw, []*kem.PrivateKey{key}, nil)
			return m, err
		}},
	}
	hidden := buildInput(share)
	hidden.Keyless, hidden.Passwords, hidden.DetailsShare, hidden.Pad = true, nil, []byte("details share"), true
	cases["keyless, hidden, padded"] = struct {
		in   EncodeInput
		open func(piece []byte) (*Manifest, error)
	}{hidden, func(p []byte) (*Manifest, error) {
		m, _, err := Decode(p, nil, nil)
		return m, err
	}}

	for name, tc := range cases {
		in := tc.in
		in.Fragment = frag
		shape := in.Shape()
		piece := bytes.Repeat([]byte{0xff}, PieceLen(shape))
		in.Fragment = piece[shape.FragmentAt():shape.ShareAt()]
		in.Share = piece[shape.ShareAt() : shape.ShareAt()+len(share)]
		copy(in.Fragment, frag)
		copy(in.Share, share)
		if err := EncodeTo(piece, in); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Contains(piece, share[:64]) {
			t.Fatalf("%s: the share is still in the clear", name)
		}
		m, err := tc.open(piece)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(m.Share, share) || !bytes.Equal(m.Fragment, frag) {
			t.Fatalf("%s: the share or the fragment did not come back", name)
		}
	}

	in := buildInput(share)
	for _, n := range []int{-1, 1} {
		piece := make([]byte, PieceLen(in.Shape())+n)
		if err := EncodeTo(piece, in); err == nil {
			t.Fatalf("a buffer %d bytes off was accepted", n)
		}
	}
}

// TestEncodeToWipesOnAnError checks a piece refused before it is sealed is wiped
// all the same: its share may already be in it, in the clear.
func TestEncodeToWipesOnAnError(t *testing.T) {
	in := buildInput([]byte("shares"))
	bad := in
	bad.Serial = 0
	for name, c := range map[string]struct {
		in    EncodeInput
		extra int
	}{"invalid input": {bad, 0}, "wrong length": {in, 1}} {
		piece := bytes.Repeat([]byte{0xAB}, PieceLen(c.in.Shape())+c.extra)
		if err := EncodeTo(piece, c.in); err == nil {
			t.Fatalf("%s: encoded", name)
		}
		if !bytes.Equal(piece, make([]byte, len(piece))) {
			t.Fatalf("%s: the piece was left as it was", name)
		}
	}
}

// TestAMislabelledPasswordEnvelopeIsRefused forges a piece whose envelope opens
// with the password key alone while its manifest says it is keyless: a keyless
// piece's manifest, sealed again under the password key. Both ways of opening a
// password piece must refuse it as mislabelled, rather than open it, and
// DecodeSealed must not go on to try the keys after that refusal.
func TestAMislabelledPasswordEnvelopeIsRefused(t *testing.T) {
	in := buildInput([]byte("keyless shares"))
	in.Keyless, in.Encrypted, in.Layers, in.Passwords = true, false, nil, nil
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	header := saltLen + kdfLen
	nonce := piece[header : header+nonceLen]
	keyless, err := chacha20poly1305.NewX(keylessKey(piece[:saltLen]))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := keyless.Open(nil, nonce, piece[header+nonceLen:], envelopeAD(piece[:header]))
	if err != nil {
		t.Fatal(err)
	}
	passwords := [][]byte{[]byte("password")}
	byPassword, err := chacha20poly1305.NewX(envelopeKey(passwords, piece[:saltLen], fast))
	if err != nil {
		t.Fatal(err)
	}
	forged := append(bytes.Clone(piece[:header+nonceLen]),
		byPassword.Seal(nil, nonce, manifest, envelopeAD(piece[:header]))...)

	if _, _, err := DecodePassword(forged, passwords, &fast); !errors.Is(err, errNotPasswordSealed) {
		t.Fatalf("DecodePassword: %v, want the piece refused as mislabelled", err)
	}
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	for _, keys := range [][]*kem.PrivateKey{nil, {priv}} {
		if _, _, err := DecodeSealed(forged, passwords, keys, &fast); !errors.Is(err, errNotPasswordSealed) {
			t.Fatalf("DecodeSealed with %d key(s): %v, want the piece refused as mislabelled", len(keys), err)
		}
	}
}
