// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kem"
)

// This file covers the requirement that a piece cannot be attributed to Riven,
// or to another piece, from its bytes alone. Each test states the property it
// pins rather than a particular byte layout, so the format can change without
// the guarantees quietly going with it.

// splitModes returns one representative set for every protection mode, which is
// what the stealth properties have to hold across.
func splitModes(t *testing.T, input []byte, n, k int) map[string][][]byte {
	t.Helper()
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	ids := ciphers.Cascade(2)
	modes := map[string]SplitOptions{
		"password": {N: n, K: k, Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("one")}}},
		"cascade": {N: n, K: k, Layers: []LayerSpec{
			{Kind: PasswordLayer, SchemeID: ids[0], Password: []byte("one")},
			{Kind: PasswordLayer, SchemeID: ids[1], Password: []byte("two")},
		}},
		"recipient": {N: n, K: k, Layers: []LayerSpec{{Kind: RecipientLayer, Recipient: priv.Public()}}},
		"hybrid": {N: n, K: k, Layers: []LayerSpec{
			{Kind: PasswordLayer, Password: []byte("one")},
			{Kind: RecipientLayer, Recipient: priv.Public()},
		}},
		"keyless": {N: n, K: k, Keyless: true},
	}
	out := make(map[string][][]byte, len(modes))
	for name, o := range modes {
		out[name] = mustSplit(t, input, o)
	}
	return out
}

// TestNoByteIsConstantAcrossSets is the no-magic-bytes requirement. If any
// offset held a fixed value, that value would be a signature for the tool.
func TestNoByteIsConstantAcrossSets(t *testing.T) {
	const sets = 48
	input := bytes.Repeat([]byte{0x41}, 400)
	var first []byte
	constant := map[int]byte{}

	for s := 0; s < sets; s++ {
		pieces := mustSplit(t, input, SplitOptions{N: 1, K: 1,
			Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("same password every time")}}})
		p := pieces[0]
		if first == nil {
			first = p
			for i, b := range p {
				constant[i] = b
			}
			continue
		}
		if len(p) != len(first) {
			t.Fatalf("set %d has a different piece length", s)
		}
		for i, b := range p {
			if v, ok := constant[i]; ok && v != b {
				delete(constant, i)
			}
		}
	}
	if len(constant) != 0 {
		offsets := make([]int, 0, len(constant))
		for i := range constant {
			offsets = append(offsets, i)
		}
		t.Fatalf("%d byte offsets are identical across %d sets: %v", len(constant), sets, offsets[:min(8, len(offsets))])
	}
}

// TestPiecesOfOneSetShareNoStructure checks that holding two pieces of the same
// set does not reveal that they belong together, in every mode.
func TestPiecesOfOneSetShareNoStructure(t *testing.T) {
	for mode, pieces := range splitModes(t, bytes.Repeat([]byte{0x41}, 600), 4, 2) {
		a, b := pieces[0], pieces[1]
		n := min(len(a), len(b))
		same := 0
		for i := 0; i < n; i++ {
			if a[i] == b[i] {
				same++
			}
		}
		// Unrelated bytes agree about one time in 256; allow generous slack for a
		// short piece while still catching a shared header.
		if limit := n/64 + 8; same > limit {
			t.Fatalf("%s: pieces share %d of %d bytes, over the %d expected by chance",
				mode, same, n, limit)
		}
	}
}

// TestPiecesLookRandom checks the byte distribution of a piece, since a piece
// that carried structured plaintext would show up as a skew.
func TestPiecesLookRandom(t *testing.T) {
	input := bytes.Repeat([]byte{0x00}, 8000) // maximally structured content
	for mode, pieces := range splitModes(t, input, 2, 2) {
		p := pieces[0]
		var counts [256]int
		for _, b := range p {
			counts[b]++
		}
		expect := float64(len(p)) / 256
		chi := 0.0
		for _, c := range counts {
			d := float64(c) - expect
			chi += d * d / expect
		}
		// 255 degrees of freedom: a uniform source lands near 255, and anything
		// with structure lands far above. 400 leaves ample room for noise.
		if chi > 400 {
			t.Fatalf("%s: byte distribution is far from uniform (chi-square %.0f)", mode, chi)
		}
		if math.IsNaN(chi) {
			t.Fatalf("%s: distribution could not be measured", mode)
		}
	}
}

// TestPiecesCarryNoPlaintext checks that a recognisable run from the input never
// appears in a piece, which is the property a person eyeballing hex would look
// for.
func TestPiecesCarryNoPlaintext(t *testing.T) {
	marker := []byte("BEGIN PGP PRIVATE KEY BLOCK")
	input := append(append([]byte("header "), marker...), []byte(" trailer")...)
	for mode, pieces := range splitModes(t, input, 3, 2) {
		for i, p := range pieces {
			if bytes.Contains(p, marker) {
				t.Fatalf("%s piece %d contains the plaintext marker", mode, i+1)
			}
			if bytes.Contains(p, []byte("riven")) {
				t.Fatalf("%s piece %d contains the tool name", mode, i+1)
			}
		}
	}
}

// TestSameInputTwiceSharesNothing checks that splitting the same file twice with
// the same password produces unrelated pieces, so two backups cannot be linked.
func TestSameInputTwiceSharesNothing(t *testing.T) {
	input := bytes.Repeat([]byte("linkable"), 100)
	opts := SplitOptions{N: 2, K: 2,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("same password")}}}
	a := mustSplit(t, input, opts)
	b := mustSplit(t, input, opts)

	if bytes.Equal(a[0], b[0]) {
		t.Fatal("two splits of the same input produced an identical piece")
	}
	same := 0
	n := min(len(a[0]), len(b[0]))
	for i := 0; i < n; i++ {
		if a[0][i] == b[0][i] {
			same++
		}
	}
	if limit := n/64 + 8; same > limit {
		t.Fatalf("pieces of two splits share %d of %d bytes, over the %d expected by chance", same, n, limit)
	}
}

// TestSizeDoesNotIdentifyTheLayerCount checks what the piece size does and does
// not give away about the protection. Each layer adds a fixed overhead, so two
// sets of the same content can differ in size; what must hold is that the size
// alone does not identify the layer count, because a one-layer set with slightly
// more content lands on exactly the same size as a two-layer set with less. An
// observer who does not already know the content length therefore learns
// nothing about the cascade from the size.
func TestSizeDoesNotIdentifyTheLayerCount(t *testing.T) {
	ids := ciphers.Cascade(2)
	sizeOf := func(contentLen, layers int) int {
		specs := make([]LayerSpec, layers)
		for i := range specs {
			specs[i] = LayerSpec{Kind: PasswordLayer, SchemeID: ids[i],
				Password: []byte(fmt.Sprintf("password-%d", i))}
		}
		pieces := mustSplit(t, bytes.Repeat([]byte("m"), contentLen),
			SplitOptions{N: 2, K: 2, Layers: specs})
		return len(pieces[0])
	}

	const base = 600
	two := sizeOf(base, 2)
	found := false
	for extra := 0; extra <= 300 && !found; extra++ {
		if sizeOf(base+extra, 1) == two {
			found = true
		}
	}
	if !found {
		t.Fatalf("no one-layer content length produced the %d bytes a two-layer set gave, "+
			"so the size would identify the layer count", two)
	}
}

// TestManyLayersRoundTrip covers the requirement that layers can be stacked as
// often as wanted: the count is not fixed by the format, and every password is
// needed in order.
func TestManyLayersRoundTrip(t *testing.T) {
	const layers = 24
	specs := make([]LayerSpec, layers)
	pws := make([][]byte, layers)
	for i := range specs {
		pws[i] = []byte(fmt.Sprintf("layer-%02d-password", i))
		specs[i] = LayerSpec{Kind: PasswordLayer, Password: pws[i]}
	}
	input := []byte("wrapped many times over")
	pieces := mustSplit(t, input, SplitOptions{N: 3, K: 2, Layers: specs})

	got, err := Combine(pieces[:2], OpenOptions{Passwords: pws})
	if err != nil {
		t.Fatalf("combine %d layers: %v", layers, err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("content changed")
	}

	// One password short, and one in the wrong order, must both fail.
	if _, err := Combine(pieces[:2], OpenOptions{Passwords: pws[:layers-1]}); err == nil {
		t.Fatal("a missing password must fail")
	}
	swapped := append([][]byte{}, pws...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if _, err := Combine(pieces[:2], OpenOptions{Passwords: swapped}); err == nil {
		t.Fatal("passwords in the wrong order must fail")
	}
}

// TestBelowThresholdRevealsNothing checks the guarantee that makes a leaked
// password harmless: below the threshold there is nothing to open, whatever is
// supplied.
func TestBelowThresholdRevealsNothing(t *testing.T) {
	secret := []byte("the whole point of the exercise")
	pw := [][]byte{[]byte("correct password")}
	pieces := mustSplit(t, secret, SplitOptions{N: 5, K: 4,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: pw[0]}}})

	for _, held := range [][][]byte{pieces[:1], pieces[:2], pieces[:3]} {
		if _, err := Combine(held, OpenOptions{Passwords: pw}); err == nil {
			t.Fatalf("%d of 4 pieces must not reconstruct", len(held))
		}
		// Even with the right password, the held pieces carry no plaintext.
		for _, p := range held {
			if bytes.Contains(p, secret[:8]) {
				t.Fatal("a piece below the threshold carries plaintext")
			}
		}
	}
	// The full threshold still works, so the failures above are the threshold and
	// not something else.
	if _, err := Combine(pieces[:4], OpenOptions{Passwords: pw}); err != nil {
		t.Fatalf("four pieces should reconstruct: %v", err)
	}
}

// TestPieceHasNoUsableLengthSignal checks that a piece of a large set is not
// distinguishable from one of a small set by length alone, since N and K live
// inside the encrypted manifest.
func TestPieceHasNoUsableLengthSignal(t *testing.T) {
	input := bytes.Repeat([]byte("n"), 400)
	small := mustSplit(t, input, SplitOptions{N: 2, K: 2,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("p")}}})
	large := mustSplit(t, input, SplitOptions{N: 200, K: 100,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("p")}}})
	if len(small[0]) != len(large[0]) {
		t.Fatalf("a 2-piece set gives %d bytes and a 200-piece set %d, so the set size leaks",
			len(small[0]), len(large[0]))
	}
}

// TestPieceSurvivesUnknownBytes checks that random data is rejected rather than
// mistaken for a piece, which is the other half of being indistinguishable from
// random: Riven must not claim ownership of arbitrary bytes either.
func TestPieceSurvivesUnknownBytes(t *testing.T) {
	junk := make([]byte, 512)
	if _, err := rand.Read(junk); err != nil {
		t.Fatal(err)
	}
	if _, err := Info(junk, OpenOptions{Passwords: [][]byte{[]byte("p")}}); err == nil {
		t.Fatal("random bytes must not open as a piece")
	}
	if _, err := Combine([][]byte{junk}, OpenOptions{Passwords: [][]byte{[]byte("p")}}); err == nil {
		t.Fatal("random bytes must not combine")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
