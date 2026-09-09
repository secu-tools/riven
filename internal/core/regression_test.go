// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
)

// This file holds one test per defect found during development, so a fix cannot
// quietly regress. Each test states the original faulty behaviour.

// Defect: padding was drawn independently per piece, so an attacker holding
// several pieces of a set could take the smallest and land within a few bytes of
// the true length. Bucketed padding gives every piece of a set the same size, so
// extra pieces add nothing.
func TestRegressionExtraPiecesDoNotNarrowTheLength(t *testing.T) {
	pieces, err := Split(bytes.Repeat([]byte("z"), 3000), SplitOptions{
		N: 64, K: 2,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("p")}},
		Params: testParams, RecordAlgo: true, RecordKDF: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range pieces {
		if len(p) != len(pieces[0]) {
			t.Fatalf("piece %d is %d bytes, piece 1 is %d: sizes must not vary within a set",
				i+1, len(p), len(pieces[0]))
		}
	}
}

// Defect: the ML-KEM layer's algorithm was never resolved by the caller that had
// to name the algorithms afterwards, so it was passed as id 0 and verification
// failed with "unknown scheme id 0" whenever recording was switched off.
func TestRegressionRecipientLayerAlgorithmIsResolved(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	layers := []LayerSpec{
		{Kind: PasswordLayer, Password: []byte("pw")},
		{Kind: RecipientLayer, Recipient: priv.Public()},
	}
	ids, err := AssignSchemes(layers)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		if id == 0 {
			t.Fatalf("layer %d was left with algorithm id 0", i+1)
		}
		if _, ok := ciphers.ByID(id); !ok {
			t.Fatalf("layer %d resolved to unknown id %d", i+1, id)
		}
	}

	// The whole path must work with recording off, which is where it used to fail.
	input := []byte("recorded nothing")
	pieces, err := Split(input, SplitOptions{
		N: 3, K: 2, Layers: layers,
		Params: testParams, RecordAlgo: false, RecordKDF: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine(pieces[:2], OpenOptions{
		Passwords:   [][]byte{[]byte("pw")},
		PrivateKeys: []*kem.PrivateKey{priv},
		Schemes:     ids,
	})
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}
}

// Defect: the adjacent-algorithm rule only looked at password layers, so a
// recipient layer could repeat the algorithm of the layer above it.
func TestRegressionAdjacentRuleCoversRecipientLayers(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	same := ciphers.Default().ID
	_, err = AssignSchemes([]LayerSpec{
		{Kind: PasswordLayer, SchemeID: same, Password: []byte("pw")},
		{Kind: RecipientLayer, SchemeID: same, Recipient: priv.Public()},
	})
	if err == nil {
		t.Fatal("a recipient layer repeating the algorithm above it must be rejected")
	}

	// Left unset, the recipient layer must be given a different algorithm.
	ids, err := AssignSchemes([]LayerSpec{
		{Kind: PasswordLayer, SchemeID: same, Password: []byte("pw")},
		{Kind: RecipientLayer, Recipient: priv.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ids[0] == ids[1] {
		t.Fatal("automatic assignment repeated the adjacent algorithm")
	}
}

// Defect: a recipient key with no password caused a password to be generated
// behind the user's back, which is not what public-key delivery means.
func TestRegressionRecipientOnlyNeedsNoPassword(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("no password anywhere")
	pieces, err := Split(input, SplitOptions{
		N: 3, K: 2,
		Layers: []LayerSpec{{Kind: RecipientLayer, Recipient: priv.Public()}},
		Params: testParams, RecordAlgo: true, RecordKDF: true,
	})
	if err != nil {
		t.Fatalf("recipient-only split must be allowed: %v", err)
	}
	got, err := Combine(pieces[:2], OpenOptions{PrivateKeys: []*kem.PrivateKey{priv}})
	if err != nil {
		t.Fatalf("the key alone must decrypt: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}
}

// Defect: the cost parameters recorded in a piece were trusted without bound, so
// arbitrary bytes could ask for the largest configuration. The parameters are read
// without deriving a key so a caller can see the cost first.
func TestRegressionCostCanBeInspectedBeforeUse(t *testing.T) {
	want := kdf.Params{Memory: 32 * 1024, Time: 4, Par: 2}
	pieces, err := Split([]byte("cost"), SplitOptions{
		N: 2, K: 2,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("p")}},
		Params: want, RecordAlgo: true, RecordKDF: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := Info(pieces[0], OpenOptions{Passwords: [][]byte{[]byte("p")}})
	if err != nil {
		t.Fatal(err)
	}
	if info.Params != want {
		t.Fatalf("recorded cost came back as %+v, want %+v", info.Params, want)
	}
}

// Defect: a set that omitted its algorithms reported the wrong error for a
// below-threshold reconstruction, sending the user to look at cost parameters.
func TestRegressionThresholdErrorIsNotAKeyOrCostError(t *testing.T) {
	pieces, err := Split([]byte("threshold"), SplitOptions{
		N: 5, K: 3,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("p")}},
		Params: testParams, RecordAlgo: true, RecordKDF: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Combine(pieces[:2], OpenOptions{Passwords: [][]byte{[]byte("p")}})
	if err == nil {
		t.Fatal("two pieces must not satisfy a threshold of three")
	}
	// The message must be about the count, not about a password or a key.
	msg := err.Error()
	for _, wrong := range []string{"password", "private key", "Argon2"} {
		if bytes.Contains([]byte(msg), []byte(wrong)) {
			t.Fatalf("threshold error mentions %q: %s", wrong, msg)
		}
	}
}

// Defect: a keyless set could be created with a threshold of one, which would put
// the whole file in the clear in every piece.
func TestRegressionKeylessRefusesThresholdOne(t *testing.T) {
	if _, err := Split([]byte("x"), SplitOptions{N: 3, K: 1, Keyless: true}); err == nil {
		t.Fatal("keyless with K=1 must be refused")
	}
}

// Defect: a password layer and a recipient layer could be described in the same
// spec, leaving it ambiguous which keyed the layer.
func TestRegressionLayerKindMustMatchItsFields(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	bad := []SplitOptions{
		{N: 2, K: 2, Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("p"), Recipient: priv.Public()}}},
		{N: 2, K: 2, Layers: []LayerSpec{{Kind: RecipientLayer, Recipient: priv.Public(), Password: []byte("p")}}},
		{N: 2, K: 2, Layers: []LayerSpec{{Kind: PasswordLayer}}},
		{N: 2, K: 2, Layers: []LayerSpec{{Kind: RecipientLayer}}},
	}
	for i, so := range bad {
		so.Params = testParams
		so.RecordAlgo = true
		so.RecordKDF = true
		if _, err := Split([]byte("x"), so); err == nil {
			t.Fatalf("case %d: a contradictory layer must be refused", i+1)
		}
	}
}
