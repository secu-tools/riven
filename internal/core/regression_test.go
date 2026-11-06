// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/format"
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

// Defect: combining a set addressed to a recipient key, with no private key
// given, returned a plain error rather than ErrKeyRequired. The callers that
// check for it, the split's self-check and verify, then reported a failure for a
// set that was fine and only needed the key.
func TestRegressionMissingKeyIsErrKeyRequired(t *testing.T) {
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	// Protected details would need the key just to open a piece, so this is a
	// set whose details are public.
	pieces := mustSplit(t, []byte("for the key holder"), SplitOptions{N: 2, K: 2, Info: InfoPublic,
		Layers: []LayerSpec{{Kind: RecipientLayer, Recipient: priv.Public()}}})
	if _, err := Combine(pieces, OpenOptions{}); !errors.Is(err, ErrKeyRequired) {
		t.Fatalf("a missing private key was reported as %v", err)
	}
}

// Defect: one piece that did not open failed the whole combine, even with K
// intact pieces beside it, which defeats keeping spares. When the damaged piece
// came first the error even blamed the password.
func TestRegressionDamagedSpareDoesNotBlockTheRest(t *testing.T) {
	pw := [][]byte{[]byte("spares are for this")}
	input := []byte("rebuilt from the intact pieces")
	pieces := mustSplit(t, input, SplitOptions{N: 4, K: 2,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: pw[0]}}})
	for _, bad := range []int{0, 1} {
		set := [][]byte{pieces[0], pieces[1], pieces[2]}
		damaged := append([]byte(nil), set[bad]...)
		damaged[len(damaged)/2] ^= 0xFF
		set[bad] = damaged

		var reported []int
		got, err := Combine(set, OpenOptions{Passwords: pw,
			Damaged: func(i int, _ error) { reported = append(reported, i) }})
		if err != nil || !bytes.Equal(got, input) {
			t.Fatalf("piece %d damaged: two intact pieces of a 2-of-4 set did not rebuild: %v", bad+1, err)
		}
		// The rebuild succeeds, but the damaged file still has to be replaced.
		if len(reported) != 1 || reported[0] != bad {
			t.Fatalf("piece %d damaged: reported %v", bad+1, reported)
		}
	}
}

// Defect: every piece of a keyless set carried BLAKE2b-256 of the payload, which
// for a keyless set is a fixed three-byte header followed by the content. The
// envelope key is public, so one piece let anyone confirm a guess of the content:
// a PIN or a short password could be read off a single piece by trying them all.
func TestRegressionOnePieceCannotConfirmAGuess(t *testing.T) {
	secret := []byte("4821")
	opts := SplitOptions{N: 3, K: 2, Keyless: true}
	a, err := Info(mustSplit(t, secret, opts)[0], OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Info(mustSplit(t, secret, opts)[0], OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	guess := fmt.Sprintf("%x", format.Hash(append([]byte{0, 1, 0}, secret...)))
	if a.PayloadHashHex == guess {
		t.Fatal("one piece confirms a guess of the content")
	}
	if a.PayloadHashHex == b.PayloadHashHex {
		t.Fatal("two splits of the same content carry the same hash, so a guess can still be checked")
	}
}

// Defect: a set with no password recorded the content length in every piece,
// readable by anyone, and was never padded, so one piece gave the exact length.
// The length now sits inside the shared bytes and the padding applies, so two
// lengths in the same size class give pieces of the same size.
func TestRegressionKeylessPieceHidesTheLength(t *testing.T) {
	opts := SplitOptions{N: 3, K: 2, Keyless: true, Padding: PadPercent(100)}
	short := mustSplit(t, []byte("4821"), opts)
	long := mustSplit(t, bytes.Repeat([]byte("seed words "), 6), opts)
	if len(short[0]) != len(long[0]) {
		t.Fatalf("a 4-byte and a 66-byte secret gave pieces of %d and %d bytes", len(short[0]), len(long[0]))
	}
}
