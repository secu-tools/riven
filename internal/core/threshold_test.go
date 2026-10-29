// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/format"
)

// This file covers the threshold from the outside: which collections of pieces
// rebuild a file, which must not, and what a forged or damaged piece can achieve.

// reseal opens a keyless piece the way anyone holding docs/format.md can, lets
// edit change its manifest, and seals it again with the public keyless key. It is
// what an attacker can do to a set that has no password.
func reseal(t *testing.T, piece []byte, edit func(m *format.Manifest)) []byte {
	t.Helper()
	m, _, err := format.Decode(piece, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := format.Encode(format.EncodeInput{
		SetID: m.SetID, K: m.K, N: m.N, Serial: m.Serial,
		Encrypted: m.Encrypted, Hybrid: m.Hybrid, RecordAlgo: m.AlgoStored, Keyless: true,
		PayloadHash: m.PayloadHash, Layers: m.Layers,
		Share: m.Share, Name: m.Name, CreatorVersion: m.CreatorVersion, CreatorCommit: m.CreatorCommit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func reversed(pieces [][]byte) [][]byte {
	out := make([][]byte, len(pieces))
	for i, p := range pieces {
		out[len(pieces)-1-i] = p
	}
	return out
}

// TestAnyEnoughPiecesRecoverInAnyOrder checks every collection of at least K
// distinct pieces rebuilds the file: any K, any number above K up to N, in
// either order, and with a repeated piece mixed in; and that no K-1 do. The
// selection logic is the same in every protection mode, so a keyless set keeps
// this cheap.
func TestAnyEnoughPiecesRecoverInAnyOrder(t *testing.T) {
	input := []byte("any three of the five, in any order")
	pieces := mustSplit(t, input, SplitOptions{N: 5, K: 3, Keyless: true})

	allSubsetsOfSize(pieces, 2, func(sub [][]byte) {
		if _, err := Combine(sub, OpenOptions{}); err == nil {
			t.Fatal("2 of a 3-of-5 set rebuilt it")
		}
	})

	for size := 3; size <= 5; size++ {
		allSubsetsOfSize(pieces, size, func(sub [][]byte) {
			for _, held := range [][][]byte{sub, reversed(sub), append(sub, sub[0])} {
				got, err := Combine(held, OpenOptions{})
				if err != nil {
					t.Fatalf("%d pieces: %v", len(held), err)
				}
				if !bytes.Equal(got, input) {
					t.Fatalf("%d pieces: content changed", len(held))
				}
			}
		})
	}
}

// TestRepeatedPiecesDoNotCountTowardsTheThreshold checks K-1 distinct pieces
// stay short however they are repeated, including a copy sealed again so that its
// bytes differ: the threshold counts pieces, not files.
func TestRepeatedPiecesDoNotCountTowardsTheThreshold(t *testing.T) {
	pieces := mustSplit(t, []byte("repeats are not new pieces"), SplitOptions{N: 5, K: 3, Keyless: true})
	copyOfFirst := reseal(t, pieces[0], func(*format.Manifest) {})
	if bytes.Equal(copyOfFirst, pieces[0]) {
		t.Fatal("the resealed copy should differ in its bytes")
	}

	for _, held := range [][][]byte{
		{pieces[0], pieces[1], pieces[0]},
		{pieces[0], pieces[0], pieces[0], pieces[1]},
		{pieces[0], pieces[1], copyOfFirst},
	} {
		got, err := Combine(held, OpenOptions{})
		if err == nil {
			t.Fatalf("%d files holding 2 distinct pieces rebuilt a 3-of-5 set: %q", len(held), got)
		}
		if !strings.Contains(err.Error(), "distinct") {
			t.Fatalf("the error should be about the count of distinct pieces: %v", err)
		}
	}
}

// TestLargestSetRecovers covers N at the field's limit of 255, where every
// non-zero x-coordinate is in use: any two of a 2-of-255 set, and a 255-of-255
// set, which must fail one piece short.
func TestLargestSetRecovers(t *testing.T) {
	input := []byte("two hundred and fifty five")

	pieces := mustSplit(t, input, SplitOptions{N: 255, K: 2, Keyless: true})
	got, err := Combine([][]byte{pieces[254], pieces[0]}, OpenOptions{})
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("pieces 255 and 1 of a 2-of-255 set: %v", err)
	}

	pieces = mustSplit(t, input, SplitOptions{N: 255, K: 255, Keyless: true})
	got, err = Combine(pieces, OpenOptions{})
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("all of a 255-of-255 set: %v", err)
	}
	if _, err := Combine(pieces[1:], OpenOptions{}); err == nil {
		t.Fatal("254 pieces rebuilt a 255-of-255 set")
	}
}

// TestForgedShareIsCaughtByThePayloadHash covers the one integrity check a
// keyless set has. Its envelope key is public, so anyone can alter a share and
// seal the piece again; the payload hash in the manifest is what refuses the
// result instead of returning altered content (docs/format.md section 10).
func TestForgedShareIsCaughtByThePayloadHash(t *testing.T) {
	input := []byte("content that must not come back altered")
	pieces := mustSplit(t, input, SplitOptions{N: 3, K: 2, Keyless: true})
	forged := reseal(t, pieces[0], func(m *format.Manifest) { m.Share[0] ^= 0x01 })

	got, err := Combine([][]byte{forged, pieces[1]}, OpenOptions{})
	if err == nil {
		t.Fatalf("a forged share was accepted, giving %q", got)
	}
	if got != nil {
		t.Fatal("a failed reconstruction must not return any content")
	}
	if !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("the failure should be the integrity check: %v", err)
	}
}

// TestForgedThresholdRevealsNothing covers an attacker who holds fewer than K
// keyless pieces and rewrites the threshold they declare. Lowering it on every
// held piece gets past the count, but the shares still interpolate to the wrong
// payload, which the hash refuses; lowering it on some pieces only is refused
// as an inconsistent set. Neither returns content.
func TestForgedThresholdRevealsNothing(t *testing.T) {
	input := []byte("three are needed, two are held")
	pieces := mustSplit(t, input, SplitOptions{N: 5, K: 3, Keyless: true})
	lower := func(k int) func(*format.Manifest) {
		return func(m *format.Manifest) { m.K = k }
	}

	cases := map[string][][]byte{
		"both claim 2": {reseal(t, pieces[0], lower(2)), reseal(t, pieces[1], lower(2))},
		"one claims 1": {reseal(t, pieces[0], lower(1))},
		"one claims 2": {reseal(t, pieces[0], lower(2)), pieces[1]},
	}
	for name, held := range cases {
		got, err := Combine(held, OpenOptions{})
		if err == nil {
			t.Fatalf("%s: the forged threshold was accepted, giving %q", name, got)
		}
		if got != nil {
			t.Fatalf("%s: a failed reconstruction must not return any content", name)
		}
	}
}

// TestDamagedPieceIsToldApartFromAWrongPassword checks the diagnosis the FAQ
// promises: when one piece opens and another does not with the same password,
// the second is reported as damaged, by its position, rather than as a wrong
// password.
func TestDamagedPieceIsToldApartFromAWrongPassword(t *testing.T) {
	pw := [][]byte{[]byte("the right password")}
	// Every piece is needed, so the damaged one cannot be stepped over.
	pieces := mustSplit(t, []byte("one of these files is damaged"), SplitOptions{N: 3, K: 3,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: pw[0]}}})
	damaged := append([]byte(nil), pieces[1]...)
	damaged[len(damaged)/2] ^= 0xFF

	_, err := Combine([][]byte{pieces[0], damaged, pieces[2]}, OpenOptions{Passwords: pw})
	if err == nil {
		t.Fatal("a damaged piece must not be accepted")
	}
	if msg := err.Error(); !strings.Contains(msg, "piece 2") || !strings.Contains(msg, "damaged") {
		t.Fatalf("the error should name piece 2 as damaged: %v", err)
	}
}

// TestSplitWithNoProtectionIsRefused checks a split has to name a password, a
// recipient key or keyless mode. Without that rule a split with no layers would
// fall back to the public envelope without keyless mode's threshold of at least
// two, and at K=1 every piece would carry the file readable by anyone.
func TestSplitWithNoProtectionIsRefused(t *testing.T) {
	for _, k := range []int{1, 2} {
		if _, err := Split([]byte("unprotected"), SplitOptions{N: 3, K: k, Params: testParams}); err == nil {
			t.Fatalf("K=%d: a split with no password, no recipient and no keyless mode was accepted", k)
		}
	}
}

// TestOnePieceRevealsOnlyItsMetadata checks what one piece tells someone who has
// the password. It describes the piece and the set, not the content: two files
// of the same length and name give the same description apart from the set id
// and the payload id. And for a password set the payload id changes with every
// split, so it cannot be used to confirm a guess at the content.
func TestOnePieceRevealsOnlyItsMetadata(t *testing.T) {
	pw := [][]byte{[]byte("holder of one piece")}
	opts := SplitOptions{N: 3, K: 2, Name: "ledger.csv",
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: pw[0]}}}

	plain := bytes.Repeat([]byte("a"), 900)
	noise := make([]byte, len(plain))
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	describe := func(input []byte) *PieceInfo {
		info, err := Info(mustSplit(t, input, opts)[0], OpenOptions{Passwords: pw})
		if err != nil {
			t.Fatal(err)
		}
		return info
	}

	a, b := describe(plain), describe(noise)
	again := describe(plain)
	if a.PayloadHashHex == again.PayloadHashHex {
		t.Fatal("two splits of the same content share a payload id, so it fingerprints the content")
	}
	a.SetID, b.SetID = "", ""
	a.PayloadHashHex, b.PayloadHashHex = "", ""
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("one piece describes different content differently:\n%+v\n%+v", a, b)
	}
}
