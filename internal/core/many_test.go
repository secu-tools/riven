// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"errors"
	"testing"

	"github.com/secu-tools/riven/internal/disperse"
	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/parallel"
	"github.com/secu-tools/riven/internal/split"
)

// TestEveryLayerAgreesOnTheMostPieces checks the limit is one number wherever it
// is enforced: the sharing, the dispersal and the format must all stop at the
// same count, or a split could make pieces a reader refuses.
func TestEveryLayerAgreesOnTheMostPieces(t *testing.T) {
	if MaxPieces != 65535 || split.MaxParts != MaxPieces || disperse.MaxFragments != MaxPieces ||
		format.MaxPieces != MaxPieces {
		t.Fatalf("the limits disagree: core %d, split %d, disperse %d, format %d",
			MaxPieces, split.MaxParts, disperse.MaxFragments, format.MaxPieces)
	}
}

// splitKeeping splits input and keeps only the pieces with the given serials,
// so a set of thousands is not held whole.
func splitKeeping(t *testing.T, input []byte, opts SplitOptions, serials ...int) [][]byte {
	t.Helper()
	want := map[int]int{}
	for i, s := range serials {
		want[s] = i
	}
	kept := make([][]byte, len(serials))
	err := SplitTo(input, opts, func(serial int, piece []byte) error {
		if i, ok := want[serial]; ok {
			kept[i] = bytes.Clone(piece)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v N=%d K=%d: %v", opts.Method, opts.N, opts.K, err)
	}
	return kept
}

// TestSetsPastAByteOfPieces splits past the 255 pieces an 8-bit field allows, for
// both methods and every way of showing the details, and rebuilds from pieces
// whose serials and thresholds need the second byte. The input is short, as a
// key would be, so the work stays small.
func TestSetsPastAByteOfPieces(t *testing.T) {
	input := []byte("a key worth splitting many ways")
	pw := []LayerSpec{{Kind: PasswordLayer, Password: []byte("pw")}}
	for _, m := range []Method{MethodFull, MethodCompact} {
		for _, c := range []struct {
			name string
			opts SplitOptions
		}{
			{"keyless", SplitOptions{Keyless: true}},
			{"protected", SplitOptions{Layers: pw, Params: testParams, RecordAlgo: true}},
			{"hidden", SplitOptions{Keyless: true, Info: InfoHidden}},
		} {
			opts := c.opts
			opts.N, opts.K, opts.Method = 300, 256, m
			serials := make([]int, 0, 256)
			for s := 45; s <= 300; s++ {
				serials = append(serials, s)
			}
			pieces := splitKeeping(t, input, opts, serials...)
			open := OpenOptions{Passwords: [][]byte{[]byte("pw")}, Params: &testParams}
			if c.opts.Keyless {
				open = OpenOptions{}
			}
			got, err := Combine(pieces, open)
			if err != nil || !bytes.Equal(got, input) {
				t.Fatalf("%v %s: pieces 45 to 300 of 300 did not rebuild: %v", m, c.name, err)
			}
			if _, err := Combine(pieces[1:], open); err == nil {
				t.Fatalf("%v %s: 255 pieces of a 256-of-300 set rebuilt it", m, c.name)
			}
			if c.name != "hidden" {
				info, err := Info(pieces[len(pieces)-1], open)
				if err != nil || info.Serial != 300 || info.N != 300 || info.K != 256 {
					t.Fatalf("%v %s: the last piece describes itself as %+v: %v", m, c.name, info, err)
				}
			}
		}
	}
}

// TestTheMostPiecesASetCanHave splits into every one of the 65535 pieces the
// field allows, with no password so nothing is stretched, and rebuilds from the
// first and the last.
func TestTheMostPiecesASetCanHave(t *testing.T) {
	input := []byte("one of 65535")
	for _, m := range []Method{MethodFull, MethodCompact} {
		pieces := splitKeeping(t, input, SplitOptions{N: MaxPieces, K: 2, Method: m, Keyless: true}, 1, MaxPieces)
		got, err := Combine(pieces, OpenOptions{})
		if err != nil || !bytes.Equal(got, input) {
			t.Fatalf("%v: pieces 1 and %d did not rebuild: %v", m, MaxPieces, err)
		}
	}
}

// TestCheckOnlyStopsBeforeTheLayers checks a check-only combine proves the pieces
// rebuild what the set shares without decrypting it: it needs no layer password,
// returns nothing, and still refuses too few pieces.
func TestCheckOnlyStopsBeforeTheLayers(t *testing.T) {
	input := []byte("checked, not decrypted")
	opts := SplitOptions{N: 4, K: 2, Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("pw")}},
		Params: testParams, Info: InfoPublic, RecordAlgo: true}
	for _, m := range []Method{MethodFull, MethodCompact} {
		opts.Method = m
		pieces, err := Split(input, opts)
		if err != nil {
			t.Fatal(err)
		}
		asked := false
		ask := func(int) ([][]byte, error) { asked = true; return nil, errors.New("no password here") }
		got, _, err := CombineFile(pieces[2:], OpenOptions{CheckOnly: true, AskPasswords: ask, Params: &testParams})
		if err != nil || got != nil || asked {
			t.Fatalf("%v: check-only gave %q, %v, asked for a password: %v", m, got, err, asked)
		}
		if _, _, err := CombineFile(pieces[:1], OpenOptions{CheckOnly: true, Params: &testParams}); err == nil {
			t.Fatalf("%v: one piece passed a check of a 2-of-4 set", m)
		}
		if _, err := Combine(pieces[2:], OpenOptions{AskPasswords: ask, Params: &testParams}); err == nil || !asked {
			t.Fatalf("%v: a full combine did not need the layer password: %v", m, err)
		}
	}
}

// TestPiecesAreSealedAheadWithinBudget checks how many pieces are sealed at
// once: as many as the derivation budget allows for a password envelope, every
// core otherwise, a full set's large pieces too, since they are made with its
// shares and sealing them ahead holds nothing more, and only as many compact
// pieces as fit in sealBudget, since each is made as it is sealed.
func TestPiecesAreSealedAheadWithinBudget(t *testing.T) {
	full := func(share int) *splitPrep {
		return &splitPrep{pieces: [][]byte{nil}, shape: format.Shape{Share: share}}
	}
	if w := full(100).sealWorkers(SplitOptions{N: 1000, K: 2}); w != parallel.Workers(1000) {
		t.Fatalf("small keyless pieces sealed %d at a time, want %d", w, parallel.Workers(1000))
	}
	pw := full(100)
	pw.envPasswords = [][]byte{[]byte("pw")}
	opts := SplitOptions{N: 1000, K: 2, Params: testParams}
	if got, want := pw.sealWorkers(opts), derivationWorkers(testParams, 1000); got != want {
		t.Fatalf("password pieces sealed %d at a time, want the derivation budget's %d", got, want)
	}
	if w := full(sealBudget).sealWorkers(SplitOptions{N: 5, K: 2}); w != parallel.Workers(5) {
		t.Fatalf("a full set's large pieces sealed %d at a time, want %d", w, parallel.Workers(5))
	}
	compact := &splitPrep{disp: &disperse.Disperser{}, shape: format.Shape{Fragment: sealBudget}}
	if w := compact.sealWorkers(SplitOptions{N: 5, K: 3}); w != 1 {
		t.Fatalf("compact pieces as large as the budget sealed %d at a time ahead of the one written", w)
	}
}
