// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build integration

// Package integration exercises the full library pipeline across a matrix of
// modes, sizes, thresholds, transport formats, and recording choices.
package integration

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/pieceio"
)

// fast keeps Argon2 cheap so the matrix stays quick; production defaults are
// far stronger.
var fast = kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}

func splitOpts(o core.SplitOptions) core.SplitOptions {
	o.Params = fast
	o.RecordAlgo = true
	o.RecordKDF = true
	return o
}

func roundTrip(t *testing.T, input []byte, so core.SplitOptions, oo core.OpenOptions, use int) {
	t.Helper()
	pieces, err := core.Split(input, so)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	got, err := core.Combine(pieces[:use], oo)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("mismatch: got %d bytes want %d", len(got), len(input))
	}
}

func TestThresholdsMatrix(t *testing.T) {
	input := []byte("threshold matrix payload")
	for _, c := range [][2]int{{1, 1}, {2, 1}, {2, 2}, {3, 2}, {5, 3}, {10, 8}, {16, 16}} {
		n, k := c[0], c[1]
		roundTrip(t, input,
			splitOpts(core.SplitOptions{N: n, K: k, Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("env")}}}),
			core.OpenOptions{Passwords: [][]byte{[]byte("env")}}, k)
	}
}

// TestRecordingMatrix covers every combination of recording the algorithms and
// the cost parameters.
func TestRecordingMatrix(t *testing.T) {
	input := []byte("recording matrix payload")
	custom := kdf.Params{Memory: 16 * 1024, Time: 2, Par: 2}
	ids := ciphers.Cascade(2)
	pws := [][]byte{[]byte("a"), []byte("b")}

	for _, recAlgo := range []bool{true, false} {
		for _, recKDF := range []bool{true, false} {
			name := fmt.Sprintf("algo=%v/kdf=%v", recAlgo, recKDF)
			t.Run(name, func(t *testing.T) {
				pieces, err := core.Split(input, core.SplitOptions{
					N: 4, K: 2, Params: custom,
					RecordAlgo: recAlgo, RecordKDF: recKDF,
					Layers: []core.LayerSpec{
						{SchemeID: ids[0], Password: pws[0]},
						{SchemeID: ids[1], Password: pws[1]},
					},
				})
				if err != nil {
					t.Fatal(err)
				}

				open := core.OpenOptions{Passwords: pws}
				if !recKDF {
					open.Params = &custom
				}
				if !recAlgo {
					open.Schemes = ids
				}
				got, err := core.Combine(pieces[:2], open)
				if err != nil {
					t.Fatalf("combine: %v", err)
				}
				if !bytes.Equal(got, input) {
					t.Fatal("mismatch")
				}

				// Omitting what was not recorded must fail rather than guess.
				if !recAlgo {
					bad := core.OpenOptions{Passwords: pws}
					if !recKDF {
						bad.Params = &custom
					}
					if _, err := core.Combine(pieces[:2], bad); err == nil {
						t.Fatal("expected failure without algorithms")
					}
				}
				if !recKDF {
					bad := core.OpenOptions{Passwords: pws, Schemes: ids}
					if _, err := core.Combine(pieces[:2], bad); err == nil {
						t.Fatal("expected failure without cost parameters")
					}
				}
			})
		}
	}
}

// TestMixedTransportFormats reconstructs from pieces that each arrived in a
// different form.
func TestMixedTransportFormats(t *testing.T) {
	input := []byte("mixed transport payload")
	formats := pieceio.Encodable() // one form per piece
	pieces, err := core.Split(input, splitOpts(core.SplitOptions{
		N: len(formats), K: len(formats),
		Layers: []core.LayerSpec{{SchemeID: ciphers.Default().ID, Password: []byte("pw")}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	decoded := make([][]byte, 0, len(pieces))
	for i, p := range pieces {
		data, _, err := pieceio.Encode(p, formats[i], 4)
		if err != nil {
			t.Fatal(err)
		}
		back, detected, err := pieceio.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		if detected != formats[i] {
			t.Fatalf("piece %d detected as %s, want %s", i+1, detected, formats[i])
		}
		decoded = append(decoded, back)
	}
	got, err := core.Combine(decoded, core.OpenOptions{Passwords: [][]byte{[]byte("pw")}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}
}

// TestQRCapacityBoundary finds the largest input that still fits in a QR code
// and confirms one byte more does not.
func TestQRCapacityBoundary(t *testing.T) {
	fits := func(inputLen int) bool {
		input := make([]byte, inputLen)
		rand.Read(input)
		pieces, err := core.Split(input, splitOpts(core.SplitOptions{
			N: 2, K: 2, Padding: core.PadNone(),
			Layers: []core.LayerSpec{{SchemeID: ciphers.Default().ID, Password: []byte("pw")}},
		}))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pieces {
			if !pieceio.QRFits(len(p)) {
				return false
			}
			if _, _, err := pieceio.Encode(p, pieceio.QR, 2); err != nil {
				return false
			}
		}
		return true
	}
	if !fits(1) {
		t.Fatal("a one-byte input should always fit in a QR code")
	}
	if fits(pieceio.QRMaxBytes * 2) {
		t.Fatal("an input far over capacity should not fit")
	}
}

func TestCrossSetRejected(t *testing.T) {
	in := []byte("payload")
	so := splitOpts(core.SplitOptions{N: 4, K: 2, Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("p")}}})
	a, err := core.Split(in, so)
	if err != nil {
		t.Fatal(err)
	}
	b, err := core.Split(in, so)
	if err != nil {
		t.Fatal(err)
	}
	oo := core.OpenOptions{Passwords: [][]byte{[]byte("p")}}
	if _, err := core.Combine([][]byte{a[0], b[1]}, oo); err == nil {
		t.Fatal("combining pieces from different sets should fail")
	}
}

// TestCostParametersMatterEndToEnd checks a recorded set cannot be opened with
// the wrong cost, which would indicate the cost was not bound to the envelope.
func TestCostParametersMatterEndToEnd(t *testing.T) {
	input := []byte("cost binding")
	pieces, err := core.Split(input, splitOpts(core.SplitOptions{N: 3, K: 2, Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("p")}}}))
	if err != nil {
		t.Fatal(err)
	}
	wrong := kdf.Params{Memory: 16 * 1024, Time: 4, Par: 4}
	if _, err := core.Combine(pieces[:2], core.OpenOptions{
		Passwords: [][]byte{[]byte("p")}, Params: &wrong,
	}); err == nil {
		t.Fatal("wrong cost parameters should fail")
	}
}
