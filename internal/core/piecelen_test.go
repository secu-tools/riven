// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/kem"
)

// TestPieceLenIsWhatSplitMakes checks PieceLen against the pieces a split
// makes, across everything that decides their size: the method, the info mode,
// the layers, the padding and the input length. A split refuses a format on
// PieceLen's word before it makes any piece, so the two must agree exactly, and
// must refuse the same options.
func TestPieceLenIsWhatSplitMakes(t *testing.T) {
	rec, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	pw := LayerSpec{Kind: PasswordLayer, Password: []byte("pw")}
	key := LayerSpec{Kind: RecipientLayer, Recipient: rec.Public()}
	layerSets := map[string][]LayerSpec{"keyless": nil, "password": {pw}, "recipient": {key}, "both": {key, pw}}
	compared := 0

	for name, layers := range layerSets {
		for _, method := range []Method{MethodFull, MethodCompact} {
			for _, info := range []InfoMode{InfoAuto, InfoProtected, InfoPublic, InfoHidden, InfoStrict} {
				for _, pad := range []Padding{{}, PadNone()} {
					for _, size := range []int{1, 70000} {
						opts := SplitOptions{N: 4, K: 3, Params: testParams, Layers: layers, Keyless: layers == nil,
							Method: method, Info: info, Padding: pad, Name: "named.txt", RecordAlgo: true, RecordKDF: true}
						want, werr := PieceLen(size, opts)
						pieces, err := Split(make([]byte, size), opts)
						if (werr == nil) != (err == nil) {
							t.Fatalf("%s, method %d, info %d, pad %+v, %d bytes: PieceLen says %v, the split %v",
								name, method, info, pad, size, werr, err)
						}
						if err != nil {
							continue
						}
						compared++
						if got := len(pieces[0]); got != want {
							t.Fatalf("%s, method %d, info %d, pad %+v, %d bytes: PieceLen says %d, the split made %d",
								name, method, info, pad, size, want, got)
						}
					}
				}
			}
		}
	}
	if compared < 64 {
		t.Fatalf("only %d layouts were compared; the rest were refused", compared)
	}
}

// TestPieceLenRefusesWhatSplitRefuses checks the options a split turns away
// before any work are turned away by PieceLen too.
func TestPieceLenRefusesWhatSplitRefuses(t *testing.T) {
	for name, opts := range map[string]SplitOptions{
		"no protection":     {N: 3, K: 2, Params: testParams},
		"bad threshold":     {N: 2, K: 3, Keyless: true},
		"keyless and layer": {N: 3, K: 2, Keyless: true, Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("pw")}}},
		"keyless key":       {N: 3, K: 2, Params: testParams, Layers: []LayerSpec{{Kind: RecipientLayer}}},
		"unknown layer":     {N: 3, K: 2, Params: testParams, Layers: []LayerSpec{{Kind: 99}}},
	} {
		if _, err := PieceLen(10, opts); err == nil {
			t.Errorf("%s: PieceLen accepted what a split refuses", name)
		}
	}
}

// TestAnUnknownAlgorithmIsRefused checks a layer naming an algorithm id this
// build does not have is refused when the algorithms are assigned, before any
// layer is built with it.
func TestAnUnknownAlgorithmIsRefused(t *testing.T) {
	_, err := AssignSchemes([]LayerSpec{{Kind: PasswordLayer, Password: []byte("pw"), SchemeID: 250}})
	if err == nil || !strings.Contains(err.Error(), "unknown algorithm id 250") {
		t.Fatalf("got %v", err)
	}
}

// TestPieceLenRefusesALayerOfNoOneKind checks the layer checks run before the
// size is given, so a caller asking about the pieces never asks its questions
// for a split that cannot run.
func TestPieceLenRefusesALayerOfNoOneKind(t *testing.T) {
	rec, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]LayerSpec{
		"password with none":  {Kind: PasswordLayer},
		"password with a key": {Kind: PasswordLayer, Password: []byte("pw"), Recipient: rec.Public()},
		"key with a password": {Kind: RecipientLayer, Recipient: rec.Public(), Password: []byte("pw")},
	} {
		opts := SplitOptions{N: 3, K: 2, Params: testParams, Layers: []LayerSpec{l}}
		if _, err := PieceLen(10, opts); err == nil {
			t.Errorf("%s: PieceLen gave a size", name)
		}
		if _, err := Split([]byte("x"), opts); err == nil {
			t.Errorf("%s: the split ran", name)
		}
	}
}
