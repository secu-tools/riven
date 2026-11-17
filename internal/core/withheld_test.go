// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"errors"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/kdf"
)

// TestCombineNamesWhatItWasNotGiven checks a combine missing something a set
// withheld says what, and how much of it: the algorithms for how many layers,
// whether no callback was given or the one given answered nothing.
func TestCombineNamesWhatItWasNotGiven(t *testing.T) {
	pws := [][]byte{[]byte("one"), []byte("two")}
	pieces, err := Split([]byte("withheld"), SplitOptions{N: 2, K: 2, Params: testParams, RecordKDF: true,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: pws[0]}, {Kind: PasswordLayer, Password: pws[1]}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, ask := range map[string]func(int) ([]uint8, error){
		"no callback":     nil,
		"an empty answer": func(int) ([]uint8, error) { return nil, nil },
	} {
		_, err := Combine(pieces, OpenOptions{Passwords: pws, AskSchemes: ask})
		if !errors.Is(err, ErrSchemesRequired) || !strings.Contains(err.Error(), "(2 layer(s))") {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, _, err := CombineFile(nil, OpenOptions{}); err == nil {
		t.Error("a combine of no pieces did not fail")
	}
}

// TestADeclinedCostStopsTheCombine checks an error from AskParams, such as the
// user cancelling the question, ends the combine with that error rather than
// with a guess at the cost.
func TestADeclinedCostStopsTheCombine(t *testing.T) {
	cancelled := errors.New("cancelled")
	ask := func(bool) (*kdf.Params, error) { return nil, cancelled }
	// The cost is not recorded, so the byte in its place is noise, which reads as
	// the real cost one time in 256; a set where it does needs no question.
	for range 4 {
		pieces, err := Split([]byte("no cost"), SplitOptions{N: 2, K: 2, Params: testParams, RecordAlgo: true,
			Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("pw")}}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = Combine(pieces, OpenOptions{Passwords: [][]byte{[]byte("pw")}, AskParams: ask})
		if err == nil {
			continue
		}
		if !errors.Is(err, cancelled) {
			t.Fatalf("got %v, want the cancelled question", err)
		}
		return
	}
	t.Fatal("four sets in a row opened at a cost byte of noise")
}
