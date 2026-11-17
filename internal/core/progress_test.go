// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"sync"
	"testing"

	"github.com/secu-tools/riven/internal/kdf"
)

// stepLog records what a Progress is told: each step as it starts, with "" for
// none under way, and the furthest a measured step got.
type stepLog struct {
	mu       sync.Mutex
	steps    []string
	furthest map[string][2]int64 // done and total
}

func (l *stepLog) progress(step string, done, total int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.steps) == 0 || l.steps[len(l.steps)-1] != step {
		l.steps = append(l.steps, step)
	}
	if total > 0 && done > l.furthest[step][0] {
		if l.furthest == nil {
			l.furthest = map[string][2]int64{}
		}
		l.furthest[step] = [2]int64{done, total}
	}
}

// idle reports whether no step is under way.
func (l *stepLog) idle() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.steps) == 0 || l.steps[len(l.steps)-1] == ""
}

// check asserts the steps include want in order, and end with none under way.
func (l *stepLog) check(t *testing.T, what string, want ...string) {
	t.Helper()
	at := 0
	for _, s := range l.steps {
		if at < len(want) && s == want[at] {
			at++
		}
	}
	if at < len(want) || !l.idle() {
		t.Fatalf("%s reported %q, want %q in order and then none under way", what, l.steps, want)
	}
}

// measured asserts a step counted all the way to a total of at least min.
func (l *stepLog) measured(t *testing.T, step string, min int64) {
	t.Helper()
	if f := l.furthest[step]; f[0] != f[1] || f[1] < min {
		t.Fatalf("%q got to %d of %d, want all of at least %d", step, f[0], f[1], min)
	}
}

// TestProgressFollowsEachMethod checks a split and a combine report their steps
// in order, measure the Shamir work by its units, and are idle when the caller
// may ask something: when the first piece is handed over, and once they return.
// The input is just over one unit, so the sharing is measured.
func TestProgressFollowsEachMethod(t *testing.T) {
	input := bytes.Repeat([]byte("p"), 600<<10)
	for _, c := range []struct {
		method         Method
		split, rebuild []string
	}{
		{MethodFull,
			[]string{"encrypting", "sharing", ""},
			[]string{"opening pieces", "", "rebuilding", "hashing", "", "decrypting", ""}},
		{MethodCompact,
			[]string{"encrypting", ""},
			[]string{"opening pieces", "", "rebuilding", "hashing", "rebuilding", "decrypting", "", "decrypting", ""}},
	} {
		var split stepLog
		var pieces [][]byte
		err := SplitTo(input, SplitOptions{N: 3, K: 2, Keyless: true, Method: c.method, Progress: split.progress},
			func(serial int, p []byte) error {
				if serial == 1 && !split.idle() {
					t.Errorf("%v: a step was under way when the first piece was handed over: %q", c.method, split.steps)
				}
				pieces = append(pieces, bytes.Clone(p))
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
		split.check(t, c.method.String()+" split", c.split...)

		var combine stepLog
		got, err := Combine(pieces[1:], OpenOptions{Progress: combine.progress})
		if err != nil || !bytes.Equal(got, input) {
			t.Fatalf("%v combine: %v", c.method, err)
		}
		combine.check(t, c.method.String()+" combine", c.rebuild...)
		if c.method == MethodFull {
			split.measured(t, "sharing", 2)
			combine.measured(t, "rebuilding", 2)
		}
	}
}

// TestProgressIsIdleWhenAsking checks no step is under way when a combine calls
// back to ask for something, so a caller's prompt is never drawn over. The set
// withholds what it can and takes a password per layer, so every question is
// asked: the envelope's password, the cost, the algorithms and the rest of the
// passwords.
func TestProgressIsIdleWhenAsking(t *testing.T) {
	pw1, pw2 := []byte("first"), []byte("second")
	specs := []LayerSpec{{Kind: PasswordLayer, Password: pw1}, {Kind: PasswordLayer, Password: pw2}}
	schemes, err := AssignSchemes(specs)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("asked for everything")
	pieces := mustSplit(t, input, SplitOptions{N: 3, K: 2, Params: testParams, Layers: specs})

	var log stepLog
	asked := map[string]int{}
	ask := func(what string) {
		asked[what]++
		if !log.idle() {
			t.Errorf("asked for %s with a step under way: %q", what, log.steps)
		}
	}
	params := testParams
	got, err := Combine(pieces[:2], OpenOptions{
		Progress: log.progress,
		EnvelopePasswords: func(bool) ([][]byte, error) {
			ask("the envelope password")
			return [][]byte{bytes.Clone(pw1)}, nil
		},
		AskPasswords: func(int) ([][]byte, error) {
			ask("the layer passwords")
			return [][]byte{bytes.Clone(pw1), bytes.Clone(pw2)}, nil
		},
		AskParams: func(bool) (*kdf.Params, error) {
			ask("the cost")
			return &params, nil
		},
		AskSchemes: func(int) ([]uint8, error) {
			ask("the algorithms")
			return schemes, nil
		},
		BeforeDerive: func(kdf.Params) { ask("nothing, but warned of the cost") },
	})
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("combine: %v", err)
	}
	if asked["the envelope password"] == 0 || asked["the layer passwords"] == 0 {
		t.Fatalf("the questions were not all asked: %v", asked)
	}
	log.check(t, "the combine", "rebuilding", "decrypting")
}

// TestSplitRefusesCountsBeforeAnyWork checks a piece count or threshold the
// field cannot hold is refused before the input is encrypted, for both methods:
// GF(2^16) has 65535 points to give pieces, and each count is two bytes.
func TestSplitRefusesCountsBeforeAnyWork(t *testing.T) {
	pw := []LayerSpec{{Kind: PasswordLayer, Password: []byte("pw")}}
	for _, m := range []Method{MethodFull, MethodCompact} {
		for _, c := range []struct{ n, k int }{{MaxPieces + 1, 2}, {1_000_000, 3}, {3, 4}, {3, 0}, {0, 0}} {
			var log stepLog
			opts := SplitOptions{N: c.n, K: c.k, Method: m, Params: testParams, Layers: pw, Progress: log.progress}
			wrote := 0
			err := SplitTo([]byte("counted"), opts, func(int, []byte) error { wrote++; return nil })
			if err == nil || wrote != 0 || len(log.steps) != 0 {
				t.Fatalf("%v with N=%d K=%d: %v, %d piece(s) written, steps %q; want refused before any work",
					m, c.n, c.k, err, wrote, log.steps)
			}
		}
	}
}

// TestProgressCountsThePiecesOpened checks opening the pieces of a password set,
// one key derivation each, says how many are open: past the first, which is
// opened alone, every piece is counted once.
func TestProgressCountsThePiecesOpened(t *testing.T) {
	pieces, err := Split([]byte("counted as they open"), SplitOptions{N: 6, K: 3,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("pw")}}, Params: testParams, RecordAlgo: true})
	if err != nil {
		t.Fatal(err)
	}
	var log stepLog
	open := OpenOptions{Passwords: [][]byte{[]byte("pw")}, Params: &testParams, Progress: log.progress}
	if _, err := Combine(pieces, open); err != nil {
		t.Fatal(err)
	}
	log.measured(t, "opening pieces", 5)
}
