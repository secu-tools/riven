// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package split

import (
	"bytes"
	"slices"
	"sync"
	"testing"
)

// unitLog records what a Progress is told, from whichever goroutine tells it.
type unitLog struct {
	mu    sync.Mutex
	done  []int
	total map[int]bool
}

func (l *unitLog) progress(done, total int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.done = append(l.done, done)
	if l.total == nil {
		l.total = map[int]bool{}
	}
	l.total[total] = true
}

// check asserts every unit was counted exactly once, against the one total.
func (l *unitLog) check(t *testing.T, what string, units int) {
	t.Helper()
	slices.Sort(l.done)
	want := make([]int, units)
	for i := range want {
		want[i] = i + 1
	}
	if !slices.Equal(l.done, want) || len(l.total) != 1 || !l.total[units] {
		t.Fatalf("%s reported done %v with totals %v, want 1..%d of %d", what, l.done, l.total, units, units)
	}
}

// splitTelling is Split telling p.
func splitTelling(secret []byte, n, k int, p Progress) ([][]byte, error) {
	dst := make([][]byte, n)
	for i := range dst {
		dst[i] = make([]byte, sizeOf(secret, k))
	}
	return dst, SplitInto(dst, secret, k, p)
}

// TestProgressCountsEveryUnit checks a split and a combine each report every
// unit once, out of the right total, though the units run concurrently. Four
// units are enough to show it.
func TestProgressCountsEveryUnit(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 3*unitBytes+2)
	var split unitLog
	shares, err := splitTelling(secret, 3, 2, split.progress)
	if err != nil {
		t.Fatal(err)
	}
	split.check(t, "the split", 4)

	var combine unitLog
	got, err := CombineProgress(shares[1:], 2, combine.progress)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("combine: %v", err)
	}
	combine.check(t, "the combine", 4)
}

// TestProgressIsQuietForOneStep checks what is done in one step reports
// nothing: a secret of one unit, and k of 1, which copies.
func TestProgressIsQuietForOneStep(t *testing.T) {
	var l unitLog
	for _, k := range []int{1, 2} {
		shares, err := splitTelling([]byte("shorts"), 3, k, l.progress)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CombineProgress(shares[:k], k, l.progress); err != nil {
			t.Fatal(err)
		}
	}
	if len(l.done) != 0 {
		t.Fatalf("one-step work reported %v", l.done)
	}
}
