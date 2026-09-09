// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// splitOpts is the cheap configuration these tests share: one password layer at
// the lowest legal cost, since none of them is about the derivation.
func splitOpts(n, k int) SplitOptions {
	return SplitOptions{
		N: n, K: k,
		Params:     testParams,
		RecordAlgo: true,
		RecordKDF:  true,
		Layers:     []LayerSpec{{Kind: PasswordLayer, Password: []byte("stream test")}},
	}
}

// TestSplitToGivesTheSamePiecesAsSplit is the contract that makes the streaming
// path safe to use: it is the same split, delivered one piece at a time.
func TestSplitToGivesTheSamePiecesAsSplit(t *testing.T) {
	input := make([]byte, 40000)
	if _, err := rand.Read(input); err != nil {
		t.Fatal(err)
	}
	opts := splitOpts(5, 3)

	var streamed [][]byte
	var serials []int
	err := SplitTo(input, opts, func(serial int, piece []byte) error {
		serials = append(serials, serial)
		// The piece is only borrowed: SplitTo wipes it once this returns.
		streamed = append(streamed, bytes.Clone(piece))
		return nil
	})
	if err != nil {
		t.Fatalf("SplitTo: %v", err)
	}

	if len(streamed) != opts.N {
		t.Fatalf("streamed %d pieces, want %d", len(streamed), opts.N)
	}
	for i, s := range serials {
		if s != i+1 {
			t.Fatalf("pieces arrived as %v, want 1..%d in order", serials, opts.N)
		}
	}

	// Every piece must be the same size, since that is what lets the export
	// format be settled from the first one.
	for i, p := range streamed {
		if len(p) != len(streamed[0]) {
			t.Fatalf("piece %d is %d bytes, piece 1 is %d", i+1, len(p), len(streamed[0]))
		}
	}

	open := OpenOptions{Passwords: [][]byte{[]byte("stream test")}}
	recovered, err := Combine(streamed[:opts.K], open)
	if err != nil {
		t.Fatalf("streamed pieces must rebuild the input: %v", err)
	}
	if !bytes.Equal(recovered, input) {
		t.Fatal("streamed pieces rebuilt something else")
	}
}

// TestSplitToReleasesEachPiece checks a piece is wiped once it has been written,
// which is what bounds the memory a split needs.
func TestSplitToReleasesEachPiece(t *testing.T) {
	input := bytes.Repeat([]byte("release me"), 500)
	var borrowed [][]byte
	err := SplitTo(input, splitOpts(4, 2), func(serial int, piece []byte) error {
		borrowed = append(borrowed, piece)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range borrowed {
		if !allZero(p) {
			t.Fatalf("piece %d was still readable after SplitTo returned", i+1)
		}
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// TestSplitToStopsAtTheFirstFailure checks a write error ends the split rather
// than being collected at the end, so a full disk does not produce a set that is
// half written and reported as complete.
func TestSplitToStopsAtTheFirstFailure(t *testing.T) {
	stop := errors.New("disk full")
	seen := 0
	err := SplitTo([]byte("stop early"), splitOpts(5, 2), func(serial int, piece []byte) error {
		seen++
		if serial == 2 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) {
		t.Fatalf("the write error should come back unchanged, got %v", err)
	}
	if seen != 2 {
		t.Fatalf("%d pieces were offered after the failure, want 2", seen)
	}
}

// TestSplitToRefusesBadOptions checks the streaming path validates before it
// starts, the same as Split does.
func TestSplitToRefusesBadOptions(t *testing.T) {
	called := false
	write := func(serial int, piece []byte) error { called = true; return nil }

	if err := SplitTo([]byte("x"), splitOpts(2, 3), write); err == nil {
		t.Fatal("a threshold above the piece count must be refused")
	}
	if err := SplitTo([]byte("x"), splitOpts(0, 0), write); err == nil {
		t.Fatal("a split into no pieces must be refused")
	}
	if err := SplitTo([]byte("x"), splitOpts(300, 2), write); err == nil {
		t.Fatal("more pieces than the field allows must be refused")
	}
	if called {
		t.Fatal("nothing should be written for a split that cannot run")
	}
}

// TestSplitToWorksForEveryThreshold covers the shapes that take different paths
// inside the sharing: a single self-sufficient piece, and a real threshold.
func TestSplitToWorksForEveryThreshold(t *testing.T) {
	input := []byte("every shape of split streams the same")
	for _, c := range []struct{ n, k int }{{1, 1}, {3, 1}, {2, 2}, {5, 3}, {7, 7}} {
		opts := splitOpts(c.n, c.k)
		var pieces [][]byte
		err := SplitTo(input, opts, func(serial int, piece []byte) error {
			pieces = append(pieces, bytes.Clone(piece))
			return nil
		})
		if err != nil {
			t.Fatalf("%d-of-%d: %v", c.k, c.n, err)
		}
		got, err := Combine(pieces[:c.k], OpenOptions{Passwords: [][]byte{[]byte("stream test")}})
		if err != nil {
			t.Fatalf("%d-of-%d: %v", c.k, c.n, err)
		}
		if !bytes.Equal(got, input) {
			t.Fatalf("%d-of-%d rebuilt %q", c.k, c.n, got)
		}
	}
}

// TestMemoryEstimateIsNotOptimistic checks the figure quoted before a large
// split is never under what the shares alone cost, which is N times the input.
func TestMemoryEstimateIsNotOptimistic(t *testing.T) {
	for _, size := range []int{1 << 10, 1 << 20, 1 << 30} {
		for _, n := range []int{2, 5, 64, 255} {
			got := MemoryEstimate(size, n)
			if floor := int64(size) * int64(n); got < floor {
				t.Errorf("%d bytes into %d pieces estimated at %d, under the %d the shares need",
					size, n, got, floor)
			}
		}
	}
	// A terabyte must not overflow into a small or negative number.
	if got := MemoryEstimate(1<<40, 255); got < 1<<40*255 {
		t.Fatalf("a large input overflowed the estimate: %d", got)
	}
}

// TestSplitToKeyless checks the streaming path for a split with no encryption,
// which builds its pieces differently.
func TestSplitToKeyless(t *testing.T) {
	input := []byte("no password, streamed all the same")
	opts := SplitOptions{N: 4, K: 2, Keyless: true, Params: testParams,
		RecordAlgo: true, RecordKDF: true}
	var pieces [][]byte
	err := SplitTo(input, opts, func(serial int, piece []byte) error {
		pieces = append(pieces, bytes.Clone(piece))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine(pieces[1:3], OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("rebuilt %q", got)
	}
}
