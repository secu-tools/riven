// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package split

import (
	"testing"

	"github.com/secu-tools/riven/internal/shamir"
)

// TestChunkedSharesRevealNothingBelowTheThreshold checks that cutting a large
// secret into chunks keeps the secrecy of a single sharing. Each chunk is an
// independent sharing, so the chunks of one share must look unrelated even where
// the chunks of the secret are identical, and shares below the threshold, sliced
// chunk by chunk as docs/format.md section 6 describes, must not give any chunk
// back. A chunk copied in the clear, or one polynomial reused across chunks,
// would fail.
func TestChunkedSharesRevealNothingBelowTheThreshold(t *testing.T) {
	// All zeros, so every chunk of the secret is the same; the last is partial.
	secret := make([]byte, 2*chunkBytes+chunkBytes/2)
	const n, k = 4, 3
	shares, err := Split(secret, n, k)
	if err != nil {
		t.Fatal(err)
	}
	chunks := chunkCount(len(shares[0]))
	if chunks != 3 {
		t.Fatalf("expected 3 chunks, got %d", chunks)
	}

	// chunkOf returns chunk c of a share: its share bytes and its x-coordinate.
	chunkOf := func(share []byte, c int) (ys []byte, x byte) {
		lo := c * (chunkBytes + 1)
		hi := lo + chunkBytes + 1
		if hi > len(share) {
			hi = len(share)
		}
		return share[lo : hi-1], share[hi-1]
	}

	// Interpolation is independent per byte, so a prefix of every chunk is enough
	// to measure, and keeps the test quick.
	const sample = 1 << 14
	for c := 0; c < chunks; c++ {
		ys, _ := chunkOf(shares[0], c)
		if chi := chiSquare(ys[:sample]); chi > 400 {
			t.Fatalf("chunk %d of one share is not uniform (chi-square %.0f)", c+1, chi)
		}

		// What an attacker holding k-1 shares can compute for this chunk.
		held := make([][]byte, k-1)
		for i := range held {
			ys, x := chunkOf(shares[i], c)
			held[i] = append(append([]byte(nil), ys[:sample]...), x)
		}
		guess, err := shamir.Combine(held)
		if err != nil {
			t.Fatal(err)
		}
		zeros := 0
		for _, b := range guess {
			if b == 0 {
				zeros++
			}
		}
		if zeros > sample/20 {
			t.Fatalf("chunk %d: %d shares give back %d of %d secret bytes", c+1, k-1, zeros, sample)
		}
		if chi := chiSquare(guess); chi > 400 {
			t.Fatalf("chunk %d: %d shares interpolate to a skewed value (chi-square %.0f)", c+1, k-1, chi)
		}
	}

	// Identical secret chunks must not give identical share chunks.
	first, _ := chunkOf(shares[0], 0)
	second, _ := chunkOf(shares[0], 1)
	same := 0
	for i := range first {
		if first[i] == second[i] {
			same++
		}
	}
	if same > len(first)/20 {
		t.Fatalf("two chunks of one share agree on %d of %d bytes", same, len(first))
	}
}

// chiSquare measures how far the byte distribution of b is from uniform. With 255
// degrees of freedom a uniform source lands near 255; 400 is over six standard
// deviations above that.
func chiSquare(b []byte) float64 {
	var counts [256]int
	for _, v := range b {
		counts[v]++
	}
	expect := float64(len(b)) / 256
	chi := 0.0
	for _, c := range counts {
		d := float64(c) - expect
		chi += d * d / expect
	}
	return chi
}
