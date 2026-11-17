// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package split

import (
	"testing"

	"github.com/secu-tools/riven/internal/testkit"
)

// TestEveryStretchOfALargeSecretIsSharedAfresh checks that cutting a large
// secret into units for the cores, and each unit into runs whose coefficients
// are drawn together, keeps the secrecy of a single sharing. Every symbol must
// get its own coefficients, so the stretches of one share must look unrelated
// even where the secret repeats, and shares below the threshold must give no
// stretch back. A stretch copied in the clear, or coefficients reused from one
// run to the next, would fail.
func TestEveryStretchOfALargeSecretIsSharedAfresh(t *testing.T) {
	// All zeros, so every stretch of the secret is the same; the last unit is
	// partial.
	secret := make([]byte, 2*unitBytes+unitBytes/2)
	const n, k = 4, 3
	shares, err := Split(secret, n, k)
	if err != nil {
		t.Fatal(err)
	}
	guess, err := Combine(shares[:k-1], k-1)
	if err != nil {
		t.Fatal(err)
	}

	// Interpolation is independent per symbol, so a sample from every stretch is
	// enough to measure, and keeps the test quick. A stretch is shorter than a
	// run of coefficients, so consecutive ones also compare runs.
	const stretch = 1 << 14
	values := func(share []byte, at int) []byte { return share[2+at : 2+at+stretch] }
	for at := 0; at+stretch <= len(secret); at += 4 * stretch {
		if chi := testkit.ChiSquare(values(shares[0], at)); chi > 400 {
			t.Fatalf("at %d one share is not uniform (chi-square %.0f)", at, chi)
		}
		zeros := 0
		for _, b := range guess[at : at+stretch] {
			if b == 0 {
				zeros++
			}
		}
		if zeros > stretch/20 {
			t.Fatalf("at %d: %d shares give back %d of %d secret bytes", at, k-1, zeros, stretch)
		}
		if chi := testkit.ChiSquare(guess[at : at+stretch]); chi > 400 {
			t.Fatalf("at %d: %d shares interpolate to a skewed value (chi-square %.0f)", at, k-1, chi)
		}
	}

	// Identical stretches of the secret must not give identical shares, however
	// far apart: coefficients reused from one word, run or unit to another would
	// repeat a block here, since the secret is zeros throughout.
	seen := map[[64]byte]int{}
	for at := 2; at+64 <= len(shares[0]); at += 64 {
		block := [64]byte(shares[0][at : at+64])
		if first, ok := seen[block]; ok {
			t.Fatalf("the share repeats its block at %d at %d", first, at)
		}
		seen[block] = at
	}
}
