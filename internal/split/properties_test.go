// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package split

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand/v2"
	"testing"

	"github.com/secu-tools/riven/internal/testkit"
)

// TestShareXCoordinatesAreNonZeroAndDistinct pins the rule secrecy rests on. A
// share is the value of each symbol's polynomial at its x-coordinate: at x = 0
// that value is the secret symbol itself, and two shares at one x are one share.
// At 65535 parts every non-zero coordinate is used exactly once.
func TestShareXCoordinatesAreNonZeroAndDistinct(t *testing.T) {
	secret := []byte("x coordinates!")
	for _, c := range []struct{ parts, runs int }{{2, 20}, {5, 20}, {256, 20}, {MaxParts, 2}} {
		for run := 0; run < c.runs; run++ {
			shares, err := Split(secret, c.parts, 2)
			if err != nil {
				t.Fatal(err)
			}
			seen := make([]bool, 1<<16)
			for i, s := range shares {
				x := binary.BigEndian.Uint16(s)
				if x == 0 {
					t.Fatalf("parts=%d: share %d has x = 0, so it carries the secret", c.parts, i+1)
				}
				if seen[x] {
					t.Fatalf("parts=%d: x = %d is used twice", c.parts, x)
				}
				seen[x] = true
			}
		}
	}
}

// TestEveryThresholdRecovers covers thresholds from two to well past what an
// 8-bit field allows, with a secret holding every byte value: exactly the
// threshold, chosen at random, and every share at once, since a reader may be
// handed more than it needs.
func TestEveryThresholdRecovers(t *testing.T) {
	allValues := make([]byte, 256)
	for i := range allValues {
		allValues[i] = byte(i)
	}
	cases := []struct {
		k, parts int
		secret   []byte
	}{
		{2, 5, allValues}, {3, 7, allValues}, {4, 9, allValues},
		{7, 15, allValues}, {16, 33, allValues},
		// The work is the shares times the threshold per symbol, so the largest
		// thresholds use a short secret.
		{254, 255, allValues[:8]}, {255, 255, allValues[248:]},
		{256, 300, allValues[:8]}, {1000, 1000, allValues[:8]},
	}
	for _, c := range cases {
		shares, err := Split(c.secret, c.parts, c.k)
		if err != nil {
			t.Fatalf("k=%d: %v", c.k, err)
		}
		pick := mathrand.Perm(c.parts)[:c.k]
		subset := make([][]byte, c.k)
		for i, j := range pick {
			subset[i] = shares[j]
		}
		got, err := Combine(subset, c.k)
		if err != nil || !bytes.Equal(got, c.secret) {
			t.Fatalf("k=%d of %d: a random %d shares did not recover the secret: %v", c.k, c.parts, c.k, err)
		}
		got, err = Combine(shares, c.k)
		if err != nil || !bytes.Equal(got, c.secret) {
			t.Fatalf("k=%d of %d: all shares together did not recover the secret: %v", c.k, c.parts, err)
		}
	}
}

// TestEverySymbolValueSurvives shares a secret holding all 65536 symbol values,
// so a product wrong for one value would show.
func TestEverySymbolValueSurvives(t *testing.T) {
	secret := make([]byte, 0, 1<<17)
	for v := 0; v < 1<<16; v++ {
		secret = binary.BigEndian.AppendUint16(secret, uint16(v))
	}
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine([][]byte{shares[4], shares[0], shares[2]}, 3)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("every symbol value did not survive: %v", err)
	}
}

// TestFewerThanThresholdSharesRevealNothing checks the property the design rests
// on the way an attacker would try it: interpolate whatever shares are held,
// regardless of what any tool says about the count, and compare with the secret.
//
// With k-1 shares of a degree k-1 polynomial the value interpolated at zero is
// the secret plus a non-zero multiple of the top coefficient. It equals the
// secret only where that coefficient happened to be zero, one symbol in 65536,
// and the attacker cannot tell which those are. A polynomial one degree short
// would give back every symbol; with a single share, its own values are the
// guess.
func TestFewerThanThresholdSharesRevealNothing(t *testing.T) {
	secret := make([]byte, 4096)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	for _, k := range []int{2, 3, 4, 5} {
		shares, err := Split(secret, k+2, k)
		if err != nil {
			t.Fatal(err)
		}
		testkit.Subsets(len(shares), k-1, func(idx []int) {
			held := make([][]byte, len(idx))
			for i, j := range idx {
				held[i] = shares[j]
			}
			guess := held[0][2:]
			if len(held) > 1 {
				if guess, err = Combine(held, len(held)); err != nil {
					t.Fatal(err)
				}
			}
			// Chance gives 16 matching bytes here; the bound is far above that
			// and far below a leak.
			if same := countEqual(guess, secret); same > len(secret)/20 {
				t.Fatalf("k=%d: shares %v agree with the secret on %d of %d bytes",
					k, idx, same, len(secret))
			}
		})
	}
}

// TestSharesAreUniformWhateverTheSecret checks a single share, and what an
// attacker interpolates from k-1 of them, are uniformly distributed even for a
// secret with no entropy at all, and that splitting the same secret twice gives
// unrelated shares. A share that copied the secret, one polynomial reused for
// every symbol, or coefficients drawn from a fixed seed would each fail here.
func TestSharesAreUniformWhateverTheSecret(t *testing.T) {
	const size = 1 << 14
	for _, fill := range []byte{0x00, 0xFF} {
		secret := bytes.Repeat([]byte{fill}, size)
		for _, k := range []int{2, 3, 5} {
			shares, err := Split(secret, k+1, k)
			if err != nil {
				t.Fatal(err)
			}
			if chi := testkit.ChiSquare(shares[0][2:]); chi > 400 {
				t.Fatalf("fill=%#02x k=%d: one share is not uniform (chi-square %.0f)", fill, k, chi)
			}
			if k > 2 {
				guess, err := Combine(shares[:k-1], k-1)
				if err != nil {
					t.Fatal(err)
				}
				if chi := testkit.ChiSquare(guess); chi > 400 {
					t.Fatalf("fill=%#02x k=%d: %d shares interpolate to a skewed value (chi-square %.0f)",
						fill, k, k-1, chi)
				}
			}
		}
	}

	// Fresh randomness per split: with every coordinate taken both splits hold a
	// share at x = 1, and with fixed coefficients those two would be identical.
	secret := make([]byte, 256)
	a, err := Split(secret, MaxParts, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Split(secret, MaxParts, 2)
	if err != nil {
		t.Fatal(err)
	}
	sa, sb := shareAt(a, 1), shareAt(b, 1)
	if same := countEqual(sa[2:], sb[2:]); same > len(secret)/20 {
		t.Fatalf("two splits of one secret agree on %d of %d bytes at x = 1", same, len(secret))
	}
}

func shareAt(shares [][]byte, x uint16) []byte {
	for _, s := range shares {
		if binary.BigEndian.Uint16(s) == x {
			return s
		}
	}
	panic("no share at that x")
}

func countEqual(a, b []byte) int {
	n := 0
	for i := range a {
		if a[i] == b[i] {
			n++
		}
	}
	return n
}
