// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// This file is Riven's own and is not part of the vendored copy: the upstream
// tests are in shamir_test.go, unchanged. Upstream checks that Split and Combine
// round-trip a four-byte secret at three of five, and spot-checks the field
// arithmetic. What Riven relies on most is not covered there: that the field is
// right for every value, that every threshold the format allows works, and that
// fewer shares than the threshold say nothing about the secret.

package shamir

import (
	"bytes"
	"crypto/rand"
	mathrand "math/rand/v2"
	"testing"
)

// refMult multiplies in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 by shift and add,
// the textbook way, as an independent check on the constant-time mult.
func refMult(a, b uint8) uint8 {
	var p uint8
	for b != 0 {
		if b&1 != 0 {
			p ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return p
}

// TestFieldArithmeticForEveryValue checks mult, div and inverse over the whole
// field. A wrong product for a single pair would corrupt every share byte that
// meets it, and only for those bytes, so spot checks would not see it.
func TestFieldArithmeticForEveryValue(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			x, y := uint8(a), uint8(b)
			if got, want := mult(x, y), refMult(x, y); got != want {
				t.Fatalf("mult(%d, %d) = %d, want %d", a, b, got, want)
			}
			if y != 0 {
				if q := div(x, y); refMult(q, y) != x {
					t.Fatalf("div(%d, %d) = %d, which does not multiply back", a, b, q)
				}
			}
		}
		if a != 0 && refMult(uint8(a), inverse(uint8(a))) != 1 {
			t.Fatalf("inverse(%d) is not an inverse", a)
		}
	}
}

// TestShareXCoordinatesAreNonZeroAndDistinct pins the rule secrecy rests on. A
// share is the value of each byte's polynomial at its x-coordinate: at x = 0 that
// value is the secret byte itself, and two shares at one x are one share. At 255
// parts every non-zero coordinate is used exactly once.
func TestShareXCoordinatesAreNonZeroAndDistinct(t *testing.T) {
	secret := []byte("x coordinates")
	for _, parts := range []int{2, 5, 255} {
		for run := 0; run < 20; run++ {
			shares, err := Split(secret, parts, 2)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[uint8]bool{}
			for i, s := range shares {
				x := s[len(s)-1]
				if x == 0 {
					t.Fatalf("parts=%d: share %d has x = 0, so it carries the secret", parts, i+1)
				}
				if seen[x] {
					t.Fatalf("parts=%d: x = %d is used twice", parts, x)
				}
				seen[x] = true
			}
		}
	}
}

// TestEveryThresholdRecovers covers thresholds up to the field's limit with a
// secret holding every byte value: exactly the threshold, chosen at random, and
// every share at once, since a reader may be handed more than it needs.
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
		// Interpolating 255 points is quadratic per byte, so the largest
		// thresholds use a short secret.
		{254, 255, allValues[:8]}, {255, 255, allValues[248:]},
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
		got, err := Combine(subset)
		if err != nil || !bytes.Equal(got, c.secret) {
			t.Fatalf("k=%d of %d: a random %d shares did not recover the secret: %v", c.k, c.parts, c.k, err)
		}
		got, err = Combine(shares)
		if err != nil || !bytes.Equal(got, c.secret) {
			t.Fatalf("k=%d of %d: all shares together did not recover the secret: %v", c.k, c.parts, err)
		}
	}
}

// TestFewerThanThresholdSharesRevealNothing checks the property the design rests
// on the way an attacker would try it: interpolate whatever shares are held,
// regardless of what any tool says about the count, and compare with the secret.
//
// With k-1 shares of a degree k-1 polynomial the value interpolated at zero is
// the secret plus a non-zero multiple of the top coefficient. It equals the
// secret only where that coefficient happened to be zero, one byte in 256, and
// the attacker cannot tell which bytes those are. A polynomial one degree short
// would give back every byte; with a single share, its own bytes are the guess.
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
		forEachSubset(len(shares), k-1, func(idx []int) {
			held := make([][]byte, len(idx))
			for i, j := range idx {
				held[i] = shares[j]
			}
			guess := held[0][:len(secret)]
			if len(held) > 1 {
				if guess, err = Combine(held); err != nil {
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
// every byte, or coefficients drawn from a fixed seed would each fail here.
func TestSharesAreUniformWhateverTheSecret(t *testing.T) {
	const size = 1 << 14
	for _, fill := range []byte{0x00, 0xFF} {
		secret := bytes.Repeat([]byte{fill}, size)
		for _, k := range []int{2, 3, 5} {
			shares, err := Split(secret, k+1, k)
			if err != nil {
				t.Fatal(err)
			}
			if chi := chiSquare(shares[0][:size]); chi > 400 {
				t.Fatalf("fill=%#02x k=%d: one share is not uniform (chi-square %.0f)", fill, k, chi)
			}
			if k > 2 {
				guess, err := Combine(shares[:k-1])
				if err != nil {
					t.Fatal(err)
				}
				if chi := chiSquare(guess); chi > 400 {
					t.Fatalf("fill=%#02x k=%d: %d shares interpolate to a skewed value (chi-square %.0f)",
						fill, k, k-1, chi)
				}
			}
		}
	}

	// Fresh randomness per split: with 255 parts both splits hold a share at
	// x = 1, and with fixed coefficients those two would be identical.
	secret := make([]byte, 4096)
	a, err := Split(secret, 255, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Split(secret, 255, 2)
	if err != nil {
		t.Fatal(err)
	}
	sa, sb := shareAt(a, 1), shareAt(b, 1)
	if same := countEqual(sa[:len(secret)], sb[:len(secret)]); same > len(secret)/20 {
		t.Fatalf("two splits of one secret agree on %d of %d bytes at x = 1", same, len(secret))
	}
}

func shareAt(shares [][]byte, x uint8) []byte {
	for _, s := range shares {
		if s[len(s)-1] == x {
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

// forEachSubset calls fn with every r-sized subset of 0..n-1, in increasing order.
func forEachSubset(n, r int, fn func(idx []int)) {
	idx := make([]int, r)
	var rec func(start, depth int)
	rec = func(start, depth int) {
		if depth == r {
			fn(append([]int(nil), idx...))
			return
		}
		for i := start; i < n; i++ {
			idx[depth] = i
			rec(i+1, depth+1)
		}
	}
	rec(0, 0)
}
