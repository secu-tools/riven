// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package testkit holds helpers shared by tests in several packages. Nothing
// outside a test imports it.
package testkit

// ChiSquare measures how far the byte distribution of b is from uniform. With 255
// degrees of freedom a uniform source lands near 255; 400 is over six standard
// deviations above that.
func ChiSquare(b []byte) float64 {
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

// Subsets calls fn with every k-element subset of [0, n), each in increasing
// order and as a slice fn may keep.
func Subsets(n, k int, fn func(idx []int)) {
	idx := make([]int, k)
	var rec func(start, depth int)
	rec = func(start, depth int) {
		if depth == k {
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

// GF16Mul multiplies in GF(2^16) modulo x^16 + x^12 + x^3 + x + 1, the field of
// docs/format.md section 6, by shift and add. It is written from the definition
// and shares no code with the field Riven uses, so tests can check that against
// it.
func GF16Mul(a, b uint16) uint16 {
	var p uint16
	for ; b != 0; b >>= 1 {
		if b&1 != 0 {
			p ^= a
		}
		carry := a & 0x8000
		a <<= 1
		if carry != 0 {
			a ^= 0x100B
		}
	}
	return p
}

// GF16Inv returns a^(2^16-2), the inverse of a non-zero a, since every non-zero
// element to the power 2^16-1 is one.
func GF16Inv(a uint16) uint16 {
	r := uint16(1)
	for e := 1<<16 - 2; e > 0; e >>= 1 {
		if e&1 != 0 {
			r = GF16Mul(r, a)
		}
		a = GF16Mul(a, a)
	}
	return r
}
