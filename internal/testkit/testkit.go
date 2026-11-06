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
