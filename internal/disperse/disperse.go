// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package disperse cuts data into n fragments, any k of which rebuild it. This is
// Rabin's information dispersal: each fragment is 1/k of the data, so n fragments
// cost n/k times the data rather than the n times Shamir sharing costs.
//
// Dispersal hides nothing on its own. A fragment is a linear mix of the data, so
// it is only for data that is already encrypted; Riven disperses a sealed package
// and shares the keys to it with Shamir.
//
// The data is read in groups of k bytes. Group j holds the coefficients of
//
//	p_j(X) = d[j*k] + d[j*k+1]*X + ... + d[j*k+k-1]*X^(k-1)
//
// over GF(2^8), the field Shamir uses. A fragment is its x-coordinate followed by
// p_j(x) for every group in order. Any k fragments with distinct coordinates give
// a k by k Vandermonde system for every group, which has exactly one solution.
package disperse

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/secu-tools/riven/internal/parallel"
)

// MaxFragments is the most fragments one dispersal can produce: the field has 255
// non-zero x-coordinates.
const MaxFragments = 255

// blockGroups is how many groups one unit of parallel work covers. It keeps each
// unit's slice of the data in cache while every fragment is computed from it.
const blockGroups = 1 << 16

// ErrTooFew is returned when fewer fragments than the threshold are supplied.
var ErrTooFew = errors.New("disperse: fewer fragments than the threshold")

// FragmentLen returns the length of every fragment of dataLen bytes dispersed at
// threshold k: one coordinate byte plus one byte per group.
func FragmentLen(dataLen, k int) int { return 1 + dataLen/k }

// Disperser is one dispersal whose fragments are computed one at a time, so a
// caller writing them out one by one holds the data and a single fragment rather
// than all n of them, each 1/k of the data. The coordinates are drawn when it is
// made, so every fragment belongs to the same dispersal.
type Disperser struct {
	data []byte
	k    int
	xs   []byte
}

// New prepares the dispersal of data into n fragments, any k of which rebuild
// it. The data length must be a positive multiple of k; the caller pads it, so
// that the padding is under its control rather than this package's. The data is
// read, not copied, so it must not change until the last fragment is taken.
func New(data []byte, n, k int) (*Disperser, error) {
	if k < 1 || n < k || n > MaxFragments {
		return nil, fmt.Errorf("disperse: need 1 <= k <= n <= %d, got k=%d n=%d", MaxFragments, k, n)
	}
	if len(data) == 0 || len(data)%k != 0 {
		return nil, fmt.Errorf("disperse: data length %d is not a positive multiple of %d", len(data), k)
	}
	xs, err := coordinates(n)
	if err != nil {
		return nil, err
	}
	return &Disperser{data: data, k: k, xs: xs}, nil
}

// Fragment computes fragment i, 0 <= i < n, as a new slice the caller owns.
func (d *Disperser) Fragment(i int) []byte {
	k := d.k
	groups := len(d.data) / k
	out := make([]byte, 1+groups)
	out[0] = d.xs[i]
	// Horner's rule, highest coefficient first, one table row for this x.
	row := &mulTable[d.xs[i]]
	frag := out[1:]
	eachBlock(groups, func(lo, hi int) {
		for j := lo; j < hi; j++ {
			g := d.data[j*k : j*k+k]
			var acc byte
			for t := k - 1; t >= 0; t-- {
				acc = row[acc] ^ g[t]
			}
			frag[j] = acc
		}
	})
	return out
}

// eachBlock runs fn over the groups [0, groups) in blocks of blockGroups, a block
// per core at a time.
func eachBlock(groups int, fn func(lo, hi int)) {
	blocks := (groups + blockGroups - 1) / blockGroups
	_ = parallel.Do(blocks, parallel.Workers(blocks), func(b int) error {
		lo := b * blockGroups
		fn(lo, min(lo+blockGroups, groups))
		return nil
	})
}

// Combine rebuilds the data from at least k fragments of one dispersal, using the
// first k. The result is the data exactly when the fragments are genuine; a wrong
// or altered fragment gives wrong bytes rather than an error, so the caller must
// authenticate what comes back.
func Combine(fragments [][]byte, k int) ([]byte, error) {
	if k < 1 {
		return nil, errors.New("disperse: threshold must be at least 1")
	}
	if len(fragments) < k {
		return nil, ErrTooFew
	}
	use := fragments[:k]
	xs, err := coordinatesOf(use)
	if err != nil {
		return nil, err
	}
	inv, err := invert(vandermonde(xs))
	if err != nil {
		return nil, err
	}
	// tables[t*k+r] multiplies by inv[t][r], so the inner loop is lookups and XORs.
	tables := make([]*[256]byte, k*k)
	for t := 0; t < k; t++ {
		for r := 0; r < k; r++ {
			tables[t*k+r] = &mulTable[inv[t][r]]
		}
	}

	groups := len(use[0]) - 1
	out := make([]byte, groups*k)
	eachBlock(groups, func(lo, hi int) {
		col := make([]byte, combineTile)
		for start := lo; start < hi; start += combineTile {
			solveTile(out, col, use, tables, start, min(start+combineTile, hi))
		}
	})
	return out, nil
}

// coordinatesOf checks the fragments are alike and returns their coordinates,
// which must be distinct and non-zero for the system to have one solution.
func coordinatesOf(use [][]byte) ([]byte, error) {
	flen := len(use[0])
	if flen < 2 {
		return nil, errors.New("disperse: fragment too short")
	}
	xs := make([]byte, len(use))
	seen := map[byte]bool{}
	for r, f := range use {
		if len(f) != flen {
			return nil, errors.New("disperse: fragments differ in length")
		}
		x := f[0]
		if x == 0 {
			return nil, errors.New("disperse: fragment has coordinate zero")
		}
		if seen[x] {
			return nil, errors.New("disperse: two fragments share a coordinate")
		}
		seen[x] = true
		xs[r] = x
	}
	return xs, nil
}

// combineTile is how many groups Combine solves together, small enough that the
// tile of every fragment stays in cache while each coefficient is computed.
const combineTile = 4096

// solveTile solves groups [start, end) into out, one coefficient at a time
// across the tile: the inner loop runs over consecutive fragment bytes with one
// table, which stays in cache. col is scratch of at least end-start bytes.
func solveTile(out, col []byte, use [][]byte, tables []*[256]byte, start, end int) {
	k := len(use)
	c := col[:end-start]
	for t := 0; t < k; t++ {
		tab := tables[t*k]
		for j, y := range use[0][1+start : 1+end] {
			c[j] = tab[y]
		}
		for r := 1; r < k; r++ {
			tab := tables[t*k+r]
			for j, y := range use[r][1+start : 1+end] {
				c[j] ^= tab[y]
			}
		}
		for j, v := range c {
			out[(start+j)*k+t] = v
		}
	}
}

// coordinates returns n distinct non-zero field elements in random order. They
// are not secret; drawing them at random means a fragment does not say which
// piece of the set it is.
func coordinates(n int) ([]byte, error) {
	all := make([]byte, MaxFragments)
	for i := range all {
		all[i] = byte(i + 1)
	}
	var rnd [MaxFragments * 2]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	// Fisher-Yates over the first n positions. Two random bytes give a value up to
	// 65535; the modulo bias that leaves is irrelevant for public coordinates.
	for i := 0; i < n; i++ {
		v := int(rnd[2*i])<<8 | int(rnd[2*i+1])
		j := i + v%(MaxFragments-i)
		all[i], all[j] = all[j], all[i]
	}
	return all[:n], nil
}

// vandermonde returns the k by k matrix with entry [r][t] = xs[r]^t, which maps a
// group's coefficients to its values at the fragment coordinates.
func vandermonde(xs []byte) [][]byte {
	k := len(xs)
	m := make([][]byte, k)
	for r, x := range xs {
		m[r] = make([]byte, k)
		p := byte(1)
		for t := 0; t < k; t++ {
			m[r][t] = p
			p = mul(p, x)
		}
	}
	return m
}

// invert returns the inverse of a square matrix over GF(2^8) by Gauss-Jordan
// elimination. A Vandermonde matrix with distinct coordinates is never singular,
// so the error is a guard rather than an expected outcome.
func invert(m [][]byte) ([][]byte, error) {
	k := len(m)
	a := make([][]byte, k)
	for r := range a {
		a[r] = make([]byte, 2*k)
		copy(a[r], m[r])
		a[r][k+r] = 1
	}
	for col := 0; col < k; col++ {
		pivot := -1
		for r := col; r < k; r++ {
			if a[r][col] != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			return nil, errors.New("disperse: singular matrix")
		}
		a[col], a[pivot] = a[pivot], a[col]
		scale := &mulTable[inverse(a[col][col])]
		for c := range a[col] {
			a[col][c] = scale[a[col][c]]
		}
		for r := 0; r < k; r++ {
			if r == col || a[r][col] == 0 {
				continue
			}
			f := &mulTable[a[r][col]]
			for c := range a[r] {
				a[r][c] ^= f[a[col][c]]
			}
		}
	}
	out := make([][]byte, k)
	for r := range out {
		out[r] = a[r][k:]
	}
	return out, nil
}
