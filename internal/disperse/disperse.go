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
// The data is read as 16-bit symbols, high byte first, in groups of k. Group j
// holds the coefficients of
//
//	p_j(X) = d[j*k] + d[j*k+1]*X + ... + d[j*k+k-1]*X^(k-1)
//
// over GF(2^16), the field Shamir uses. A fragment is its u16 x-coordinate
// followed by p_j(x) for every group in order. Any k fragments with distinct
// coordinates give a k by k Vandermonde system for every group, which has exactly
// one solution.
//
// The data is ciphertext, so the arithmetic here uses tables, whose timing
// depends on the values.
package disperse

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/secu-tools/riven/internal/gf16"
	"github.com/secu-tools/riven/internal/parallel"
)

// MaxFragments is the most fragments one dispersal can produce: the field has
// 65535 non-zero x-coordinates.
const MaxFragments = gf16.MaxPoints

// blockWork is about how many multiplications one unit of parallel work does:
// enough to outweigh handing it to a core, few enough to share the work out.
const blockWork = 1 << 20

// ErrTooFew is returned when fewer fragments than the threshold are supplied.
var ErrTooFew = errors.New("disperse: fewer fragments than the threshold")

// GroupLen returns how many bytes of data one fragment symbol stands for at
// threshold k: a group of k symbols.
func GroupLen(k int) int { return gf16.Size * k }

// FragmentLen returns the length of every fragment of dataLen bytes dispersed at
// threshold k: a coordinate plus one symbol per group.
func FragmentLen(dataLen, k int) int { return gf16.Size + dataLen/k }

// Disperser is one dispersal whose fragments are computed one at a time, so a
// caller writing them out one by one holds the data and a single fragment rather
// than all n of them, each 1/k of the data. The coordinates are drawn when it is
// made, so every fragment belongs to the same dispersal.
type Disperser struct {
	data []byte
	k    int
	xs   []uint16
}

// New prepares the dispersal of data into n fragments, any k of which rebuild
// it. The data length must be a positive multiple of GroupLen(k); the caller pads
// it, so that the padding is under its control rather than this package's. The
// data is read, not copied, so it must not change until the last fragment is
// taken.
func New(data []byte, n, k int) (*Disperser, error) {
	if k < 1 || n < k || n > MaxFragments {
		return nil, fmt.Errorf("disperse: need 1 <= k <= n <= %d, got k=%d n=%d", MaxFragments, k, n)
	}
	if len(data) == 0 || len(data)%GroupLen(k) != 0 {
		return nil, fmt.Errorf("disperse: data length %d is not a positive multiple of %d", len(data), GroupLen(k))
	}
	xs, err := gf16.Points(n)
	if err != nil {
		return nil, err
	}
	return &Disperser{data: data, k: k, xs: xs}, nil
}

// Fragment computes fragment i, 0 <= i < n, as a new slice the caller owns.
func (d *Disperser) Fragment(i int) []byte {
	out := make([]byte, FragmentLen(len(d.data), d.k))
	d.FragmentTo(out, i)
	return out
}

// FragmentTo is Fragment writing into out, which must be FragmentLen bytes, so
// a caller can have the fragment land where it is used next. Any other length
// is the caller's mistake and panics: a longer one would otherwise come back
// with its end unwritten and be taken for part of the fragment.
func (d *Disperser) FragmentTo(out []byte, i int) {
	if len(out) != FragmentLen(len(d.data), d.k) {
		panic(fmt.Sprintf("disperse: a fragment is %d bytes, and was given %d to land in",
			FragmentLen(len(d.data), d.k), len(out)))
	}
	group := GroupLen(d.k)
	groups := len(d.data) / group
	binary.BigEndian.PutUint16(out, d.xs[i])
	// Horner's rule, highest coefficient first, by the tables for this x.
	x := gf16.NewTable(d.xs[i])
	frag := out[gf16.Size:]
	eachBlock(groups, d.k, func(lo, hi int) {
		for j := lo; j < hi; j++ {
			g := d.data[j*group : (j+1)*group]
			var acc uint16
			for t := group - gf16.Size; t >= 0; t -= gf16.Size {
				acc = x.Mul(acc) ^ binary.BigEndian.Uint16(g[t:])
			}
			binary.BigEndian.PutUint16(frag[gf16.Size*j:], acc)
		}
	})
}

// eachBlock runs fn over the groups [0, groups) in blocks of about blockWork
// multiplications, at work per group, a block per core at a time.
func eachBlock(groups, work int, fn func(lo, hi int)) {
	size := max(1, blockWork/max(1, work))
	blocks := (groups + size - 1) / size
	_ = parallel.Do(blocks, parallel.Workers(blocks), func(b int) error {
		lo := b * size
		fn(lo, min(lo+size, groups))
		return nil
	})
}

// basisBudget is how many basis coefficients Combine holds at once, four bytes
// each. A threshold up to 1024 fits in one batch; past that the fragments are
// taken in batches, so the memory does not grow with the square of k.
const basisBudget = 1 << 20

// Combine rebuilds the data from at least k fragments of one dispersal, using the
// first k. The result is the data exactly when the fragments are genuine; a wrong
// or altered fragment gives wrong bytes rather than an error, so the caller must
// authenticate what comes back.
//
// Interpolation gives coefficient t of every group as the sum over the fragments
// r of y_r times coefficient t of L_r, the Lagrange basis polynomial that is one
// at x_r and zero at every other coordinate. Each L_r takes O(k) work from the
// product of all the (X + x_r), so the whole basis is O(k^2) rather than the
// O(k^3) of inverting the matrix, and it is made a batch of fragments at a time.
func Combine(fragments [][]byte, k int) ([]byte, error) {
	if k < 1 {
		return nil, errors.New("disperse: threshold must be at least 1")
	}
	if len(fragments) < k {
		return nil, ErrTooFew
	}
	use := fragments[:k]
	xs, err := gf16.Coordinates(use)
	if err != nil {
		return nil, fmt.Errorf("disperse: fragments %w", err)
	}
	p := master(xs)
	group := GroupLen(k)
	groups := len(use[0])/gf16.Size - 1
	out := make([]byte, groups*group)
	batch := max(1, min(k, basisBudget/k))
	basis := make([]uint32, batch*k)
	for r0 := 0; r0 < k; r0 += batch {
		rows := min(batch, k-r0)
		_ = parallel.Do(rows, parallel.Workers(rows), func(r int) error {
			basisRow(p, xs[r0+r], basis[r*k:(r+1)*k])
			return nil
		})
		eachBlock(groups, rows*k, func(lo, hi int) {
			acc := make([]uint16, k)
			for g := lo; g < hi; g++ {
				addGroup(out[g*group:(g+1)*group], acc, use[r0:r0+rows], basis[:rows*k], g)
			}
		})
	}
	return out, nil
}

// addGroup adds into dst, the coefficients of group g, what each fragment of a
// batch contributes: its value for the group times its row of the basis. acc is
// scratch for the k coefficients.
func addGroup(dst []byte, acc []uint16, frags [][]byte, basis []uint32, g int) {
	k := len(acc)
	clear(acc)
	at := gf16.Size * (1 + g)
	for r, f := range frags {
		y := binary.BigEndian.Uint16(f[at:])
		if y == 0 {
			continue
		}
		ly := gf16.Log(y)
		for t, l := range basis[r*k : (r+1)*k] {
			acc[t] ^= gf16.Exp(int(l) + ly)
		}
	}
	for t, v := range acc {
		binary.BigEndian.PutUint16(dst[2*t:], binary.BigEndian.Uint16(dst[2*t:])^v)
	}
}

// master returns the coefficients of P(X) = (X + x_0)(X + x_1)...(X + x_(k-1)),
// lowest first.
func master(xs []uint16) []uint16 {
	p := make([]uint16, len(xs)+1)
	p[0] = 1
	for d, x := range xs {
		mul := gf16.NewTable(x)
		for m := d + 1; m > 0; m-- {
			p[m] = p[m-1] ^ mul.Mul(p[m])
		}
		p[0] = mul.Mul(p[0])
	}
	return p
}

// basisRow writes the coefficients of the Lagrange basis polynomial for the
// coordinate x into row, as logs (gf16.ZeroLog for a zero), lowest first:
//
//	L(X) = q(X) / q(x)   where q(X) = P(X) / (X + x),
//
// q being P with the factor for x divided out, so zero at every other coordinate.
func basisRow(p []uint16, x uint16, row []uint32) {
	k := len(row)
	mul := gf16.NewTable(x)
	// Synthetic division: q[k-1] = p[k], and q[m-1] = p[m] + x*q[m].
	q := p[k]
	row[k-1] = uint32(q)
	for m := k - 1; m > 0; m-- {
		q = p[m] ^ mul.Mul(q)
		row[m-1] = uint32(q)
	}
	var at uint16 // q(x), by Horner's rule; never zero, as the coordinates differ
	for m := k - 1; m >= 0; m-- {
		at = mul.Mul(at) ^ uint16(row[m])
	}
	shift := gf16.MaxPoints - gf16.Log(at)
	for m, v := range row {
		if v == 0 {
			row[m] = gf16.ZeroLog
		} else {
			row[m] = uint32((gf16.Log(uint16(v)) + shift) % gf16.MaxPoints)
		}
	}
}
