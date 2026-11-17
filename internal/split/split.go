// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package split is Shamir secret sharing over GF(2^16), with the semantics Riven
// needs: parameter validation and a k==1 fast path (a single required piece is
// just a self-sufficient copy, which a polynomial cannot express because it needs
// a threshold of at least two).
//
// The secret is read as 16-bit symbols, high byte first. Each symbol s gets its
// own random polynomial of degree k-1,
//
//	f(x) = s + a1*x + ... + a(k-1)*x^(k-1),
//
// and a share is f(x) for every symbol at one x-coordinate, coordinate first:
//
//	share = u16 x || f(x) for every symbol
//
// Everything that touches the secret, its coefficients or a share runs in
// constant time (gf16.Scalar); only the public coordinates go through tables.
package split

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/secu-tools/riven/internal/gf16"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/parallel"
)

// MaxParts is the hard limit imposed by the GF(2^16) field: at most 65535
// distinct non-zero x-coordinates exist.
const MaxParts = gf16.MaxPoints

// ErrInsufficientShares is returned when fewer than the threshold shares are
// supplied to Combine.
var ErrInsufficientShares = errors.New("split: fewer shares than the threshold")

// ValidateParams checks that n (total parts) and k (threshold) form a legal
// split for a secret of the given length.
func ValidateParams(n, k, secretLen int) error {
	if secretLen < 1 {
		return errors.New("split: secret must be at least one byte")
	}
	if k < 1 {
		return errors.New("split: threshold must be at least 1")
	}
	if n < k {
		return fmt.Errorf("split: total parts (%d) cannot be less than threshold (%d)", n, k)
	}
	if n > MaxParts {
		return fmt.Errorf("split: total parts (%d) cannot exceed %d", n, MaxParts)
	}
	return nil
}

// Fit returns the length a secret of n bytes is shared at: n rounded up to whole
// symbols. Split takes no other length at a threshold above one, so the caller
// pads, where it can tell the padding from the secret. A copy, at a threshold of
// one, takes any length, but a caller that keeps to whole symbols there too has
// shares of an even length whatever the threshold.
func Fit(n int) int { return (n + gf16.Size - 1) / gf16.Size * gf16.Size }

// ShareLen returns the length of each share of a secret of secretLen bytes, once
// it is padded to Fit.
func ShareLen(secretLen, k int) int {
	if k == 1 {
		return Fit(secretLen)
	}
	return gf16.Size + Fit(secretLen)
}

// SecretLen returns the longest secret of whole symbols whose shares are at most
// shareLen bytes. It inverts ShareLen exactly for those secrets.
func SecretLen(shareLen, k int) int {
	if k != 1 {
		shareLen -= gf16.Size
	}
	return max(0, shareLen-shareLen%gf16.Size)
}

// unitBytes is how much of the secret one unit of parallel work covers, and so
// how finely Progress hears about a large secret. A multiple of eight keeps
// every unit on whole words of four symbols.
const unitBytes = 512 << 10

// Progress is told how many units of a large secret are done, out of how many,
// as SplitInto and CombineProgress work through them. It is called from
// several goroutines at once, so done can arrive out of order.
type Progress func(done, total int)

// tally counts finished units for a Progress, which may be nil.
type tally struct {
	p     Progress
	total int
	done  atomic.Int64
}

// newTally counts units for p. A secret of one unit is done in one step, so p
// hears nothing about it.
func newTally(p Progress, units int) *tally {
	if units <= 1 {
		p = nil
	}
	return &tally{p: p, total: units}
}

func (t *tally) add() {
	if t.p != nil {
		t.p(int(t.done.Add(1)), t.total)
	}
}

// Split divides secret into n parts, k of which are required to reconstruct it.
//
// For k == 1 each part is an independent full copy of the secret. For k >= 2 the
// secret must be a whole number of symbols (see Fit), and each share is that
// long plus its coordinate.
func Split(secret []byte, n, k int) ([][]byte, error) {
	if err := ValidateParams(n, k, len(secret)); err != nil {
		return nil, err
	}
	out := make([][]byte, n)
	for i := range out {
		out[i] = make([]byte, sizeOf(secret, k))
	}
	if err := SplitInto(out, secret, k, nil); err != nil {
		return nil, err
	}
	return out, nil
}

// SplitInto is Split writing the shares into dst, one for each part, so a caller
// can have them land where they are used next, and telling p as each unit is
// shared. Each must be the length of a share: that of the secret, plus a
// coordinate when k >= 2. On an error dst is wiped. A secret of one unit, or a
// split with k == 1, is done in one step and tells p nothing.
func SplitInto(dst [][]byte, secret []byte, k int, p Progress) error {
	n := len(dst)
	if err := ValidateParams(n, k, len(secret)); err != nil {
		return err
	}
	for _, d := range dst {
		if len(d) != sizeOf(secret, k) {
			return fmt.Errorf("split: a share of a %d-byte secret is %d bytes, not %d", len(secret), sizeOf(secret, k), len(d))
		}
	}

	if k == 1 {
		for _, d := range dst {
			copy(d, secret)
		}
		return nil
	}
	if len(secret)%gf16.Size != 0 {
		return fmt.Errorf("split: a secret of %d bytes is not a whole number of %d-byte symbols", len(secret), gf16.Size)
	}

	xs, err := gf16.Points(n)
	if err != nil {
		return err
	}
	scalars := make([]gf16.Scalar, n)
	for i, x := range xs {
		scalars[i] = gf16.NewScalar(x)
		binary.BigEndian.PutUint16(dst[i], x)
	}

	// Each worker owns a span of every share, so the shares are written in place
	// with no lock, and the set is held once rather than assembled from parts. A
	// short secret has fewer spans than cores, so the cores left over share out
	// the shares within a span instead: a key split into thousands of pieces.
	units := (len(secret) + unitBytes - 1) / unitBytes
	outer := parallel.Workers(units)
	inner := max(1, parallel.Workers(n)/outer)
	t := newTally(p, units)
	err = parallel.Do(units, outer, func(u int) error {
		lo := u * unitBytes
		if err := shareSpan(dst, secret, lo, min(lo+unitBytes, len(secret)), scalars, k, inner); err != nil {
			return err
		}
		t.add()
		return nil
	})
	if err != nil {
		for _, d := range dst {
			memory.Zero(d)
		}
		return err
	}
	return nil
}

// sizeOf is the length of each share of secret at threshold k: a copy at one,
// and with a coordinate in front above it.
func sizeOf(secret []byte, k int) int {
	if k == 1 {
		return len(secret)
	}
	return gf16.Size + len(secret)
}

// coefBudget is how many bytes of random coefficients a worker draws at once:
// few enough to stay in cache while every share is evaluated from them, and
// drawn in bulk rather than a call to the random source per symbol.
const coefBudget = 256 << 10

// shareSpan writes the shares of secret[lo:hi] into out, with up to workers
// goroutines each evaluating a block of the shares. The span is taken a run of
// words at a time, each word of a run with its own k-1 random coefficient words,
// and every share evaluates each word's four polynomials by Horner's rule.
func shareSpan(out [][]byte, secret []byte, lo, hi int, scalars []gf16.Scalar, k, workers int) error {
	words := (hi - lo + 7) / 8
	per := 8 * (k - 1) // coefficient bytes for one word
	run := max(1, min(words, coefBudget/per))
	coef := make([]byte, per*run)
	defer memory.Zero(coef)
	blocks := min(len(out), 4*workers)
	for w0 := 0; w0 < words; w0 += run {
		m := min(run, words-w0)
		c := coef[:per*m]
		if _, err := rand.Read(c); err != nil {
			return err
		}
		_ = parallel.Do(blocks, workers, func(b int) error {
			for i := b * len(out) / blocks; i < (b+1)*len(out)/blocks; i++ {
				evaluate(out[i][gf16.Size:], secret, c, lo+8*w0, hi, m, &scalars[i])
			}
			return nil
		})
	}
	return nil
}

// evaluate writes one share's values for m words of the secret from at, given
// their coefficients c, k-1 words per secret word.
func evaluate(ys, secret, c []byte, at, hi, m int, sc *gf16.Scalar) {
	per := len(c) / m
	for w := range m {
		a := c[per*w : per*(w+1)] // a1..a(k-1), a word each
		acc := binary.LittleEndian.Uint64(a[per-8:])
		for j := per - 16; j >= 0; j -= 8 {
			acc = sc.Mul(acc) ^ binary.LittleEndian.Uint64(a[j:])
		}
		end := min(at+8, hi)
		store(ys[at:end], sc.Mul(acc)^load(secret[at:end]))
		at += 8
	}
}

// load reads up to eight bytes as a word of four symbols, the first symbol in
// the top lane, zero-filling a short tail.
func load(b []byte) uint64 {
	if len(b) == 8 {
		return binary.BigEndian.Uint64(b)
	}
	var w [8]byte
	copy(w[:], b)
	return binary.BigEndian.Uint64(w[:])
}

// store writes the symbols of v that b has room for, the inverse of load.
func store(b []byte, v uint64) {
	if len(b) == 8 {
		binary.BigEndian.PutUint64(b, v)
		return
	}
	var w [8]byte
	binary.BigEndian.PutUint64(w[:], v)
	copy(b, w[:])
}

// Combine reconstructs a secret from shares produced by Split. The threshold k
// must match the value used at split time. At least k shares must be supplied;
// supplying more is allowed, and all of them are used. Supplying fewer than k for
// a k >= 2 split cannot be detected here (interpolation would silently yield
// garbage), so callers MUST verify the result against an authenticated hash.
func Combine(shares [][]byte, k int) ([]byte, error) {
	return CombineProgress(shares, k, nil)
}

// CombineProgress is Combine telling p as each unit is recovered, as SplitInto
// does.
func CombineProgress(shares [][]byte, k int, p Progress) ([]byte, error) {
	if k < 1 {
		return nil, errors.New("split: threshold must be at least 1")
	}
	if len(shares) < k {
		return nil, ErrInsufficientShares
	}

	if k == 1 {
		if len(shares[0]) == 0 {
			return nil, errors.New("split: empty share")
		}
		out := make([]byte, len(shares[0]))
		copy(out, shares[0])
		return out, nil
	}

	xs, err := gf16.Coordinates(shares)
	if err != nil {
		return nil, fmt.Errorf("split: shares %w", err)
	}
	w := weights(xs)
	scalars := make([]gf16.Scalar, len(w))
	for i, c := range w {
		scalars[i] = gf16.NewScalar(c)
	}

	out := make([]byte, len(shares[0])-gf16.Size)
	units := (len(out) + unitBytes - 1) / unitBytes
	t := newTally(p, units)
	_ = parallel.Do(units, parallel.Workers(units), func(u int) error {
		lo := u * unitBytes
		combineSpan(out, shares, lo, min(lo+unitBytes, len(out)), scalars)
		t.add()
		return nil
	})
	return out, nil
}

// weights returns the Lagrange coefficients that evaluate the polynomial through
// the shares at zero,
//
//	w_i = product over j != i of x_j / (x_i + x_j),
//
// summing logarithms. They depend only on the public coordinates. The work is
// quadratic in the share count, so it is spread across cores.
func weights(xs []uint16) []uint16 {
	const m = gf16.MaxPoints
	var all uint64 // the log of the product of every coordinate
	for _, x := range xs {
		all += uint64(gf16.Log(x))
	}
	w := make([]uint16, len(xs))
	_ = parallel.Do(len(xs), parallel.Workers(len(xs)), func(i int) error {
		var den uint64
		for j, x := range xs {
			if j != i {
				den += uint64(gf16.Log(xs[i] ^ x))
			}
		}
		num := all - uint64(gf16.Log(xs[i]))
		w[i] = gf16.Exp(int((num%m + m - den%m) % m))
		return nil
	})
	return w
}

// combineRun is how many words combineSpan sums at once, in a buffer that stays
// in the L1 cache while every share is added in.
const combineRun = 1024

// combineSpan recovers secret[lo:hi] into out as the weighted sum of the shares.
func combineSpan(out []byte, shares [][]byte, lo, hi int, scalars []gf16.Scalar) {
	var acc [combineRun]uint64
	defer clear(acc[:])
	for r0 := lo; r0 < hi; r0 += 8 * combineRun {
		r1 := min(r0+8*combineRun, hi)
		m := (r1 - r0 + 7) / 8
		clear(acc[:m])
		for i, s := range shares {
			sc := &scalars[i]
			ys := s[gf16.Size:]
			for w := range m {
				at := r0 + 8*w
				acc[w] ^= sc.Mul(load(ys[at:min(at+8, r1)]))
			}
		}
		for w := range m {
			at := r0 + 8*w
			store(out[at:min(at+8, r1)], acc[w])
		}
	}
}
