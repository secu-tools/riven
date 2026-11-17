// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package split

// These tests hold Split and Combine against a second implementation of Shamir's
// scheme, written from the definitions and sharing no code with gf16: products
// by shift and add and inverses by Fermat's little theorem, from testkit, and
// the whole polynomial through the shares by Lagrange interpolation. A round
// trip from Split to Combine cannot see a mistake made the same way on both
// sides, such as the wrong field or symbol order; a second implementation can.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand/v2"
	"testing"

	"github.com/secu-tools/riven/internal/testkit"
)

// lagrange returns the Lagrange basis polynomials of xs, constant term first:
// L_i is one at xs[i] and zero at every other coordinate.
func lagrange(xs []uint16) [][]uint16 {
	basis := make([][]uint16, len(xs))
	for i, xi := range xs {
		l, den := []uint16{1}, uint16(1)
		for j, xj := range xs {
			if j == i {
				continue
			}
			// Multiply by (X + xj), which is (X - xj) in characteristic two.
			next := make([]uint16, len(l)+1)
			for d, c := range l {
				next[d+1] ^= c
				next[d] ^= testkit.GF16Mul(c, xj)
			}
			l, den = next, testkit.GF16Mul(den, xi^xj)
		}
		inv := testkit.GF16Inv(den)
		for d := range l {
			l[d] = testkit.GF16Mul(l[d], inv)
		}
		basis[i] = l
	}
	return basis
}

// interpolate returns the coefficients, constant first, of the polynomial of
// degree below len(ys) through the points (xs[i], ys[i]), given lagrange(xs).
func interpolate(basis [][]uint16, ys []uint16) []uint16 {
	c := make([]uint16, len(ys))
	for i, l := range basis {
		for d, b := range l {
			c[d] ^= testkit.GF16Mul(ys[i], b)
		}
	}
	return c
}

// reval evaluates the polynomial with coefficients c, constant first, at x.
func reval(c []uint16, x uint16) uint16 {
	var y uint16
	for d := len(c) - 1; d >= 0; d-- {
		y = testkit.GF16Mul(y, x) ^ c[d]
	}
	return y
}

// symbol returns the s-th value of a share, after its coordinate.
func symbol(share []byte, s int) uint16 {
	return binary.BigEndian.Uint16(share[2+2*s:])
}

// TestSharesLieOnOneRandomPolynomial recovers, with the reference, the whole
// polynomial behind every symbol from k shares taken in a random order, and
// checks what Shamir's scheme is: its constant term is the secret, every other
// share lies on it, and its other k-1 coefficients are uniform whatever the
// secret. The last is what makes fewer than k shares say nothing; a coefficient
// left at zero, reused, or tied to the secret would show in it.
func TestSharesLieOnOneRandomPolynomial(t *testing.T) {
	random := make([]byte, 8192)
	rand.Read(random)
	cases := []struct {
		n, k   int
		secret []byte
	}{
		{3, 2, make([]byte, 8192)}, {3, 2, random},
		{6, 3, make([]byte, 8192)}, {6, 3, random},
		{9, 5, bytes.Repeat([]byte{0xFF}, 4096)},
		{40, 17, random[:1024]},
		{300, 256, random[:16]},
	}
	for _, c := range cases {
		shares, err := Split(c.secret, c.n, c.k)
		if err != nil {
			t.Fatal(err)
		}
		order := mathrand.Perm(c.n)
		held, rest := order[:c.k], order[c.k:]
		xs := make([]uint16, c.k)
		for i, j := range held {
			xs[i] = binary.BigEndian.Uint16(shares[j])
		}
		basis := lagrange(xs)

		symbols := len(c.secret) / 2
		coef := make([][]byte, c.k) // the bytes of each coefficient, by degree
		ys := make([]uint16, c.k)
		for s := range symbols {
			for i, j := range held {
				ys[i] = symbol(shares[j], s)
			}
			poly := interpolate(basis, ys)
			if want := binary.BigEndian.Uint16(c.secret[2*s:]); poly[0] != want {
				t.Fatalf("k=%d of %d: symbol %d has constant term %#04x, the secret is %#04x", c.k, c.n, s, poly[0], want)
			}
			for _, j := range rest {
				x := binary.BigEndian.Uint16(shares[j])
				if got := symbol(shares[j], s); got != reval(poly, x) {
					t.Fatalf("k=%d of %d: share at x=%#04x is off the polynomial at symbol %d", c.k, c.n, x, s)
				}
			}
			for d := 1; d < c.k; d++ {
				coef[d] = binary.BigEndian.AppendUint16(coef[d], poly[d])
			}
		}

		// Each degree on its own where there are enough symbols to measure, and
		// all of them together otherwise.
		var all []byte
		for d := 1; d < c.k; d++ {
			if len(coef[d]) >= 4096 {
				if chi := testkit.ChiSquare(coef[d]); chi > 400 {
					t.Fatalf("k=%d of %d: the degree %d coefficients are not uniform (chi-square %.0f)", c.k, c.n, d, chi)
				}
			}
			all = append(all, coef[d]...)
		}
		if len(all) >= 4096 {
			if chi := testkit.ChiSquare(all); chi > 400 {
				t.Fatalf("k=%d of %d: the coefficients are not uniform (chi-square %.0f)", c.k, c.n, chi)
			}
		}
	}
}

// TestCombineRebuildsATextbookSharing builds shares with the reference alone,
// from chosen polynomials, in the layout docs/format.md gives, and checks Combine
// reads them back in every order and with more shares than it needs.
func TestCombineRebuildsATextbookSharing(t *testing.T) {
	const n, k, symbols = 5, 3, 512
	secret := make([]byte, 2*symbols)
	rand.Read(secret)
	xs := []uint16{1, 0x8000, 0xFFFF, 0x1234, 2}
	shares := make([][]byte, n)
	for i, x := range xs {
		shares[i] = binary.BigEndian.AppendUint16(nil, x)
	}
	for s := range symbols {
		poly := []uint16{binary.BigEndian.Uint16(secret[2*s:]), uint16(mathrand.Uint32()), uint16(mathrand.Uint32())}
		for i, x := range xs {
			shares[i] = binary.BigEndian.AppendUint16(shares[i], reval(poly, x))
		}
	}

	// Every ordered choice of k: the order shares arrive in must not matter.
	for a := range n {
		for b := range n {
			for c := range n {
				if a == b || a == c || b == c {
					continue
				}
				got, err := Combine([][]byte{shares[a], shares[b], shares[c]}, k)
				if err != nil || !bytes.Equal(got, secret) {
					t.Fatalf("shares %d, %d, %d did not rebuild the secret: %v", a+1, b+1, c+1, err)
				}
			}
		}
	}
	if got, err := Combine(shares, k); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("all %d shares did not rebuild the secret: %v", n, err)
	}
}
