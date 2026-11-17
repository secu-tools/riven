// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package gf16

import (
	mathrand "math/rand/v2"
	"testing"

	"github.com/secu-tools/riven/internal/testkit"
)

// refMul is the textbook product, an independent check on the tables and on
// Scalar.
var refMul = testkit.GF16Mul

// someFactors is every power of two, the extremes, and random elements: the
// second factor for checks that run over every first factor.
func someFactors() []uint16 {
	f := []uint16{0, 1, 2, 3, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF}
	for b := 2; b < 16; b++ {
		f = append(f, 1<<b)
	}
	r := mathrand.New(mathrand.NewPCG(1, 2))
	for range 40 {
		f = append(f, uint16(r.Uint32()))
	}
	return f
}

// TestTheGeneratorReachesEveryElement checks the polynomial is primitive: the
// powers of 2 run through all 65535 non-zero elements before repeating, so Log
// and Exp are inverse bijections. A reducible polynomial would make some
// products collide, and a sharing over it would lose secrets.
func TestTheGeneratorReachesEveryElement(t *testing.T) {
	seen := make([]bool, 1<<16)
	for i := 0; i < MaxPoints; i++ {
		x := Exp(i)
		if x == 0 || seen[x] {
			t.Fatalf("2^%d = %#04x repeats or is zero", i, x)
		}
		seen[x] = true
		if Log(x) != i || Exp(i+MaxPoints) != x {
			t.Fatalf("Log and Exp disagree at %d", i)
		}
	}
}

// TestMulMatchesShiftAndAdd checks the table product and Table against the
// reference for every element times a spread of factors, and that a zero log
// makes Exp give zero as the bulk loops rely on.
func TestMulMatchesShiftAndAdd(t *testing.T) {
	for _, b := range someFactors() {
		tab := NewTable(b)
		for a := 0; a < 1<<16; a++ {
			x := uint16(a)
			want := refMul(x, b)
			if got := Mul(x, b); got != want {
				t.Fatalf("Mul(%#04x, %#04x) = %#04x, want %#04x", x, b, got, want)
			}
			if got := tab.Mul(x); got != want {
				t.Fatalf("Table(%#04x).Mul(%#04x) = %#04x, want %#04x", b, x, got, want)
			}
			if x != 0 && b != 0 {
				if got := Exp(Log(x) + Log(b)); got != want {
					t.Fatalf("Exp(Log(%#04x)+Log(%#04x)) = %#04x, want %#04x", x, b, got, want)
				}
			}
			if x != 0 && Exp(Log(x)+ZeroLog) != 0 {
				t.Fatalf("Exp(Log(%#04x)+ZeroLog) is not zero", x)
			}
		}
	}
}

// TestLogsGiveEveryInverse checks the inverse of every non-zero element is 2 to
// the power MaxPoints less its log, which is how the dispersal divides.
func TestLogsGiveEveryInverse(t *testing.T) {
	for a := 1; a < 1<<16; a++ {
		if p := refMul(uint16(a), Exp(MaxPoints-Log(uint16(a)))); p != 1 {
			t.Fatalf("%#04x times its inverse is %#04x, want 1", a, p)
		}
	}
}

// TestScalarMatchesShiftAndAdd checks the constant-time product in every lane,
// with the other lanes holding different values, so a mask that leaked across
// lanes would show.
func TestScalarMatchesShiftAndAdd(t *testing.T) {
	for _, c := range someFactors() {
		s := NewScalar(c)
		for a := 0; a < 1<<16; a++ {
			v := [4]uint16{uint16(a), ^uint16(a), uint16(a * 7919), uint16(a) ^ 0x5A5A}
			packed := uint64(v[0]) | uint64(v[1])<<16 | uint64(v[2])<<32 | uint64(v[3])<<48
			got := s.Mul(packed)
			for l, x := range v {
				if lane, want := uint16(got>>(16*l)), refMul(x, c); lane != want {
					t.Fatalf("Scalar(%#04x) lane %d: %#04x * %#04x = %#04x, want %#04x", c, l, x, c, lane, want)
				}
			}
		}
	}
}

// TestPointsAreDistinctAndNonZero checks every sharing's coordinates can be
// told apart and none is zero, where a share would be the secret itself; that
// all 65535 can be handed out; and that they are drawn afresh each time.
func TestPointsAreDistinctAndNonZero(t *testing.T) {
	all, err := Points(MaxPoints)
	if err != nil {
		t.Fatal(err)
	}
	seen := make([]bool, 1<<16)
	for _, x := range all {
		if x == 0 || seen[x] {
			t.Fatalf("coordinate %#04x is zero or repeats", x)
		}
		seen[x] = true
	}
	if _, err := Points(MaxPoints + 1); err == nil {
		t.Fatal("more points than the field has were handed out")
	}
	if p, err := Points(0); err != nil || len(p) != 0 {
		t.Fatalf("Points(0) = %v, %v", p, err)
	}
	a, _ := Points(8)
	b, _ := Points(8)
	if a == nil || b == nil || [8]uint16(a) == [8]uint16(b) {
		t.Fatal("two draws gave the same coordinates")
	}
}

// TestCoordinatesChecksTheRows checks rows that can be interpolated through
// give their coordinates in order, and every way they cannot is refused with
// an error rather than a panic or a wrong answer: no rows, a row with no
// symbol, half a symbol, rows of two lengths, a zero coordinate, a repeat.
func TestCoordinatesChecksTheRows(t *testing.T) {
	row := func(x uint16, symbols int) []byte {
		r := make([]byte, Size*(1+symbols))
		r[0], r[1] = byte(x>>8), byte(x)
		return r
	}
	xs, err := Coordinates([][]byte{row(0x0102, 3), row(0xFFFF, 3), row(1, 3)})
	if err != nil || len(xs) != 3 || xs[0] != 0x0102 || xs[1] != 0xFFFF || xs[2] != 1 {
		t.Fatalf("three good rows gave %#04x, %v", xs, err)
	}
	for name, rows := range map[string][][]byte{
		"no rows":             nil,
		"no symbol":           {row(1, 0), row(2, 0)},
		"half a symbol":       {make([]byte, 5)},
		"two lengths":         {row(1, 2), row(2, 3)},
		"a zero coordinate":   {row(1, 2), row(0, 2)},
		"a repeat coordinate": {row(7, 2), row(8, 2), row(7, 2)},
	} {
		if xs, err := Coordinates(rows); err == nil {
			t.Errorf("%s: accepted, as %#04x", name, xs)
		}
	}
}

func BenchmarkScalarMul(b *testing.B) {
	s := NewScalar(0x1234)
	buf := make([]uint64, 4096)
	b.SetBytes(int64(8 * len(buf)))
	for b.Loop() {
		for i, v := range buf {
			buf[i] = s.Mul(v) ^ uint64(i)
		}
	}
}
