// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package gf16 is arithmetic in GF(2^16), the field Riven shares and disperses
// over. Its 65535 non-zero elements are the x-coordinates pieces can take, which
// is what caps a set at 65535 pieces.
//
// The field is GF(2)[x] modulo x^16 + x^12 + x^3 + x + 1 (0x1100B), a primitive
// polynomial, so x (the element 2) generates every non-zero element. Addition is
// XOR. An element is stored as two bytes, high byte first.
//
// There are two ways to multiply. Mul and Table look products up, which is fast
// but takes time that depends on the values, so they are for values that are not
// secret: coordinates, interpolation weights, and dispersed ciphertext. Scalar
// multiplies four elements at a time by a fixed one with only shifts, masks and
// XORs, in time that does not depend on them, and is what touches a secret.
package gf16

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// Size is the length of one element in bytes.
	Size = 2

	// MaxPoints is the number of non-zero elements, and so of distinct
	// x-coordinates a sharing can hand out.
	MaxPoints = 1<<16 - 1

	poly = 0x1100B

	// ZeroLog is what Log returns for zero. It is past every real logarithm and
	// sum of two, and Exp is zero from there on, so a product of logs needs no
	// test for zero as long as at most one of the two is ZeroLog.
	ZeroLog = 2 * MaxPoints
)

var (
	expTable [ZeroLog + MaxPoints]uint16 // 2^i, twice over, then zeros
	logTable [1 << 16]uint32             // logTable[2^i] = i; logTable[0] = ZeroLog
)

func init() {
	x := uint16(1)
	for i := 0; i < MaxPoints; i++ {
		expTable[i], expTable[i+MaxPoints] = x, x
		logTable[x] = uint32(i)
		x = double(x)
	}
	logTable[0] = ZeroLog
}

// double multiplies by x, the generator.
func double(a uint16) uint16 {
	if a&0x8000 != 0 {
		return a<<1 ^ poly&0xFFFF
	}
	return a << 1
}

// Log returns the discrete logarithm of a to base 2, or ZeroLog for zero.
func Log(a uint16) int { return int(logTable[a]) }

// Exp returns 2^i for 0 <= i < ZeroLog, and zero from ZeroLog to
// ZeroLog+MaxPoints, so Exp(Log(a)+Log(b)) is a*b.
func Exp(i int) uint16 { return expTable[i] }

// Mul returns a*b by table lookup. Not for secrets.
func Mul(a, b uint16) uint16 {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[logTable[a]+logTable[b]]
}

// Table multiplies by one fixed element through two 256-entry tables, one per
// byte of the other factor: two lookups that stay in the L1 cache. Not for
// secrets.
type Table struct{ lo, hi [256]uint16 }

// NewTable returns the tables for multiplying by c.
func NewTable(c uint16) *Table {
	t := new(Table)
	for b := 0; b < 256; b++ {
		t.lo[b] = Mul(c, uint16(b))
		t.hi[b] = Mul(c, uint16(b)<<8)
	}
	return t
}

// Mul returns c*v.
func (t *Table) Mul(v uint16) uint16 { return t.lo[v&0xFF] ^ t.hi[v>>8] }

// Scalar multiplies by one fixed element c in constant time. A product c*v is
// the XOR of c*2^b for every bit b set in v; Scalar holds those 16 multiples,
// each repeated in all four 16-bit lanes of a word, and selects them with masks
// built from the bits of v, never with a branch or a lookup indexed by v.
type Scalar [16]uint64

// lanes has the low bit of each 16-bit lane set.
const lanes = 0x0001000100010001

// NewScalar returns the multiples of c.
func NewScalar(c uint16) Scalar {
	var s Scalar
	for b := range s {
		s[b] = uint64(c) * lanes
		c = double(c)
	}
	return s
}

// Mul multiplies each of the four elements packed in v, one per 16-bit lane, by
// c. A lane's bit times 0xFFFF is all ones or all zeros within the lane and
// cannot carry into the next.
func (s *Scalar) Mul(v uint64) uint64 {
	r := ((v & lanes) * 0xFFFF) & s[0]
	r ^= ((v >> 1 & lanes) * 0xFFFF) & s[1]
	r ^= ((v >> 2 & lanes) * 0xFFFF) & s[2]
	r ^= ((v >> 3 & lanes) * 0xFFFF) & s[3]
	r ^= ((v >> 4 & lanes) * 0xFFFF) & s[4]
	r ^= ((v >> 5 & lanes) * 0xFFFF) & s[5]
	r ^= ((v >> 6 & lanes) * 0xFFFF) & s[6]
	r ^= ((v >> 7 & lanes) * 0xFFFF) & s[7]
	r ^= ((v >> 8 & lanes) * 0xFFFF) & s[8]
	r ^= ((v >> 9 & lanes) * 0xFFFF) & s[9]
	r ^= ((v >> 10 & lanes) * 0xFFFF) & s[10]
	r ^= ((v >> 11 & lanes) * 0xFFFF) & s[11]
	r ^= ((v >> 12 & lanes) * 0xFFFF) & s[12]
	r ^= ((v >> 13 & lanes) * 0xFFFF) & s[13]
	r ^= ((v >> 14 & lanes) * 0xFFFF) & s[14]
	r ^= ((v >> 15 & lanes) * 0xFFFF) & s[15]
	return r
}

// Coordinates checks rows are alike, each a coordinate followed by at least one
// symbol and all of one length, and returns their coordinates, which must be
// distinct and non-zero for interpolation through them to have one answer.
// Its errors follow a name for the rows, as in "shares include two at the same
// coordinate".
func Coordinates(rows [][]byte) ([]uint16, error) {
	if len(rows) == 0 {
		return nil, errors.New("are missing")
	}
	size := len(rows[0])
	if size < 2*Size || size%Size != 0 {
		return nil, errors.New("do not hold a coordinate and whole symbols")
	}
	xs := make([]uint16, len(rows))
	seen := make([]bool, 1<<16)
	for i, r := range rows {
		if len(r) != size {
			return nil, errors.New("are not all of one length, so not from one set")
		}
		x := binary.BigEndian.Uint16(r)
		if x == 0 {
			return nil, errors.New("include one at coordinate zero")
		}
		if seen[x] {
			return nil, errors.New("include two at the same coordinate")
		}
		seen[x] = true
		xs[i] = x
	}
	return xs, nil
}

// Points returns n distinct non-zero elements in random order. They are the
// x-coordinates of a sharing or a dispersal: not secret, but drawn at random so a
// piece does not say which of the set it is.
func Points(n int) ([]uint16, error) {
	if n < 0 || n > MaxPoints {
		return nil, fmt.Errorf("gf16: %d points asked for, the field has %d", n, MaxPoints)
	}
	all := make([]uint16, MaxPoints)
	for i := range all {
		all[i] = uint16(i + 1)
	}
	rnd := make([]byte, 4*n)
	if _, err := rand.Read(rnd); err != nil {
		return nil, err
	}
	// Fisher-Yates over the first n positions. A 32-bit draw reduced modulo at
	// most 65535 leaves a bias under 2^-16, irrelevant for public coordinates.
	for i := 0; i < n; i++ {
		j := i + int(binary.BigEndian.Uint32(rnd[4*i:])%uint32(MaxPoints-i))
		all[i], all[j] = all[j], all[i]
	}
	return append([]uint16(nil), all[:n]...), nil
}
