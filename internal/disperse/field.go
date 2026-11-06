// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package disperse

// The field is GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x11B), the one AES and
// the vendored Shamir code use, so docs/format.md describes a single field.

var (
	expTable [510]byte // expTable[i] = 3^i, doubled so a sum of two logs needs no modulo
	logTable [256]byte // logTable[3^i] = i; logTable[0] is unused
	mulTable [256][256]byte
)

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		expTable[i] = x
		expTable[i+255] = x
		logTable[x] = byte(i)
		x = slowMul(x, 3)
	}
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			mulTable[a][b] = mul(byte(a), byte(b))
		}
	}
}

// slowMul multiplies by shift and add. It builds the tables, and the tests check
// the tables against it.
func slowMul(a, b byte) byte {
	var p byte
	for ; b != 0; b >>= 1 {
		if b&1 != 0 {
			p ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1B
		}
	}
	return p
}

// mul multiplies through the log tables.
func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[int(logTable[a])+int(logTable[b])]
}

// inverse returns the multiplicative inverse of a non-zero element.
func inverse(a byte) byte {
	return expTable[255-int(logTable[a])]
}
