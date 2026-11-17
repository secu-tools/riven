// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package split

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/secu-tools/riven/internal/testkit"
)

// TestShareLayoutMatchesTheSpecification checks a share is laid out as
// docs/format.md section 6.2 says, a u16 coordinate and then one u16 per
// symbol, by rebuilding the secret from two shares with the formula written
// there rather than with Combine.
func TestShareLayoutMatchesTheSpecification(t *testing.T) {
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	shares, err := Split(secret, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range shares {
		if len(s) != 2+len(secret) {
			t.Fatalf("share %d is %d bytes, the specification says %d", i+1, len(s), 2+len(secret))
		}
	}
	// s = y1 * x2/(x1+x2) + y2 * x1/(x1+x2)
	x1, x2 := binary.BigEndian.Uint16(shares[0]), binary.BigEndian.Uint16(shares[2])
	w1 := testkit.GF16Mul(x2, testkit.GF16Inv(x1^x2))
	w2 := testkit.GF16Mul(x1, testkit.GF16Inv(x1^x2))
	var got []byte
	for at := 2; at < len(shares[0]); at += 2 {
		y1, y2 := binary.BigEndian.Uint16(shares[0][at:]), binary.BigEndian.Uint16(shares[2][at:])
		got = binary.BigEndian.AppendUint16(got, testkit.GF16Mul(y1, w1)^testkit.GF16Mul(y2, w2))
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("the documented interpolation does not rebuild the secret")
	}

	// A threshold of one is a plain copy, with no coordinate.
	copySecret := []byte("copy me")
	shares, err = Split(copySecret, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range shares {
		if !bytes.Equal(s, copySecret) {
			t.Fatalf("k=1 share %d is not the secret", i+1)
		}
	}
}
