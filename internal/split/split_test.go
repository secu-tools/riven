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

func TestParamValidation(t *testing.T) {
	if err := ValidateParams(3, 2, 0); err == nil {
		t.Fatal("empty secret should fail")
	}
	if err := ValidateParams(0, 0, 5); err == nil {
		t.Fatal("no parts should fail")
	}
	if err := ValidateParams(3, 0, 5); err == nil {
		t.Fatal("k=0 should fail")
	}
	if _, err := Combine([][]byte{{0, 1, 2, 3}}, 0); err == nil {
		t.Fatal("combining at k=0 should fail")
	}
	if err := ValidateParams(2, 3, 5); err == nil {
		t.Fatal("k>n should fail")
	}
	if err := ValidateParams(MaxParts+1, 2, 5); err == nil {
		t.Fatalf("n>%d should fail", MaxParts)
	}
	if err := ValidateParams(MaxParts, MaxParts, 5); err != nil {
		t.Fatalf("n=k=%d should be allowed: %v", MaxParts, err)
	}
	if err := ValidateParams(5, 1, 5); err != nil {
		t.Fatalf("k=1 should be allowed: %v", err)
	}
}

func TestSingleParts(t *testing.T) {
	secret := []byte("only encryption, no real split")
	shares, err := Split(secret, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 1 {
		t.Fatalf("expected 1 share")
	}
	got, err := Combine(shares, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("mismatch")
	}
}

func TestKOneMultiParts(t *testing.T) {
	// k=1, n=4: any single piece reconstructs.
	secret := []byte("redundant copies")
	shares, err := Split(secret, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range shares {
		got, err := Combine([][]byte{s}, 1)
		if err != nil {
			t.Fatalf("share %d: %v", i, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("share %d mismatch", i)
		}
	}
}

func TestThresholdAllSubsets(t *testing.T) {
	secret := []byte{0x00, 0xFF, 0x42, 0x00, 0x01, 0x00} // includes zero symbols
	n, k := 6, 4
	shares, err := Split(secret, n, k)
	if err != nil {
		t.Fatal(err)
	}
	// Every k-subset reconstructs.
	testkit.Subsets(n, k, func(idx []int) {
		sub := make([][]byte, k)
		for i, j := range idx {
			sub[i] = shares[j]
		}
		got, err := Combine(sub, k)
		if err != nil {
			t.Fatalf("combine: %v", err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("mismatch for %v", idx)
		}
	})
}

func TestInsufficientShares(t *testing.T) {
	shares, _ := Split([]byte("abcdef"), 5, 3)
	if _, err := Combine(shares[:2], 3); err != ErrInsufficientShares {
		t.Fatalf("expected ErrInsufficientShares, got %v", err)
	}
}

func TestOneSymbol(t *testing.T) {
	for _, s := range []uint16{0x0000, 0x0001, 0x8000, 0xFFFF} {
		secret := binary.BigEndian.AppendUint16(nil, s)
		shares, err := Split(secret, 10, 8)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Combine(shares[:8], 8)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("one symbol %04x failed: %x", s, got)
		}
	}
}

// TestOddSecretsAreRefused checks Split takes only whole symbols at a threshold
// above one, rather than padding where Combine could not undo it, and that Fit
// says how long to make the secret.
func TestOddSecretsAreRefused(t *testing.T) {
	if _, err := Split([]byte("odd"), 3, 2); err == nil {
		t.Fatal("a secret of an odd length was shared")
	}
	if _, err := Split([]byte("odd"), 3, 1); err != nil {
		t.Fatalf("a copy needs no whole symbols: %v", err)
	}
	for n, want := range map[int]int{1: 2, 2: 2, 3: 4, 100: 100} {
		if got := Fit(n); got != want {
			t.Fatalf("Fit(%d) = %d, want %d", n, got, want)
		}
	}
}

// TestRoundTripAcrossUnits covers the lengths where the work changes shape:
// every tail a word can end with, and either side of the boundary between the
// units the cores share. A miscounted tail or unit would corrupt what follows,
// so every pair of shares is checked rather than just the first one.
func TestRoundTripAcrossUnits(t *testing.T) {
	sizes := []int{2, 4, 6, 8, 10, 14,
		unitBytes - 2, unitBytes, unitBytes + 2,
		2*unitBytes - 2, 2 * unitBytes, 2*unitBytes + 6,
		3*unitBytes + 12346,
	}
	for _, size := range sizes {
		secret := make([]byte, size)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		const n, k = 4, 2
		shares, err := Split(secret, n, k)
		if err != nil {
			t.Fatalf("size=%d: %v", size, err)
		}
		for i, s := range shares {
			if len(s) != size+2 {
				t.Fatalf("size=%d share %d is %d bytes, want %d", size, i+1, len(s), size+2)
			}
		}
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				got, err := Combine([][]byte{shares[i], shares[j]}, k)
				if err != nil {
					t.Fatalf("size=%d shares %d,%d: %v", size, i+1, j+1, err)
				}
				if !bytes.Equal(got, secret) {
					t.Fatalf("size=%d shares %d,%d: content changed", size, i+1, j+1)
				}
			}
		}
	}
}

// TestShareLenMatchesSplit checks the size helpers padding is computed from
// against real shares, and that SecretLen undoes ShareLen. A drift would put
// pieces off their size class.
func TestShareLenMatchesSplit(t *testing.T) {
	for _, size := range []int{2, 4, 6, 254, unitBytes, unitBytes + 2} {
		for _, k := range []int{1, 2} {
			shares, err := Split(make([]byte, size), 2, k)
			if err != nil {
				t.Fatal(err)
			}
			if got := ShareLen(size, k); got != len(shares[0]) {
				t.Fatalf("k=%d secret %d bytes: ShareLen says %d, the share is %d", k, size, got, len(shares[0]))
			}
			if got := SecretLen(len(shares[0]), k); got != size {
				t.Fatalf("k=%d share %d bytes: SecretLen says %d, want %d", k, len(shares[0]), got, size)
			}
		}
	}
	// No secret Split takes has shares of an odd length, so the answer falls
	// short; an odd secret is measured as Fit pads it.
	if got := SecretLen(9, 2); got != 6 {
		t.Fatalf("SecretLen(9, 2) = %d, want 6", got)
	}
	if got := ShareLen(7, 2); got != 10 {
		t.Fatalf("ShareLen(7, 2) = %d, want 10", got)
	}
}

// TestSplitIntoWritesInPlace checks SplitInto writes every share into the buffer
// it is given, leaving what is around it alone, and that they rebuild; and that a
// buffer too short or too long is refused before anything is written.
func TestSplitIntoWritesInPlace(t *testing.T) {
	secret := make([]byte, unitBytes+6)
	rand.Read(secret)
	for _, k := range []int{1, 3} {
		size := len(secret)
		if k > 1 {
			size += 2
		}
		bufs, dst := make([][]byte, 4), make([][]byte, 4)
		for i := range bufs {
			bufs[i] = bytes.Repeat([]byte{0xee}, size+10)
			dst[i] = bufs[i][5 : 5+size]
		}
		if err := SplitInto(dst, secret, k, nil); err != nil {
			t.Fatal(err)
		}
		for _, b := range bufs {
			if !bytes.Equal(b[:5], []byte{0xee, 0xee, 0xee, 0xee, 0xee}) || !bytes.Equal(b[5+size:], b[:5]) {
				t.Fatalf("k=%d: SplitInto wrote outside its share", k)
			}
		}
		for _, use := range [][][]byte{dst[:k], dst[len(dst)-k:]} {
			got, err := Combine(use, k)
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("k=%d: the shares did not rebuild the secret: %v", k, err)
			}
		}
	}

	for _, n := range []int{5, 7} {
		dst := [][]byte{make([]byte, 6), make([]byte, n)}
		if err := SplitInto(dst, []byte("abcd"), 2, nil); err == nil || !bytes.Equal(dst[0], make([]byte, 6)) {
			t.Fatalf("a share buffer of %d bytes, not 6, was not refused first: %v", n, err)
		}
	}
}

// TestSharesMustAgreeInLength checks that shares of different lengths are
// refused: they cannot be from one set.
func TestSharesMustAgreeInLength(t *testing.T) {
	secret := make([]byte, 3*unitBytes)
	rand.Read(secret)
	shares, err := Split(secret, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	truncated := append([][]byte{}, shares[0], shares[1][:len(shares[1])-2])
	if _, err := Combine(truncated, 2); err == nil {
		t.Fatal("shares of different lengths must be refused")
	}
}

// TestCombineRefusesMalformedShares checks what cannot be a sharing is refused
// rather than interpolated: a coordinate of zero, two shares at one coordinate,
// and shares too short or of an odd length to hold symbols.
func TestCombineRefusesMalformedShares(t *testing.T) {
	shares, err := Split([]byte("abcd"), 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	zero := append([]byte{0, 0}, shares[0][2:]...)
	cases := map[string][][]byte{
		"zero coordinate":  {zero, shares[1]},
		"same coordinate":  {shares[0], shares[0]},
		"too short":        {shares[0][:2], shares[1][:2]},
		"odd length":       {shares[0][:5], shares[1][:5]},
		"lengths disagree": {shares[0], shares[1][:4]},
	}
	for name, c := range cases {
		if _, err := Combine(c, 2); err == nil {
			t.Errorf("%s: combined", name)
		}
	}
}

// TestManyParts checks a set past the 255 an 8-bit field allows, with a short
// secret so it stays quick: every one of 65535 shares has its own coordinate,
// and any two rebuild; a threshold of a few hundred rebuilds from that many and
// not one fewer.
func TestManyParts(t *testing.T) {
	secret := []byte("sixteen byte key")
	shares, err := Split(secret, MaxParts, 2)
	if err != nil {
		t.Fatal(err)
	}
	seen := make([]bool, 1<<16)
	for _, s := range shares {
		x := binary.BigEndian.Uint16(s)
		if seen[x] {
			t.Fatalf("coordinate %d used twice", x)
		}
		seen[x] = true
	}
	for _, pair := range [][2]int{{0, MaxParts - 1}, {123, 45678}} {
		got, err := Combine([][]byte{shares[pair[0]], shares[pair[1]]}, 2)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("shares %v: %v", pair, err)
		}
	}

	const n, k = 700, 300
	shares, err = Split(secret, n, k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine(shares[n-k:], k)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("%d of %d: %v", k, n, err)
	}
	if got, _ := Combine(shares[:k-1], k-1); bytes.Equal(got, secret) {
		t.Fatalf("%d shares rebuilt a threshold of %d", k-1, k)
	}
}

func BenchmarkSplit(b *testing.B) {
	secret := make([]byte, 8<<20)
	b.SetBytes(int64(len(secret)))
	for b.Loop() {
		if _, err := Split(secret, 5, 3); err != nil {
			b.Fatal(err)
		}
	}
}

// TestAnEmptyShareIsNotASecret checks a threshold of one, where the share is
// the secret itself, refuses an empty share rather than rebuild nothing.
func TestAnEmptyShareIsNotASecret(t *testing.T) {
	if _, err := Combine([][]byte{{}}, 1); err == nil {
		t.Fatal("an empty share was taken for a secret")
	}
}
