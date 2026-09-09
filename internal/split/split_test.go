// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package split

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestParamValidation(t *testing.T) {
	if err := ValidateParams(3, 2, 0); err == nil {
		t.Fatal("empty secret should fail")
	}
	if err := ValidateParams(2, 3, 5); err == nil {
		t.Fatal("k>n should fail")
	}
	if err := ValidateParams(256, 2, 5); err == nil {
		t.Fatal("n>255 should fail")
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
	secret := []byte{0x00, 0xFF, 0x42, 0x00, 0x01} // includes zero bytes
	n, k := 6, 4
	shares, err := Split(secret, n, k)
	if err != nil {
		t.Fatal(err)
	}
	// Every k-subset reconstructs.
	idx := make([]int, k)
	var rec func(start, depth int)
	rec = func(start, depth int) {
		if depth == k {
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
			return
		}
		for i := start; i < n; i++ {
			idx[depth] = i
			rec(i+1, depth+1)
		}
	}
	rec(0, 0)
}

func TestInsufficientShares(t *testing.T) {
	shares, _ := Split([]byte("abcdef"), 5, 3)
	if _, err := Combine(shares[:2], 3); err != ErrInsufficientShares {
		t.Fatalf("expected ErrInsufficientShares, got %v", err)
	}
}

func TestOneByte(t *testing.T) {
	for _, b := range []byte{0x00, 0x01, 0x80, 0xFF} {
		shares, err := Split([]byte{b}, 10, 8)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Combine(shares[:8], 8)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != b {
			t.Fatalf("one-byte %02x failed: %v", b, got)
		}
	}
}

// TestChunkedRoundTrip covers the sizes where the chunking changes shape: side
// of the chunk boundary, several whole chunks, and a part chunk at the end. A
// chunk miscount would corrupt everything past the first chunk, so every K-sized
// subset is checked rather than just the first one.
func TestChunkedRoundTrip(t *testing.T) {
	sizes := []int{
		chunkBytes - 1, chunkBytes, chunkBytes + 1,
		2*chunkBytes - 1, 2 * chunkBytes, 2*chunkBytes + 1,
		3*chunkBytes + 12345,
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
		wantLen := size + (size+chunkBytes-1)/chunkBytes
		for i, s := range shares {
			if len(s) != wantLen {
				t.Fatalf("size=%d share %d is %d bytes, want %d", size, i+1, len(s), wantLen)
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

// TestChunkCountMatchesSplit checks the count Combine derives from a share
// length against the count Split actually used, across the boundaries where an
// off-by-one would show up.
func TestChunkCountMatchesSplit(t *testing.T) {
	for _, size := range []int{1, 2, 255, chunkBytes - 1, chunkBytes, chunkBytes + 1,
		2 * chunkBytes, 2*chunkBytes + 1, 5 * chunkBytes, 5*chunkBytes + 7} {
		want := (size + chunkBytes - 1) / chunkBytes
		shareLen := size + want
		if got := chunkCount(shareLen); got != want {
			t.Fatalf("secret %d bytes: chunkCount(%d) = %d, want %d", size, shareLen, got, want)
		}
	}
}

// TestChunkedSharesMustAgreeInLength checks that shares of different lengths are
// refused, since the chunk layout is read from the length.
func TestChunkedSharesMustAgreeInLength(t *testing.T) {
	secret := make([]byte, 3*chunkBytes)
	rand.Read(secret)
	shares, err := Split(secret, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	truncated := append([][]byte{}, shares[0], shares[1][:len(shares[1])-1])
	if _, err := Combine(truncated, 2); err == nil {
		t.Fatal("shares of different lengths must be refused")
	}
}
