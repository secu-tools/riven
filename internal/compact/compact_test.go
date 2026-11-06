// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package compact

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20"

	"github.com/secu-tools/riven/internal/testkit"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// sealed seals payload into size bytes the way a caller does: the payload
// written at PayloadAt, then sealed in place.
func sealed(t *testing.T, payload []byte, size int) (data, secret []byte) {
	t.Helper()
	data = make([]byte, size)
	copy(data[PayloadAt:], payload)
	secret, err := Seal(data, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	return data, secret
}

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 100, 1 << 20} {
		payload := randomBytes(t, n)
		size := PackageLen(n) + 37
		data, secret := sealed(t, payload, size)
		if len(data) != size || len(secret) != SecretLen {
			t.Fatalf("%d bytes: got %d data bytes and %d secret bytes", n, len(data), len(secret))
		}
		got, err := Open(data, secret)
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%d bytes: opened to different content", n)
		}
	}
}

// TestParallelKeystreamIsTheSingleStream checks the chunked keystream gives the
// same bytes as one ChaCha20 stream, across chunk boundaries and for a length
// that is not a whole number of blocks, so splitting the work changes nothing in
// the format.
func TestParallelKeystreamIsTheSingleStream(t *testing.T) {
	key := randomBytes(t, 32)
	for _, n := range []int{0, 1, 63, 65, streamChunk - 1, streamChunk, streamChunk + 1, 3*streamChunk + 129} {
		buf := randomBytes(t, n)
		want := append([]byte(nil), buf...)
		s, err := chacha20.NewUnauthenticatedCipher(key, make([]byte, chacha20.NonceSize))
		if err != nil {
			t.Fatal(err)
		}
		s.XORKeyStream(want, want)
		if err := keystream(key, buf); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf, want) {
			t.Fatalf("%d bytes: the chunked keystream differs from the single stream", n)
		}
	}
}

func TestSealRejectsASizeUnderThePackage(t *testing.T) {
	if _, err := Seal(make([]byte, PackageLen(10)-1), 10); err == nil {
		t.Fatal("a size too small for the package was accepted")
	}
}

// TestEveryByteMatters is the all-or-nothing property, and the integrity one: a
// change anywhere in the data, including the transform's own tail and the fill,
// stops it opening, rather than spoiling just the bytes nearby.
func TestEveryByteMatters(t *testing.T) {
	payload := randomBytes(t, 64)
	data, secret := sealed(t, payload, PackageLen(len(payload))+5)
	for i := range data {
		changed := append([]byte(nil), data...)
		changed[i] ^= 0x01
		if _, err := Open(changed, secret); err != ErrIntegrity {
			t.Fatalf("flipping byte %d of %d: got %v, want ErrIntegrity", i, len(changed), err)
		}
	}
}

// TestEachKeyIsNeeded checks both shared keys matter, each on its own, so neither
// layer can be skipped by someone who learned the other key, and that the length
// in the secret is checked too: a longer one runs past the data and a shorter one
// cuts the outer layer short.
func TestEachKeyIsNeeded(t *testing.T) {
	payload := randomBytes(t, 300)
	data, secret := sealed(t, payload, PackageLen(len(payload))+200)
	for _, at := range []int{8, 8 + KeysLen/2, SecretLen - 1, 7, 6} {
		wrong := append([]byte(nil), secret...)
		wrong[at] ^= 0x80
		if _, err := Open(append([]byte(nil), data...), wrong); err != ErrIntegrity {
			t.Fatalf("a wrong secret at offset %d: got %v, want ErrIntegrity", at, err)
		}
	}
	if _, err := Open(data, secret[:10]); err == nil {
		t.Fatal("a short secret was accepted")
	}
	if _, err := Open(data[:Overhead-1], secret); err != ErrIntegrity {
		t.Fatalf("data shorter than the overhead: got %v", err)
	}
}

// TestFreshKeysEverySeal checks two seals of the same payload share nothing, so a
// set cannot be linked to another by its keys or its package.
func TestFreshKeysEverySeal(t *testing.T) {
	payload := []byte("the same payload twice")
	a, sa := sealed(t, payload, PackageLen(len(payload)))
	b, sb := sealed(t, payload, PackageLen(len(payload)))
	if bytes.Equal(sa[8:40], sb[8:40]) || bytes.Equal(sa[40:72], sb[40:72]) || bytes.Equal(a, b) {
		t.Fatal("two seals repeated a key or the package")
	}
}

// TestPackageHidesTheContent checks a regular payload leaves no trace in the
// package or the fill: no plaintext run survives, and the bytes are as flat as
// noise.
func TestPackageHidesTheContent(t *testing.T) {
	marker := []byte("CONFIDENTIAL-")
	payload := bytes.Repeat(append(append([]byte(nil), marker...), "a very regular line\n"...), 2000)
	data, _ := sealed(t, payload, PackageLen(len(payload))+4096)
	if bytes.Contains(data, marker) {
		t.Fatal("the content appears in the package")
	}
	if chi := testkit.ChiSquare(data); chi > 400 {
		t.Fatalf("the package is not uniform (chi-square %.0f)", chi)
	}
}
