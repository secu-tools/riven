// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package kem

import (
	"bytes"
	"testing"
)

func TestEncapsulateDecapsulate(t *testing.T) {
	for _, s := range All() {
		t.Run(s.Name(), func(t *testing.T) {
			priv, err := Generate(s)
			if err != nil {
				t.Fatal(err)
			}
			ss, ct, err := priv.Public().Encapsulate()
			if err != nil {
				t.Fatal(err)
			}
			if len(ss) != SharedSecretSize {
				t.Fatalf("shared secret is %d bytes, want %d", len(ss), SharedSecretSize)
			}
			if len(ct) != s.CiphertextSize() {
				t.Fatalf("encapsulated key is %d bytes, want %d", len(ct), s.CiphertextSize())
			}
			got, err := priv.Decapsulate(ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ss, got) {
				t.Fatal("decapsulated secret does not match")
			}
		})
	}
}

// TestEncapsulationIsFresh checks two encapsulations to the same key differ, so
// pieces of different sets cannot be linked by their encapsulated key.
func TestEncapsulationIsFresh(t *testing.T) {
	for _, s := range All() {
		priv, err := Generate(s)
		if err != nil {
			t.Fatal(err)
		}
		ss1, ct1, err := priv.Public().Encapsulate()
		if err != nil {
			t.Fatal(err)
		}
		ss2, ct2, err := priv.Public().Encapsulate()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(ct1, ct2) || bytes.Equal(ss1, ss2) {
			t.Fatalf("%s: two encapsulations produced the same material", s.Name())
		}
	}
}

func TestSerialization(t *testing.T) {
	for _, s := range All() {
		t.Run(s.Name(), func(t *testing.T) {
			priv, err := Generate(s)
			if err != nil {
				t.Fatal(err)
			}
			pubBytes := priv.Public().Bytes()
			if len(pubBytes) != s.PublicKeySize() {
				t.Fatalf("public key is %d bytes, want %d", len(pubBytes), s.PublicKeySize())
			}
			privBytes, err := priv.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if len(privBytes) != s.PrivateKeySize() {
				t.Fatalf("private key is %d bytes, want %d", len(privBytes), s.PrivateKeySize())
			}

			pub2, err := PublicFromBytes(pubBytes, s)
			if err != nil {
				t.Fatal(err)
			}
			priv2, err := PrivateFromBytes(privBytes, s)
			if err != nil {
				t.Fatal(err)
			}
			// A key pair rebuilt from bytes must still work together.
			ss, ct, err := pub2.Encapsulate()
			if err != nil {
				t.Fatal(err)
			}
			got, err := priv2.Decapsulate(ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ss, got) {
				t.Fatal("rebuilt keys do not agree")
			}
			if priv2.Scheme() != s || pub2.Scheme() != s {
				t.Fatal("scheme lost in serialization")
			}
		})
	}
}

// TestWrongKeyDoesNotRecoverTheSecret covers the case the cascade relies on: a
// key of the right scheme but the wrong pair must not produce the sender's
// secret. Some mechanisms return an unrelated secret instead of an error, which
// is why a layer is confirmed by its AEAD tag rather than here.
func TestWrongKeyDoesNotRecoverTheSecret(t *testing.T) {
	for _, s := range All() {
		a, err := Generate(s)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Generate(s)
		if err != nil {
			t.Fatal(err)
		}
		ss, ct, err := a.Public().Encapsulate()
		if err != nil {
			t.Fatal(err)
		}
		got, err := b.Decapsulate(ct)
		if err == nil && bytes.Equal(ss, got) {
			t.Fatalf("%s: the wrong key recovered the secret", s.Name())
		}
	}
}

// TestCrossSchemeIsRejected checks a key of one scheme refuses a ciphertext from
// another, and says so, since supplying the wrong key file is the likely mistake.
func TestCrossSchemeIsRejected(t *testing.T) {
	for _, a := range All() {
		for _, b := range All() {
			if a == b || a.CiphertextSize() == b.CiphertextSize() {
				continue
			}
			pa, err := Generate(a)
			if err != nil {
				t.Fatal(err)
			}
			pb, err := Generate(b)
			if err != nil {
				t.Fatal(err)
			}
			_, ct, err := pa.Public().Encapsulate()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pb.Decapsulate(ct); err == nil {
				t.Fatalf("a %s key accepted a %s ciphertext", b.Name(), a.Name())
			}
		}
	}
}

// TestKeySizesAreDistinct guards the assumption that a public key length points
// at one scheme, which is what makes a mislabelled file detectable.
func TestKeySizesAreDistinct(t *testing.T) {
	seen := map[int]Scheme{}
	for _, s := range All() {
		n := s.PublicKeySize()
		if other, ok := seen[n]; ok {
			t.Fatalf("%s and %s both have %d-byte public keys", s.Name(), other.Name(), n)
		}
		seen[n] = s
		if got := SchemeForPublicKeySize(n); len(got) != 1 || got[0] != s {
			t.Fatalf("%d bytes resolved to %v, want just %s", n, got, s.Name())
		}
	}
}

// TestPieceCostIsOrdered pins the reason a user picks one scheme over another:
// the encapsulated key rides in every piece, and the classical schemes are far
// smaller than the post-quantum ones.
func TestPieceCostIsOrdered(t *testing.T) {
	if X25519.CiphertextSize() >= MLKEM768.CiphertextSize() {
		t.Fatal("x25519 should carry far less than ml-kem-768")
	}
	if XWing.CiphertextSize() <= MLKEM768.CiphertextSize() {
		t.Fatal("x-wing carries ml-kem-768 plus x25519, so it must be larger")
	}
	if XWing.CiphertextSize() >= MLKEM1024.CiphertextSize() {
		t.Fatal("x-wing should still be smaller than ml-kem-1024")
	}
	for _, s := range []Scheme{X25519, P256, P384} {
		if s.PostQuantum() {
			t.Fatalf("%s is not post-quantum", s.Name())
		}
	}
	for _, s := range []Scheme{XWing, MLKEM768, MLKEM1024} {
		if !s.PostQuantum() {
			t.Fatalf("%s is post-quantum", s.Name())
		}
	}
}

func TestParse(t *testing.T) {
	cases := map[string]Scheme{
		"":                  XWing,
		"x-wing":            XWing,
		"XWing":             XWing,
		"ml-kem-768":        MLKEM768,
		"mlkem768":          MLKEM768,
		"768":               MLKEM768,
		"ml-kem-1024":       MLKEM1024,
		"1024":              MLKEM1024,
		"x25519":            X25519,
		" X25519 ":          X25519,
		"p256":              P256,
		"P-256":             P256,
		"secp384r1":         P384,
		"ml_kem_768":        MLKEM768,
		"ml-kem-768-x25519": XWing,
	}
	for in, want := range cases {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("Parse(%q) = %s, want %s", in, got.Name(), want.Name())
		}
	}
	for _, bad := range []string{"rsa", "ed25519", "p521", "ml-kem-512", "pgp"} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("Parse(%q) should fail", bad)
		}
	}
	// Every name round-trips through Parse, so help text and input agree.
	for _, s := range All() {
		got, err := Parse(s.Name())
		if err != nil || got != s {
			t.Fatalf("name %q does not parse back: %v", s.Name(), err)
		}
	}
}

func TestInvalidInputs(t *testing.T) {
	unknown := Scheme(200)
	if _, err := Generate(unknown); err == nil {
		t.Fatal("an unknown scheme must not generate a key")
	}
	if _, err := PublicFromBytes([]byte{1, 2, 3}, X25519); err == nil {
		t.Fatal("a short public key must be refused")
	}
	if _, err := PrivateFromBytes(nil, X25519); err == nil {
		t.Fatal("an empty private key must be refused")
	}
	priv, err := Generate(X25519)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := priv.Decapsulate(nil); err == nil {
		t.Fatal("an empty ciphertext must be refused")
	}
	if _, err := priv.Decapsulate(make([]byte, 31)); err == nil {
		t.Fatal("a short ciphertext must be refused")
	}
}

// TestSchemeDescription covers the strings and lookups the command line and the
// summaries are built from.
func TestSchemeDescription(t *testing.T) {
	if Default() != XWing {
		t.Fatalf("the default is %s, want the hybrid", Default().Name())
	}
	for _, s := range All() {
		if s.Summary() == "" {
			t.Fatalf("%s has no summary", s.Name())
		}
		if s.String() != s.Name() {
			t.Fatalf("%s prints as %q", s.Name(), s.String())
		}
		if got := SchemeForCiphertextSize(s.CiphertextSize()); len(got) != 1 || got[0] != s {
			t.Fatalf("%d bytes resolved to %v, want just %s", s.CiphertextSize(), got, s.Name())
		}
	}
	if got := SchemeForCiphertextSize(7); got != nil {
		t.Fatalf("an unknown size resolved to %v", got)
	}
	// An unregistered scheme must describe itself rather than panic.
	unknown := Scheme(200)
	if unknown.Name() == "" || unknown.Summary() != "" || unknown.PostQuantum() {
		t.Fatalf("an unknown scheme describes itself as %q", unknown.Name())
	}
	if unknown.PublicKeySize() != 0 || unknown.CiphertextSize() != 0 {
		t.Fatal("an unknown scheme should report no sizes")
	}
}
