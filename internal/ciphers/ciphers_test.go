// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package ciphers

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestAllSchemesRoundTrip(t *testing.T) {
	for _, s := range All() {
		t.Run(s.Name, func(t *testing.T) {
			key := make([]byte, s.KeyLen)
			rand.Read(key)
			aead, err := s.New(key)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if aead.NonceSize() != s.NonceLen {
				t.Fatalf("nonce size mismatch: got %d want %d", aead.NonceSize(), s.NonceLen)
			}
			for _, n := range []int{0, 1, 15, 16, 17, 1000} {
				pt := make([]byte, n)
				rand.Read(pt)
				nonce := make([]byte, aead.NonceSize())
				rand.Read(nonce)
				ad := []byte("associated")
				ct := aead.Seal(nil, nonce, pt, ad)
				if len(ct) != n+aead.Overhead() {
					t.Fatalf("len(ct)=%d want %d", len(ct), n+aead.Overhead())
				}
				got, err := aead.Open(nil, nonce, ct, ad)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if !bytes.Equal(got, pt) {
					t.Fatalf("round trip mismatch")
				}
				// Tamper: flip a byte -> must fail.
				if len(ct) > 0 {
					ct[len(ct)/2] ^= 0xFF
					if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
						t.Fatalf("expected auth failure on tamper")
					}
					ct[len(ct)/2] ^= 0xFF
				}
				// Wrong AD -> must fail.
				if _, err := aead.Open(nil, nonce, ct, []byte("wrong")); err == nil {
					t.Fatalf("expected auth failure on wrong AD")
				}
			}
		})
	}
}

// TestRegistryIsConsistent enforces the invariants a newly added scheme must
// satisfy, so extending the registry cannot silently break callers.
func TestRegistryIsConsistent(t *testing.T) {
	ids := map[uint8]bool{}
	names := map[string]bool{}
	for _, s := range All() {
		if s.ID == 0 {
			t.Fatalf("%s: id 0 is reserved for 'not recorded'", s.Name)
		}
		if ids[s.ID] {
			t.Fatalf("duplicate id %d", s.ID)
		}
		ids[s.ID] = true
		if s.Name == "" || names[s.Name] {
			t.Fatalf("empty or duplicate name %q", s.Name)
		}
		names[s.Name] = true
		if s.Name != strings.ToLower(s.Name) {
			t.Fatalf("%s: names must be lower case so parsing is predictable", s.Name)
		}
		if s.KeyLen != 32 {
			t.Fatalf("%s: key length %d, want 32 for post-quantum margin", s.Name, s.KeyLen)
		}
		if s.NonceLen <= 0 {
			t.Fatalf("%s: nonce length %d", s.Name, s.NonceLen)
		}
	}
	if Count() != len(All()) {
		t.Fatal("Count disagrees with All")
	}
	if len(Names()) != Count() {
		t.Fatal("Names disagrees with Count")
	}
}

func TestDefaultIsRegistered(t *testing.T) {
	d := Default()
	if _, ok := ByID(d.ID); !ok {
		t.Fatal("default scheme is not in the registry")
	}
	if d.Name != defaultName {
		t.Fatalf("default is %s, want %s", d.Name, defaultName)
	}
}

// TestCascadeNeverRepeatsAdjacent covers the sequence used to suggest algorithms
// for successive layers.
func TestCascadeNeverRepeatsAdjacent(t *testing.T) {
	for n := 1; n <= Count()*3; n++ {
		seq := Cascade(n)
		if len(seq) != n {
			t.Fatalf("Cascade(%d) returned %d ids", n, len(seq))
		}
		for i := range seq {
			if _, ok := ByID(seq[i]); !ok {
				t.Fatalf("Cascade(%d) produced unknown id %d", n, seq[i])
			}
			if i > 0 && seq[i] == seq[i-1] {
				t.Fatalf("Cascade(%d) repeated id %d at %d", n, seq[i], i)
			}
			if Nth(i) != seq[i] {
				t.Fatalf("Nth(%d) disagrees with Cascade", i)
			}
		}
	}
	if Cascade(0) != nil {
		t.Fatal("Cascade(0) should be empty")
	}
	if seq := Cascade(1); seq[0] != Default().ID {
		t.Fatal("first cascade algorithm should be the default")
	}
}

func TestParseList(t *testing.T) {
	all := All()
	names := make([]string, len(all))
	for i, s := range all {
		names[i] = s.Name
	}
	ids, err := ParseList(strings.Join(names, ","))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != len(all) {
		t.Fatalf("got %d ids, want %d", len(ids), len(all))
	}
	// Whitespace and case are tolerated.
	if _, err := ParseList("  " + strings.ToUpper(all[0].Name) + " , " + all[1].Name); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", ",", "nope", all[0].Name + ",nope"} {
		if _, err := ParseList(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

func TestName(t *testing.T) {
	if Name(Default().ID) != Default().Name {
		t.Fatal("Name should resolve registered ids")
	}
	if Name(0) == "" {
		t.Fatal("Name should describe unknown ids")
	}
}

func TestByIDByName(t *testing.T) {
	for _, s := range All() {
		if got, ok := ByID(s.ID); !ok || got.Name != s.Name {
			t.Fatalf("ByID(%d) failed", s.ID)
		}
		if got, ok := ByName(s.Name); !ok || got.ID != s.ID {
			t.Fatalf("ByName(%s) failed", s.Name)
		}
	}
	if _, ok := ByID(0); ok {
		t.Fatalf("ByID(0) should not exist")
	}
	if _, ok := ByName("nope"); ok {
		t.Fatalf("ByName(nope) should not exist")
	}
}
