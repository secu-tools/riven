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
			if aead.Overhead() != s.TagLen {
				t.Fatalf("tag length mismatch: got %d want %d", aead.Overhead(), s.TagLen)
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
	if len(Names()) != len(All()) {
		t.Fatal("Names disagrees with All")
	}
}

// TestCascadeTakesTurnsAmongDesigns covers the order layers that name no
// algorithm take one in: AES, then ChaCha20, then Twofish, starting over.
func TestCascadeTakesTurnsAmongDesigns(t *testing.T) {
	want := []string{"aes-256-gcm", "xchacha20-poly1305", "twofish-256-gcm", "aes-256-gcm"}
	for i, id := range Cascade(len(want)) {
		if Name(id) != want[i] {
			t.Fatalf("layer %d defaults to %s, want %s", i+1, Name(id), want[i])
		}
	}
	for n := 1; n <= len(All())*3; n++ {
		seq := Cascade(n)
		if len(seq) != n {
			t.Fatalf("Cascade(%d) returned %d ids", n, len(seq))
		}
		for i := 1; i < n; i++ {
			if a, b := mustID(t, seq[i-1]), mustID(t, seq[i]); a.design == b.design {
				t.Fatalf("Cascade(%d) puts %s under %s, the same design", n, b.Name, a.Name)
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

// A layer chosen by hand may share a design with the next layer's turn, as
// chacha20-poly1305 does with xchacha20-poly1305: the default then moves on, so
// one break still cannot reach both.
func TestSuggestedNeverSharesTheDesignAbove(t *testing.T) {
	for _, s := range All() {
		if s.design == "" {
			t.Fatalf("%s names no design", s.Name)
		}
	}
	for i := 0; i < len(suggested)*2; i++ {
		for _, above := range All() {
			got := mustID(t, Suggested(i, above.ID))
			if got.design == above.design {
				t.Fatalf("layer %d under %s defaults to %s, the same design", i+1, above.Name, got.Name)
			}
		}
	}
	if got := Name(Suggested(1, mustName(t, "chacha20-poly1305").ID)); got != "twofish-256-gcm" {
		t.Fatalf("a second layer under chacha20-poly1305 defaults to %s, want twofish-256-gcm", got)
	}
}

func mustID(t *testing.T, id uint8) Scheme {
	t.Helper()
	s, ok := ByID(id)
	if !ok {
		t.Fatalf("unknown id %d", id)
	}
	return s
}

func mustName(t *testing.T, name string) Scheme {
	t.Helper()
	s, ok := ByName(name)
	if !ok {
		t.Fatalf("unknown scheme %s", name)
	}
	return s
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
