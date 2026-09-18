// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package kdf

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// fast keeps Argon2 cheap for tests while staying encodable.
var fast = Params{Memory: 8 * 1024, Time: 1, Par: 1}

func TestDeriveDeterministic(t *testing.T) {
	salt := bytes.Repeat([]byte{0x01}, SaltLen)
	a := fast.Derive([]byte("password"), salt)
	b := fast.Derive([]byte("password"), salt)
	if !bytes.Equal(a, b) {
		t.Fatal("derivation not deterministic")
	}
	if len(a) != KeyLen {
		t.Fatalf("key length %d, want %d", len(a), KeyLen)
	}
	if bytes.Equal(a, fast.Derive([]byte("different"), salt)) {
		t.Fatal("different passwords produced same key")
	}
	salt2 := bytes.Repeat([]byte{0x02}, SaltLen)
	if bytes.Equal(a, fast.Derive([]byte("password"), salt2)) {
		t.Fatal("different salt produced same key")
	}
	// Different cost must produce a different key.
	other := Params{Memory: 8 * 1024, Time: 2, Par: 1}
	if bytes.Equal(a, other.Derive([]byte("password"), salt)) {
		t.Fatal("different cost produced same key")
	}
}

func TestMixPasswordsOrderAndBoundary(t *testing.T) {
	a := MixPasswords([][]byte{[]byte("ab"), []byte("c")})
	b := MixPasswords([][]byte{[]byte("a"), []byte("bc")})
	if bytes.Equal(a, b) {
		t.Fatal("length-prefixing failed: concatenation collision")
	}
	if bytes.Equal(a, MixPasswords([][]byte{[]byte("c"), []byte("ab")})) {
		t.Fatal("order should matter")
	}
	if !bytes.Equal(a, MixPasswords([][]byte{[]byte("ab"), []byte("c")})) {
		t.Fatal("mix not deterministic")
	}
}

// TestEncodeDecodeAllBytes is the property the stealth design depends on: every
// one of the 256 byte values must decode to a valid, re-encodable configuration,
// so a random byte is indistinguishable from a recorded one.
func TestEncodeDecodeAllBytes(t *testing.T) {
	for i := 0; i < 256; i++ {
		b := byte(i)
		p := DecodeParams(b)
		if err := p.Validate(); err != nil {
			t.Fatalf("byte %d decoded to invalid params %+v: %v", i, p, err)
		}
		got, err := p.Encode()
		if err != nil {
			t.Fatalf("byte %d: re-encode failed: %v", i, err)
		}
		if got != b {
			t.Fatalf("byte %d round-tripped to %d", i, got)
		}
	}
}

func TestEncodeAllValidCombinations(t *testing.T) {
	count := 0
	for _, m := range MemoryChoices() {
		for tt := uint32(1); tt <= MaxTime; tt++ {
			for _, par := range ParChoices() {
				p := Params{Memory: m * 1024, Time: tt, Par: par}
				b, err := p.Encode()
				if err != nil {
					t.Fatalf("%+v: %v", p, err)
				}
				if DecodeParams(b) != p {
					t.Fatalf("%+v did not round-trip", p)
				}
				count++
			}
		}
	}
	if count != 256 {
		t.Fatalf("expected 256 encodable combinations, got %d", count)
	}
}

func TestValidateRejectsUnencodable(t *testing.T) {
	bad := []Params{
		{Memory: 19 * 1024, Time: 2, Par: 1},   // memory not in table
		{Memory: 64 * 1024, Time: 0, Par: 1},   // zero passes
		{Memory: 64 * 1024, Time: 9, Par: 1},   // too many passes
		{Memory: 64 * 1024, Time: 1, Par: 3},   // parallelism not in table
		{Memory: 4 * 1024, Time: 1, Par: 1},    // below the smallest size
		{Memory: 2048 * 1024, Time: 1, Par: 1}, // above the largest size
	}
	for _, p := range bad {
		if err := p.Validate(); err == nil {
			t.Fatalf("%+v should be rejected", p)
		}
		if _, err := p.Encode(); err == nil {
			t.Fatalf("%+v should not encode", p)
		}
	}
}

func TestMaskIsInvolutionAndSaltDependent(t *testing.T) {
	salt := bytes.Repeat([]byte{0xAB}, SaltLen)
	enc, err := Recommended.Encode()
	if err != nil {
		t.Fatal(err)
	}
	masked := MaskParams(enc, salt)
	if MaskParams(masked, salt) != enc {
		t.Fatal("mask is not its own inverse")
	}
	other := bytes.Repeat([]byte{0xCD}, SaltLen)
	if MaskParams(enc, other) == masked {
		t.Fatal("mask does not depend on the salt")
	}
}

func TestParse(t *testing.T) {
	if p, err := Parse(""); err != nil || p != Default() {
		t.Fatalf("empty spec should give the default: %+v %v", p, err)
	}
	for _, name := range PresetNames() {
		if _, err := Parse(name); err != nil {
			t.Fatalf("preset %q: %v", name, err)
		}
	}
	p, err := Parse("m=128,t=3,p=4")
	if err != nil {
		t.Fatal(err)
	}
	if p.Memory != 128*1024 || p.Time != 3 || p.Par != 4 {
		t.Fatalf("bad parse: %+v", p)
	}
	// Partial specs inherit from the default.
	if p, err := Parse("t=2"); err != nil || p.Time != 2 || p.Memory != Default().Memory {
		t.Fatalf("partial spec: %+v %v", p, err)
	}
	for _, bad := range []string{"nope", "m=19,t=1,p=1", "m=64,t=99,p=1", "x=1", "m=abc"} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

func TestStringRoundTripsThroughParse(t *testing.T) {
	for _, p := range []Params{Recommended, Paranoid, Max, fast} {
		got, err := Parse(p.String())
		if err != nil {
			t.Fatalf("%s: %v", p.String(), err)
		}
		if got != p {
			t.Fatalf("%s round-tripped to %+v", p.String(), got)
		}
	}
}

func TestPresetsAreEncodable(t *testing.T) {
	for _, name := range PresetNames() {
		p, err := Parse(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("preset %q is not encodable: %v", name, err)
		}
	}
}

// A number too large for its field was narrowed before it was checked, so it
// could wrap into a value that happens to be legal: m=4194312 became 8 MiB and
// p=257 one lane. A mistyped cost was then accepted as a weaker one instead of
// being refused, and with --record-kdf false the user would have to reproduce
// the same mistake to open the pieces again.
func TestParseRefusesNumbersThatWouldWrap(t *testing.T) {
	for _, spec := range []string{
		"m=4194312",    // (2^22 + 8) * 1024 wraps a uint32 to 8192 KiB
		"m=4194368",    // wraps to 64 MiB, the default itself
		"p=257",        // wraps a uint8 to 1
		"p=260",        // wraps a uint8 to 4
		"t=4294967297", // wraps a uint32 to 1
		"t=4294967299", // wraps a uint32 to 3
		"m=1025",       // above the largest choice, in range of the type
		"m=64,t=3,p=4,m=4194368",
	} {
		p, err := Parse(spec)
		if err == nil {
			t.Errorf("%q parsed as %s; it must be refused", spec, p.Describe())
			continue
		}
		if !strings.Contains(err.Error(), "bad value") {
			t.Errorf("%q: error does not name the value: %v", spec, err)
		}
	}
	// The bound is the largest legal value, so every real choice still parses.
	for _, m := range MemoryChoices() {
		if _, err := Parse(fmt.Sprintf("m=%d,t=%d,p=%d", m, MaxTime, ParChoices()[len(ParChoices())-1])); err != nil {
			t.Errorf("m=%d: %v", m, err)
		}
	}
}
