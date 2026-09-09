// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package password

import (
	"bytes"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/unicode/norm"
)

// TestASCIIUnchanged checks that ordinary passwords, including generated ones,
// pass through byte-for-byte. A change here would break every existing ASCII use.
func TestASCIIUnchanged(t *testing.T) {
	cases := []string{
		"",
		"password",
		"Tr0ub4dor&3",
		"correct horse battery staple",
		"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+?",
	}
	for _, c := range cases {
		got := Canonical([]byte(c))
		if string(got) != c {
			t.Errorf("Canonical(%q) = %q, want unchanged", c, got)
		}
	}
}

// TestResultNeverAliasesInput is what lets the caller wipe the input and the
// result independently.
func TestResultNeverAliasesInput(t *testing.T) {
	for _, c := range []string{"", "ascii", "café", "中文密码"} {
		raw := []byte(c)
		got := Canonical(raw)
		if len(raw) > 0 && len(got) > 0 && &raw[0] == &got[0] {
			t.Errorf("Canonical(%q) aliases its input", c)
		}
	}
}

// TestNFCIdempotent checks that canonicalizing an already-canonical password is a
// no-op, so encrypting and decrypting on the same machine always agrees.
func TestNFCIdempotent(t *testing.T) {
	// A spread of scripts a real user might choose.
	cases := []string{
		"中文密码",                            // Chinese: "Chinese password"
		"繁體中文",                            // Traditional Chinese
		"ひらがなパス",                          // Japanese hiragana + katakana
		"日本語パスワード",                        // Japanese with kanji
		"비밀번호",                            // Korean: "password"
		"كلمةالسر",                        // Arabic: "password"
		"סיסמה",                           // Hebrew
		"Пароль",                          // Russian Cyrillic
		"κωδικός",                         // Greek
		"\U0001f510\U0001f512\U0001f6e1️", // Emoji: lock, closed lock, shield
		"Pässwört-中文-123",                 // Mixed scripts + ASCII
	}
	for _, c := range cases {
		once := Canonical([]byte(c))
		twice := Canonical(once)
		if !bytes.Equal(once, twice) {
			t.Errorf("Canonical not idempotent for %q: %x vs %x", c, once, twice)
		}
		if !utf8.Valid(once) {
			t.Errorf("Canonical(%q) produced invalid UTF-8", c)
		}
		if !norm.NFC.IsNormal(once) {
			t.Errorf("Canonical(%q) is not NFC-normalized", c)
		}
	}
}

// TestComposedEqualsDecomposed is the core promise: the same characters typed in
// different Unicode compositions derive the same key. This is the most common way
// two "identical" passwords silently differ (accented Latin, Korean jamo, ...).
func TestComposedEqualsDecomposed(t *testing.T) {
	cases := []struct {
		name             string
		composed, decomp string
	}{
		{"e-acute", "café", "café"},    // é vs e + combining acute
		{"a-umlaut", "äpfel", "äpfel"}, // ä vs a + diaeresis
		{"o-tilde", "niño", "niño"},    // ñ vs n + tilde
		{"korean-syllable", "가", "가"},  // precomposed GA vs jamo
		{"vietnamese", "Tiếng Việt", "Tiếng Việt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.composed == tc.decomp {
				t.Fatal("test bug: forms are byte-identical, nothing is being checked")
			}
			a := Canonical([]byte(tc.composed))
			b := Canonical([]byte(tc.decomp))
			if !bytes.Equal(a, b) {
				t.Errorf("composed %q and decomposed %q canonicalize differently: %x vs %x",
					tc.composed, tc.decomp, a, b)
			}
		})
	}
}

// TestGB18030DecodesToUTF8 covers the stated scenario: a password encrypted as
// UTF-8 and later pasted from a GB18030 (legacy Chinese) source must still open.
func TestGB18030DecodesToUTF8(t *testing.T) {
	for _, s := range []string{
		"中文密码",     // "Chinese password"
		"密碼ABC123", // Chinese + ASCII mix
		"你好世界",     // "hello world"
	} {
		gb, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(s))
		if err != nil {
			t.Fatalf("encoding %q to GB18030: %v", s, err)
		}
		if utf8.Valid(gb) && !isASCII(gb) {
			t.Fatalf("test bug: GB18030 of %q happens to be valid UTF-8; pick another string", s)
		}
		fromUTF8 := Canonical([]byte(s))
		fromGB := Canonical(gb)
		if !bytes.Equal(fromUTF8, fromGB) {
			t.Errorf("UTF-8 and GB18030 of %q canonicalize differently: %x vs %x", s, fromUTF8, fromGB)
		}
	}
}

// TestGBKSubsetDecodes checks the older GBK subset also lands on the same bytes,
// since GB18030 is a superset of it.
func TestGBKSubsetDecodes(t *testing.T) {
	s := "简体中文" // "simplified Chinese"
	gbk, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatalf("encoding to GBK: %v", err)
	}
	if !bytes.Equal(Canonical(gbk), Canonical([]byte(s))) {
		t.Errorf("GBK form of %q did not match its UTF-8 form", s)
	}
}

// TestInvalidEncodingIsDeterministic checks that bytes we cannot make sense of
// still canonicalize deterministically, so they at least round-trip rather than
// failing outright.
func TestInvalidEncodingIsDeterministic(t *testing.T) {
	junk := []byte{0xff, 0xfe, 0x00, 0x81, 0x20, 0xc0}
	a := Canonical(junk)
	b := Canonical(junk)
	if !bytes.Equal(a, b) {
		t.Errorf("Canonical is not deterministic on invalid input: %x vs %x", a, b)
	}
}

// TestCanonicalAll checks the batch helper matches element-wise Canonical and
// leaves its inputs untouched.
func TestCanonicalAll(t *testing.T) {
	raws := [][]byte{[]byte("café"), []byte("café"), []byte("ascii")}
	before := make([][]byte, len(raws))
	for i, r := range raws {
		before[i] = append([]byte(nil), r...)
	}
	out := CanonicalAll(raws)
	if len(out) != len(raws) {
		t.Fatalf("CanonicalAll returned %d entries, want %d", len(out), len(raws))
	}
	for i := range raws {
		if !bytes.Equal(raws[i], before[i]) {
			t.Errorf("CanonicalAll mutated input %d", i)
		}
		if !bytes.Equal(out[i], Canonical(before[i])) {
			t.Errorf("CanonicalAll[%d] disagrees with Canonical", i)
		}
	}
	// The first two are the same characters in different compositions.
	if !bytes.Equal(out[0], out[1]) {
		t.Errorf("composed and decomposed entries did not converge")
	}
}

// TestOtherLegacyEncodingsRoundTripWithinThemselves is a sanity check that a
// password produced and re-entered in the same non-UTF-8, non-GB encoding is at
// least self-consistent (deterministic), even when we cannot map it to UTF-8.
func TestOtherLegacyEncodingsRoundTripWithinThemselves(t *testing.T) {
	encoders := map[string][]byte{
		"shift-jis": mustEncode(t, japanese.ShiftJIS, "パスワード"),
		"euc-kr":    mustEncode(t, korean.EUCKR, "비밀번호"),
		"big5":      mustEncode(t, traditionalchinese.Big5, "繁體"),
	}
	for name, b := range encoders {
		if !bytes.Equal(Canonical(b), Canonical(b)) {
			t.Errorf("%s: Canonical not deterministic", name)
		}
	}
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

func mustEncode(t *testing.T, e encoding.Encoding, s string) []byte {
	t.Helper()
	out, err := e.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatalf("encoding %q: %v", s, err)
	}
	return out
}
