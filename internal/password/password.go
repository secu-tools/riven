// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package password puts a user-supplied password into one canonical form before
// it is turned into a key, so the same password always derives the same key no
// matter how it was typed or which encoding the terminal delivered.
//
// Two real problems break decryption otherwise:
//
//   - Composition. The same character can be one code point or several combining
//     ones (for example an accented letter, or a Korean syllable). They look
//     identical and mean the same thing but are different bytes. Unicode NFC
//     folds them together. This follows RFC 8265's password rules.
//   - Encoding. A password entered as UTF-8 at split time and pasted as GB18030
//     (a common Chinese encoding) at combine time is different bytes for the same
//     characters. Input that is not valid UTF-8 is transcoded from GB18030 to
//     UTF-8 first, so both reduce to the same canonical bytes.
//
// Pure ASCII passwords are unaffected: they are already valid UTF-8 and already
// normalized, so generated passwords pass through unchanged.
package password

import (
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/unicode/norm"

	"github.com/secu-tools/riven/internal/memory"
)

// Canonical returns the canonical form of raw: valid UTF-8 normalized to NFC.
// Input that is not valid UTF-8 is transcoded from GB18030 when that yields valid
// UTF-8. The result is always a fresh slice that does not alias raw, so the
// caller can wipe raw and the result independently.
//
// It never fails: input that is neither valid UTF-8 nor decodable as GB18030 is
// normalized as-is, which is still deterministic and so still round-trips.
func Canonical(raw []byte) []byte {
	src := raw
	if !utf8.Valid(src) {
		if conv, err := simplifiedchinese.GB18030.NewDecoder().Bytes(src); err == nil && utf8.Valid(conv) {
			defer memory.Zero(conv)
			src = conv
		}
	}
	if norm.NFC.IsNormal(src) {
		// Already canonical; copy so the result never aliases raw or the
		// transcoded temporary above.
		out := memory.Bytes(len(src))
		copy(out, src)
		return out
	}
	// NFC.Bytes allocates on the ordinary heap, so the canonical form is moved
	// into locked memory and the intermediate wiped: this value is what the key
	// is actually derived from.
	nfc := norm.NFC.Bytes(src)
	out := memory.Bytes(len(nfc))
	copy(out, nfc)
	memory.Zero(nfc)
	return out
}

// CanonicalAll canonicalizes every password in place order, returning a new
// slice of new slices. The inputs are left untouched for the caller to wipe.
func CanonicalAll(raws [][]byte) [][]byte {
	out := make([][]byte, len(raws))
	for i, r := range raws {
		out[i] = Canonical(r)
	}
	return out
}
