// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package pieceio

import (
	"errors"
	"strings"
	"unicode"

	"github.com/secu-tools/riven/internal/format"
)

// BIP-39 as an encoding: 11 bits per word from the standard English list. See
// docs/format.md for what this format is for and what it costs.
const (
	bip39Bits      = 11
	bip39WordsLine = 6
)

// Bip39Expansion is roughly how many times larger the text is than the piece.
const Bip39Expansion = 4.7

// Bip39Words reports how many words a piece of the given size produces.
func Bip39Words(pieceLen int) int {
	bits := (pieceLen + checksumLen) * 8
	return (bits + bip39Bits - 1) / bip39Bits
}

// encodeBip39 renders piece plus its checksum as word-list text.
func encodeBip39(piece []byte) string {
	body := withChecksum(piece)
	words := make([]string, 0, Bip39Words(len(piece)))

	var acc uint32
	var bits uint
	for _, b := range body {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= bip39Bits {
			bits -= bip39Bits
			words = append(words, bip39Words[(acc>>bits)&0x7FF])
		}
	}
	if bits > 0 {
		// Pad the last group with zero bits. The decoder resolves the resulting
		// length ambiguity with the checksum.
		words = append(words, bip39Words[(acc<<(bip39Bits-bits))&0x7FF])
	}

	var sb strings.Builder
	for i, w := range words {
		sb.WriteString(w)
		switch {
		case i == len(words)-1:
			sb.WriteByte('\n')
		case (i+1)%bip39WordsLine == 0:
			sb.WriteByte('\n')
		default:
			sb.WriteByte(' ')
		}
	}
	return sb.String()
}

// tryBip39 decodes word-list text. It accepts any spacing and either case, and
// ignores the numbering a person may add while writing the words down.
func tryBip39(raw []byte) (piece []byte, verified, ok bool) {
	indexes, ok := bip39Indexes(string(raw))
	if !ok {
		return nil, false, false
	}

	var acc uint32
	var bits uint
	body := make([]byte, 0, len(indexes)*bip39Bits/8)
	for _, idx := range indexes {
		acc = acc<<bip39Bits | uint32(idx)
		bits += bip39Bits
		for bits >= 8 {
			bits -= 8
			body = append(body, byte(acc>>bits))
		}
	}
	if len(body) < format.MinPieceLen+checksumLen {
		return nil, false, false
	}

	// The word count does not always determine the byte count: the final word
	// may carry padding bits that add a whole byte. The checksum decides.
	if p, v := stripChecksum(body); v {
		return p, true, true
	}
	if p, v := stripChecksum(body[:len(body)-1]); v {
		return p, true, true
	}
	return body, false, true
}

// bip39Indexes turns text into word indexes, or reports that it is not a word
// list. Every token has to be on the list, which is what keeps this from
// claiming arbitrary prose.
func bip39Indexes(text string) ([]int, bool) {
	// FieldsFunc materialises every token before any of them is checked, so it is
	// bounded here rather than after. This decoder is tried against whatever file
	// was handed in, and a word list is small by construction: past the ceiling
	// the input is something else, whatever it turns out to be.
	if len(text) > bip39MaxText {
		return nil, false
	}
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';'
	})
	indexes := make([]int, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimFunc(f, func(r rune) bool {
			return r == '.' || r == ')' || r == ':' || r == '-'
		})
		if f == "" {
			continue
		}
		if isNumber(f) {
			continue // a list may be numbered
		}
		idx, ok := bip39Index(strings.ToLower(f))
		if !ok {
			return nil, false
		}
		indexes = append(indexes, idx)
	}
	// A piece is at least 57 bytes, so a real word list is never short.
	if len(indexes) < Bip39Words(format.MinPieceLen) {
		return nil, false
	}
	return indexes, true
}

func isNumber(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// bip39Index looks a word up in the sorted list.
func bip39Index(word string) (int, bool) {
	lo, hi := 0, len(bip39Words)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		switch {
		case bip39Words[mid] == word:
			return mid, true
		case bip39Words[mid] < word:
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	return 0, false
}

// errBip39TooLarge guards against producing a word list nobody could use.
var errBip39TooLarge = errors.New("this piece would need more words than anyone could transcribe; use base32 or a smaller piece")

// Bip39MaxPiece is the largest piece this format will produce: past it the
// output is thousands of words, which nobody would transcribe.
const Bip39MaxPiece = 4096

// bip39MaxText bounds the text the decoder will look at. The longest list it can
// have written is Bip39MaxPiece plus its checksum, and the longest word on the
// list is 8 characters; the rest is slack for numbering, punctuation and line
// breaks, several times over.
const bip39MaxText = (Bip39MaxPiece + checksumLen) * 8 * 4
