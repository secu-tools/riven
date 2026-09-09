// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package pieceio

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/format"
)

// TestWordsRoundTrip covers every length modulo the 11-bit group, since the last
// word carries padding and the byte count has to come back exactly.
func TestWordsRoundTrip(t *testing.T) {
	for size := format.MinPieceLen; size < format.MinPieceLen+24; size++ {
		piece := samplePiece(t, size)
		data, note, err := Encode(piece, Words, 0)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if !strings.Contains(note, "words") {
			t.Fatalf("%d bytes: the note should state the word count, got %q", size, note)
		}
		got, det, err := decodeDetail(data)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if det.Format != Words {
			t.Fatalf("%d bytes: detected as %s", size, det.Format)
		}
		if !det.Verified {
			t.Fatalf("%d bytes: the checksum should have been verified", size)
		}
		if !bytes.Equal(got, piece) {
			t.Fatalf("%d bytes: content changed (got %d bytes)", size, len(got))
		}
	}
}

// TestWordsAreFromTheList checks the output is nothing but list words, which is
// what makes it transcribable and what detection relies on.
func TestWordsAreFromTheList(t *testing.T) {
	data, _, err := Encode(samplePiece(t, 200), Words, 0)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data))
	if len(fields) != Bip39Words(200) {
		t.Fatalf("wrote %d words, Bip39Words says %d", len(fields), Bip39Words(200))
	}
	for _, w := range fields {
		if _, ok := bip39Index(w); !ok {
			t.Fatalf("%q is not in the word list", w)
		}
	}
}

// TestWordsSurviveHandCopying covers what a person writes down: numbering, mixed
// case, ragged spacing, commas, and everything on one line.
func TestWordsSurviveHandCopying(t *testing.T) {
	piece := samplePiece(t, 120)
	data, _, err := Encode(piece, Words, 0)
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(string(data))

	numbered := make([]string, 0, len(words))
	capitalised := make([]string, 0, len(words))
	for i, w := range words {
		numbered = append(numbered, fmt.Sprintf("%d. %s", i+1, w))
		capitalised = append(capitalised, strings.ToUpper(w[:1])+w[1:])
	}

	variants := map[string]string{
		"as written":  string(data),
		"one line":    strings.Join(words, " "),
		"numbered":    strings.Join(numbered, "\n"),
		"upper case":  strings.ToUpper(string(data)),
		"mixed case":  strings.Join(capitalised, " "),
		"commas":      strings.Join(words, ", "),
		"wide spaces": strings.Join(words, "    "),
	}
	for name, v := range variants {
		got, f, err := Decode([]byte(v))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if f != Words {
			t.Fatalf("%s: detected as %s", name, f)
		}
		if !bytes.Equal(got, piece) {
			t.Fatalf("%s: content changed", name)
		}
	}
}

// TestWordsCatchAMisreadWord checks the checksum covers the word list too: one
// wrong word has to be reported rather than passed on.
func TestWordsCatchAMisreadWord(t *testing.T) {
	piece := samplePiece(t, 150)
	data, _, err := Encode(piece, Words, 0)
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(string(data))
	// Swap one word for its neighbour in the list, the kind of slip a reader makes.
	idx, _ := bip39Index(words[3])
	words[3] = bip39Words[(idx+1)%len(bip39Words)]

	got, det, err := decodeDetail([]byte(strings.Join(words, " ")))
	if err != nil {
		return // rejected outright is also correct
	}
	if det.Verified {
		t.Fatal("a changed word reported a good checksum")
	}
	if bytes.Equal(got, piece) {
		t.Fatal("the change did not reach the piece")
	}
}

// TestWordsAreNotConfusedWithOtherText checks prose and other formats are not
// claimed by the word list decoder.
func TestWordsAreNotConfusedWithOtherText(t *testing.T) {
	piece := samplePiece(t, 200)
	for _, f := range []Format{Base64, Base32} {
		data, _, err := Encode(piece, f, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, detected, err := Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		if detected != f {
			t.Fatalf("%s was detected as %s", f, detected)
		}
	}

	// Ordinary prose, long enough to pass the length gate, must not decode.
	prose := strings.Repeat("the quick brown fox jumps over the lazy dog ", 20)
	if _, _, ok := tryBip39([]byte(prose)); ok {
		t.Fatal("prose was taken for a word list")
	}
	// A list of real words but too short to be a piece must not decode either.
	if _, _, ok := tryBip39([]byte("abandon ability able about")); ok {
		t.Fatal("four words were taken for a piece")
	}
}

// TestWordsRefusesLargePieces checks the format declines rather than producing a
// list nobody would transcribe.
func TestWordsRefusesLargePieces(t *testing.T) {
	if _, _, err := Encode(samplePiece(t, Bip39MaxPiece+1), Words, 0); err == nil {
		t.Fatal("an oversized piece should be refused")
	}
	if _, _, err := Encode(samplePiece(t, Bip39MaxPiece), Words, 0); err != nil {
		t.Fatalf("a piece at the limit should encode: %v", err)
	}
}

// TestWordListIsTheStandardOne pins the properties the specification gives it,
// so a bad edit to the list is caught here rather than by a user.
func TestWordListIsTheStandardOne(t *testing.T) {
	if len(bip39Words) != 2048 {
		t.Fatalf("the list has %d words, want 2048", len(bip39Words))
	}
	seen := map[string]bool{}
	prefixes := map[string]bool{}
	for i, w := range bip39Words {
		if w == "" || strings.ToLower(w) != w {
			t.Fatalf("word %d is %q", i, w)
		}
		for _, r := range w {
			if r < 'a' || r > 'z' {
				t.Fatalf("word %d (%q) is not plain letters", i, w)
			}
		}
		if seen[w] {
			t.Fatalf("word %q appears twice", w)
		}
		seen[w] = true

		p := w
		if len(p) > 4 {
			p = p[:4]
		}
		if prefixes[p] {
			t.Fatalf("prefix %q is shared, which the specification forbids", p)
		}
		prefixes[p] = true

		if i > 0 && bip39Words[i-1] >= w {
			t.Fatalf("the list is not sorted at %q", w)
		}
	}
}

// TestBip39ExpansionIsHonest checks the figure shown to the user matches what is
// actually written, since that number is the reason to pick another format.
func TestBip39ExpansionIsHonest(t *testing.T) {
	piece := samplePiece(t, 512)
	data, _, err := Encode(piece, Words, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := float64(len(data)) / float64(len(piece))
	if got < Bip39Expansion-0.5 || got > Bip39Expansion+0.5 {
		t.Fatalf("the text is %.2f times the piece, but Bip39Expansion says %.1f", got, Bip39Expansion)
	}
}
