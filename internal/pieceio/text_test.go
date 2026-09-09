// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package pieceio

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/format"
)

// samplePiece returns bytes shaped like a piece: at least the minimum length and
// uniformly random, which is what the detection rules assume.
func samplePiece(t *testing.T, n int) []byte {
	t.Helper()
	if n < format.MinPieceLen {
		n = format.MinPieceLen
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTextFormatsRoundTrip is the guarantee that matters for a piece written as
// text: whatever went in comes back, at every size, in either text format.
func TestTextFormatsRoundTrip(t *testing.T) {
	for _, f := range []Format{Base64, Base32} {
		for _, size := range []int{format.MinPieceLen, 100, 1000, 4096} {
			piece := samplePiece(t, size)
			data, _, err := Encode(piece, f, 4)
			if err != nil {
				t.Fatalf("%s %d: %v", f, size, err)
			}
			got, det, err := decodeDetail(data)
			if err != nil {
				t.Fatalf("%s %d: %v", f, size, err)
			}
			if det.Format != f {
				t.Fatalf("%s %d: detected as %s", f, size, det.Format)
			}
			if !det.Verified {
				t.Fatalf("%s %d: the checksum should have been verified", f, size)
			}
			if !bytes.Equal(got, piece) {
				t.Fatalf("%s %d: content changed", f, size)
			}
		}
	}
}

// TestChecksumCatchesACopyingMistake is why the text formats carry one: a single
// wrong character has to be reported rather than passed on as a piece.
func TestChecksumCatchesACopyingMistake(t *testing.T) {
	for _, f := range []Format{Base64, Base32} {
		piece := samplePiece(t, 300)
		data, _, err := Encode(piece, f, 4)
		if err != nil {
			t.Fatal(err)
		}

		// Change one character to another of the same alphabet, the way a typo
		// would, and keep the length identical.
		damaged := append([]byte{}, data...)
		for i, c := range damaged {
			if c == 'A' {
				damaged[i] = 'B'
				break
			} else if c == 'B' {
				damaged[i] = 'A'
				break
			}
		}
		if bytes.Equal(damaged, data) {
			t.Fatalf("%s: the fixture did not change anything", f)
		}

		got, det, err := decodeDetail(damaged)
		if err != nil {
			continue // rejected outright, which is also a correct answer
		}
		if det.Verified {
			t.Fatalf("%s: a damaged blob reported a good checksum", f)
		}
		if bytes.Equal(got, piece) {
			t.Fatalf("%s: the damage did not reach the piece", f)
		}
	}
}

// TestChecksumIsInvisible checks the text keeps no structure a checksum line
// would add: one run of alphabet characters and separators, nothing else.
func TestChecksumIsInvisible(t *testing.T) {
	piece := samplePiece(t, 200)
	for _, f := range []Format{Base64, Base32} {
		data, _, err := Encode(piece, f, 4)
		if err != nil {
			t.Fatal(err)
		}
		valid := isBase64Char
		if f == Base32 {
			valid = isBase32Char
		}
		for i, c := range data {
			switch c {
			case ' ', '\n':
				continue
			}
			if !valid(c) {
				t.Fatalf("%s: byte %d is %q, which is outside the alphabet", f, i, c)
			}
		}
	}
}

// TestBase32SurvivesHandCopying checks the shapes a person produces: lower case,
// extra spaces, hyphens between groups, and lines rejoined.
func TestBase32SurvivesHandCopying(t *testing.T) {
	piece := samplePiece(t, 300)
	data, _, err := Encode(piece, Base32, 4)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)

	variants := map[string]string{
		"as written":  text,
		"lower case":  strings.ToLower(text),
		"hyphenated":  strings.ReplaceAll(strings.TrimSpace(text), " ", "-"),
		"one line":    strings.ReplaceAll(strings.ReplaceAll(text, "\n", ""), " ", ""),
		"extra space": strings.ReplaceAll(text, " ", "   "),
		"tabs":        strings.ReplaceAll(text, " ", "\t"),
	}
	for name, v := range variants {
		got, f, err := Decode([]byte(v))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if f != Base32 {
			t.Fatalf("%s: detected as %s", name, f)
		}
		if !bytes.Equal(got, piece) {
			t.Fatalf("%s: content changed", name)
		}
	}
}

// TestBase32IsGroupedForReading checks the layout a person has to work through:
// short blocks, a bounded line length, and nothing but the alphabet and spaces.
func TestBase32IsGroupedForReading(t *testing.T) {
	data, _, err := Encode(samplePiece(t, 400), Base32, 4)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	for i, line := range lines {
		groups := strings.Fields(line)
		if len(groups) > base32GroupsPerLine {
			t.Fatalf("line %d has %d groups, more than %d", i+1, len(groups), base32GroupsPerLine)
		}
		for j, g := range groups {
			last := i == len(lines)-1 && j == len(groups)-1
			if len(g) > base32GroupLen || (!last && len(g) != base32GroupLen) {
				t.Fatalf("line %d group %d is %q", i+1, j+1, g)
			}
		}
	}
}

// TestTextFormatsAreNotConfused checks the detection order holds: base32 text is
// never read as base64, and base64 text is never read as base32.
func TestTextFormatsAreNotConfused(t *testing.T) {
	for i := 0; i < 20; i++ {
		piece := samplePiece(t, 200+i)
		for _, f := range []Format{Base64, Base32} {
			data, _, err := Encode(piece, f, 4)
			if err != nil {
				t.Fatal(err)
			}
			got, detected, err := Decode(data)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if detected != f {
				t.Fatalf("%s was detected as %s", f, detected)
			}
			if !bytes.Equal(got, piece) {
				t.Fatalf("%s: content changed", f)
			}
		}
	}
}

// TestBinaryIsNotMistakenForText checks a raw piece is still read as binary,
// which is what stops a random file being decoded as text and truncated.
func TestBinaryIsNotMistakenForText(t *testing.T) {
	for i := 0; i < 50; i++ {
		piece := samplePiece(t, 300)
		got, f, err := Decode(piece)
		if err != nil {
			t.Fatal(err)
		}
		if f != Binary {
			t.Fatalf("a raw piece was detected as %s", f)
		}
		if !bytes.Equal(got, piece) {
			t.Fatal("content changed")
		}
	}
}

// TestSheetRoundTrip covers the printable page: it carries the piece, says which
// piece it is, and reads back as an input file.
func TestSheetRoundTrip(t *testing.T) {
	piece := samplePiece(t, 300)
	data, note, err := EncodeSheet(piece, SheetInfo{Serial: 2, Total: 5, Needed: 3, Name: "secret.pdf"}, 4)
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)

	for _, want := range []string{
		"Recovery piece 2 of 5", "Any 3 of the 5", "secret.pdf",
		"riven combine", "data:image/png;base64,", `id="piece-text"`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("the sheet is missing %q", want)
		}
	}
	if note == "" {
		t.Fatal("the sheet should report its error correction level")
	}
	// Self-contained: nothing to fetch when it is opened years later.
	for _, bad := range []string{"http://", "https://", "<script"} {
		if strings.Contains(strings.ToLower(page), bad) {
			t.Fatalf("the sheet references %q, so it is not self-contained", bad)
		}
	}

	got, det, err := decodeDetail(data)
	if err != nil {
		t.Fatal(err)
	}
	if det.Format != Sheet {
		t.Fatalf("a saved sheet was detected as %s", det.Format)
	}
	if !det.Verified {
		t.Fatal("the sheet text should carry a verified checksum")
	}
	if !bytes.Equal(got, piece) {
		t.Fatal("content changed")
	}
}

// TestSheetWithoutAQRCode checks the page still works for a piece too large to
// scan: the text is there and the page says so.
func TestSheetWithoutAQRCode(t *testing.T) {
	piece := samplePiece(t, QRMaxBytes+500)
	data, note, err := EncodeSheet(piece, SheetInfo{Serial: 1, Total: 2, Needed: 2}, 4)
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	if strings.Contains(page, "data:image/png") {
		t.Fatal("a piece over the QR limit should have no code")
	}
	if !strings.Contains(page, "too large for a QR code") {
		t.Fatalf("the page should explain the missing code:\n%s", note)
	}
	got, f, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if f != Sheet || !bytes.Equal(got, piece) {
		t.Fatal("the text-only sheet did not read back")
	}
}

// TestSheetGrowsToSeveralPages checks a piece too large for one page still
// produces a usable sheet, and that the page says how many pages it is. Losing
// one page of a multi-page piece loses the piece, so it has to be visible.
func TestSheetGrowsToSeveralPages(t *testing.T) {
	piece := samplePiece(t, 4000)
	pages := SheetPages(len(piece))
	if pages < 2 {
		t.Fatalf("a %d byte piece should need several pages, got %d", len(piece), pages)
	}

	data, note, err := EncodeSheet(piece, SheetInfo{Serial: 1, Total: 3, Needed: 2}, 4)
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	if !strings.Contains(page, "Keep them together") {
		t.Fatalf("a multi-page sheet should warn about keeping the pages:\n%s", page)
	}
	if !strings.Contains(note, "pages per piece") {
		t.Fatalf("the note should report the page count, got %q", note)
	}
	// The identity has to repeat, or a stray page cannot be placed.
	if !strings.Contains(page, "<header>") || !strings.Contains(page, "position: fixed") {
		t.Fatal("a printed sheet needs a running header")
	}
	got, f, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if f != Sheet || !bytes.Equal(got, piece) {
		t.Fatal("the multi-page sheet did not read back")
	}
}

// TestSheetRefusesAnUnprintablePiece checks the upper limit exists, since past it
// the format is not doing what it is for.
func TestSheetRefusesAnUnprintablePiece(t *testing.T) {
	if _, _, err := EncodeSheet(samplePiece(t, SheetMaxPiece), SheetInfo{Serial: 1, Total: 1, Needed: 1}, 4); err != nil {
		t.Fatalf("a piece at the limit must still work: %v", err)
	}
	_, _, err := EncodeSheet(samplePiece(t, SheetMaxPiece+1), SheetInfo{Serial: 1, Total: 1, Needed: 1}, 4)
	if err == nil {
		t.Fatal("a piece over the limit must be refused")
	}
	if !strings.Contains(err.Error(), "base32") {
		t.Fatalf("the message should name the format to use instead: %v", err)
	}
}

// TestSheetPagesIsMonotone checks the estimate behaves: never zero, never
// shrinking as the piece grows, and consistent with the limit.
func TestSheetPagesIsMonotone(t *testing.T) {
	last := 0
	for _, n := range []int{1, 100, 780, 800, 2000, 8000, SheetMaxPiece} {
		pages := SheetPages(n)
		if pages < 1 || pages < last {
			t.Fatalf("%d bytes gave %d pages, after %d", n, pages, last)
		}
		last = pages
	}
	if SheetPages(SheetMaxPiece) > SheetMaxPages {
		t.Fatalf("the largest allowed piece is %d pages, over the %d limit",
			SheetPages(SheetMaxPiece), SheetMaxPages)
	}
	if SheetPages(SheetMaxPiece+1) <= SheetMaxPages {
		t.Fatal("the limit should be the point where the page count goes over")
	}
}

// TestSheetTellsYouHowToReadItBack checks the instructions offer a way that is
// not retyping thousands of characters.
func TestSheetTellsYouHowToReadItBack(t *testing.T) {
	data, _, err := EncodeSheet(samplePiece(t, 300), SheetInfo{Serial: 1, Total: 2, Needed: 2}, 4)
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	for _, want := range []string{"QR reader", "OCR", "riven combine"} {
		if !strings.Contains(page, want) {
			t.Errorf("the instructions should mention %q:\n%s", want, page)
		}
	}
}

// TestSheetNameIsEscaped checks a file name cannot inject markup into the page.
func TestSheetNameIsEscaped(t *testing.T) {
	data, _, err := EncodeSheet(samplePiece(t, 100),
		SheetInfo{Serial: 1, Total: 1, Needed: 1, Name: `<script>alert(1)</script>`}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "<script>") {
		t.Fatal("the file name was not escaped")
	}
	if !strings.Contains(string(data), "&lt;script&gt;") {
		t.Fatal("the escaped name is missing")
	}
}

// TestFormatPathsAndNames checks each format has its own extension and a
// description, so nothing overwrites another format's file.
func TestFormatPathsAndNames(t *testing.T) {
	seen := map[string]Format{}
	for _, f := range All() {
		p := Path("dir", "piece.1", f)
		if other, ok := seen[p]; ok {
			t.Fatalf("%s and %s both write %s", f, other, p)
		}
		seen[p] = f
		if f.Describe() == "" {
			t.Fatalf("%s has no description", f)
		}
		back, err := ParseFormat(string(f))
		if err != nil || back != f {
			t.Fatalf("%s does not parse back: %v", f, err)
		}
	}
}

// TestEncodeRejectsSheet checks the one format Encode cannot produce says why.
func TestEncodeRejectsSheet(t *testing.T) {
	_, _, err := Encode(samplePiece(t, 100), Sheet, 4)
	if err == nil {
		t.Fatal("Encode should refuse a sheet")
	}
	if !strings.Contains(err.Error(), "EncodeSheet") {
		t.Fatalf("the error should name the alternative: %v", err)
	}
}
