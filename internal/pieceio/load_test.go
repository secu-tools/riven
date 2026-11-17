// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package pieceio

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/format"
)

// A directory of pieces may hold anything, including a link to a device or a
// FIFO. Reading one would run until memory ran out, or block forever.
func TestLoadRejectsAnythingButARegularFile(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a directory")
	} else if !strings.Contains(err.Error(), "regular file") {
		t.Errorf("error does not say why: %v", err)
	}

}

// A symlink to a device is the delivery vector: a tar of "pieces" preserving one
// that points at /dev/zero. Creating a symlink needs a privilege on Windows, so
// this runs where it can.
func TestLoadRejectsASymlinkToADevice(t *testing.T) {
	link := filepath.Join(t.TempDir(), "piece7")
	if err := os.Symlink(os.DevNull, link); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	if _, _, err := Load(link); err == nil {
		t.Error("Load followed a symlink to a device")
	}
}

// The bound exists so an absurd size is refused rather than allocated. It must
// not refuse any file a split can write: the largest piece in each form with no
// size limit of its own, its size scaled from a real encoding.
func TestMaxStoredLenCannotRefuseARealPiece(t *testing.T) {
	largest := format.MaxCarriedLen + 1<<20 // and everything around what it carries
	piece := make([]byte, 64<<10)
	for _, f := range []Format{Binary, Base64, Base32} {
		data, err := Encode(piece, f, 0)
		if err != nil {
			t.Fatal(err)
		}
		if stored := largest/int64(len(piece))*int64(len(data)) + 1<<20; stored > MaxStoredLen {
			t.Errorf("the largest %s piece is about %d bytes, past the %d MaxStoredLen allows", f, stored, int64(MaxStoredLen))
		}
	}
}

// TestLoadAllReadsEveryCopy checks a file's every copy of its piece is read: one
// for a plain format and for a sheet too large for a code, and two, the text and
// the code, for a sheet that carries both.
func TestLoadAllReadsEveryCopy(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sheet := func(piece []byte) []byte {
		t.Helper()
		page, err := EncodeSheet(piece, SheetInfo{Serial: 1, Total: 2, Needed: 2}, 2)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	small, large := samplePiece(t, 300), samplePiece(t, QRMaxBytes+100)
	text, err := Encode(small, Base32, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		data  []byte
		piece []byte
		want  int
	}{
		{"base32", text, small, 1},
		{"sheet with a code", sheet(small), small, 2},
		{"sheet too large for a code", sheet(large), large, 1},
	} {
		copies, err := LoadAll(write(c.name, c.data))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(copies) != c.want {
			t.Fatalf("%s: %d copies read, want %d", c.name, len(copies), c.want)
		}
		for i, got := range copies {
			if !bytes.Equal(got, c.piece) {
				t.Fatalf("%s: copy %d is not the piece", c.name, i)
			}
		}
	}
	if _, err := LoadAll(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing file was read")
	}
	if _, err := LoadAll(write("empty", nil)); err == nil {
		t.Fatal("an empty file was read")
	}
}

// TestLoadAllWantsTheCodeOnASheet checks a sheet whose piece fits a code is
// refused when the code is gone or does not read: its text alone would pass for
// the whole sheet, and the code is what most people will scan.
func TestLoadAllWantsTheCodeOnASheet(t *testing.T) {
	piece := samplePiece(t, 300)
	page, err := EncodeSheet(piece, SheetInfo{Serial: 1, Total: 2, Needed: 2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	png, ok := sheetQR(page)
	if !ok {
		t.Fatal("the sheet has no code")
	}
	code := []byte(base64.StdEncoding.EncodeToString(png))
	notAnImage := []byte(base64.StdEncoding.EncodeToString([]byte("not an image")))
	for name, spoiled := range map[string][]byte{
		"no code":            bytes.Replace(page, []byte(`src="`+sheetQRSource), []byte(`src="`), 1),
		"code is not base64": bytes.Replace(page, code, []byte("!!!!"), 1),
		"code is not a QR":   bytes.Replace(page, code, notAnImage, 1),
	} {
		if bytes.Equal(spoiled, page) {
			t.Fatalf("%s: the sheet was not changed", name)
		}
		path := filepath.Join(t.TempDir(), "sheet.html")
		if err := os.WriteFile(path, spoiled, 0o600); err != nil {
			t.Fatal(err)
		}
		// The text is untouched, so the sheet still loads as a piece.
		if got, _, err := Load(path); err != nil || !bytes.Equal(got, piece) {
			t.Fatalf("%s: the text no longer reads: %v", name, err)
		}
		if _, err := LoadAll(path); err == nil || !strings.Contains(err.Error(), "QR code") {
			t.Fatalf("%s: got %v, want the code reported as unreadable", name, err)
		}
	}
}

// TestTextDecodersTurnBinaryAwayWithoutCopyingIt checks the text decoders, which
// are tried on every file before it is taken as binary, allocate nothing for a
// binary piece. Each once made a copy the size of the file before looking at it,
// so reading a large piece took several times its size in memory.
func TestTextDecodersTurnBinaryAwayWithoutCopyingIt(t *testing.T) {
	binary := bytes.Repeat([]byte{0xA7, 0x00, 0x1F}, 1<<18)
	allocs := testing.AllocsPerRun(5, func() {
		_, _, words := tryBip39(binary)
		_, _, b32 := tryBase32(binary)
		_, _, b64 := tryBase64(binary)
		if words || b32 || b64 {
			t.Fatal("binary was read as text")
		}
	})
	if allocs != 0 {
		t.Fatalf("the text decoders made %.0f allocations for a binary piece, want none", allocs)
	}
}

// bip39Indexes materialises every token before checking any of them, and it is
// tried against whatever file was handed in. Without a bound a large file costs
// roughly 24 times its size in heap before being rejected.
func TestWordDecodeRefusesOversizeTextEarly(t *testing.T) {
	huge := strings.Repeat("abandon ", (bip39MaxText/8)+64)
	if len(huge) <= bip39MaxText {
		t.Fatal("test input is not over the bound")
	}
	if _, _, ok := tryBip39([]byte(huge)); ok {
		t.Fatal("an oversize word list was accepted")
	}
	// It is turned away before any token is made of it.
	raw := []byte(huge)
	if allocs := testing.AllocsPerRun(5, func() { tryBip39(raw) }); allocs != 0 {
		t.Fatalf("an oversize word list cost %.0f allocations before it was refused", allocs)
	}
}

// The bound must clear a real word list by a wide margin: the largest piece the
// format writes is Bip39MaxPiece, and that has to decode.
func TestWordDecodeAcceptsTheLargestRealList(t *testing.T) {
	piece := make([]byte, Bip39MaxPiece)
	for i := range piece {
		piece[i] = byte(i)
	}
	text := encodeBip39(piece)
	if len(text) > bip39MaxText {
		t.Fatalf("the largest real word list is %d bytes, past the %d bound",
			len(text), bip39MaxText)
	}
	got, _, ok := tryBip39([]byte(text))
	if !ok {
		t.Fatal("the largest real word list did not decode")
	}
	if len(got) != len(piece) {
		t.Fatalf("decoded %d bytes, want %d", len(got), len(piece))
	}
}
