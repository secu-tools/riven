// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package pieceio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
// stay far above any piece that could actually be combined, since rebuilding
// needs several times the piece size in memory at once.
func TestMaxStoredLenCannotRefuseARealPiece(t *testing.T) {
	const plausibleLargestPiece = 4 << 30 // a 4 GiB input already needs ~32 GiB to split
	if MaxStoredLen < plausibleLargestPiece {
		t.Fatalf("MaxStoredLen is %d, which would refuse a piece a user could make", MaxStoredLen)
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
	if _, ok := bip39Indexes(huge); ok {
		t.Fatal("an oversize word list was accepted")
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
