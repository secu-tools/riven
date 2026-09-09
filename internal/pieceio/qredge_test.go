// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package pieceio

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/secu-tools/riven/internal/qrcode"
)

// TestQRLevelForBoundaries pins the level chosen either side of every capacity
// boundary. A piece one byte over a boundary must drop to the next level, never
// fail, until the last boundary where it must fail rather than silently truncate.
func TestQRLevelForBoundaries(t *testing.T) {
	caps := qrcode.Capacities
	for i, c := range caps {
		name, _, _, ok := QRLevelFor(c.Capacity)
		if !ok || name != c.Name {
			t.Fatalf("%d bytes should use level %s, got %s (ok=%v)", c.Capacity, c.Name, name, ok)
		}
		over := c.Capacity + 1
		name, _, _, ok = QRLevelFor(over)
		if i+1 < len(caps) {
			if !ok || name != caps[i+1].Name {
				t.Fatalf("%d bytes should fall back to %s, got %s (ok=%v)", over, caps[i+1].Name, name, ok)
			}
		} else if ok {
			t.Fatalf("%d bytes is past every level and must not encode", over)
		}
	}
	if _, _, _, ok := QRLevelFor(0); ok {
		t.Fatal("zero length must not report a level")
	}
}

// TestQRLevelForMatchesEncoder checks the reported level is the level the encoder
// actually uses, at every boundary. A mismatch would misreport how much damage a
// printed code can take.
func TestQRLevelForMatchesEncoder(t *testing.T) {
	var sizes []int
	for _, c := range qrcode.Capacities {
		sizes = append(sizes, c.Capacity-1, c.Capacity)
	}
	sizes = append(sizes, 1, 2, 100)

	for _, n := range sizes {
		if n < 1 || n > QRMaxBytes {
			continue
		}
		piece := make([]byte, n)
		rand.Read(piece)
		want, _, _, ok := QRLevelFor(n)
		if !ok {
			t.Fatalf("%d bytes: no level reported", n)
		}
		_, note, err := Encode(piece, QR, 2)
		if err != nil {
			t.Fatalf("%d bytes: encode: %v", n, err)
		}
		if !bytes.Contains([]byte(note), []byte("error correction "+want)) {
			t.Fatalf("%d bytes: reported %s but the encoder said %q", n, want, note)
		}
	}
}

// TestQRRoundTripAtEveryBoundary is the safety property that matters: a piece that
// encodes must decode back byte for byte, including right at the point where the
// level changes.
func TestQRRoundTripAtEveryBoundary(t *testing.T) {
	var sizes []int
	for _, c := range qrcode.Capacities {
		sizes = append(sizes, c.Capacity-1, c.Capacity)
		if c.Capacity+1 <= QRMaxBytes {
			sizes = append(sizes, c.Capacity+1)
		}
	}
	for _, n := range sizes {
		piece := make([]byte, n)
		rand.Read(piece)
		data, _, err := Encode(piece, QR, 3)
		if err != nil {
			t.Fatalf("%d bytes: encode: %v", n, err)
		}
		got, detected, err := Decode(data)
		if err != nil {
			t.Fatalf("%d bytes: decode: %v", n, err)
		}
		if detected != QR {
			t.Fatalf("%d bytes: detected as %s", n, detected)
		}
		if !bytes.Equal(got, piece) {
			t.Fatalf("%d bytes: content changed through a QR round trip", n)
		}
	}
}

// TestQRMixedLevelsAllRoundTrip covers a set whose pieces straddle a boundary, so
// some get one level and some another. Every piece must still round-trip: differing
// levels within a set are fine, silently losing one is not.
func TestQRMixedLevelsAllRoundTrip(t *testing.T) {
	boundary := qrcode.Capacities[0].Capacity // strongest level's limit
	sizes := []int{boundary - 40, boundary - 1, boundary, boundary + 1, boundary + 40}

	levels := map[string]bool{}
	for _, n := range sizes {
		piece := make([]byte, n)
		rand.Read(piece)
		name, _, _, ok := QRLevelFor(n)
		if !ok {
			t.Fatalf("%d bytes: no level", n)
		}
		levels[name] = true

		data, _, err := Encode(piece, QR, 3)
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		got, _, err := Decode(data)
		if err != nil || !bytes.Equal(got, piece) {
			t.Fatalf("%d bytes at level %s did not survive: %v", n, name, err)
		}
	}
	if len(levels) < 2 {
		t.Fatalf("expected the sizes to span at least two levels, got %v", levels)
	}
}

// TestQROverCapacityIsRefused checks the one byte past the maximum is an error
// rather than a partial or corrupt code.
func TestQROverCapacityIsRefused(t *testing.T) {
	for _, n := range []int{QRMaxBytes + 1, QRMaxBytes + 100, QRMaxBytes * 3} {
		piece := make([]byte, n)
		rand.Read(piece)
		if QRFits(n) {
			t.Fatalf("%d bytes should not be reported as fitting", n)
		}
		if _, _, err := Encode(piece, QR, 2); err == nil {
			t.Fatalf("%d bytes should not encode", n)
		}
	}
}
