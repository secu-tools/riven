// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package qrcode

import (
	"bytes"
	"crypto/rand"
	"image"
	"image/png"
	"testing"
)

func TestSelectLevelPicksStrongestThatFits(t *testing.T) {
	cases := []struct {
		size int
		want string
	}{
		{1, "H"},
		{Capacities[0].Capacity, "H"},
		{Capacities[0].Capacity + 1, "Q"},
		{Capacities[1].Capacity, "Q"},
		{Capacities[1].Capacity + 1, "M"},
		{Capacities[2].Capacity, "M"},
		{Capacities[2].Capacity + 1, "L"},
		{MaxBytes, "L"},
	}
	for _, c := range cases {
		l, err := SelectLevel(c.size)
		if err != nil {
			t.Fatalf("%d bytes: %v", c.size, err)
		}
		if l.Name != c.want {
			t.Fatalf("%d bytes: got level %s, want %s", c.size, l.Name, c.want)
		}
	}
	if _, err := SelectLevel(0); err == nil {
		t.Fatal("zero length should fail")
	}
	if _, err := SelectLevel(MaxBytes + 1); err == nil {
		t.Fatal("over capacity should fail")
	}
}

func TestFits(t *testing.T) {
	if Fits(0) || Fits(MaxBytes+1) {
		t.Fatal("out-of-range sizes should not fit")
	}
	if !Fits(1) || !Fits(MaxBytes) {
		t.Fatal("in-range sizes should fit")
	}
}

// TestCapacitiesMatchEncoder guards the documented limits against the encoder:
// each level must encode its stated capacity and reject one byte more.
func TestCapacitiesMatchEncoder(t *testing.T) {
	for _, l := range Capacities {
		data := make([]byte, l.Capacity)
		rand.Read(data)
		if _, got, err := Encode(data, 1); err != nil {
			t.Fatalf("level %s: %d bytes should encode: %v", l.Name, l.Capacity, err)
		} else if got.Name != l.Name {
			t.Fatalf("%d bytes selected %s, want %s", l.Capacity, got.Name, l.Name)
		}
	}
	over := make([]byte, MaxBytes+1)
	if _, _, err := Encode(over, 1); err == nil {
		t.Fatal("over-capacity payload should not encode")
	}
}

func TestRoundTripSizesAndContent(t *testing.T) {
	sizes := []int{1, 2, 32, 300, 1272, 1273, 1662, 1663, 2330, 2331, MaxBytes}
	for _, n := range sizes {
		data := make([]byte, n)
		rand.Read(data)
		pngBytes, level, err := Encode(data, 4)
		if err != nil {
			t.Fatalf("%d bytes: encode: %v", n, err)
		}
		got, err := Decode(pngBytes)
		if err != nil {
			t.Fatalf("%d bytes (level %s): decode: %v", n, level.Name, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("%d bytes (level %s): content mismatch", n, level.Name)
		}
	}
}

// TestRoundTripEdgePatterns covers byte values that text-oriented encoders tend
// to mangle: NUL, high bytes, and invalid UTF-8 sequences.
func TestRoundTripEdgePatterns(t *testing.T) {
	patterns := map[string][]byte{
		"zeros":        make([]byte, 200),
		"ones":         bytes.Repeat([]byte{0xFF}, 200),
		"invalid-utf8": bytes.Repeat([]byte{0xC3, 0x28, 0x80, 0xFE}, 50),
		"all-values":   allByteValues(),
		"single-nul":   {0x00},
	}
	for name, data := range patterns {
		pngBytes, _, err := Encode(data, 4)
		if err != nil {
			t.Fatalf("%s: encode: %v", name, err)
		}
		got, err := Decode(pngBytes)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("%s: content mismatch", name)
		}
	}
}

func allByteValues() []byte {
	out := make([]byte, 256)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func TestScales(t *testing.T) {
	data := make([]byte, 400)
	rand.Read(data)
	for _, s := range []int{0, 1, 2, 8} {
		pngBytes, _, err := Encode(data, s)
		if err != nil {
			t.Fatalf("scale %d: %v", s, err)
		}
		got, err := Decode(pngBytes)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("scale %d: round trip failed: %v", s, err)
		}
		cfg, _, err := image.DecodeConfig(bytes.NewReader(pngBytes))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Width != cfg.Height || cfg.Width == 0 {
			t.Fatalf("scale %d: bad image %dx%d", s, cfg.Width, cfg.Height)
		}
	}
}

func TestIsImage(t *testing.T) {
	data := make([]byte, 100)
	rand.Read(data)
	pngBytes, _, err := Encode(data, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !IsImage(pngBytes) {
		t.Fatal("PNG should be detected as an image")
	}
	if IsImage(data) {
		t.Fatal("random bytes should not be detected as an image")
	}
	if IsImage(nil) || IsImage([]byte("hello")) {
		t.Fatal("non-images should not be detected as images")
	}
}

func TestDecodeRejectsJunk(t *testing.T) {
	if _, err := Decode(nil); err == nil {
		t.Fatal("nil should fail")
	}
	if _, err := Decode([]byte("not an image")); err == nil {
		t.Fatal("text should fail")
	}
	// A valid image with no QR code in it must fail cleanly, not panic.
	blank := image.NewGray(image.Rect(0, 0, 64, 64))
	var buf bytes.Buffer
	if err := png.Encode(&buf, blank); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(buf.Bytes()); err == nil {
		t.Fatal("blank image should fail")
	}
}

func TestWeakest(t *testing.T) {
	last := Capacities[len(Capacities)-1]
	if !last.Weakest() {
		t.Fatal("last level should report as weakest")
	}
	if Capacities[0].Weakest() {
		t.Fatal("first level should not report as weakest")
	}
}

// FuzzDecode ensures hostile image-shaped input never panics.
func FuzzDecode(f *testing.F) {
	data := make([]byte, 64)
	rand.Read(data)
	if pngBytes, _, err := Encode(data, 2); err == nil {
		f.Add(pngBytes)
	}
	f.Add([]byte{})
	f.Add([]byte("\x89PNG\r\n\x1a\n garbage"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = IsImage(b)
		_, _ = Decode(b)
	})
}
