// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package qrcode

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/png"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// pngHeaderOnly builds a valid PNG header declaring w x h with a token IDAT.
// The pixel data is nowhere near complete, which is the point: image.Decode
// allocates width*height*4 from the header alone, before it reads any of it.
func pngHeaderOnly(w, h uint32) []byte {
	chunk := func(typ string, data []byte) []byte {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint32(len(data)))
		b.WriteString(typ)
		b.Write(data)
		c := crc32.NewIEEE()
		c.Write([]byte(typ))
		c.Write(data)
		binary.Write(&b, binary.BigEndian, c.Sum32())
		return b.Bytes()
	}
	var out bytes.Buffer
	out.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	ihdr := new(bytes.Buffer)
	binary.Write(ihdr, binary.BigEndian, w)
	binary.Write(ihdr, binary.BigEndian, h)
	ihdr.Write([]byte{8, 6, 0, 0, 0}) // 8-bit RGBA
	out.Write(chunk("IHDR", ihdr.Bytes()))
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(make([]byte, 64))
	zw.Close()
	out.Write(chunk("IDAT", z.Bytes()))
	out.Write(chunk("IEND", nil))
	return out.Bytes()
}

// A piece can arrive as an image from anywhere, and the decoded size follows
// from the header rather than the file size. A 72-byte file claiming 23000
// square asks for 2.1 GB; at 65535 square it is 17 GB, which is a fatal
// out-of-memory rather than an error that can be reported. The header has to be
// checked before the decoder allocates for it.
func TestOversizeImageIsRejectedBeforeDecoding(t *testing.T) {
	for _, side := range []uint32{23000, 65535} {
		b := pngHeaderOnly(side, side)
		if len(b) > 512 {
			t.Fatalf("test input is %d bytes, expected a tiny header", len(b))
		}
		if IsImage(b) {
			t.Errorf("IsImage accepted a %dx%d image", side, side)
		}
		if _, err := Decode(b); err == nil {
			t.Errorf("Decode accepted a %dx%d image", side, side)
		}
	}
}

// The limit must not cost a real photograph: the frames the photo tests read a
// code out of are well inside it.
func TestPlausiblePhotoSizesAreAccepted(t *testing.T) {
	for _, dim := range [][2]uint32{{4000, 3000}, {8000, 6000}, {7266, 7266}} {
		if _, err := checkImageSize(pngHeaderOnly(dim[0], dim[1])); err != nil {
			t.Errorf("checkImageSize rejected %dx%d: %v", dim[0], dim[1], err)
		}
	}
}

// TestImagesDecodedAtOnceStayWithinTheBudget checks the gate Decode goes
// through: however many images are read together, the pixels under way never
// pass the budget for one, an image as large as the budget runs alone, and
// every one still gets its turn.
func TestImagesDecodedAtOnceStayWithinTheBudget(t *testing.T) {
	const budget = 10
	g := newPixelGate(budget)
	var mu sync.Mutex
	under, worst, alone, done := int64(0), int64(0), true, 0
	var wg sync.WaitGroup
	for i := range 60 {
		n := int64(i%4 + 1)
		if i%15 == 0 {
			n = budget
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			release := g.acquire(n)
			mu.Lock()
			under += n
			worst = max(worst, under)
			if n == budget && under != budget {
				alone = false
			}
			mu.Unlock()
			runtime.Gosched()
			mu.Lock()
			under -= n
			done++
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()
	if worst > budget || !alone {
		t.Fatalf("%d pixels under way at once against a budget of %d (largest alone: %v)", worst, budget, alone)
	}
	if done != 60 || g.free != budget {
		t.Fatalf("%d of 60 decodes ran, and %d of %d of the budget came back", done, g.free, budget)
	}
}

// TestDecodeReturnsItsShareOfTheBudget checks Decode gives back what it took
// whether it read a code, found none, or was handed something that is no image,
// so one bad file cannot leave later ones waiting for good.
func TestDecodeReturnsItsShareOfTheBudget(t *testing.T) {
	code, _, err := Encode([]byte("a code that reads"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(code); err != nil {
		t.Fatal(err)
	}
	blank := image.NewGray(image.Rect(0, 0, 64, 64))
	var noCode bytes.Buffer
	if err := png.Encode(&noCode, blank); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(noCode.Bytes()); err == nil {
		t.Fatal("a blank image read as a code")
	}
	if _, err := Decode(pngHeaderOnly(64, 64)); err == nil {
		t.Fatal("a truncated image read as a code")
	}
	if _, err := Decode([]byte("not an image")); err == nil {
		t.Fatal("text read as a code")
	}
	if decoding.free != maxImagePixels {
		t.Fatalf("%d of the %d pixel budget came back", decoding.free, int64(maxImagePixels))
	}
}

// TestEveryScaleWrittenReadsBack checks the largest code at MaxScale is an
// image Decode takes and one module more is not, so no scale Encode accepts
// writes a code that cannot be read back; that the largest code is maxModules
// wide, as MaxScale assumes; and that Encode refuses a scale past it. The sizes
// are checked from the header alone, so no image that large is drawn.
func TestEveryScaleWrittenReadsBack(t *testing.T) {
	code, _, err := Encode(make([]byte, MaxBytes), 1)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(code))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Width != maxModules || cfg.Height != maxModules {
		t.Fatalf("the largest code is %dx%d modules, MaxScale assumes %d", cfg.Width, cfg.Height, maxModules)
	}
	side := uint32(maxModules * MaxScale)
	if _, err := checkImageSize(pngHeaderOnly(side, side)); err != nil {
		t.Fatalf("the largest code at MaxScale (%d) would not read back: %v", MaxScale, err)
	}
	side = uint32(maxModules * (MaxScale + 1))
	if _, err := checkImageSize(pngHeaderOnly(side, side)); err == nil {
		t.Fatalf("MaxScale (%d) is not the largest: one more still reads back", MaxScale)
	}
	if _, _, err := Encode([]byte("small"), MaxScale+1); err == nil || !strings.Contains(err.Error(), "too large to read back") {
		t.Fatalf("a scale past MaxScale was taken: %v", err)
	}
	if _, _, err := Encode([]byte("small"), MaxScale); err != nil {
		t.Fatalf("MaxScale was refused: %v", err)
	}
}

// An empty or absurdly shaped image is rejected too.
func TestDegenerateImageSizes(t *testing.T) {
	if _, err := checkImageSize(pngHeaderOnly(0, 100)); err == nil {
		t.Error("a zero-width image was accepted")
	}
	// Under the pixel budget, but far past the per-side cap.
	if _, err := checkImageSize(pngHeaderOnly(100000, 2)); err == nil {
		t.Error("a 100000-wide image was accepted")
	}
}

// TestAnImageOfNoSizeIsNotOne checks a header declaring no pixels at all is
// turned away by name. PNG's own parser refuses one, but a GIF's screen
// descriptor may say 0x0, and the budget check reads it before any decoder
// does.
func TestAnImageOfNoSizeIsNotOne(t *testing.T) {
	// GIF89a, a 0x0 logical screen, no colour table, then the trailer.
	empty := append([]byte("GIF89a"), 0, 0, 0, 0, 0, 0, 0, 0x3b)
	if IsImage(empty) {
		t.Fatal("a 0x0 image was taken for one")
	}
	if _, err := Decode(empty); err == nil || !strings.Contains(err.Error(), "empty size") {
		t.Fatalf("got %v", err)
	}
}

// TestDecodedTextMustBeBytes checks content read out of a code is refused when
// it holds a character no byte stands for, since this package only ever writes
// one byte per character.
func TestDecodedTextMustBeBytes(t *testing.T) {
	if _, err := fromLatin1("ok" + string(rune(0x100))); err == nil {
		t.Fatal("a character past 0xFF was read as a byte")
	}
	if b, err := fromLatin1(string(rune(0xff))); err != nil || len(b) != 1 || b[0] != 0xff {
		t.Fatalf("0xFF read as %v, %v", b, err)
	}
}
