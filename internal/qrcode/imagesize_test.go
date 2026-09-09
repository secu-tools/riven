// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package qrcode

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
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
		if err := checkImageSize(pngHeaderOnly(dim[0], dim[1])); err != nil {
			t.Errorf("checkImageSize rejected %dx%d: %v", dim[0], dim[1], err)
		}
	}
}

// An empty or absurdly shaped image is rejected too.
func TestDegenerateImageSizes(t *testing.T) {
	if err := checkImageSize(pngHeaderOnly(0, 100)); err == nil {
		t.Error("a zero-width image was accepted")
	}
	// Under the pixel budget, but far past the per-side cap.
	if err := checkImageSize(pngHeaderOnly(100000, 2)); err == nil {
		t.Error("a 100000-wide image was accepted")
	}
}
