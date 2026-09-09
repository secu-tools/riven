// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package qrcode

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math"
	mrand "math/rand"
	"testing"
)

// A printed piece is photographed, not scanned: the code arrives rotated, at an
// angle, small in a larger frame, unevenly lit, blurred and JPEG-compressed.
// These tests build those conditions from a real encoded piece and require the
// decoder to read it back exactly.

// photo renders src the way a camera would: pasted into a larger background at
// the given scale, warped by the given corner offsets, lit unevenly, blurred and
// re-encoded as JPEG.
type photo struct {
	scale      float64 // code size relative to the frame
	tiltX      float64 // horizontal perspective, as a fraction of the width
	tiltY      float64 // vertical perspective
	rotation   float64 // degrees
	blur       int     // box blur passes
	lighting   float64 // 0 = even, 1 = one edge in shadow
	jpegQual   int     // 0 keeps PNG
	background bool    // busy background rather than flat
}

// render turns a QR image into a simulated photograph and returns the encoded
// bytes a user would hand to riven.
func (p photo) render(t *testing.T, qr image.Image) []byte {
	t.Helper()
	rng := mrand.New(mrand.NewSource(1))

	qrB := qr.Bounds()
	side := float64(qrB.Dx())
	frameW := int(side / p.scale)
	frameH := int(side / p.scale)
	frame := image.NewRGBA(image.Rect(0, 0, frameW, frameH))

	// Background: flat grey, or a busy pattern the detector has to ignore.
	for y := 0; y < frameH; y++ {
		for x := 0; x < frameW; x++ {
			v := uint8(190)
			if p.background {
				v = uint8(120 + rng.Intn(90))
				if (x/17+y/13)%3 == 0 {
					v = uint8(60 + rng.Intn(60))
				}
			}
			frame.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}

	// Destination corners of the code inside the frame, after tilt and rotation.
	cx, cy := float64(frameW)/2, float64(frameH)/2
	half := side / 2
	corners := [4][2]float64{{-half, -half}, {half, -half}, {half, half}, {-half, half}}
	corners[1][1] += p.tiltY * side
	corners[2][1] -= p.tiltY * side
	corners[2][0] -= p.tiltX * side
	corners[3][0] += p.tiltX * side

	rad := p.rotation * math.Pi / 180
	sin, cos := math.Sin(rad), math.Cos(rad)
	var dst [4][2]float64
	for i, c := range corners {
		dst[i][0] = cx + c[0]*cos - c[1]*sin
		dst[i][1] = cy + c[0]*sin + c[1]*cos
	}

	// Inverse-map every frame pixel that lands inside the quad back to the code.
	inv := invert3(squareToQuad(dst))
	minX, minY, maxX, maxY := dst[0][0], dst[0][1], dst[0][0], dst[0][1]
	for _, d := range dst[1:] {
		minX, maxX = math.Min(minX, d[0]), math.Max(maxX, d[0])
		minY, maxY = math.Min(minY, d[1]), math.Max(maxY, d[1])
	}
	for y := int(minY) - 1; y <= int(maxY)+1; y++ {
		for x := int(minX) - 1; x <= int(maxX)+1; x++ {
			if x < 0 || y < 0 || x >= frameW || y >= frameH {
				continue
			}
			u, v, ok := applyHomography(inv, float64(x)+0.5, float64(y)+0.5)
			if !ok || u < 0 || v < 0 || u >= 1 || v >= 1 {
				continue
			}
			sx := int(u * side)
			sy := int(v * side)
			if sx >= qrB.Dx() {
				sx = qrB.Dx() - 1
			}
			if sy >= qrB.Dy() {
				sy = qrB.Dy() - 1
			}
			frame.Set(x, y, qr.At(qrB.Min.X+sx, qrB.Min.Y+sy))
		}
	}

	out := image.Image(frame)
	if p.lighting > 0 {
		out = applyLighting(frame, p.lighting)
	}
	for i := 0; i < p.blur; i++ {
		out = boxBlur(out)
	}

	var buf bytes.Buffer
	if p.jpegQual > 0 {
		if err := jpeg.Encode(&buf, out, &jpeg.Options{Quality: p.jpegQual}); err != nil {
			t.Fatal(err)
		}
	} else if err := png.Encode(&buf, out); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// invert3 inverts a 3x3 matrix.
func invert3(m [3][3]float64) [3][3]float64 {
	det := m[0][0]*(m[1][1]*m[2][2]-m[1][2]*m[2][1]) -
		m[0][1]*(m[1][0]*m[2][2]-m[1][2]*m[2][0]) +
		m[0][2]*(m[1][0]*m[2][1]-m[1][1]*m[2][0])
	var out [3][3]float64
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			a := m[(j+1)%3][(i+1)%3]*m[(j+2)%3][(i+2)%3] -
				m[(j+1)%3][(i+2)%3]*m[(j+2)%3][(i+1)%3]
			out[i][j] = a / det
		}
	}
	return out
}

// applyLighting darkens one side of the frame, the way a hand or a lamp does.
func applyLighting(src image.Image, strength float64) image.Image {
	b := src.Bounds()
	out := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			f := 1 - strength*float64(x-b.Min.X)/float64(b.Dx())
			r, g, bl, _ := src.At(x, y).RGBA()
			out.Set(x, y, color.RGBA{
				uint8(float64(r>>8) * f),
				uint8(float64(g>>8) * f),
				uint8(float64(bl>>8) * f),
				255,
			})
		}
	}
	return out
}

// boxBlur is one pass of a 3x3 average, standing in for camera softness.
func boxBlur(src image.Image) image.Image {
	b := src.Bounds()
	out := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			var sum, n uint32
			for dy := -1; dy <= 1; dy++ {
				for dx := -1; dx <= 1; dx++ {
					px, py := x+dx, y+dy
					if px < b.Min.X || py < b.Min.Y || px >= b.Max.X || py >= b.Max.Y {
						continue
					}
					r, g, bl, _ := src.At(px, py).RGBA()
					sum += (r>>8 + g>>8 + bl>>8) / 3
					n++
				}
			}
			v := uint8(sum / n)
			out.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}
	return out
}

// TestDecodePhotographs is the guarantee for paper backups: a code that was
// printed and photographed still reads back exactly.
func TestDecodePhotographs(t *testing.T) {
	// A fixed payload keeps the result reproducible: a different symbol changes
	// which cases sit on the edge of readability.
	payload := patternedPayload(400, 7)
	imgBytes, _, err := Encode(payload, 8)
	if err != nil {
		t.Fatal(err)
	}
	qr, _, err := image.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]photo{
		"straight on":        {scale: 0.9},
		"small in frame":     {scale: 0.25, background: true},
		"tiny in frame":      {scale: 0.12, background: true},
		"rotated 15":         {scale: 0.7, rotation: 15},
		"rotated 45":         {scale: 0.6, rotation: 45},
		"upside down":        {scale: 0.8, rotation: 180},
		"slight angle":       {scale: 0.75, tiltX: 0.04, tiltY: 0.03},
		"steep angle":        {scale: 0.7, tiltX: 0.12, tiltY: 0.10},
		"very steep angle":   {scale: 0.65, tiltX: 0.20, tiltY: 0.16},
		"angled and rotated": {scale: 0.6, tiltX: 0.10, tiltY: 0.08, rotation: 20},
		"blurred":            {scale: 0.8, blur: 2},
		"uneven lighting":    {scale: 0.8, lighting: 0.55},
		"jpeg artifacts":     {scale: 0.7, jpegQual: 40},
		"phone photo":        {scale: 0.45, tiltX: 0.08, tiltY: 0.06, rotation: 8, blur: 1, lighting: 0.35, jpegQual: 70, background: true},
		"bad phone photo":    {scale: 0.3, tiltX: 0.14, tiltY: 0.10, rotation: 25, blur: 2, lighting: 0.5, jpegQual: 50, background: true},
	}

	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			data := p.render(t, qr)
			got, err := Decode(data)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("%s: content changed", name)
			}
		})
	}
}

// patternedPayload returns deterministic pseudo-random bytes, so a photo test
// exercises the same symbol on every run.
func patternedPayload(n int, seed int64) []byte {
	r := mrand.New(mrand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
	return b
}

// TestPhotoLimitBySymbolSize pins where photographing stops working, so the
// documentation and the export warning can state it rather than guess.
//
// A larger payload means a larger symbol, and a larger symbol means smaller
// modules in the same photograph. Up to roughly 400 bytes every condition below
// reads; past that, only the extreme angle fails, and past 1500 bytes a poor
// photograph of it fails too.
func TestPhotoLimitBySymbolSize(t *testing.T) {
	straight := photo{scale: 0.9}
	mild := photo{scale: 0.75, tiltX: 0.04, tiltY: 0.03}
	steep := photo{scale: 0.7, tiltX: 0.12, tiltY: 0.10}
	phone := photo{scale: 0.45, tiltX: 0.08, tiltY: 0.06, rotation: 8, blur: 1, lighting: 0.35, jpegQual: 70, background: true}

	for _, size := range []int{100, 400, 900, 1500, 2500} {
		payload := patternedPayload(size, 11)
		imgBytes, _, err := Encode(payload, 8)
		if err != nil {
			t.Fatal(err)
		}
		qr, _, err := image.Decode(bytes.NewReader(imgBytes))
		if err != nil {
			t.Fatal(err)
		}
		// These must hold at every size a piece can reach.
		for name, p := range map[string]photo{
			"straight": straight, "mild angle": mild, "steep angle": steep, "phone photo": phone,
		} {
			got, err := Decode(p.render(t, qr))
			if err != nil {
				t.Fatalf("%d bytes, %s: %v", size, name, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("%d bytes, %s: content changed", size, name)
			}
		}
	}

	// PhotoFriendlyBytes is the size below which even a poor photograph reads.
	worst := photo{scale: 0.3, tiltX: 0.14, tiltY: 0.10, rotation: 25, blur: 2, lighting: 0.5, jpegQual: 50, background: true}
	payload := patternedPayload(PhotoFriendlyBytes, 11)
	imgBytes, _, err := Encode(payload, 8)
	if err != nil {
		t.Fatal(err)
	}
	qr, _, err := image.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(worst.render(t, qr))
	if err != nil {
		t.Fatalf("a %d-byte piece should survive a bad photograph: %v", PhotoFriendlyBytes, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("content changed")
	}
}
