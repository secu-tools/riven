// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package qrcode encodes binary data as a QR code PNG and reads it back.
//
// Data is carried in byte mode, which is the densest mode for arbitrary bytes,
// giving the capacities in Capacities. The error correction level is chosen
// automatically: the strongest level that still fits the data, so small pieces
// get maximum damage tolerance and only near-capacity pieces fall back to the
// weaker levels.
package qrcode

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"  // registered so photographed or converted codes still decode
	_ "image/jpeg" // registered so photographed or converted codes still decode
	"image/png"
	"math"

	"github.com/makiuchi-d/gozxing"
	zxmulti "github.com/makiuchi-d/gozxing/multi/qrcode"
	zxqr "github.com/makiuchi-d/gozxing/qrcode"
	"github.com/makiuchi-d/gozxing/qrcode/decoder"
	zxdet "github.com/makiuchi-d/gozxing/qrcode/detector"
)

// PhotoFriendlyBytes is the payload size below which a printed code still reads
// from a poor photograph: small, steeply angled, rotated, blurred and shadowed.
// A larger symbol has smaller modules and needs a flatter, sharper shot. The
// figure is measured by the package tests.
const PhotoFriendlyBytes = 400

// Level identifies a QR error correction level.
type Level struct {
	Name     string // "L", "M", "Q", "H"
	Recovery int    // approximate recoverable damage, percent
	Capacity int    // maximum byte-mode payload at QR version 40
	ecc      decoder.ErrorCorrectionLevel
}

// Capacities lists the levels from strongest correction to largest capacity.
// The capacity values are the byte-mode maxima at version 40 and are verified
// against the encoder by the package tests.
var Capacities = []Level{
	{Name: "H", Recovery: 30, Capacity: 1272, ecc: decoder.ErrorCorrectionLevel_H},
	{Name: "Q", Recovery: 25, Capacity: 1662, ecc: decoder.ErrorCorrectionLevel_Q},
	{Name: "M", Recovery: 15, Capacity: 2330, ecc: decoder.ErrorCorrectionLevel_M},
	{Name: "L", Recovery: 7, Capacity: 2952, ecc: decoder.ErrorCorrectionLevel_L},
}

// MaxBytes is the largest payload any QR code can carry, reached only at the
// weakest error correction level.
var MaxBytes = Capacities[len(Capacities)-1].Capacity

// DefaultScale is the pixel size of one QR module in the written image. Eight
// pixels keeps a full-size code legible when printed at normal page sizes.
const DefaultScale = 8

// quietZone is the mandatory light border, in modules, required by the spec.
const quietZone = 4

// ErrTooLarge indicates the payload exceeds even the weakest level's capacity.
var ErrTooLarge = errors.New("qrcode: data too large for a QR code")

// Fits reports whether n bytes can be encoded at all.
func Fits(n int) bool { return n > 0 && n <= MaxBytes }

// SelectLevel returns the strongest error correction level that fits n bytes.
func SelectLevel(n int) (Level, error) {
	if n <= 0 {
		return Level{}, errors.New("qrcode: no data to encode")
	}
	for _, l := range Capacities {
		if n <= l.Capacity {
			return l, nil
		}
	}
	return Level{}, fmt.Errorf("%w: %d bytes exceeds the %d byte maximum", ErrTooLarge, n, MaxBytes)
}

// Weakest reports whether l is the lowest error correction level, which is worth
// warning about for printed codes.
func (l Level) Weakest() bool { return l.Name == Capacities[len(Capacities)-1].Name }

// Encode renders data as a QR code PNG. scale is the pixel size of one module;
// values below one use DefaultScale. It returns the PNG bytes and the level used.
func Encode(data []byte, scale int) ([]byte, Level, error) {
	level, err := SelectLevel(len(data))
	if err != nil {
		return nil, Level{}, err
	}
	if scale < 1 {
		scale = DefaultScale
	}

	matrix, err := zxqr.NewQRCodeWriter().Encode(
		toLatin1(data), gozxing.BarcodeFormat_QR_CODE, 1, 1,
		map[gozxing.EncodeHintType]interface{}{
			gozxing.EncodeHintType_ERROR_CORRECTION: level.ecc,
			gozxing.EncodeHintType_CHARACTER_SET:    latin1,
			gozxing.EncodeHintType_MARGIN:           quietZone,
		})
	if err != nil {
		return nil, Level{}, fmt.Errorf("qrcode: encode failed: %w", err)
	}

	w, h := matrix.GetWidth(), matrix.GetHeight()
	if w <= 0 || h <= 0 {
		return nil, Level{}, errors.New("qrcode: encoder produced an empty matrix")
	}
	img := image.NewGray(image.Rect(0, 0, w*scale, h*scale))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.Gray{Y: 0xFF}), image.Point{}, draw.Src)
	for my := 0; my < h; my++ {
		for mx := 0; mx < w; mx++ {
			if !matrix.Get(mx, my) {
				continue
			}
			r := image.Rect(mx*scale, my*scale, (mx+1)*scale, (my+1)*scale)
			draw.Draw(img, r, image.NewUniform(color.Gray{Y: 0x00}), image.Point{}, draw.Src)
		}
	}

	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, Level{}, err
	}
	return buf.Bytes(), level, nil
}

// Decode reads the payload from a QR code image. PNG, JPEG, and GIF inputs are
// accepted, so a photograph of a printed piece works as well as the file this
// package wrote.
//
// A photographed code arrives rotated, at an angle, small in a larger frame and
// unevenly lit, and no single reader configuration handles all of that. Decode
// therefore tries a series of them, cheapest first, and stops at the first that
// reads. The order matters only for speed: every attempt is exact, since a QR
// code carries its own error correction and checksum.
func Decode(imageBytes []byte) ([]byte, error) {
	if err := checkImageSize(imageBytes); err != nil {
		return nil, err
	}
	img, _, err := image.Decode(bytes.NewReader(imageBytes))
	if err != nil {
		return nil, fmt.Errorf("qrcode: not a readable image: %w", err)
	}

	attempts := append(append([]decodeAttempt{}, decodeAttempts...), finderAttempts()...)
	attempts = append(attempts, blindAttempts()...)
	var lastErr error
	for _, candidate := range decodeCandidates(img) {
		for _, attempt := range attempts {
			text, err := attempt(candidate)
			if err != nil {
				lastErr = err
				continue
			}
			return fromLatin1(text)
		}
	}
	return nil, fmt.Errorf("qrcode: no QR code found in image: %w", lastErr)
}

// decodeCandidates returns the images to try, in order. A photograph is often
// far larger than it needs to be, and a very large frame is both slow to search
// and no more readable, so a downscaled copy is tried first; the original
// follows in case the reduction cost the code its detail.
func decodeCandidates(img image.Image) []image.Image {
	const maxSide = 1600
	b := img.Bounds()
	side := b.Dx()
	if b.Dy() > side {
		side = b.Dy()
	}
	if side <= maxSide {
		return []image.Image{img}
	}
	// Past a few times maxSide the original is no longer worth retrying: every
	// attempt resamples it in full, so the cost grows with the pixel count while
	// the detail the downscale lost does not come back. Bounding it keeps a large
	// image that holds no code from costing minutes of CPU.
	if side > 4*maxSide {
		return []image.Image{downscale(img, maxSide)}
	}
	return []image.Image{downscale(img, maxSide), img}
}

// decodeAttempt reads a QR code from an image, or fails.
type decodeAttempt func(image.Image) (string, error)

// decodeAttempts are ordered cheapest and most likely first:
//
//  1. pure barcode, which is exact for an unmodified file this package wrote;
//  2. the full detector, which models rotation and perspective;
//  3. the same with a global-histogram binarizer, which copes better with the
//     even lighting of a scan than the adaptive one;
//  4. the multi-code detector, whose search finds finder patterns the single
//     detector misses on a steeply angled photograph;
//  5. inverted, for a code printed light on dark.
var decodeAttempts = []decodeAttempt{
	func(img image.Image) (string, error) {
		return readQR(img, false, false, map[gozxing.DecodeHintType]interface{}{
			gozxing.DecodeHintType_CHARACTER_SET: latin1,
			gozxing.DecodeHintType_PURE_BARCODE:  true,
			gozxing.DecodeHintType_TRY_HARDER:    true,
		})
	},
	func(img image.Image) (string, error) { return readQR(img, false, false, tryHarder()) },
	func(img image.Image) (string, error) { return readQR(img, true, false, tryHarder()) },
	func(img image.Image) (string, error) { return readQR(img, false, true, tryHarder()) },
	func(img image.Image) (string, error) { return readQR(img, true, true, tryHarder()) },
	func(img image.Image) (string, error) { return readQR(invert(img), false, false, tryHarder()) },
	func(img image.Image) (string, error) { return readQR(invert(img), false, true, tryHarder()) },
}

func tryHarder() map[gozxing.DecodeHintType]interface{} {
	return map[gozxing.DecodeHintType]interface{}{
		gozxing.DecodeHintType_CHARACTER_SET: latin1,
		gozxing.DecodeHintType_TRY_HARDER:    true,
	}
}

// readQR runs one reader over one image. A fresh bitmap is built per call
// because the binarizer caches per-row state.
func readQR(img image.Image, globalHistogram, multi bool, hints map[gozxing.DecodeHintType]interface{}) (string, error) {
	src := gozxing.NewLuminanceSourceFromImage(img)
	var bmp *gozxing.BinaryBitmap
	var err error
	if globalHistogram {
		bmp, err = gozxing.NewBinaryBitmap(gozxing.NewGlobalHistgramBinarizer(src))
	} else {
		bmp, err = gozxing.NewBinaryBitmap(gozxing.NewHybridBinarizer(src))
	}
	if err != nil {
		return "", err
	}

	if multi {
		results, err := zxmulti.NewQRCodeMultiReader().DecodeMultiple(bmp, hints)
		if err != nil {
			return "", err
		}
		if len(results) == 0 {
			return "", errors.New("qrcode: no code found")
		}
		return results[0].GetText(), nil
	}
	res, err := zxqr.NewQRCodeReader().Decode(bmp, hints)
	if err != nil {
		return "", err
	}
	return res.GetText(), nil
}

// downscale reduces an image so its longest side is at most maxSide, averaging
// the pixels that collapse together so module edges stay meaningful.
// toGray reduces a colour to an 8-bit grey level by averaging its channels.
func toGray(c color.Color) uint8 {
	r, g, b, _ := c.RGBA()
	return uint8((r + g + b) / 3 >> 8)
}

func downscale(src image.Image, maxSide int) image.Image {
	b := src.Bounds()
	side := b.Dx()
	if b.Dy() > side {
		side = b.Dy()
	}
	step := (side + maxSide - 1) / maxSide
	if step < 2 {
		return src
	}
	out := image.NewGray(image.Rect(0, 0, (b.Dx()+step-1)/step, (b.Dy()+step-1)/step))
	for y := out.Bounds().Min.Y; y < out.Bounds().Max.Y; y++ {
		for x := out.Bounds().Min.X; x < out.Bounds().Max.X; x++ {
			var sum, n uint32
			for dy := 0; dy < step; dy++ {
				for dx := 0; dx < step; dx++ {
					sx, sy := b.Min.X+x*step+dx, b.Min.Y+y*step+dy
					if sx >= b.Max.X || sy >= b.Max.Y {
						continue
					}
					sum += uint32(toGray(src.At(sx, sy)))
					n++
				}
			}
			if n > 0 {
				out.SetGray(x, y, color.Gray{Y: uint8(sum / n)})
			}
		}
	}
	return out
}

// invert flips light and dark, for a code printed as white on black.
func invert(src image.Image) image.Image {
	b := src.Bounds()
	out := image.NewGray(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			out.SetGray(x, y, color.Gray{Y: 255 - toGray(src.At(x, y))})
		}
	}
	return out
}

// Image size limits.
//
// An image decodes to width*height*4 bytes before any pixel data is read, so the
// header alone decides the allocation: a 72-byte PNG claiming 23000x23000 asks
// for 2.1 GB, and a larger claim is a fatal out-of-memory rather than an error
// that can be reported. The budget bounds that at about 340 MB.
//
// 80 megapixels is above any current camera and above the largest frame the
// photograph tests read a code out of, so it costs no real capability; the
// per-side cap catches an extreme aspect ratio that stays under the pixel
// budget.
const (
	maxImagePixels = 80 << 20
	maxImageSide   = 20000
)

// checkImageSize rejects an image whose header declares more pixels than the
// budget allows, before image.Decode allocates for them.
func checkImageSize(b []byte) error {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("qrcode: not a readable image: %w", err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return fmt.Errorf("qrcode: image declares an empty size (%dx%d)", cfg.Width, cfg.Height)
	}
	if cfg.Width > maxImageSide || cfg.Height > maxImageSide ||
		int64(cfg.Width)*int64(cfg.Height) > maxImagePixels {
		return fmt.Errorf("qrcode: image is %dx%d, larger than this reads (limit %d megapixels, %d per side)",
			cfg.Width, cfg.Height, maxImagePixels>>20, maxImageSide)
	}
	return nil
}

// IsImage reports whether b looks like an image this package can read. It only
// inspects the header, so it is cheap and safe on hostile input. An image too
// large to decode within the budget is not one this package can read.
func IsImage(b []byte) bool {
	return checkImageSize(b) == nil
}

// latin1 maps each byte to one code point, which is how byte-mode payloads are
// passed through the encoder's text interface without transformation.
const latin1 = "ISO-8859-1"

func toLatin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func fromLatin1(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xFF {
			return nil, fmt.Errorf("qrcode: decoded content is not binary data (code point %U)", r)
		}
		out = append(out, byte(r))
	}
	return out, nil
}

// applyHomography maps a point through a row-vector homography.
func applyHomography(m [3][3]float64, x, y float64) (float64, float64, bool) {
	w := x*m[0][2] + y*m[1][2] + m[2][2]
	if w == 0 {
		return 0, 0, false
	}
	return (x*m[0][0] + y*m[1][0] + m[2][0]) / w,
		(x*m[0][1] + y*m[1][1] + m[2][1]) / w, true
}

// rectifyByFinders resamples the code onto a square using its three finder
// patterns, undoing the rotation and the perspective of a photograph before the
// detector runs.
//
// The finder patterns are the most robust part of a QR code to locate: they are
// found by scanning rows for a 1:1:3:1:1 run, which survives rotation and a fair
// amount of perspective. Their centres fix three corners of the symbol, and the
// module size measured at each one gives the missing fourth constraint: under a
// projective map the local scale falls off as the perspective divisor grows, so
// a finder that reads smaller is simply farther away. That yields a full
// homography rather than an affine fit, which is what a steeply angled photo
// needs.
//
// scale nudges the estimated perspective, since the measured module sizes carry
// some noise; 1 uses the estimate as measured.
//
// The symbol dimension is deliberately not estimated. The module size read off a
// tilted photograph is unreliable, and a wrong dimension resamples onto the
// wrong grid; placing the three centres at fixed fractions leaves the module
// size for the detector to work out, as on any other image.
func rectifyByFinders(img image.Image, scale float64) (image.Image, error) {
	src := gozxing.NewLuminanceSourceFromImage(img)
	bmp, err := gozxing.NewBinaryBitmap(gozxing.NewHybridBinarizer(src))
	if err != nil {
		return nil, err
	}
	matrix, err := bmp.GetBlackMatrix()
	if err != nil {
		return nil, err
	}
	info, err := zxdet.NewFinderPatternFinder(matrix, nil).Find(tryHarder())
	if err != nil {
		return nil, err
	}
	tl, tr, bl := info.GetTopLeft(), info.GetTopRight(), info.GetBottomLeft()

	span := math.Max(
		math.Hypot(tr.GetX()-tl.GetX(), tr.GetY()-tl.GetY()),
		math.Hypot(bl.GetX()-tl.GetX(), bl.GetY()-tl.GetY()))
	if span < 20 {
		return nil, errors.New("qrcode: the finder patterns are too close together to rectify")
	}
	side := int(math.Min(2400, math.Max(600, span*1.4)))

	// Perspective divisors at the two far corners, from how much smaller their
	// modules read. Clamped so a bad measurement cannot invert the map.
	a13 := clampPerspective(tl.GetEstimatedModuleSize()/tr.GetEstimatedModuleSize()-1) * scale
	a23 := clampPerspective(tl.GetEstimatedModuleSize()/bl.GetEstimatedModuleSize()-1) * scale

	m := [3][3]float64{
		{tr.GetX()*(1+a13) - tl.GetX(), tr.GetY()*(1+a13) - tl.GetY(), a13},
		{bl.GetX()*(1+a23) - tl.GetX(), bl.GetY()*(1+a23) - tl.GetY(), a23},
		{tl.GetX(), tl.GetY(), 1},
	}

	// The three centres land at these fractions of the output, leaving room for
	// the rest of the symbol and a quiet zone.
	const lo, hi = 0.14, 0.86
	origin := float64(side) * lo
	unit := float64(side) * (hi - lo)

	b := img.Bounds()
	out := image.NewGray(image.Rect(0, 0, side, side))
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			u := (float64(x) - origin) / unit
			v := (float64(y) - origin) / unit
			sx, sy, ok := applyHomography(m, u, v)
			if !ok {
				continue
			}
			ix, iy := b.Min.X+int(sx), b.Min.Y+int(sy)
			if sx < 0 || sy < 0 || ix >= b.Max.X || iy >= b.Max.Y {
				out.SetGray(x, y, color.Gray{Y: 255}) // quiet zone
				continue
			}
			out.SetGray(x, y, color.Gray{Y: toGray(img.At(ix, iy))})
		}
	}
	return out, nil
}

// clampPerspective bounds the estimated divisor to what a readable photograph
// can produce, so a mismeasured finder cannot fold the image.
func clampPerspective(v float64) float64 {
	const limit = 0.6
	if v > limit {
		return limit
	}
	if v < -limit {
		return -limit
	}
	return v
}

// finderAttempts rectify by the finder patterns, then read the square that
// produces. The measured module sizes are quantised by the scan that produced
// them, so the perspective estimate is swept either side of the measurement
// rather than trusted exactly.
func finderAttempts() []decodeAttempt {
	var out []decodeAttempt
	for _, scale := range []float64{1, 0.75, 1.3, 0.5, 1.7, 0.25, 2.2} {
		s := scale
		out = append(out, func(img image.Image) (string, error) {
			r, err := rectifyByFinders(img, s)
			if err != nil {
				return "", err
			}
			return readQR(r, false, false, tryHarder())
		})
	}
	return out
}

// tiltCandidates are blind counter-warps, tried when everything derived from the
// image has failed. They cover the case where the finder patterns were located
// but their measured module sizes were too noisy to give a usable perspective.
// The values are fractions of the frame width, up to roughly 40 degrees off
// perpendicular in either axis.
var tiltCandidates = [][2]float64{
	{0.12, 0}, {-0.12, 0}, {0, 0.12}, {0, -0.12},
	{0.12, 0.10}, {-0.12, -0.10}, {0.12, -0.10}, {-0.12, 0.10},
	{0.20, 0.16}, {-0.20, -0.16}, {0.20, -0.16}, {-0.20, 0.16},
}

// blindAttempts returns one attempt per counter-warp. They run last: each
// resamples the whole image, and they are a guess rather than a measurement.
func blindAttempts() []decodeAttempt {
	out := make([]decodeAttempt, 0, len(tiltCandidates))
	for _, t := range tiltCandidates {
		tx, ty := t[0], t[1]
		out = append(out, func(img image.Image) (string, error) {
			return readQR(unTilt(img, tx, ty), false, false, tryHarder())
		})
	}
	return out
}

// unTilt resamples an image as though it were photographed with the given tilt,
// which cancels a tilt of the same size in the original.
func unTilt(src image.Image, tiltX, tiltY float64) image.Image {
	b := src.Bounds()
	w, h := float64(b.Dx()), float64(b.Dy())

	quad := [4][2]float64{{0, 0}, {w, 0}, {w, h}, {0, h}}
	quad[1][1] += tiltY * h
	quad[2][1] -= tiltY * h
	quad[2][0] -= tiltX * w
	quad[3][0] += tiltX * w
	m := squareToQuad(quad)

	out := image.NewGray(image.Rect(0, 0, b.Dx(), b.Dy()))
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			sx, sy, ok := applyHomography(m, (float64(x)+0.5)/w, (float64(y)+0.5)/h)
			if !ok {
				continue
			}
			ix, iy := b.Min.X+int(sx), b.Min.Y+int(sy)
			if ix < b.Min.X || iy < b.Min.Y || ix >= b.Max.X || iy >= b.Max.Y {
				out.SetGray(x, y, color.Gray{Y: 255})
				continue
			}
			out.SetGray(x, y, color.Gray{Y: toGray(src.At(ix, iy))})
		}
	}
	return out
}

// squareToQuad returns the homography mapping the unit square onto quad, in
// row-vector form: [u v 1] * M = [x' y' w].
func squareToQuad(q [4][2]float64) [3][3]float64 {
	x0, y0 := q[0][0], q[0][1]
	x1, y1 := q[1][0], q[1][1]
	x2, y2 := q[2][0], q[2][1]
	x3, y3 := q[3][0], q[3][1]

	dx1, dx2, dx3 := x1-x2, x3-x2, x0-x1+x2-x3
	dy1, dy2, dy3 := y1-y2, y3-y2, y0-y1+y2-y3

	var a13, a23 float64
	if dx3 != 0 || dy3 != 0 {
		if den := dx1*dy2 - dy1*dx2; den != 0 {
			a13 = (dx3*dy2 - dy3*dx2) / den
			a23 = (dx1*dy3 - dy1*dx3) / den
		}
	}
	return [3][3]float64{
		{x1 - x0 + a13*x1, y1 - y0 + a13*y1, a13},
		{x3 - x0 + a23*x3, y3 - y0 + a23*y3, a23},
		{x0, y0, 1},
	}
}
