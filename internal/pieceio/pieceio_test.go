// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package pieceio

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/format"
)

// randomPiece returns bytes shaped like a real piece: uniformly random and at
// least the minimum piece length.
func randomPiece(n int) []byte {
	if n < format.MinPieceLen {
		n = format.MinPieceLen
	}
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestParseFormats(t *testing.T) {
	cases := map[string][]Format{
		"":              {Binary},
		"binary":        {Binary},
		"bin":           {Binary},
		"base64":        {Base64},
		"b64":           {Base64},
		"qr":            {QR},
		"png":           {QR},
		"all":           All(),
		"binary,qr":     {Binary, QR},
		"QR , Base64":   {QR, Base64},
		"qr,qr":         {QR},
		"binary,b64,qr": {Binary, Base64, QR},
	}
	for spec, want := range cases {
		got, err := ParseFormats(spec)
		if err != nil {
			t.Fatalf("%q: %v", spec, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%q: got %v, want %v", spec, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%q: got %v, want %v", spec, got, want)
			}
		}
	}
	for _, bad := range []string{"pdf", "binary,pdf", ","} {
		if _, err := ParseFormats(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

// TestRoundTripEveryFormat is the core guarantee: whatever we write, Decode must
// return the exact piece and identify the format.
func TestRoundTripEveryFormat(t *testing.T) {
	for _, size := range []int{format.MinPieceLen, 200, 1000, QRMaxBytes} {
		piece := randomPiece(size)
		for _, f := range Encodable() {
			data, _, err := Encode(piece, f, 4)
			if err != nil {
				t.Fatalf("%s %d bytes: encode: %v", f, size, err)
			}
			got, detected, err := Decode(data)
			if err != nil {
				t.Fatalf("%s %d bytes: decode: %v", f, size, err)
			}
			if detected != f {
				t.Fatalf("%s %d bytes: detected as %s", f, size, detected)
			}
			if !bytes.Equal(got, piece) {
				t.Fatalf("%s %d bytes: content mismatch", f, size)
			}
		}
	}
}

// TestBinaryNotMisreadAsBase64 checks the detection ordering on many random
// pieces: raw binary must never be mistaken for base64 text.
func TestBinaryNotMisreadAsBase64(t *testing.T) {
	for i := 0; i < 300; i++ {
		piece := randomPiece(60 + i)
		got, detected, err := Decode(piece)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if detected != Binary {
			t.Fatalf("iteration %d: random binary detected as %s", i, detected)
		}
		if !bytes.Equal(got, piece) {
			t.Fatalf("iteration %d: content changed", i)
		}
	}
}

// TestBase64Tolerance checks that base64 input survives the mangling that
// messengers and copy-paste introduce.
func TestBase64Tolerance(t *testing.T) {
	piece := randomPiece(300)
	data, _, err := Encode(piece, Base64, 0)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)

	variants := map[string]string{
		"as-written":     text,
		"no-newlines":    strings.ReplaceAll(text, "\n", ""),
		"crlf":           strings.ReplaceAll(text, "\n", "\r\n"),
		"leading-space":  "   \n" + text,
		"trailing-space": text + "\n\n  \t\n",
		"spaces-inside":  strings.ReplaceAll(text, "\n", " \n "),
	}
	for name, v := range variants {
		got, detected, err := Decode([]byte(v))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if detected != Base64 {
			t.Fatalf("%s: detected as %s", name, detected)
		}
		if !bytes.Equal(got, piece) {
			t.Fatalf("%s: content mismatch", name)
		}
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":     {},
		"tiny":      []byte("hi"),
		"short-b64": []byte("aGVsbG8="), // valid base64, too short to be a piece
	} {
		if _, _, err := Decode(in); err == nil {
			t.Fatalf("%s should be rejected", name)
		}
	}
}

func TestPathExtensions(t *testing.T) {
	dir := filepath.Join("out", "pieces")
	if got := Path(dir, "f.1", Binary); got != filepath.Join(dir, "f.1") {
		t.Fatalf("binary path %q", got)
	}
	if got := Path(dir, "f.1", Base64); got != filepath.Join(dir, "f.1.txt") {
		t.Fatalf("base64 path %q", got)
	}
	if got := Path(dir, "f.1", QR); got != filepath.Join(dir, "f.1.png") {
		t.Fatalf("qr path %q", got)
	}
}

func TestQRLimits(t *testing.T) {
	if !QRFits(QRMaxBytes) {
		t.Fatal("max size should fit")
	}
	if QRFits(QRMaxBytes + 1) {
		t.Fatal("over max should not fit")
	}
	if _, _, err := Encode(randomPiece(QRMaxBytes+1), QR, 4); err == nil {
		t.Fatal("over-capacity QR should fail")
	}
}

// TestQRTooLargeMessage checks the compression hint appears only when it could
// plausibly help.
func TestQRTooLargeMessage(t *testing.T) {
	near := QRTooLargeMessage(QRMaxBytes + 100)
	if !strings.Contains(near, "Compress") {
		t.Fatalf("near-limit message should suggest compression: %q", near)
	}
	huge := QRTooLargeMessage(5 << 30)
	if strings.Contains(huge, "Compress") {
		t.Fatalf("multi-gigabyte message should not suggest compression: %q", huge)
	}
}

// TestQRNoteMentionsLevel checks the encoder reports the chosen protection and
// warns only at the weakest level.
func TestQRNoteMentionsLevel(t *testing.T) {
	small := randomPiece(200)
	_, note, err := Encode(small, QR, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "error correction H") {
		t.Fatalf("small piece should use level H: %q", note)
	}
	if strings.Contains(note, "print at high quality") {
		t.Fatalf("strong level should not warn: %q", note)
	}
	big := randomPiece(QRMaxBytes)
	_, note, err = Encode(big, QR, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "error correction L") || !strings.Contains(note, "print at high quality") {
		t.Fatalf("near-capacity piece should warn: %q", note)
	}
}

func TestLoadAndWrite(t *testing.T) {
	dir := t.TempDir()
	piece := randomPiece(250)
	for _, f := range Encodable() {
		data, _, err := Encode(piece, f, 4)
		if err != nil {
			t.Fatal(err)
		}
		path := Path(dir, "piece.1", f)
		if err := Write(path, data); err != nil {
			t.Fatal(err)
		}
		got, det, err := Load(path)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if det.Format != f || det.Path != path {
			t.Fatalf("%s: bad detection %+v", f, det)
		}
		if !bytes.Equal(got, piece) {
			t.Fatalf("%s: content mismatch", f)
		}
	}
	if _, _, err := Load(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file should fail")
	}
}

// TestEncodeDoesNotAliasInput makes sure the caller's piece is never handed out
// or mutated, since callers wipe their buffers.
func TestEncodeDoesNotAliasInput(t *testing.T) {
	piece := randomPiece(120)
	original := append([]byte(nil), piece...)
	data, _, err := Encode(piece, Binary, 0)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 0xFF
	if !bytes.Equal(piece, original) {
		t.Fatal("Encode returned a slice aliasing its input")
	}
}

func TestWritePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows does not implement POSIX mode bits; access is governed by
		// inherited ACLs, so the reported permissions are not meaningful.
		t.Skip("mode bits are not enforced on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "p")
	if err := Write(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("piece should not be group or world readable: %v", fi.Mode().Perm())
	}
}

// FuzzDecode ensures arbitrary stored bytes never panic.
func FuzzDecode(f *testing.F) {
	f.Add(randomPiece(80))
	f.Add([]byte("QUJDRA=="))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = Decode(b)
	})
}
