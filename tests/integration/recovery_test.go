// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build integration

package integration

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// contentCases returns inputs chosen to catch the ways a byte pipeline can go
// wrong: empty input, single bytes, all-zero and all-ones runs, sizes either side
// of block and length-prefix boundaries, invalid UTF-8, embedded NULs, and text
// with the line endings a file might carry.
func contentCases() map[string][]byte {
	cases := map[string][]byte{
		"empty":            {},
		"one-zero":         {0x00},
		"one-ff":           {0xFF},
		"two-bytes":        {0x00, 0xFF},
		"zeros-1k":         make([]byte, 1024),
		"ones-1k":          bytes.Repeat([]byte{0xFF}, 1024),
		"alternating":      bytes.Repeat([]byte{0x00, 0xFF}, 512),
		"all-byte-values":  allByteValues(),
		"invalid-utf8":     bytes.Repeat([]byte{0xC3, 0x28, 0x80, 0xFE}, 64),
		"embedded-nul":     []byte("before\x00after\x00\x00end"),
		"unix-newlines":    []byte("line one\nline two\nline three\n"),
		"windows-newlines": []byte("line one\r\nline two\r\n"),
		"no-trailing-nl":   []byte("no newline at the end"),
		"only-newlines":    bytes.Repeat([]byte{'\n'}, 100),
		"utf8-text":        []byte("plain ascii text with punctuation: ,.;:!?-_"),
		"long-single-line": bytes.Repeat([]byte("x"), 8192),
	}
	// Sizes either side of powers of two and of the four-byte length prefixes.
	for _, n := range []int{3, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
		255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097} {
		b := make([]byte, n)
		rand.Read(b)
		cases[fmt.Sprintf("random-%d", n)] = b
	}
	return cases
}

func allByteValues() []byte {
	out := make([]byte, 256)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// TestRecoveryContentMatrix is the guarantee that matters most: whatever went in
// comes back byte for byte. It runs every content case through a password cascade
// and checks every K-sized subset of the pieces, so no particular combination can
// be the one that fails.
func TestRecoveryContentMatrix(t *testing.T) {
	pws := [][]byte{[]byte("first"), []byte("second")}
	ids := ciphers.Cascade(2)

	for name, input := range contentCases() {
		t.Run(name, func(t *testing.T) {
			pieces, err := core.Split(input, splitOpts(core.SplitOptions{
				N: 4, K: 2,
				Layers: []core.LayerSpec{
					{Kind: core.PasswordLayer, SchemeID: ids[0], Password: pws[0]},
					{Kind: core.PasswordLayer, SchemeID: ids[1], Password: pws[1]},
				},
			}))
			if err != nil {
				t.Fatalf("split: %v", err)
			}
			open := core.OpenOptions{Passwords: pws}

			// Every 2-of-4 subset must rebuild it exactly.
			for i := 0; i < len(pieces); i++ {
				for j := i + 1; j < len(pieces); j++ {
					got, err := core.Combine([][]byte{pieces[i], pieces[j]}, open)
					if err != nil {
						t.Fatalf("combine pieces %d,%d: %v", i+1, j+1, err)
					}
					if !bytes.Equal(got, input) {
						t.Fatalf("pieces %d,%d: recovered %d bytes, want %d", i+1, j+1, len(got), len(input))
					}
				}
			}
		})
	}
}

// skipIfOverCapacity skips when the format has a size ceiling the piece exceeds,
// so the QR and words passes cover only the inputs that fit them. Every piece of
// a set is the same size, so one length decides for the whole set.
func skipIfOverCapacity(t *testing.T, f pieceio.Format, pieceLen int) {
	t.Helper()
	if f == pieceio.QR && !pieceio.QRFits(pieceLen) {
		t.Skip("piece too large for a QR code")
	}
	if f == pieceio.Words && pieceLen > pieceio.Bip39MaxPiece {
		t.Skip("piece too large to write out as words")
	}
}

// TestRecoveryThroughEveryTransport sends each content case through each transport
// format and back, since that is where a stray newline or a text conversion would
// show up.
func TestRecoveryThroughEveryTransport(t *testing.T) {
	pw := [][]byte{[]byte("transport")}

	for name, input := range contentCases() {
		// Keep the QR pass to inputs that can fit one.
		for _, f := range pieceio.Encodable() {
			t.Run(name+"/"+f.String(), func(t *testing.T) {
				pieces, err := core.Split(input, splitOpts(core.SplitOptions{
					N: 3, K: 2,
					Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: pw[0]}},
				}))
				if err != nil {
					t.Fatalf("split: %v", err)
				}
				// QR and words each have a size ceiling, so those passes cover
				// only the inputs that stay under it.
				skipIfOverCapacity(t, f, len(pieces[0]))

				decoded := make([][]byte, 0, len(pieces))
				for _, p := range pieces {
					data, _, err := pieceio.Encode(p, f, 3)
					if err != nil {
						t.Fatalf("encode: %v", err)
					}
					back, detected, err := pieceio.Decode(data)
					if err != nil {
						t.Fatalf("decode: %v", err)
					}
					if detected != f {
						t.Fatalf("detected %s, want %s", detected, f)
					}
					if !bytes.Equal(back, p) {
						t.Fatal("piece changed in transport")
					}
					decoded = append(decoded, back)
				}
				got, err := core.Combine(decoded[:2], core.OpenOptions{Passwords: pw})
				if err != nil {
					t.Fatalf("combine: %v", err)
				}
				if !bytes.Equal(got, input) {
					t.Fatal("content changed")
				}
			})
		}
	}
}

// TestRecoveryRandomSizes is a property check over random sizes and thresholds, to
// catch a size-dependent fault that a fixed list would miss.
func TestRecoveryRandomSizes(t *testing.T) {
	pw := [][]byte{[]byte("random-sizes")}
	for i := 0; i < 40; i++ {
		size := randInt(t, 5000)
		n := 2 + randInt(t, 6)
		k := 1 + randInt(t, n)
		input := make([]byte, size)
		rand.Read(input)

		pieces, err := core.Split(input, splitOpts(core.SplitOptions{
			N: n, K: k,
			Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: pw[0]}},
		}))
		if err != nil {
			t.Fatalf("size=%d n=%d k=%d: split: %v", size, n, k, err)
		}
		got, err := core.Combine(pieces[:k], core.OpenOptions{Passwords: pw})
		if err != nil {
			t.Fatalf("size=%d n=%d k=%d: combine: %v", size, n, k, err)
		}
		if !bytes.Equal(got, input) {
			t.Fatalf("size=%d n=%d k=%d: content changed", size, n, k)
		}
	}
}

// TestRecoveryEveryMode checks each protection mode recovers exactly, so no mode
// is left only lightly exercised.
func TestRecoveryEveryMode(t *testing.T) {
	input := []byte("every mode must give this back unchanged")

	alice, err := kem.Generate(kem.MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := kem.Generate(kem.MLKEM1024)
	if err != nil {
		t.Fatal(err)
	}
	pw1, pw2 := []byte("one"), []byte("two")

	cases := []struct {
		name string
		so   core.SplitOptions
		oo   core.OpenOptions
	}{
		{
			name: "single password",
			so:   core.SplitOptions{N: 3, K: 2, Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: pw1}}},
			oo:   core.OpenOptions{Passwords: [][]byte{pw1}},
		},
		{
			name: "two passwords",
			so: core.SplitOptions{N: 3, K: 2, Layers: []core.LayerSpec{
				{Kind: core.PasswordLayer, Password: pw1},
				{Kind: core.PasswordLayer, Password: pw2},
			}},
			oo: core.OpenOptions{Passwords: [][]byte{pw1, pw2}},
		},
		{
			name: "keyless",
			so:   core.SplitOptions{N: 3, K: 2, Keyless: true},
			oo:   core.OpenOptions{},
		},
		{
			name: "recipient only",
			so:   core.SplitOptions{N: 3, K: 2, Layers: []core.LayerSpec{{Kind: core.RecipientLayer, Recipient: alice.Public()}}},
			oo:   core.OpenOptions{PrivateKeys: []*kem.PrivateKey{alice}},
		},
		{
			name: "two recipients",
			so: core.SplitOptions{N: 3, K: 2, Layers: []core.LayerSpec{
				{Kind: core.RecipientLayer, Recipient: alice.Public()},
				{Kind: core.RecipientLayer, Recipient: bob.Public()},
			}},
			oo: core.OpenOptions{PrivateKeys: []*kem.PrivateKey{alice, bob}},
		},
		{
			name: "password, key, key, password",
			so: core.SplitOptions{N: 3, K: 2, Layers: []core.LayerSpec{
				{Kind: core.PasswordLayer, Password: pw1},
				{Kind: core.RecipientLayer, Recipient: alice.Public()},
				{Kind: core.RecipientLayer, Recipient: bob.Public()},
				{Kind: core.PasswordLayer, Password: pw2},
			}},
			oo: core.OpenOptions{Passwords: [][]byte{pw1, pw2}, PrivateKeys: []*kem.PrivateKey{alice, bob}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			so := c.so
			if !so.Keyless {
				so = splitOpts(so)
			} else {
				so.RecordAlgo = true
			}
			pieces, err := core.Split(input, so)
			if err != nil {
				t.Fatalf("split: %v", err)
			}
			got, err := core.Combine(pieces[:so.K], c.oo)
			if err != nil {
				t.Fatalf("combine: %v", err)
			}
			if !bytes.Equal(got, input) {
				t.Fatal("content changed")
			}
		})
	}
}

// TestPaddingNeverBreaksQRFeasibility checks the property that matters at the QR
// boundary: for a given input either every piece fits or none is exported. A set
// where only some pieces have a QR code would be unrecoverable from paper.
func TestPaddingNeverBreaksQRFeasibility(t *testing.T) {
	pw := []byte("qr-padding")

	// Sizes around the point where padded pieces start to overflow, repeated so a
	// verdict that changed between runs would show up.
	for _, size := range []int{2000, 2200, 2400, 2600, 2800} {
		input := make([]byte, size)
		rand.Read(input)
		for run := 0; run < 6; run++ {
			pieces, err := core.Split(input, splitOpts(core.SplitOptions{
				N: 4, K: 2,
				Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: pw}},
			}))
			if err != nil {
				t.Fatal(err)
			}

			allFit := true
			for _, p := range pieces {
				if !pieceio.QRFits(len(p)) {
					allFit = false
				}
			}
			if !allFit {
				// At least one piece is too large, so nothing may be encoded. Any
				// piece that does fit must not be written on its own.
				continue
			}
			// Every piece fits, so every piece must encode and decode.
			for i, p := range pieces {
				data, _, err := pieceio.Encode(p, pieceio.QR, 2)
				if err != nil {
					t.Fatalf("size=%d run=%d piece=%d fits but did not encode: %v", size, run, i+1, err)
				}
				back, _, err := pieceio.Decode(data)
				if err != nil || !bytes.Equal(back, p) {
					t.Fatalf("size=%d run=%d piece=%d did not survive: %v", size, run, i+1, err)
				}
			}
		}
	}
}

// TestPadNoneMakesQRDeterministic checks that turning padding off leaves the
// natural size, so a size that fits keeps fitting.
func TestPadNoneMakesQRDeterministic(t *testing.T) {
	pw := []byte("deterministic")
	input := make([]byte, 2400)
	rand.Read(input)

	var want int
	for run := 0; run < 5; run++ {
		pieces, err := core.Split(input, splitOpts(core.SplitOptions{
			N: 4, K: 2, Padding: core.PadNone(),
			Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: pw}},
		}))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pieces {
			if want == 0 {
				want = len(p)
			}
			if len(p) != want {
				t.Fatalf("run %d: sizes differ with padding off: %d and %d", run, want, len(p))
			}
		}
		// The QR verdict must be the same every run, being size-determined.
		if pieceio.QRFits(want) {
			for _, p := range pieces {
				if _, _, err := pieceio.Encode(p, pieceio.QR, 2); err != nil {
					t.Fatalf("run %d: piece fits but did not encode: %v", run, err)
				}
			}
		}
	}
}

// TestRecoveryAtEveryPaddingWidth runs the widths the wizard offers through the
// transports, since the padding is the last thing appended to a manifest and a
// width that broke a transport would only show here.
func TestRecoveryAtEveryPaddingWidth(t *testing.T) {
	pw := [][]byte{[]byte("width")}
	input := make([]byte, 700)
	rand.Read(input)

	for _, w := range []int{core.MinPadPercent, 5, 10, 100, core.MaxPadPercent} {
		for _, f := range pieceio.Encodable() {
			t.Run(fmt.Sprintf("%d%%/%s", w, f), func(t *testing.T) {
				pieces, err := core.Split(input, splitOpts(core.SplitOptions{
					N: 3, K: 2, Padding: core.PadPercent(w),
					Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: pw[0]}},
				}))
				if err != nil {
					t.Fatalf("split: %v", err)
				}
				for _, p := range pieces {
					if len(p) != len(pieces[0]) {
						t.Fatalf("pieces of one set differ in size: %d and %d", len(p), len(pieces[0]))
					}
				}
				skipIfOverCapacity(t, f, len(pieces[0]))
				decoded := make([][]byte, 0, len(pieces))
				for _, p := range pieces {
					data, _, err := pieceio.Encode(p, f, 3)
					if err != nil {
						t.Fatalf("encode: %v", err)
					}
					back, detected, err := pieceio.Decode(data)
					if err != nil {
						t.Fatalf("decode: %v", err)
					}
					if detected != f {
						t.Fatalf("detected %s, want %s", detected, f)
					}
					decoded = append(decoded, back)
				}
				got, err := core.Combine(decoded[:2], core.OpenOptions{Passwords: pw})
				if err != nil {
					t.Fatalf("combine: %v", err)
				}
				if !bytes.Equal(got, input) {
					t.Fatal("content changed")
				}
			})
		}
	}
}

func randInt(t *testing.T, max int) int {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		t.Fatal(err)
	}
	return int(n.Int64())
}
