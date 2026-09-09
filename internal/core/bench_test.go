// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"crypto/rand"
	"testing"

	"github.com/secu-tools/riven/internal/kdf"
)

// benchParams is the shipped default, which is what a user actually pays.
var benchParams = kdf.Default()

func benchInput(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// BenchmarkSplitPieces measures how the split scales with the piece count. Every
// piece needs its own envelope key, so this is where the Argon2 cost multiplies.
func BenchmarkSplitPieces(b *testing.B) {
	input := benchInput(64 * 1024)
	for _, n := range []int{1, 3, 5, 10} {
		b.Run(pieceLabel(n), func(b *testing.B) {
			opts := SplitOptions{
				N: n, K: 2, Params: benchParams, RecordAlgo: true, RecordKDF: true,
				Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("benchmark")}},
			}
			if n == 1 {
				opts.K = 1
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Split(input, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkCombinePieces measures the reading side, which pays one envelope key
// per piece supplied.
func BenchmarkCombinePieces(b *testing.B) {
	input := benchInput(64 * 1024)
	pw := [][]byte{[]byte("benchmark")}
	for _, k := range []int{2, 5, 10} {
		pieces, err := Split(input, SplitOptions{
			N: k, K: k, Params: benchParams, RecordAlgo: true, RecordKDF: true,
			Layers: []LayerSpec{{Kind: PasswordLayer, Password: pw[0]}},
		})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(pieceLabel(k), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := Combine(pieces, OpenOptions{Passwords: pw}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSplitSize measures the part that scales with the content rather than
// with the piece count.
func BenchmarkSplitSize(b *testing.B) {
	opts := SplitOptions{
		N: 3, K: 2, Params: testParams, RecordAlgo: true, RecordKDF: true,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("benchmark")}},
	}
	for _, size := range []int{1024, 256 * 1024, 4 * 1024 * 1024} {
		input := benchInput(size)
		b.Run(sizeLabel(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				if _, err := Split(input, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func pieceLabel(n int) string {
	switch n {
	case 1:
		return "1piece"
	case 3:
		return "3pieces"
	case 5:
		return "5pieces"
	default:
		return "10pieces"
	}
}

func sizeLabel(n int) string {
	switch {
	case n < 1024*1024:
		return "small"
	case n < 4*1024*1024:
		return "medium"
	default:
		return "large"
	}
}
