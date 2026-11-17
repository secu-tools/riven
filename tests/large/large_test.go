// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build large

// Package large splits and combines an input just past 4 GiB with each method,
// which no other tier can afford: it needs about 32 GiB of memory and five
// minutes, so it runs only when asked.
//
//	go test -tags large -count=1 -timeout 30m ./tests/large/
package large

import (
	"crypto/sha256"
	"encoding/binary"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
)

// inputLen is just past 4 GiB, so every share and fragment below is too: the
// length a u32 once wrapped at.
const inputLen = 4<<30 + 1<<20

func TestSplitPastFourGiB(t *testing.T) {
	// Collect often: each step frees gigabytes the next one needs.
	defer debug.SetGCPercent(debug.SetGCPercent(10))

	// Two Shamir shares, each past 4 GiB.
	full := core.SplitOptions{N: 2, K: 2, Method: core.MethodFull, Keyless: true}
	t.Run("full", func(t *testing.T) { roundTrip(t, full, core.OpenOptions{}) })
	runtime.GC()

	// A fragment past 4 GiB takes K=1, which a keyless set may not use, so this
	// set has a password, at a cost that keeps the test about the size.
	pw := []byte("large")
	compact := core.SplitOptions{N: 2, K: 1, Method: core.MethodCompact,
		Params: kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}, RecordAlgo: true, RecordKDF: true,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: pw}}}
	t.Run("compact", func(t *testing.T) { roundTrip(t, compact, core.OpenOptions{Passwords: [][]byte{pw}}) })
	runtime.GC()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("memory taken from the system: %d GiB", ms.Sys>>30)
}

func roundTrip(t *testing.T, split core.SplitOptions, open core.OpenOptions) {
	input := counting(inputLen)
	want := sha256.Sum256(input)
	var pieces [][]byte
	err := core.SplitTo(input, split, func(serial int, p []byte) error {
		if len(p) <= 1<<32 {
			t.Errorf("piece %d is %d bytes, not past 4 GiB", serial, len(p))
		}
		if serial <= split.K {
			pieces = append(pieces, p) // write owns p: SplitTo is done with it
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	input = nil
	runtime.GC()

	got, err := core.Combine(pieces, open)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != inputLen || sha256.Sum256(got) != want {
		t.Fatalf("rebuilt %d bytes that differ from the %d split", len(got), inputLen)
	}
}

// counting returns n bytes where each 8-byte word holds its own offset, so no
// two parts of the input match and a part read from the wrong place, as a
// wrapped length would read it, changes the hash.
func counting(n int) []byte {
	b := make([]byte, n)
	for i := 0; i+8 <= n; i += 8 {
		binary.LittleEndian.PutUint64(b[i:], uint64(i))
	}
	return b
}
