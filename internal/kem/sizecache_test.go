// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package kem

import (
	"sync"
	"testing"
)

// sizes() fills a package-level map on a cache miss, and the miss path generates
// a key pair, so the window is wide. Nothing in the CLI reaches it concurrently
// today, but a map written from two goroutines corrupts silently or panics, and
// the callers are ordinary accessors that give no hint they must be serialised.
//
// Without the mutex this reliably trips the runtime's "concurrent map writes"
// detector; the race detector is not available on every builder, so the hammer
// is the portable check.
func TestSizesIsSafeFromManyGoroutines(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, s := range All() {
				_ = s.CiphertextSize()
				_ = s.PublicKeySize()
				_ = s.PrivateKeySize()
				_ = SchemeForCiphertextSize(s.CiphertextSize())
			}
		}()
	}
	wg.Wait()
}

// The sizes are fixed by the mechanism, so every reader must see the same value
// however many goroutines raced to compute it first.
func TestSizesAreStableAcrossGoroutines(t *testing.T) {
	want := map[Scheme]schemeSizes{}
	for _, s := range All() {
		want[s] = s.sizes()
	}

	var mu sync.Mutex
	var bad []string
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, s := range All() {
				got := s.sizes()
				if got != want[s] {
					mu.Lock()
					bad = append(bad, s.Name())
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if len(bad) > 0 {
		t.Fatalf("sizes disagreed between goroutines for %v", bad)
	}
}

// Every scheme must report a non-zero size; a zero would mean sizes() hit one of
// its error paths and cached nothing, which callers would read as "no bytes".
func TestEverySchemeReportsRealSizes(t *testing.T) {
	for _, s := range All() {
		if s.CiphertextSize() == 0 || s.PublicKeySize() == 0 || s.PrivateKeySize() == 0 {
			t.Errorf("%s reports a zero size: ct=%d pub=%d priv=%d",
				s.Name(), s.CiphertextSize(), s.PublicKeySize(), s.PrivateKeySize())
		}
	}
}
