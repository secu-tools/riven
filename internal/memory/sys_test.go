// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build unix || windows

package memory

import (
	"os"
	"testing"
	"unsafe"
)

// TestLockedBuffersHavePagesOfTheirOwn checks each locked buffer starts on a
// page of its own. Locking works on whole pages and does not count, so two
// buffers sharing a page would unlock each other when either is released.
func TestLockedBuffersHavePagesOfTheirOwn(t *testing.T) {
	page := uintptr(os.Getpagesize())
	seen := map[uintptr]bool{}
	for range 4 {
		b, err := NewLocked(16)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Destroy()
		start := uintptr(unsafe.Pointer(&b.Bytes()[0]))
		if start%page != 0 {
			t.Fatalf("a locked buffer starts mid-page, at %#x", start)
		}
		if seen[start] {
			t.Fatalf("two locked buffers share the page at %#x", start)
		}
		seen[start] = true
	}
}
