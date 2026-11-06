// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package memory

import (
	"bytes"
	"strings"
	"testing"
)

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
	}
	Zero(nil) // must not panic
}

func TestLockedBuffer(t *testing.T) {
	b, err := NewLocked(64)
	if err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	if len(data) != 64 {
		t.Fatalf("len %d", len(data))
	}
	for _, v := range data {
		if v != 0 {
			t.Fatal("buffer not zero-initialised")
		}
	}
	copy(data, []byte("secret"))
	b.Destroy()
	if b.Bytes() != nil {
		t.Fatal("Bytes should be nil after Destroy")
	}
	b.Destroy() // idempotent
}

// WipeAll runs from the signal handler, so it clears the contents but leaves
// the memory mapped: unmapping it there could pull a buffer out from under a
// goroutine still reading the slice. Destroy is for the owner, which knows when
// nobody is using it.
func TestWipeAllClearsButKeepsMemoryValid(t *testing.T) {
	b1, _ := NewLocked(16)
	b2, _ := NewLocked(16)
	defer b1.Destroy()
	defer b2.Destroy()
	copy(b1.Bytes(), bytes.Repeat([]byte{0xAA}, 16))
	copy(b2.Bytes(), bytes.Repeat([]byte{0xBB}, 16))

	WipeAll()

	for i, b := range []*LockedBuffer{b1, b2} {
		s := b.Bytes()
		if s == nil {
			t.Fatalf("buffer %d was unmapped; a slice still in use would dangle", i+1)
		}
		if !bytes.Equal(s, make([]byte, 16)) {
			t.Fatalf("buffer %d was not cleared: %x", i+1, s)
		}
	}
}

func TestZeroSizeLocked(t *testing.T) {
	b, err := NewLocked(0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Bytes() != nil {
		t.Fatal("zero-size buffer should have nil bytes")
	}
	b.Destroy()
}

// TestInstallCleanupStops checks the signal handler can be installed and torn
// down without leaving anything behind, since it runs for the life of the
// process in normal use.
func TestInstallCleanupStops(t *testing.T) {
	stop := InstallCleanup()
	if stop == nil {
		t.Fatal("InstallCleanup must return a stop function")
	}
	stop()
	// Stopping twice must not panic, because a command can return by more than
	// one path.
	stop()
}

// lockedSecret returns a registered locked buffer holding s.
func lockedSecret(t *testing.T, s string) *LockedBuffer {
	t.Helper()
	b, err := NewLocked(len(s))
	if err != nil {
		t.Fatal(err)
	}
	copy(b.Bytes(), s)
	return b
}

// TestGuardPanicWipesAndRepanics checks the crash path: live locked buffers are
// destroyed and the panic continues, so a crash does not become a silent
// success.
func TestGuardPanicWipesAndRepanics(t *testing.T) {
	buf := lockedSecret(t, "panic time secret")

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("the panic should have continued past GuardPanic")
			}
			if b := buf.Bytes(); b != nil {
				for _, c := range b {
					if c != 0 {
						t.Fatalf("the locked buffer survived the panic: %q", b)
					}
				}
			}
		}()
		defer GuardPanic()
		panic("crash")
	}()

	// GuardPanic with no panic in flight must do nothing at all.
	func() {
		defer GuardPanic()
	}()
}

// TestCleanupRunsTheHooks checks what the signal handler and GuardPanic run on
// the way out: every hook still registered, newest first, each once, then the
// wipe. A hook that was removed, because what it undoes is already undone, does
// not run, and one that panics does not keep the rest from running.
func TestCleanupRunsTheHooks(t *testing.T) {
	var order []string
	buf := lockedSecret(t, "cleanup secret")
	OnCleanup(func() { order = append(order, "first") })
	removed := OnCleanup(func() { order = append(order, "removed") })
	OnCleanup(func() { panic("a hook that fails") })
	OnCleanup(func() { order = append(order, "last") })
	removed()
	removed()

	Cleanup()
	Cleanup()
	if got := strings.Join(order, ","); got != "last,first" {
		t.Fatalf("hooks ran as %q, want last,first, once each", got)
	}
	if b := buf.Bytes(); b != nil && !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatalf("the locked buffer survived the cleanup: %q", b)
	}
}

// TestGuardPanicRunsTheHooks checks a crash undoes what the hooks undo, such as
// a terminal mode, before the panic carries on.
func TestGuardPanicRunsTheHooks(t *testing.T) {
	ran := false
	OnCleanup(func() { ran = true })
	func() {
		defer func() { _ = recover() }()
		defer GuardPanic()
		panic("crash")
	}()
	if !ran {
		t.Fatal("GuardPanic did not run the cleanup hooks")
	}
}

// TestDisableCoreDumps checks the hardening call succeeds or reports why, on
// every platform.
func TestDisableCoreDumps(t *testing.T) {
	if err := DisableCoreDumps(); err != nil {
		t.Logf("core dumps could not be disabled here: %v", err)
	}
}

// Bytes hands out a slice the caller can use like any other, and Free releases
// it. The registry means an interrupt reaches it in between.
func TestBytesFreeRoundTrip(t *testing.T) {
	b := Bytes(32)
	if len(b) != 32 {
		t.Fatalf("Bytes(32) returned %d bytes", len(b))
	}
	if !bytes.Equal(b, make([]byte, 32)) {
		t.Fatal("Bytes returned non-zero memory")
	}
	copy(b, bytes.Repeat([]byte{0xCD}, 32))

	WipeAll() // what a Ctrl-C does
	if !bytes.Equal(b, make([]byte, 32)) {
		t.Fatal("a slice from Bytes was not reached by WipeAll")
	}
	Free(b)
}

// Free must be usable wherever Zero was, including on ordinary slices it never
// handed out, so callers need no separate path.
func TestFreeOnOrdinarySliceJustZeroes(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	Free(b)
	if !bytes.Equal(b, make([]byte, 4)) {
		t.Fatalf("Free left %v", b)
	}
	Free(nil)
	Free([]byte{})
}

// Copy moves a secret into locked memory and leaves nothing behind.
func TestCopyWipesSource(t *testing.T) {
	src := []byte("correct horse battery staple")
	want := append([]byte(nil), src...)

	got := Copy(src)
	defer Free(got)

	if !bytes.Equal(got, want) {
		t.Fatalf("Copy returned %q, want %q", got, want)
	}
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Fatalf("Copy left the source readable: %q", src)
	}
}

// Zero-length is a normal case: an empty password, or a layer with none.
func TestBytesZeroLength(t *testing.T) {
	if b := Bytes(0); b != nil {
		t.Fatalf("Bytes(0) = %v, want nil", b)
	}
	FreeAll(nil)
	FreeAll([][]byte{nil, {}})
}
