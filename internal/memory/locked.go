// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package memory

import "sync"

// LockedBuffer holds secret bytes in off-heap memory that is pinned with
// mlock/VirtualLock (best effort) so it is never written to swap, and is zeroed
// on Destroy. The backing memory is not managed by the Go garbage collector, so
// it is never relocated or copied.
type LockedBuffer struct {
	mu        sync.Mutex
	mem       []byte // full platform allocation
	n         int    // requested usable length
	locked    bool
	destroyed bool
}

// NewLocked allocates a zeroed locked buffer of size bytes.
func NewLocked(size int) (*LockedBuffer, error) {
	if size <= 0 {
		return &LockedBuffer{destroyed: true}, nil
	}
	mem, err := sysAlloc(size)
	if err != nil {
		return nil, err
	}
	for i := range mem {
		mem[i] = 0
	}
	b := &LockedBuffer{mem: mem, n: size}
	if err := sysLock(mem); err == nil {
		b.locked = true
	}
	// Locking is best effort; a failure (e.g. working-set limits) still leaves
	// the buffer usable and zeroed on Destroy.

	regMu.Lock()
	secrets[b] = struct{}{}
	regMu.Unlock()
	return b, nil
}

// NewLockedFrom copies src into a fresh locked buffer and then zeros src.
func NewLockedFrom(src []byte) (*LockedBuffer, error) {
	b, err := NewLocked(len(src))
	if err != nil {
		return nil, err
	}
	copy(b.Bytes(), src)
	Zero(src)
	return b, nil
}

// Bytes returns the usable slice. It aliases the locked memory; do not retain it
// past Destroy. Returns nil after Destroy.
func (b *LockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return nil
	}
	return b.mem[:b.n:b.n]
}

// Locked reports whether the memory was successfully pinned.
func (b *LockedBuffer) Locked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.locked
}

// Wipe zeros the contents but keeps the memory mapped.
//
// WipeAll uses this rather than Destroy so a signal arriving mid-run cannot
// unmap a buffer another goroutine is still reading: the secret is gone, the
// address stays valid.
func (b *LockedBuffer) Wipe() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return
	}
	Zero(b.mem)
}

// Destroy zeros, unlocks, and frees the buffer. Safe to call multiple times.
func (b *LockedBuffer) Destroy() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return
	}
	b.destroyed = true

	regMu.Lock()
	delete(secrets, b)
	regMu.Unlock()

	Zero(b.mem)
	if b.locked {
		_ = sysUnlock(b.mem)
	}
	_ = sysFree(b.mem)
	b.mem = nil
}

// byBase finds the buffer behind a slice handed out by Bytes, so a caller that
// holds only the slice can still release it.
var byBase = map[*byte]*LockedBuffer{}

// Bytes returns n zeroed bytes in memory that is pinned out of swap, and
// registered so an interrupt or a panic wipes it. Free releases it.
//
// Locking is best effort: where the platform or the process limit refuses, the
// result is ordinary memory, so a caller never needs a second path for that.
func Bytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	b, err := NewLocked(n)
	if err != nil {
		return make([]byte, n)
	}
	s := b.Bytes()
	if len(s) == 0 {
		return make([]byte, n)
	}
	regMu.Lock()
	byBase[&s[0]] = b
	regMu.Unlock()
	return s
}

// Copy returns a locked copy of src and zeros src.
func Copy(src []byte) []byte {
	out := Bytes(len(src))
	copy(out, src)
	Zero(src)
	return out
}

// Free zeros b, and releases it when it came from Bytes. Anything else is only
// zeroed, so Free is safe anywhere Zero is.
func Free(b []byte) {
	if len(b) == 0 {
		return
	}
	regMu.Lock()
	buf, ok := byBase[&b[0]]
	if ok {
		delete(byBase, &b[0])
	}
	regMu.Unlock()
	if ok {
		buf.Destroy()
		return
	}
	Zero(b)
}

// FreeAll releases every buffer in bufs.
func FreeAll(bufs [][]byte) {
	for _, b := range bufs {
		Free(b)
	}
}
