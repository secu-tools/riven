// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build unix

package memory

import "golang.org/x/sys/unix"

// sysAlloc returns anonymous, private, off-heap memory (not managed by the Go
// GC, so it is never relocated).
func sysAlloc(size int) ([]byte, error) {
	return unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE)
}

func sysLock(b []byte) error   { return unix.Mlock(b) }
func sysUnlock(b []byte) error { return unix.Munlock(b) }
func sysFree(b []byte) error   { return unix.Munmap(b) }
