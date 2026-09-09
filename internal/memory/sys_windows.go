// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build windows

package memory

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the buffer is a Go allocation pinned with VirtualLock, which keeps
// the pages resident and out of the pagefile. The current Go runtime does not
// relocate heap memory, so the locked address stays valid for the buffer's life.

func sysAlloc(size int) ([]byte, error) { return make([]byte, size), nil }

func sysLock(b []byte) error {
	return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func sysUnlock(b []byte) error {
	return windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func sysFree(b []byte) error { return nil }
