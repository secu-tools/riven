// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build windows

package memory

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the buffer is its own VirtualAlloc region, off the Go heap, pinned
// with VirtualLock so it stays resident and out of the pagefile. The region must
// be its own: VirtualLock works on whole pages and does not count, so two
// buffers on one page would unlock each other when either is released.

func sysAlloc(size int) ([]byte, error) {
	addr, err := windows.VirtualAlloc(0, uintptr(size),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, err
	}
	return unsafe.Slice((*byte)(unsafe.Add(nil, addr)), size), nil
}

func sysLock(b []byte) error {
	return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func sysUnlock(b []byte) error {
	return windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func sysFree(b []byte) error {
	return windows.VirtualFree(uintptr(unsafe.Pointer(&b[0])), 0, windows.MEM_RELEASE)
}
