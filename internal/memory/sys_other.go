// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build !unix && !windows

package memory

// Fallback for platforms without a locking primitive we support. Memory is a
// plain heap allocation; it is still zeroed on Destroy, just not pinned.

func sysAlloc(size int) ([]byte, error) { return make([]byte, size), nil }
func sysLock(b []byte) error            { return nil }
func sysUnlock(b []byte) error          { return nil }
func sysFree(b []byte) error            { return nil }
