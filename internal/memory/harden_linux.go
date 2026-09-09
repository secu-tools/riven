// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build linux

package memory

import "golang.org/x/sys/unix"

// extraHarden marks the process non-dumpable, which also blocks ptrace-based
// inspection by non-privileged processes.
func extraHarden() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
