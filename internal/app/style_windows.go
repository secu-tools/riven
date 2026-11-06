// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableColor turns on escape-code processing for a console stream, which the
// Windows console does only when a program asks. It reports false where the
// console cannot, as on Windows before 10, or where f is not a console at all,
// and the output then stays plain. The returned function restores the mode the
// console had, so the shell is left as it was found.
func enableColor(f *os.File) (bool, func()) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false, func() {}
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true, func() {}
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return false, func() {}
	}
	return true, func() { _ = windows.SetConsoleMode(h, mode) }
}
