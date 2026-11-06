// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import "testing"

// TestEnableColorRefusesWhatIsNotAConsole checks the Windows console switch
// fails safely, leaving the output plain, on a handle that is not a console:
// a file here, and the same holds for a pipe or a down-level console that does
// not know the mode.
func TestEnableColorRefusesWhatIsNotAConsole(t *testing.T) {
	f := tempFile(t)
	ok, restore := enableColor(f)
	restore()
	if ok {
		t.Fatal("colour was switched on for a file")
	}
}
