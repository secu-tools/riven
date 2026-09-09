// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import "testing"

// The recorded name comes from whoever wrote the piece, and combine turns it
// into a path. These are the forms that address a device or misrepresent what
// the file is, rather than the traversal forms name_test.go already covers.
//
// The offending characters are written as escapes on purpose: a name that is
// invisible in an editor is the whole point of this class of input.
func TestSafeNameRejectsDevicesAndDisplaySpoofing(t *testing.T) {
	reject := []struct{ name, why string }{
		{"CONOUT$", "console handle: the write succeeds, no file appears, the data goes to the terminal"},
		{"conin$", "console handle"},
		{"CLOCK$", "device"},
		{"com\u00b9", "superscript one: Windows resolves this as COM1"},
		{"LPT\u00b2", "superscript two"},
		{"com0", "COM0"},
		{"\u202egpj.exe", "right-to-left override: displays as exe.jpg"},
		{"a\u202db.txt", "left-to-right override"},
		{"a\u200fb.txt", "right-to-left mark"},
		{"a\u2066b.txt", "isolate"},
		{"a\u0085b.txt", "C1 control"},
		{"\ufeffnotes.txt", "byte order mark"},
		{"a\u00adb.txt", "soft hyphen"},
		{"a\u061cb.txt", "Arabic letter mark"},
	}
	for _, c := range reject {
		if got := SafeName(c.name); got != "" {
			t.Errorf("SafeName(%q) = %q, want rejected (%s)", c.name, got, c.why)
		}
	}
}

// The filter is about how a name renders, not about it being non-ASCII: an
// ordinary international file name must survive, including the zero-width
// joiner that Indic and Arabic scripts need.
func TestSafeNameKeepsInternationalNames(t *testing.T) {
	keep := []string{
		"notes.txt",
		".bashrc",
		"caf\u00e9.pdf",                // French
		"\u4e2d\u6587.txt",             // Chinese
		"\u0928\u092e\u200d\u0938.txt", // Devanagari with a zero-width joiner
		"\u0645\u0644\u0641.txt",       // Arabic
		"communications.log",           // starts with "com", is not COM1
		"nullable.go",                  // starts with "nul", is not NUL
		"con-artists.txt",              // stem is "con-artists", not "con"
	}
	for _, name := range keep {
		if got := SafeName(name); got != name {
			t.Errorf("SafeName(%q) = %q, want it kept", name, got)
		}
	}
}
