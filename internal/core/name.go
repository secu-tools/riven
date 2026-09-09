// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"strings"

	"github.com/secu-tools/riven/internal/format"
)

// windowsReserved are device names Windows resolves anywhere in the filesystem.
// Writing to one would talk to the device instead of creating a file. CONIN$ and
// CONOUT$ are the console handles: writing to CONOUT$ succeeds and puts the
// recovered data on the terminal while creating no file at all.
var windowsReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"conin$": true, "conout$": true, "clock$": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true, "com0": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true, "lpt0": true,
}

// superscriptDigits map the forms Windows also accepts in a device name, so
// "com" followed by a superscript one is recognised as COM1 rather than passing
// as an ordinary name.
var superscriptDigits = map[rune]rune{0x00b9: '1', 0x00b2: '2', 0x00b3: '3'}

// unsafeDisplay reports whether r has no place in a file name because of how it
// renders rather than what it is: the bidirectional overrides, which let a name
// ending "gpj.exe" display as "exe.jpg", the C1 control block, and the byte
// order mark. Ordinary international text is unaffected, including the joiners
// that Indic and Arabic scripts need.
func unsafeDisplay(r rune) bool {
	switch {
	case r >= 0x80 && r <= 0x9f: // C1 controls
		return true
	case r == 0x061c, r == 0x00ad, r == 0xfeff:
		return true
	case r >= 0x200e && r <= 0x200f: // LRM, RLM
		return true
	case r >= 0x202a && r <= 0x202e: // embedding and override
		return true
	case r >= 0x2066 && r <= 0x2069: // isolates
		return true
	}
	return false
}

// SafeName reduces a recorded file name to one that is safe to create, or
// returns empty when it cannot be.
//
// The name comes out of a piece, which means it comes from whoever wrote that
// piece: it is never a path, only a name in the current directory, and it must
// not be able to name a device or escape upwards. Both separators are stripped,
// because a piece written on one system is often opened on another.
func SafeName(raw string) string {
	if raw == "" || len(raw) > format.MaxNameLen {
		return ""
	}
	name := raw
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	// A Windows drive-relative name such as "c:file" is still a path.
	if i := strings.LastIndex(name, ":"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimRight(name, " .")

	if name == "" || name == "." || name == ".." {
		return ""
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7F || strings.ContainsRune(`<>:"|?*`, r) || unsafeDisplay(r) {
			return ""
		}
	}
	stem := name
	if i := strings.Index(stem, "."); i > 0 {
		stem = stem[:i]
	}
	if windowsReserved[deviceKey(stem)] {
		return ""
	}
	return name
}

// deviceKey folds a name stem to the form the reserved-name table is keyed by:
// lower case, with the superscript digits Windows also accepts written plainly.
func deviceKey(stem string) string {
	var b strings.Builder
	b.Grow(len(stem))
	for _, r := range strings.ToLower(stem) {
		if d, ok := superscriptDigits[r]; ok {
			r = d
		}
		b.WriteRune(r)
	}
	return b.String()
}
