// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/secu-tools/riven/internal/memory"
)

// Colour is used sparingly: a word that already says what a line is, such as
// "error" or "Done", gets a colour that makes it easy to find. Nothing is said
// by colour alone, so a terminal without it loses nothing.
//
// It is off unless the stream is a terminal, NO_COLOR is unset or empty, TERM is
// not "dumb", and --no-color was not given. Only bold and the basic red, green
// and yellow are used: every terminal that takes colour at all, the Windows
// console included, shows those, while dim and blue are unreadable on some.

// tone is the SGR parameters of one style.
type tone string

const (
	toneError   tone = "1;31" // bold red
	toneWarning tone = "1;33" // bold yellow
	toneGood    tone = "1;32" // bold green
	toneHeading tone = "1"    // bold
)

// colorOn records which streams take colour. It is filled once, at start-up, by
// setupColor, so it is empty, and every line plain, unless that ran.
var colorOn = map[*os.File]bool{}

// colorWanted applies the conventions that decide colour, before a terminal is
// asked: --no-color, a non-empty NO_COLOR (no-color.org), and TERM=dumb all turn
// it off. Outside Windows an unset TERM does too, since nothing then says the
// terminal understands escape codes; the Windows console sets no TERM.
func colorWanted(lookup func(string) (string, bool), flagOff bool, goos string) bool {
	if flagOff {
		return false
	}
	if v, ok := lookup("NO_COLOR"); ok && v != "" {
		return false
	}
	t, _ := lookup("TERM")
	if t == "dumb" {
		return false
	}
	return t != "" || goos == "windows"
}

// streamIsTerminal and enableStream are what setupColor asks of a stream. They
// are variables so the tests, which have no console, can stand one in.
var (
	streamIsTerminal = func(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
	enableStream     = enableColor
)

// setupColor decides colour for standard output and standard error and turns it
// on where a console needs that. The returned function puts the consoles back
// as they were; call it before exiting. A signal or a crash ends the process
// without coming back here, so the same restore is also left with the cleanup
// that memory.Cleanup runs on those paths.
func setupColor(flagOff bool) func() {
	colorOn = map[*os.File]bool{}
	if !colorWanted(os.LookupEnv, flagOff, runtime.GOOS) {
		return func() {}
	}
	var restores []func()
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		if !streamIsTerminal(f) {
			continue
		}
		ok, restore := enableStream(f)
		if !ok {
			continue
		}
		colorOn[f] = true
		restores = append(restores, restore)
	}
	// The cleanup may run on the signal handler's goroutine while this one is
	// still printing, so it only restores the consoles and leaves colorOn,
	// which nothing then prints with for long, alone.
	var once sync.Once
	restoreConsoles := func() {
		once.Do(func() {
			for i := len(restores) - 1; i >= 0; i-- {
				restores[i]()
			}
		})
	}
	remove := memory.OnCleanup(restoreConsoles)
	return func() {
		restoreConsoles()
		remove()
		colorOn = map[*os.File]bool{}
	}
}

// noColorRequested reports whether --no-color is among the arguments. Colour is
// set up before the arguments are parsed, so an error from the parser is styled
// like any other; the flag is still parsed, and accepted, with the rest.
func noColorRequested(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--no-color" {
			return true
		}
	}
	return false
}

// paint wraps s in t when w is a stream that takes colour.
func paint(w io.Writer, t tone, s string) string {
	f, ok := w.(*os.File)
	if !ok || !colorOn[f] || s == "" {
		return s
	}
	return "\x1b[" + string(t) + "m" + s + "\x1b[0m"
}

// writeLabeled prints a message that starts with a label such as "warning:",
// folded at the line width with every line after the first indented past the
// label, and with only the label coloured. The fold is worked out on the plain
// text, so the escape codes never count towards the width.
func writeLabeled(out io.Writer, label string, t tone, body string) {
	lead := label + " "
	indent := utf8.RuneCountInString(lead)
	avail := max(lineWidth()-indent, minTextWidth)
	lines := wrapWords(body, avail)
	if len(lines) == 0 {
		fmt.Fprintln(out, paint(out, t, label))
		return
	}
	fmt.Fprintln(out, paint(out, t, label)+" "+lines[0])
	pad := strings.Repeat(" ", indent)
	for _, l := range lines[1:] {
		fmt.Fprintln(out, pad+l)
	}
}

// warn prints a warning: something the user should act on, or know before
// relying on what was written.
func warn(out io.Writer, msg string) {
	writeLabeled(out, "warning:", toneWarning, msg)
}

// heading prints the title of a group of choices or results.
func heading(out io.Writer, s string) {
	fmt.Fprintln(out, paint(out, toneHeading, s))
}
