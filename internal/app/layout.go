// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// Line widths, in columns.
//
// A terminal narrower than minLineWidth is treated as that wide: folding to
// less leaves two or three words per line, which is harder to follow than
// letting the terminal overflow. Past maxLineWidth the eye loses its way back
// to the start of the next line, so a very wide terminal is not filled.
// fallbackLineWidth is what is assumed when there is no terminal to ask: a
// pipe, a redirect, or a test.
const (
	minLineWidth      = 40
	maxLineWidth      = 100
	fallbackLineWidth = 80
)

// clampWidth turns a raw terminal width into the width a line may use.
func clampWidth(raw int) int {
	if raw <= 0 {
		raw = fallbackLineWidth
	}
	// Filling the last column makes some terminals, Windows consoles among
	// them, fold to a blank line, so that column is left unused.
	raw--
	if raw < minLineWidth {
		return minLineWidth
	}
	if raw > maxLineWidth {
		return maxLineWidth
	}
	return raw
}

// lineWidth reports how many columns a printed line may use.
//
// Either stream can be the one on screen -- messages go to standard output, or
// to standard error under -y -- so whichever is a terminal decides the width.
//
// It is a variable so the tests can fix a width and check the folding itself,
// rather than whatever terminal happens to be running them.
var lineWidth = func() int {
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		if n, _, err := term.GetSize(int(f.Fd())); err == nil && n > 0 {
			return clampWidth(n)
		}
	}
	return clampWidth(fallbackLineWidth)
}

// minTextWidth is the narrowest column a folded body is given, however long the
// lead in front of it. Without a floor a wide lead would leave a word per line.
const minTextWidth = 24

// wrapWords folds s into lines of at most width columns, breaking only between
// words. A word wider than the line gets a line to itself rather than being cut
// in two: these are paths, flags and file names, which stay recognisable only
// whole.
func wrapWords(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	lines := []string{words[0]}
	for _, w := range words[1:] {
		last := len(lines) - 1
		if utf8.RuneCountInString(lines[last])+1+utf8.RuneCountInString(w) <= width {
			lines[last] += " " + w
			continue
		}
		lines = append(lines, w)
	}
	return lines
}

// writeWrapped prints lead followed by body, folded at the line width, with
// every line after the first indented to the end of lead. The body stays in one
// column, so a menu entry or a report line reads as a block rather than running
// back to the left margin.
func writeWrapped(out io.Writer, lead, body string) {
	indent := utf8.RuneCountInString(lead)
	avail := lineWidth() - indent
	if avail < minTextWidth {
		avail = minTextWidth
	}
	lines := wrapWords(body, avail)
	if len(lines) == 0 {
		fmt.Fprintln(out, strings.TrimRight(lead, " "))
		return
	}
	fmt.Fprintln(out, lead+lines[0])
	pad := strings.Repeat(" ", indent)
	for _, l := range lines[1:] {
		fmt.Fprintln(out, pad+l)
	}
}

// writeItem prints one menu entry: lead, what the entry is, and a note about
// it. The note stays beside the description while the whole entry fits on a
// line, and takes its own indented line when it does not, so a long note reads
// as a block instead of folding through the middle of the description.
func writeItem(out io.Writer, lead, desc, note string) {
	if note == "" {
		writeWrapped(out, lead, desc)
		return
	}
	indent := utf8.RuneCountInString(lead)
	const gap = 2
	if indent+utf8.RuneCountInString(desc)+gap+utf8.RuneCountInString(note) <= lineWidth() {
		fmt.Fprintln(out, lead+desc+strings.Repeat(" ", gap)+note)
		return
	}
	writeWrapped(out, lead, desc)
	writeWrapped(out, strings.Repeat(" ", indent), note)
}

// writePrompt writes a question, folded at the line width so a long one breaks
// between words rather than wherever the edge of the screen falls, and leaves
// the cursor after it for the answer.
//
// question carries no trailing space: the one the answer is typed after is
// added here, which is why the fold is a column short of the rest.
func writePrompt(question string) {
	lines := wrapWords(question, lineWidth()-1)
	if len(lines) == 0 {
		return
	}
	for _, l := range lines[:len(lines)-1] {
		fmt.Println(l)
	}
	fmt.Print(lines[len(lines)-1] + " ")
}
