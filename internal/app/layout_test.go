// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// The wizard's longest lines are assembled at run time -- a format note with a
// byte count in it, a question carrying its own default -- so they cannot be
// wrapped by hand in the source. These cover the folding that does it instead.

// withLineWidth fixes the width output folds at, so a test checks the folding
// rather than whatever terminal happens to be running it.
func withLineWidth(t *testing.T, w int, fn func()) {
	t.Helper()
	old := lineWidth
	lineWidth = func() int { return w }
	defer func() { lineWidth = old }()
	fn()
}

func TestWrapWordsBreaksOnlyBetweenWords(t *testing.T) {
	const width = 20
	const body = "pieces are 3477121 bytes, over the 4096 limit"
	lines := wrapWords(body, width)
	if len(lines) < 2 {
		t.Fatalf("%q was not folded: %q", body, lines)
	}
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > width {
			t.Errorf("line %q is %d columns, over %d", l, n, width)
		}
	}
	if got := strings.Join(lines, " "); got != body {
		t.Errorf("folding changed the text:\n got %q\nwant %q", got, body)
	}
}

// A path or a file name is useless in halves, so a word past the width keeps a
// line to itself and overflows rather than being cut in two.
func TestWrapWordsKeepsAnOverlongWordWhole(t *testing.T) {
	long := "pieces/" + strings.Repeat("a", 40) + ".words.txt"
	lines := wrapWords("see "+long+" now", 20)
	whole := false
	for _, l := range lines {
		if l == long {
			whole = true
		}
	}
	if !whole {
		t.Errorf("the long word was broken up: %q", lines)
	}
}

func TestWrapWordsOnBlankInput(t *testing.T) {
	if lines := wrapWords("   ", 20); lines != nil {
		t.Errorf("blank input folded to %q", lines)
	}
}

// Nothing asks a terminal for its width in a test or behind a pipe, so the
// fallback and the bounds are what decide the width there.
func TestClampWidthStaysWithinTheBounds(t *testing.T) {
	cases := []struct{ raw, want int }{
		{0, fallbackLineWidth - 1},
		{-1, fallbackLineWidth - 1},
		{80, 79},
		{20, minLineWidth},
		{400, maxLineWidth},
	}
	for _, c := range cases {
		if got := clampWidth(c.raw); got != c.want {
			t.Errorf("clampWidth(%d) = %d, want %d", c.raw, got, c.want)
		}
	}
}

func TestWriteWrappedIndentsUnderTheLead(t *testing.T) {
	const lead = "  warning: "
	var buf bytes.Buffer
	withLineWidth(t, 40, func() {
		writeWrapped(&buf, lead, "anyone with K pieces can rebuild the file, and nothing authenticates the set")
	})
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("the body was not folded:\n%s", buf.String())
	}
	if !strings.HasPrefix(lines[0], lead+"anyone") {
		t.Errorf("the lead does not open the first line: %q", lines[0])
	}
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, strings.Repeat(" ", len(lead))) || strings.HasPrefix(l, strings.Repeat(" ", len(lead)+1)) {
			t.Errorf("continuation %q is not aligned to the end of the lead", l)
		}
	}
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > 40 {
			t.Errorf("line %q is %d columns, over 40", l, n)
		}
	}
}

// A note that fits sits beside its description; one that does not takes a line
// of its own rather than folding through the middle of the description.
func TestWriteItemPlacesTheNote(t *testing.T) {
	const lead = "  4) words   "
	const desc = "BIP-39 words, the largest form, for writing out by hand"
	const note = "NOT AVAILABLE: pieces are 3477121 bytes, over the 4096 limit"

	var wide bytes.Buffer
	withLineWidth(t, 200, func() { writeItem(&wide, lead, desc, note) })
	if n := strings.Count(wide.String(), "\n"); n != 1 {
		t.Errorf("a note that fits should stay beside the description:\n%s", wide.String())
	}

	var narrow bytes.Buffer
	withLineWidth(t, 79, func() { writeItem(&narrow, lead, desc, note) })
	lines := strings.Split(strings.TrimRight(narrow.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want a description line and a note line, got:\n%s", narrow.String())
	}
	if lines[0] != lead+desc {
		t.Errorf("the description should hold the first line alone: %q", lines[0])
	}
	if lines[1] != strings.Repeat(" ", len(lead))+note {
		t.Errorf("the note should start its own line under the description: %q", lines[1])
	}
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > 79 {
			t.Errorf("line %q is %d columns, over 79", l, n)
		}
	}
}

// However long a question runs, the cursor stays on its last line: that is
// where the answer is typed.
func TestWritePromptLeavesTheCursorAfterTheQuestion(t *testing.T) {
	const long = "Record the algorithms inside each piece (No means you must supply --algo to decrypt)? (y/n) [default: yes]:"
	var out string
	withLineWidth(t, 60, func() {
		out = withInput(t, "", func() { writePrompt(long) })
	})
	if !strings.HasSuffix(out, "[default: yes]: ") {
		t.Errorf("the prompt should end with the cursor after it: %q", out)
	}
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		t.Fatalf("the question was not folded: %q", out)
	}
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > 60 {
			t.Errorf("line %q is %d columns, over 60", l, n)
		}
	}
}
