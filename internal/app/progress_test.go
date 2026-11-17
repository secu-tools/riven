// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/pieceio"
)

// clock is a time that moves only when a test says so.
type clock struct{ t time.Time }

func newClock() *clock                { return &clock{t: time.Unix(1_800_000_000, 0)} }
func (c *clock) now() time.Time       { return c.t }
func (c *clock) pass(d time.Duration) { c.t = c.t.Add(d) }

// blank is what wipes a line of n columns.
func blank(n int) string { return "\r" + strings.Repeat(" ", n) + "\r" }

// drawn returns what was drawn since it was last asked.
func drawn(out *bytes.Buffer) string {
	s := out.String()
	out.Reset()
	return s
}

// linePast starts a line whose command has run for the delay already.
func linePast(c *clock, out *bytes.Buffer) *progressLine {
	p := newProgressLine(out, c.now)
	c.pass(progressDelay)
	return p
}

// TestProgressLineWaitsBeforeShowing checks a command quicker than the delay
// prints nothing extra, and a slower one shows its step once the delay is up.
func TestProgressLineWaitsBeforeShowing(t *testing.T) {
	var out bytes.Buffer
	c := newClock()
	p := newProgressLine(&out, c.now)
	p.report("encrypting", 0, 0)
	c.pass(progressDelay - time.Millisecond)
	p.tick()
	if out.Len() != 0 {
		t.Fatalf("drew %q before the delay", out.String())
	}
	c.pass(time.Millisecond)
	p.tick()
	if got := drawn(&out); got != "\r  encrypting (1s)" {
		t.Fatalf("drew %q", got)
	}
}

// TestProgressLineShowsHowFar checks a measured step shows its percentage,
// which only moves forward though the units finish out of order, and that a
// step moving on is drawn at the next tick rather than on every unit.
func TestProgressLineShowsHowFar(t *testing.T) {
	var out bytes.Buffer
	c := newClock()
	p := linePast(c, &out)
	p.report("sharing", 0, 0)
	p.report("sharing", 3, 10)
	if got := drawn(&out); got != "\r  sharing (1s)" {
		t.Fatalf("drew %q", got)
	}
	c.pass(progressRedraw)
	p.report("sharing", 3, 10)
	p.tick()
	if got := drawn(&out); got != "\r  sharing 30% (1s)" {
		t.Fatalf("drew %q", got)
	}
	p.report("sharing", 5, 10)
	p.report("sharing", 4, 10)
	if out.Len() != 0 {
		t.Fatalf("drew %q for each unit", out.String())
	}
	c.pass(time.Minute)
	p.tick()
	if got := drawn(&out); got != "\r  sharing 50% (1m1s)" {
		t.Fatalf("drew %q", got)
	}
}

// TestProgressLineBlanksWhenIdle checks the line is wiped when no step is under
// way, the cursor left at its start for what is printed next, and not redrawn.
func TestProgressLineBlanksWhenIdle(t *testing.T) {
	var out bytes.Buffer
	c := newClock()
	p := linePast(c, &out)
	p.report("writing piece 12 of 20", 0, 0)
	c.pass(progressRedraw)
	p.report("decrypting", 0, 0)
	if got := drawn(&out); got != "\r  writing piece 12 of 20 (1s)\r  decrypting (1s)            " {
		t.Fatalf("a shorter step did not cover the longer one: %q", got)
	}
	p.report("", 0, 0)
	p.tick()
	if got := drawn(&out); got != blank(len("  decrypting (1s)")) {
		t.Fatalf("idle drew %q", got)
	}
}

// TestProgressLineKeepsUpWithManySteps checks a command stepping through
// thousands of pieces is not slowed by drawing every one: a step that follows
// another too soon waits for the tick, which shows the latest, while blanking
// the line is never put off.
func TestProgressLineKeepsUpWithManySteps(t *testing.T) {
	var out bytes.Buffer
	c := newClock()
	p := linePast(c, &out)
	draws := 0
	for i := 1; i <= 10000; i++ {
		p.report(fmt.Sprintf("writing piece %d of 10000", i), 0, 0)
		draws += strings.Count(drawn(&out), "\r")
		c.pass(time.Millisecond)
		if i%250 == 0 {
			p.tick()
			if got := drawn(&out); !strings.Contains(got, fmt.Sprintf("piece %d of", i)) {
				t.Fatalf("the tick after piece %d drew %q", i, got)
			}
		}
	}
	// Ten seconds of steps: one at once every progressRedraw at most.
	if draws > 100 {
		t.Fatalf("10000 steps over ten seconds drew %d times", draws)
	}
	p.report("writing piece 1 of 2", 0, 0)
	p.report("", 0, 0)
	if got := drawn(&out); !strings.HasSuffix(got, "\r") || strings.TrimSpace(got) != "" {
		t.Fatalf("idle right after a step drew %q, want the line blanked", got)
	}
}

// TestProgressLineHoldsForAPrompt checks a prompt blanks the line and keeps it
// blank while it waits, and the line comes back once it is answered.
func TestProgressLineHoldsForAPrompt(t *testing.T) {
	var out bytes.Buffer
	c := newClock()
	p := linePast(c, &out)
	p.report("rebuilding", 1, 4)
	shown := len(drawn(&out)) - 1
	release := p.hold()
	p.tick()
	p.report("rebuilding", 2, 4)
	p.tick()
	if got := drawn(&out); got != blank(shown) {
		t.Fatalf("a held line drew %q", got)
	}
	release()
	p.tick()
	if got := drawn(&out); got != "\r  rebuilding 50% (1s)" {
		t.Fatalf("after the prompt the line drew %q", got)
	}
}

// TestProgressLineFitsOneRow checks the line never wraps, which would leave the
// carriage return redrawing only its last row.
func TestProgressLineFitsOneRow(t *testing.T) {
	old := lineWidth
	lineWidth = func() int { return minLineWidth }
	defer func() { lineWidth = old }()
	var out bytes.Buffer
	p := linePast(newClock(), &out)
	p.report("checking: "+strings.Repeat("a long step ", 6), 1, 3)
	if got := drawn(&out); len(got) != minLineWidth {
		t.Fatalf("drew %d columns, want the %d a %d-column line leaves: %q", len(got)-1, minLineWidth-1, minLineWidth, got)
	}
}

// TestStartProgressNeedsATerminal checks the line is only drawn where it can be
// redrawn in place: on a terminal that is not TERM=dumb.
func TestStartProgressNeedsATerminal(t *testing.T) {
	old := streamIsTerminal
	defer func() { streamIsTerminal = old }()
	for _, c := range []struct {
		terminal bool
		term     string
		shows    bool
	}{{false, "xterm", false}, {true, "dumb", false}, {true, "xterm", true}} {
		streamIsTerminal = func(*os.File) bool { return c.terminal }
		t.Setenv("TERM", c.term)
		stop := startProgress()
		if shows := activeProgress.Load() != nil; shows != c.shows {
			t.Errorf("terminal %v, TERM=%s: shows %v, want %v", c.terminal, c.term, shows, c.shows)
		}
		stop()
		if activeProgress.Load() != nil {
			t.Fatal("the line outlived its command")
		}
	}
}

// showProgress makes the running command's line draw into a buffer for the rest
// of the test, as if the command had been running a minute, on a clock that
// moves on enough to draw every step.
func showProgress(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	now := time.Now()
	p := newProgressLine(&out, func() time.Time { now = now.Add(progressRedraw); return now })
	p.start = now.Add(-time.Minute)
	activeProgress.Store(p)
	t.Cleanup(func() { activeProgress.Store(nil) })
	return &out
}

// TestCommandsShowWhatTheyDo follows a split, its full check, and a combine
// through the steps a terminal shows, from both the core and the commands. The
// input is just over one unit, so the sharing is measured.
func TestCommandsShowWhatTheyDo(t *testing.T) {
	out := showProgress(t)
	plan := planFor(t, "--keyless", "-n", "3", "-k", "2")
	plan.outDir = t.TempDir()
	plan.opts.Progress = progress
	input := bytes.Repeat([]byte("w"), 600<<10)
	written, formats, err := exportSplit(io.Discard, plan, &cliOptions{yes: true, format: "binary"}, input, "doc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifySplit(verifyFull, input, written, formats, plan); err != nil {
		t.Fatal(err)
	}
	items, err := loadInputs(io.Discard, written[pieceio.Binary][:2], true)
	if err != nil {
		t.Fatal(err)
	}
	recovered, _, err := combinePieces(&cliOptions{}, copied(pieceBytes(items)), nil)
	if err != nil || !bytes.Equal(recovered, input) {
		t.Fatalf("combine: %v", err)
	}
	withInput(t, "", func() {
		err = writeRecovered(&cliOptions{outDir: filepath.Join(t.TempDir(), "back")}, recovered, "")
	})
	if err != nil {
		t.Fatal(err)
	}

	shown := out.String()
	for _, step := range []string{"encrypting", "sharing 50%", "writing piece 3 of 3",
		"checking: reading file 3 of 3", "checking: rebuilding", "checking: decrypting",
		"reading file 2 of 2", "opening pieces", "rebuilding", "decrypting", "writing the result"} {
		if !strings.Contains(shown, "\r  "+step+" ") {
			t.Errorf("never showed %q", step)
		}
	}
	if !strings.HasSuffix(shown, "\r") {
		t.Errorf("the line was left drawn: %q", shown[max(0, len(shown)-60):])
	}
}

// TestAFormatThePiecesCannotFitIsRefusedFirst checks a split asked for a form
// its pieces are too large for is refused before any of the work: nothing is
// encrypted, and no file is written. It was once refused only when the first
// piece was ready, after the input had been encrypted and shared.
func TestAFormatThePiecesCannotFitIsRefusedFirst(t *testing.T) {
	out := showProgress(t)
	plan := planFor(t, "--keyless", "-n", "3", "-k", "2")
	plan.outDir = t.TempDir()
	plan.opts.Progress = progress
	input := bytes.Repeat([]byte("q"), 2*pieceio.QRMaxBytes)
	_, _, err := exportSplit(io.Discard, plan, &cliOptions{yes: true, format: "qr"}, input, "doc")
	if err == nil || !strings.Contains(err.Error(), "QR") {
		t.Fatalf("a QR code too small for the pieces was not refused: %v", err)
	}
	if shown := out.String(); strings.Contains(shown, "encrypting") {
		t.Fatalf("the input was encrypted before the refusal: %q", shown)
	}
	if files, _ := os.ReadDir(plan.outDir); len(files) != 0 {
		t.Fatalf("the refused split wrote %d files", len(files))
	}
}

// TestCombineLetsThePiecesGo checks a combine releases the piece files it is
// given once they have opened, so they are not held through the rebuild.
func TestCombineLetsThePiecesGo(t *testing.T) {
	pieces, err := core.Split([]byte("let go"), core.SplitOptions{N: 2, K: 2, Keyless: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := combinePieces(&cliOptions{yes: true}, pieces, nil); err != nil || string(got) != "let go" {
		t.Fatalf("combine: %q, %v", got, err)
	}
	for i, p := range pieces {
		if p != nil {
			t.Fatalf("piece %d was held after the combine", i+1)
		}
	}
}

// TestTheCheckKeepsItsLineDrawn checks the line stays drawn through a full
// check of many small groups, and is blank when the check is over, in both
// modes. Each group's rebuild once blanked it as it ended, a moment after the
// step before had been drawn, so the check looked stuck.
func TestTheCheckKeepsItsLineDrawn(t *testing.T) {
	blanked := regexp.MustCompile(`\r +\r`)
	for _, mode := range []verifyMode{verifyFull, verifyFast} {
		input, written, formats, plan := uncheckedSplit(t, 40, 2, "binary")
		out := showProgress(t)
		if _, err := verifySplit(mode, input, written, formats, plan); err != nil {
			t.Fatal(err)
		}
		shown := out.String()
		if !strings.Contains(shown, "checking: ") {
			t.Fatalf("%v: the check showed nothing: %q", mode, shown)
		}
		// The fast check blanks once between reading and rebuilding.
		if n := len(blanked.FindAllString(shown, -1)); n > 2 {
			t.Errorf("%v: the line was blanked %d times during the check", mode, n)
		}
		if !blanked.MatchString(shown[max(0, len(shown)-200):]) || !strings.HasSuffix(shown, "\r") {
			t.Errorf("%v: the line was left drawn after the check: %q", mode, shown[max(0, len(shown)-60):])
		}
	}

	// A rebuild ending inside the check leaves the line for the next step.
	out := showProgress(t)
	checkStep("rebuilding", 0, 0)
	drawnBefore := out.Len()
	checkStep("", 0, 0)
	if out.Len() != drawnBefore {
		t.Errorf("the end of a rebuild redrew the line: %q", out.String()[drawnBefore:])
	}
	if !strings.Contains(out.String(), "checking: rebuilding") {
		t.Errorf("the rebuild's step was not shown: %q", out.String())
	}
}

// TestASlowFileIsNamedWhileItIsRead checks the line names the file a command is
// waiting on, not the one before it. The second file is held back until the
// line names it, which it never did when the step was set only once a file had
// been read.
func TestASlowFileIsNamedWhileItIsRead(t *testing.T) {
	showProgress(t)
	dir := t.TempDir()
	var paths []string
	for i := range 3 {
		p := filepath.Join(dir, fmt.Sprintf("p%d", i))
		if err := os.WriteFile(p, bytes.Repeat([]byte{byte(i + 1)}, 100), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	step := func() string {
		p := activeProgress.Load()
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.step
	}
	named := make(chan bool, 1)
	saved := loadPiece
	t.Cleanup(func() { loadPiece = saved })
	loadPiece = func(path string) ([]byte, pieceio.Detected, error) {
		if path == paths[1] {
			deadline := time.Now().Add(10 * time.Second)
			for step() != "reading file 2 of 3" && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			named <- step() == "reading file 2 of 3"
		}
		return saved(path)
	}
	if _, err := loadInputs(io.Discard, paths, true); err != nil {
		t.Fatal(err)
	}
	if !<-named {
		t.Fatal("the line did not name the file being waited for")
	}
}

// TestNoLineOverDataOnATerminal checks the line is blank while data goes to or
// comes from the terminal it is drawn on, where it would be drawn over the
// recovered secret, or over the input as it is typed: a step already shown is
// blanked, and the data's own step is not shown.
func TestNoLineOverDataOnATerminal(t *testing.T) {
	old, oldIn := streamIsTerminal, os.Stdin
	defer func() { streamIsTerminal, os.Stdin = old, oldIn }()
	streamIsTerminal = func(*os.File) bool { return true }
	out := showProgress(t)
	progress("decrypting", 0, 0)
	shown := drawn(out)

	var err error
	printed := withInput(t, "", func() { err = writeRecovered(&cliOptions{yes: true}, []byte("the secret"), "") })
	if err != nil || printed != "the secret" {
		t.Fatalf("printed %q: %v", printed, err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString("typed")
	w.Close()
	defer swap(&os.Stdin, r)()
	in, err := readSplitInput(&cliOptions{yes: true, files: []string{"-"}})
	r.Close()
	if err != nil || string(in.data) != "typed" {
		t.Fatalf("read %q: %v", in.data, err)
	}
	if got := drawn(out); got != blank(len(shown)-1) {
		t.Fatalf("drew %q around data on the terminal, want %q", got, blank(len(shown)-1))
	}
}

// TestProgressLineIsBlankedForGood checks the line an interrupt leaves is
// blanked, and stays blank whatever ticks after.
func TestProgressLineIsBlankedForGood(t *testing.T) {
	var out bytes.Buffer
	c := newClock()
	p := linePast(c, &out)
	p.report("decrypting", 0, 0)
	p.clear()
	p.tick()
	if got, want := drawn(&out), "\r  decrypting (1s)"+blank(len("  decrypting (1s)")); got != want {
		t.Fatalf("drew %q, want %q", got, want)
	}
}

// TestPromptBlanksTheLine checks a question is never drawn over: the line is
// wiped before it is asked and stays wiped until it is answered.
func TestPromptBlanksTheLine(t *testing.T) {
	out := showProgress(t)
	progress("rebuilding", 1, 4)
	shown := len(drawn(out)) - 1
	withTerminal(t, "yes\n", func() {
		if ok, err := confirm("Go on", false); err != nil || !ok {
			t.Fatalf("confirm: %v, %v", ok, err)
		}
	})
	if got := drawn(out); got != blank(shown) {
		t.Fatalf("around the question the line drew %q", got)
	}
	activeProgress.Load().tick()
	if !strings.Contains(drawn(out), "rebuilding 25%") {
		t.Fatal("the line did not come back after the question")
	}
}
