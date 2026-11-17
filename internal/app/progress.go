// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/secu-tools/riven/internal/memory"
)

// A long split or combine says what it is doing, so it never looks stuck: one
// line on standard error, redrawn in place, with the step, how far it has got
// when that can be measured, and the time since the command started. It shows
// only on a terminal, and only once the command has run for progressDelay, so a
// quick one prints nothing extra. The line is blank whenever no step is under
// way, which the core arranges before any question and before it returns, and
// a prompt blanks it too, so nothing else is printed across it.

const (
	progressDelay  = time.Second
	progressTick   = 250 * time.Millisecond
	progressRedraw = 100 * time.Millisecond // the least time between draws of new steps
)

// progressLine is the line one command draws.
type progressLine struct {
	mu          sync.Mutex
	out         io.Writer
	now         func() time.Time
	start       time.Time // when the command started
	step        string
	done, total int64
	shown       int       // columns drawn, so the next draw can blank them
	drawnAt     time.Time // when the line was last drawn
	held        int       // prompts under way
}

func newProgressLine(out io.Writer, now func() time.Time) *progressLine {
	return &progressLine{out: out, now: now, start: now()}
}

// report is a core.Progress. A new step is drawn at once, so the line never
// lags behind what the command is doing, unless the line was drawn less than
// progressRedraw ago: a split into thousands of pieces has a step for each, and
// a console cannot redraw that fast. That step, and the same step moving on, are
// left to the next tick. No step, which blanks the line before anything else is
// printed, is never held back.
func (p *progressLine) report(step string, done, total int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if step == p.step && total == p.total {
		p.done = max(p.done, done) // the units of a step finish out of order
		return
	}
	p.step, p.done, p.total = step, done, total
	if step == "" || p.now().Sub(p.drawnAt) >= progressRedraw {
		p.draw()
	}
}

// tick redraws the line, so the time moves on through a step that cannot be
// measured.
func (p *progressLine) tick() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.draw()
}

// hold blanks the line for a prompt and keeps it blank until the returned
// function is called.
func (p *progressLine) hold() func() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.held++
	p.draw()
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.held--
	}
}

// draw shows the current step, or blanks the line when there is none, a prompt
// holds it, or the command is too young for it. p.mu is held.
func (p *progressLine) draw() {
	text := ""
	if p.step != "" && p.held == 0 && p.now().Sub(p.start) >= progressDelay {
		text = p.text()
	}
	if text == "" && p.shown == 0 {
		return
	}
	line := "\r" + text + strings.Repeat(" ", max(p.shown-len(text), 0))
	if text == "" {
		line += "\r"
	}
	fmt.Fprint(p.out, line)
	p.shown = len(text)
	p.drawnAt = p.now()
}

// text is the line for the current step, kept to one row so the carriage
// return goes back to its start.
func (p *progressLine) text() string {
	s := "  " + p.step
	if p.total > 0 {
		s += fmt.Sprintf(" %d%%", min(p.done, p.total)*100/p.total)
	}
	s += fmt.Sprintf(" (%s)", p.now().Sub(p.start).Truncate(time.Second))
	if w := lineWidth() - 1; len(s) > w {
		s = s[:w]
	}
	return s
}

// run redraws the line every interval until the returned function is called,
// which blanks it.
func (p *progressLine) run(interval time.Duration) func() {
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				p.tick()
			}
		}
	}()
	return func() {
		close(stop)
		<-stopped
		p.report("", 0, 0)
	}
}

// activeProgress is the line of the command running, when it shows one.
var activeProgress atomic.Pointer[progressLine]

// startProgress shows the progress line while a command runs, when standard
// error is a terminal that can redraw a line. Call the returned function before
// the command returns.
func startProgress() func() {
	if !streamIsTerminal(os.Stderr) || os.Getenv("TERM") == "dumb" {
		return func() {}
	}
	p := newProgressLine(os.Stderr, time.Now)
	stop := p.run(progressTick)
	activeProgress.Store(p)
	// An interrupt exits without coming back here, so the line is blanked on the
	// way out rather than left for the shell prompt to follow.
	unhook := memory.OnCleanup(p.clear)
	return func() {
		unhook()
		activeProgress.Store(nil)
		stop()
	}
}

// clear blanks the line for good. A draw under way may be stuck on a terminal
// that is not taking output, and an interrupt must still exit, so it gives up
// rather than wait for one.
func (p *progressLine) clear() {
	if !p.mu.TryLock() {
		return
	}
	defer p.mu.Unlock()
	p.step = ""
	p.draw()
}

// progress is a core.Progress for the running command's line. Without one it
// does nothing.
func progress(step string, done, total int64) {
	if p := activeProgress.Load(); p != nil {
		p.report(step, done, total)
	}
}

// checking is progress for the check after a split, which runs the same steps
// as a combine.
func checking(step string, done, total int64) {
	if step != "" {
		step = "checking: " + step
	}
	progress(step, done, total)
}

// readingFile names file i of n, counted from zero, as the one being read. Files
// are read ahead of the one in use, so it is told both the file taken and the
// one waited for: without the second, a slow file, such as a large photograph to
// decode, would show the step of the one before it, or none, while it is read.
func readingFile(report func(step string, done, total int64), n int) func(i int) {
	return func(i int) { report(fmt.Sprintf("reading file %d of %d", i+1, n), 0, 0) }
}

// checkStep is checking for a rebuild inside the check. core reports no step
// each time a rebuild ends, which would blank the line while the check goes on,
// and in a check of thousands of small groups leave it blank nearly throughout.
// The step is left for the next one to replace, and verifySplit blanks the line
// when the check is over.
func checkStep(step string, done, total int64) {
	if step != "" {
		checking(step, done, total)
	}
}

// during runs fn, which moves the command's data, under step. When the data
// goes through f to or from the terminal the line is drawn on, the line is held
// blank instead, as for a prompt, so it is not drawn over the data shown or the
// input as it is typed. f is nil for a file.
func during(step string, f *os.File, fn func() error) error {
	if f != nil && streamIsTerminal(f) {
		defer holdProgress()()
	} else {
		progress(step, 0, 0)
	}
	defer progress("", 0, 0)
	return fn()
}

// holdProgress blanks the running command's line while a prompt waits for an
// answer.
func holdProgress() func() {
	if p := activeProgress.Load(); p != nil {
		return p.hold()
	}
	return func() {}
}
