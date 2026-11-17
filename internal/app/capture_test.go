// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// drained is a pipe whose reading end is emptied as it fills, so output larger
// than a pipe buffer cannot block whatever writes it.
type drained struct {
	r, w *os.File
	done chan string
}

func newDrained(t *testing.T) *drained {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	d := &drained{r: r, w: w, done: make(chan string, 1)}
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		d.done <- b.String()
	}()
	// A test that stops early never asks for the text; this ends the drain.
	t.Cleanup(func() { _ = w.Close(); _ = r.Close() })
	return d
}

// text closes the writing end and returns everything written to it.
func (d *drained) text() string {
	_ = d.w.Close()
	return <-d.done
}

// swap points *stream at f and returns what puts it back. Deferred, it puts it
// back however the test ends, t.Fatal included, so the tests after it print to
// the real stream rather than a closed pipe.
func swap(stream **os.File, f *os.File) (restore func()) {
	old := *stream
	*stream = f
	return func() { *stream = old }
}

// capture returns whatever fn prints to standard output.
func capture(t *testing.T, fn func()) string {
	t.Helper()
	out := newDrained(t)
	defer swap(&os.Stdout, out.w)()
	fn()
	return out.text()
}

// captureBoth runs fn and returns what it printed to standard output and to
// standard error, each on its own.
func captureBoth(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	o, e := newDrained(t), newDrained(t)
	defer swap(&os.Stdout, o.w)()
	defer swap(&os.Stderr, e.w)()
	fn()
	return o.text(), e.text()
}

// captureOutput runs fn and returns what it printed to both standard streams,
// together and in order, so a command's human-readable output can be inspected.
func captureOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	out := newDrained(t)
	defer swap(&os.Stdout, out.w)()
	defer swap(&os.Stderr, out.w)()
	err := fn()
	return out.text(), err
}

// captureStderr returns what fn writes to the standard streams. The verify
// command sends its report to standard error under -y, which is how the tests
// invoke it, so that report is what comes back.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	out, _ := captureOutput(t, func() error {
		fn()
		return nil
	})
	return out
}
