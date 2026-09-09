// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"os"
	"strings"
	"testing"
)

// withArgs runs fn with os.Args replaced, as the process would see them.
func withArgs(t *testing.T, args []string, fn func()) {
	t.Helper()
	old := os.Args
	os.Args = append([]string{"riven"}, args...)
	defer func() { os.Args = old }()
	fn()
}

// Run is the process entry point: it installs the signal handler and the panic
// guard before dispatching. Nothing else exercises it, so a mistake there --
// a nil map, a panicking init, a cleanup that fails to install -- would only
// show up when a user ran the binary.
//
// Only a command that cannot fail is used, because Run calls os.Exit on error,
// which would take the test binary with it.
func TestRunStartsAndDispatches(t *testing.T) {
	out := capture(t, func() {
		withArgs(t, []string{"version"}, Run)
	})
	if !strings.Contains(out, "riven") {
		t.Fatalf("the entry point produced no version line: %q", out)
	}
}

// Running the binary with nothing to do must still come back. Without a
// terminal there is nobody to prompt, so it prints usage rather than blocking
// on a read that will never be answered -- a hang here would look like a crash
// to anything driving riven from a script.
func TestNoArgumentsPrintsUsageWithoutATerminal(t *testing.T) {
	out := capture(t, func() {
		if err := run(nil); err != nil {
			t.Errorf("a bare invocation returned an error: %v", err)
		}
	})
	for _, want := range []string{"USAGE", "split", "combine"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output is missing %q", want)
		}
	}
}

// Every command has to reach its own argument checking rather than falling over
// on the way in. Each is invoked with no arguments and -y, so none can prompt:
// an error is the expected answer for most, and a panic is never one.
func TestEveryCommandStartsWithoutPanicking(t *testing.T) {
	t.Chdir(t.TempDir())

	for name := range knownCommands {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%q panicked on startup: %v", name, r)
				}
			}()
			capture(t, func() {
				// The error is the point for most of these; only the crash matters.
				_ = run([]string{name, "-y"})
			})
		})
	}
}

// An unknown command is a user mistake, not a crash, and it must say so.
func TestUnknownCommandIsReported(t *testing.T) {
	err := run([]string{"frobnicate"})
	if err == nil {
		t.Fatal("an unknown command was accepted")
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("the error does not name the command: %v", err)
	}
}

// version and help are the two commands a user runs first, and both must work
// with no setup at all.
func TestVersionAndHelpNeedNothing(t *testing.T) {
	for _, cmd := range []string{"version", "help"} {
		out := capture(t, func() {
			if err := run([]string{cmd}); err != nil {
				t.Errorf("%s: %v", cmd, err)
			}
		})
		if strings.TrimSpace(out) == "" {
			t.Errorf("%s printed nothing", cmd)
		}
	}
}
