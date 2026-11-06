// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/pieceio"
)

// TestColorWanted covers the conventions that decide colour before a terminal
// is asked: --no-color, NO_COLOR (any non-empty value), TERM=dumb, and an unset
// TERM outside Windows.
func TestColorWanted(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		flag bool
		goos string
		want bool
	}{
		{"a terminal", map[string]string{"TERM": "xterm-256color"}, false, "linux", true},
		{"the flag", map[string]string{"TERM": "xterm"}, true, "linux", false},
		{"NO_COLOR", map[string]string{"TERM": "xterm", "NO_COLOR": "1"}, false, "linux", false},
		{"NO_COLOR=0 still counts", map[string]string{"TERM": "xterm", "NO_COLOR": "0"}, false, "linux", false},
		{"an empty NO_COLOR does not", map[string]string{"TERM": "xterm", "NO_COLOR": ""}, false, "linux", true},
		{"TERM=dumb", map[string]string{"TERM": "dumb"}, false, "linux", false},
		{"no TERM outside Windows", map[string]string{}, false, "linux", false},
		{"no TERM on Windows", map[string]string{}, false, "windows", true},
		{"TERM=dumb on Windows", map[string]string{"TERM": "dumb"}, false, "windows", false},
		{"NO_COLOR on Windows", map[string]string{"NO_COLOR": "yes"}, false, "windows", false},
	}
	for _, c := range cases {
		lookup := func(k string) (string, bool) { v, ok := c.env[k]; return v, ok }
		if got := colorWanted(lookup, c.flag, c.goos); got != c.want {
			t.Errorf("%s: colour %v, want %v", c.name, got, c.want)
		}
	}
}

// TestNoColorRequested checks the flag is found before parsing, and that a file
// named after it, after --, is not taken for it.
func TestNoColorRequested(t *testing.T) {
	cases := map[string]bool{
		"split f --no-color":    true,
		"--no-color info p":     true,
		"split f":               false,
		"split -- --no-color":   false,
		"combine --no-colour p": false,
	}
	for args, want := range cases {
		if got := noColorRequested(strings.Fields(args)); got != want {
			t.Errorf("%q: %v, want %v", args, got, want)
		}
	}
	if _, err := parseArgs([]string{"split", "f", "--no-color"}); err != nil {
		t.Fatalf("the parser refuses --no-color: %v", err)
	}
}

// TestSetupColorHonoursNoColor checks a set NO_COLOR leaves every stream plain,
// whatever they are attached to.
func TestSetupColorHonoursNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	restore := setupColor(false)
	defer restore()
	if len(colorOn) != 0 {
		t.Fatal("NO_COLOR left colour on")
	}
}

// withFakeConsole stands a console in for standard output and standard error,
// one that takes colour, and returns how many times one has been put back.
func withFakeConsole(t *testing.T) *int {
	t.Helper()
	restored := 0
	oldTerm, oldEnable := streamIsTerminal, enableStream
	streamIsTerminal = func(*os.File) bool { return true }
	enableStream = func(*os.File) (bool, func()) { return true, func() { restored++ } }
	t.Cleanup(func() {
		streamIsTerminal, enableStream = oldTerm, oldEnable
		colorOn = map[*os.File]bool{}
	})
	t.Setenv("TERM", "xterm")
	t.Setenv("NO_COLOR", "")
	return &restored
}

// TestConsoleIsRestoredOnASignalOrACrash checks the path that does not return:
// memory.Cleanup, which the signal handler and GuardPanic run before the process
// ends, puts both consoles back, and the ordinary restore afterwards does not
// do it a second time.
func TestConsoleIsRestoredOnASignalOrACrash(t *testing.T) {
	restored := withFakeConsole(t)
	finish := setupColor(false)
	if len(colorOn) != 2 {
		t.Fatalf("colour is on for %d streams, want 2", len(colorOn))
	}
	memory.Cleanup()
	if *restored != 2 {
		t.Fatalf("the cleanup put %d console(s) back, want 2", *restored)
	}
	finish()
	if *restored != 2 {
		t.Fatalf("the consoles were put back %d times in all, want once each", *restored)
	}
}

// TestConsoleIsRestoredOnANormalExit checks the ordinary path puts the consoles
// back and takes its cleanup hook away, so a signal arriving later does nothing
// further.
func TestConsoleIsRestoredOnANormalExit(t *testing.T) {
	restored := withFakeConsole(t)
	finish := setupColor(false)
	finish()
	if *restored != 2 || len(colorOn) != 0 {
		t.Fatalf("put back %d console(s), colour still on for %d stream(s)", *restored, len(colorOn))
	}
	memory.Cleanup()
	if *restored != 2 {
		t.Fatalf("a later cleanup put the consoles back again (%d)", *restored)
	}
}

// withColor marks f as a stream that takes colour for the length of the test.
func withColor(t *testing.T, f *os.File) {
	t.Helper()
	colorOn = map[*os.File]bool{f: true}
	t.Cleanup(func() { colorOn = map[*os.File]bool{} })
}

func tempFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// TestPaintOnlyWhereColourIsOn checks escape codes go only to a stream that takes
// them, and wrap the text exactly.
func TestPaintOnlyWhereColourIsOn(t *testing.T) {
	f := tempFile(t)
	if got := paint(f, toneError, "error:"); got != "error:" {
		t.Fatalf("painted a stream without colour: %q", got)
	}
	withColor(t, f)
	if got := paint(f, toneError, "error:"); got != "\x1b[1;31merror:\x1b[0m" {
		t.Fatalf("painted as %q", got)
	}
	if got := paint(os.Stderr, toneError, "error:"); got != "error:" {
		t.Fatalf("painted another stream: %q", got)
	}
	if got := paint(f, toneGood, ""); got != "" {
		t.Fatalf("painted nothing as %q", got)
	}
}

// escapes matches an SGR escape sequence.
var escapes = regexp.MustCompile("\x1b\\[[0-9;]*m")

// TestWriteLabeledFoldsByVisibleWidth checks the escape codes around a label do
// not count towards the width: with colour on, every line is as wide as it would
// be without it, and the label alone is coloured.
func TestWriteLabeledFoldsByVisibleWidth(t *testing.T) {
	f := tempFile(t)
	withColor(t, f)
	body := strings.Repeat("a few words that have to fold ", 6)
	withLineWidth(t, 40, func() { writeLabeled(f, "warning:", toneWarning, body) })
	raw, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "\x1b[1;33mwarning:\x1b[0m ") {
		t.Fatalf("the label is not coloured: %q", raw)
	}
	lines := strings.Split(strings.TrimRight(escapes.ReplaceAllString(string(raw), ""), "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected the body to fold: %q", lines)
	}
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > 40 {
			t.Errorf("line of %d columns, over 40: %q", n, l)
		}
	}
	if strings.Count(string(raw), "\x1b[") != 2 {
		t.Errorf("more than the label is coloured: %q", raw)
	}
}

// TestNoEscapeCodesWithoutColour runs the commands a script runs, with colour
// off as it is for a pipe, and checks no escape code reaches the output, so a
// log or a file never fills with them.
func TestNoEscapeCodesWithoutColour(t *testing.T) {
	t.Setenv("RIVEN_UNIT_ESC", "plain output")
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte("no colour here"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "o")
	runs := [][]string{
		{"split", in, "-n", "3", "-k", "2", "--password-env", "RIVEN_UNIT_ESC", "--kdf", "m=8,t=1,p=1",
			"--algo", "chacha20-poly1305", "--record-algo", "false", "--out", out, "-y"},
		{"info", out, "--password-env", "RIVEN_UNIT_ESC", "--algo", "chacha20-poly1305", "-y"},
		{"verify", out, "--password-env", "RIVEN_UNIT_ESC", "--algo", "chacha20-poly1305", "-y"},
		{"combine", filepath.Join(out, "in.txt.1"), "--password-env", "RIVEN_UNIT_ESC", "-y"},
		{"help"},
	}
	for _, args := range runs {
		got, err := captureOutput(t, func() error {
			if err := run(args); err != nil {
				printError(os.Stderr, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(got, "\x1b") {
			t.Fatalf("riven %v printed an escape code:\n%q", args, got)
		}
	}
}

// TestHelpFitsEightyColumns checks the help, which is printed as it is rather
// than folded, fits the narrowest common window: PuTTY's and the classic
// console's 80 columns, with the last left free.
func TestHelpFitsEightyColumns(t *testing.T) {
	for i, line := range strings.Split(capture(t, printUsage), "\n") {
		if n := utf8.RuneCountInString(line); n > helpWidth {
			t.Errorf("help line %d is %d columns: %q", i+1, n, line)
		}
	}
}

// TestMessagesFitEightyColumns runs a split, its summary and warnings, info,
// verify and the failures they report at a width of 80, and checks no line is
// wider than 79. A line that is a single path is the one exception: it has no
// space to break at.
func TestMessagesFitEightyColumns(t *testing.T) {
	t.Setenv("RIVEN_UNIT_W", "eighty columns")
	// Relative paths, as typed at a prompt: a long absolute path cannot fit any
	// width, and is not what a window this narrow is usually given.
	t.Chdir(t.TempDir())
	in := "a-rather-long-file-name-for-the-summary.bin"
	if err := os.WriteFile(in, []byte("fits the window"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("other", 0o700); err != nil {
		t.Fatal(err)
	}
	other := writeSet(t, "other", core.SplitOptions{N: 2, K: 2, Keyless: true}, []byte("other"), pieceio.Binary)
	piece := filepath.Join("o", in+".1")
	runs := [][]string{
		{"split", in, "-n", "5", "-k", "3", "--password-env", "RIVEN_UNIT_W", "--kdf", "m=8,t=1,p=1",
			"--algo", "chacha20-poly1305", "--record-algo", "false", "--record-kdf", "false", "--pad", "none",
			"--method", "compact",
			"--format", "binary,qr", "--out", "o", "-y"},
		{"info", "o", "--password-env", "RIVEN_UNIT_W", "--algo", "chacha20-poly1305", "--kdf", "m=8,t=1,p=1", "-y"},
		{"verify", "o", "--password-env", "RIVEN_UNIT_W", "--algo", "chacha20-poly1305", "--kdf", "m=8,t=1,p=1", "-y"},
		{"combine", piece, other[0], "-y"},
		{"combine", piece, "--password-env", "RIVEN_UNIT_W", "-y"},
		{"split", ".", "-y"},
	}
	withLineWidth(t, fallbackLineWidth-1, func() {
		for _, args := range runs {
			got, err := captureOutput(t, func() error {
				if err := run(args); err != nil {
					printError(os.Stderr, err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(got, "\n") {
				if n := utf8.RuneCountInString(line); n > 79 && len(strings.Fields(line)) > 1 {
					t.Errorf("riven %s: a line of %d columns:\n%s", args[0], n, line)
				}
			}
		}
	})
}

// TestErrorsReadAsSentences checks an error names no internal package, and that
// a piece that did not open is named by its file rather than its position.
func TestErrorsReadAsSentences(t *testing.T) {
	t.Setenv("RIVEN_UNIT_SENT", "the password")
	t.Setenv("RIVEN_UNIT_WRONG", "not the password")
	dir := t.TempDir()
	paths := writeSet(t, dir, core.SplitOptions{N: 2, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("the password")}}},
		[]byte("named"), pieceio.Binary)
	opts := verifyOpts(t, paths)
	opts.command, opts.layerSources = "combine", []layerSource{{kind: core.PasswordLayer, env: "RIVEN_UNIT_WRONG"}}
	got, _ := captureOutput(t, func() error {
		printError(os.Stderr, cmdCombine(opts))
		return nil
	})
	got = strings.Join(strings.Fields(got), " ")
	for _, prefix := range []string{"core:", "format:", "cascade:"} {
		if strings.Contains(got, prefix) {
			t.Errorf("the error names an internal package (%s): %s", prefix, got)
		}
	}
	if !strings.Contains(got, "riven: error:") || !strings.Contains(got, filepath.Base(paths[0])) {
		t.Fatalf("the error does not name the piece's file: %s", got)
	}
}

// TestHumanizeDropsPackageNames checks the prefixes come off wherever they sit
// in a chain of wrapped errors, and that nothing else does.
func TestHumanizeDropsPackageNames(t *testing.T) {
	cases := map[string]string{
		"core: piece 1 did not open: format: wrong password": "piece 1 did not open: wrong password",
		"cascade: a key is required: layer 2: kem: too long": "a key is required: layer 2: too long",
		"invalid --format: core: nothing":                    "invalid --format: nothing",
		"export format: kept":                                "export format: kept",
	}
	for in, want := range cases {
		if got := humanize(errorString(in)); got != want {
			t.Errorf("%q became %q, want %q", in, got, want)
		}
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
