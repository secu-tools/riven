// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// captureOutput runs fn with os.Stdout and os.Stderr redirected to a pipe, so a
// command's human-readable output can be inspected. A goroutine drains the pipe
// to avoid blocking on a full buffer.
func captureOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	runErr := fn()
	w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return <-done, runErr
}

// runSplit runs a non-interactive split with the given extra args, returning the
// output directory.
func runSplit(t *testing.T, extra ...string) (dir, out string) {
	t.Helper()
	dir = t.TempDir()
	args := append([]string{"split", "--text", "split-me", "-n", "3", "-k", "2",
		"--keyless", "-o", dir, "-y"}, extra...)
	opts, err := parseArgs(args)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	out, err = captureOutput(t, func() error { return cmdSplit(opts) })
	if err != nil {
		t.Fatalf("cmdSplit: %v\n%s", err, out)
	}
	return dir, out
}

func TestSplitVerifyReporting(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    string
		notWant string
	}{
		{"default verifies", nil, "Verification: PASSED", ""},
		{"--no-verify skips", []string{"--no-verify"}, "Verification: SKIPPED", "Verification: PASSED"},
		{"--verify false skips", []string{"--verify", "false"}, "Verification: SKIPPED", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, out := runSplit(t, c.args...)
			if !strings.Contains(out, c.want) {
				t.Errorf("expected %q in output:\n%s", c.want, out)
			}
			if c.notWant != "" && strings.Contains(out, c.notWant) {
				t.Errorf("did not expect %q in output:\n%s", c.notWant, out)
			}
		})
	}
}

// TestInfoShowsCreatorLine checks the CLI reports which build wrote a piece. The
// test binary's version globals are the "dev" defaults, so that is what appears.
func TestInfoShowsCreatorLine(t *testing.T) {
	dir, _ := runSplit(t)

	opts, err := parseArgs([]string{"info", filepath.Join(dir, "secret.1"), "-y"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := captureOutput(t, func() error { return cmdInfo(opts) })
	if err != nil {
		t.Fatalf("info: %v\n%s", err, out)
	}
	if !strings.Contains(out, "created by : riven "+version+"."+buildNumber+" ("+commit+")") {
		t.Errorf("info did not report the creating build:\n%s", out)
	}
}

// TestCombineI18nPasswordDifferentComposition is the CLI-level promise: a set
// split with a password entered in one Unicode composition reconstructs when the
// same password is supplied in another. Both forms are valid UTF-8 so they round
// trip through the environment on every platform; the GB18030 path is covered by
// the core package, which is not constrained by the OS environment encoding.
func TestCombineI18nPasswordDifferentComposition(t *testing.T) {
	nfc := norm.NFC.String("clé-café-Über") // precomposed
	nfd := norm.NFD.String(nfc)             // combining marks
	if nfc == nfd {
		t.Fatal("test bug: NFC and NFD are byte-identical")
	}

	dir := t.TempDir()
	t.Setenv("RIVEN_I18N_SPLIT", nfc)
	splitArgs := []string{"split", "--text", "i18n secret payload", "-n", "3", "-k", "2",
		"--password-env", "RIVEN_I18N_SPLIT", "--kdf", "m=8,t=1,p=1",
		"-o", dir, "-y"}
	sOpts, err := parseArgs(splitArgs)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := captureOutput(t, func() error { return cmdSplit(sOpts) }); err != nil {
		t.Fatalf("split: %v\n%s", err, out)
	}

	outPath := filepath.Join(dir, "recovered.txt")
	t.Setenv("RIVEN_I18N_COMBINE", nfd)
	combineArgs := []string{"combine",
		filepath.Join(dir, "secret.1"), filepath.Join(dir, "secret.2"),
		"--password-env", "RIVEN_I18N_COMBINE", "-o", outPath, "-y"}
	cOpts, err := parseArgs(combineArgs)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := captureOutput(t, func() error { return cmdCombine(cOpts) }); err != nil {
		t.Fatalf("combine with alternate composition failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "i18n secret payload" {
		t.Fatalf("recovered %q, want the original payload", got)
	}
}
