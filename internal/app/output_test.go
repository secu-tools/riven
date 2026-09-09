// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// captureBoth runs fn with stdout and stderr replaced by pipes. Both are drained
// while fn runs, since output larger than a pipe buffer would otherwise deadlock.
func captureBoth(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wOut, wErr

	outCh, errCh := make(chan string), make(chan string)
	drain := func(r *os.File, ch chan string) {
		var b bytes.Buffer
		io.Copy(&b, r)
		ch <- b.String()
	}
	go drain(rOut, outCh)
	go drain(rErr, errCh)

	fn()

	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	o, e := <-outCh, <-errCh
	rOut.Close()
	rErr.Close()
	return o, e
}

// A generated password is the only copy that will exist. isInteractive tests
// stdin, so with stdin a terminal and stdout redirected -- `riven split x > log`
// -- gating on it would write the password into the log. It has to reach the
// terminal instead.
func TestGeneratedPasswordDoesNotFollowRedirectedStdout(t *testing.T) {
	plan := planFor(t, "--generate", "--kdf", "m=8,t=1,p=1")
	if len(plan.generated) == 0 {
		t.Fatal("no password was generated")
	}
	secret := string(plan.generated[0])

	// yes:false is the human path; the pipes make stdout a non-terminal, which is
	// what a redirect looks like.
	stdout, stderr := captureBoth(t, func() {
		if err := reportGeneratedPasswords(&cliOptions{}, plan); err != nil {
			t.Error(err)
		}
	})

	if strings.Contains(stdout, secret) {
		t.Error("the generated password was written to redirected standard output")
	}
	if !strings.Contains(stderr, secret) {
		t.Errorf("the generated password did not reach the terminal:\nstderr=%q", stderr)
	}
}

// The recorded name comes from whoever wrote the piece, so it must never create
// a file on its own. Without a terminal the data goes to standard output; with
// one the name is offered as a prompt default, which needs a pty and is covered
// only by hand.
func TestRecoveredDataDoesNotCreateTheRecordedName(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	data := []byte("recovered contents")
	stdout, _ := captureBoth(t, func() {
		if err := writeRecovered(&cliOptions{yes: true}, data, ".bash_profile"); err != nil {
			t.Error(err)
		}
	})

	if _, err := os.Stat(".bash_profile"); err == nil {
		t.Fatal("a name recorded in a piece created a file with no confirmation")
	}
	if !strings.Contains(stdout, string(data)) {
		t.Errorf("the recovered data did not reach standard output: %q", stdout)
	}
}

// --out still names the file, and that is the user's own choice.
func TestRecoveredDataHonoursOut(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	data := []byte("recovered contents")
	captureBoth(t, func() {
		if err := writeRecovered(&cliOptions{yes: true, outDir: "out.bin"}, data, "ignored.txt"); err != nil {
			t.Error(err)
		}
	})

	got, err := os.ReadFile("out.bin")
	if err != nil {
		t.Fatalf("--out was not honoured: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("wrote %q, want %q", got, data)
	}
}

// os.WriteFile applies its mode only when it creates the file, so writing a
// private key over an existing world-readable one would have kept that mode.
func TestWriteSecretTightensAnExistingFilesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are not enforced on Windows; access follows inherited ACLs")
	}
	path := filepath.Join(t.TempDir(), "id.key")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSecret(path, []byte("a private key")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode is %04o, want 0600: a private key stayed readable by others", perm)
	}
}

// A file name is attacker-controlled when a directory of "pieces" is unpacked
// from an archive, and on unix it may contain terminal escapes.
func TestUnreadableFileNameIsEscapedInOutput(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "piece\x1b[31m.bin")
	if err := os.WriteFile(name, []byte("not a piece"), 0o600); err != nil {
		t.Skipf("this filesystem will not hold an escape in a name: %v", err)
	}

	var out bytes.Buffer
	if _, err := loadInputs(&out, []string{name}, false); err == nil {
		t.Fatal("a file that is not a piece was accepted")
	}
	if strings.ContainsRune(out.String(), 0x1b) {
		t.Errorf("a raw escape reached the terminal: %q", out.String())
	}
}
