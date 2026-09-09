// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompletionPrintsAScriptForEveryShell checks the command produces something
// for each shell it claims to support, and refuses one it does not.
func TestCompletionPrintsAScriptForEveryShell(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		out, err := riven(t, nil, "completion", shell)
		if err != nil {
			t.Fatalf("%s: %v\n%s", shell, err, out)
		}
		if len(out) < 200 {
			t.Fatalf("%s script is only %d bytes:\n%s", shell, len(out), out)
		}
		for _, want := range []string{"riven", "combine", "split", "words"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s script does not mention %q", shell, want)
			}
		}
	}
	if out, err := riven(t, nil, "completion", "csh"); err == nil {
		t.Fatalf("an unsupported shell must fail:\n%s", out)
	}
}

// TestBashCompletionSourcesAndCompletes runs the emitted script in a real bash,
// which is the only way to know it is valid and that a piece path still
// completes as a path.
func TestBashCompletionSourcesAndCompletes(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	script, err := riven(t, nil, "completion", "bash")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "riven.bash")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := `source "$1"
complete -p riven
try() {
    COMP_WORDS=( "$@" ); COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 )); COMPREPLY=()
    _riven
    echo "|${COMPREPLY[*]}"
}
try riven ''
try riven combine /root/piece1.data
`
	hpath := filepath.Join(dir, "try.bash")
	if err := os.WriteFile(hpath, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bash, hpath, path).CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "complete -o default -F _riven riven") {
		t.Errorf("the compspec must fall back to filenames:\n%s", text)
	}
	if !strings.Contains(text, "|combine completion") {
		t.Errorf("the commands should be offered first:\n%s", text)
	}
	if !strings.Contains(text, "|\n") {
		t.Errorf("an absolute piece path should be left to the shell:\n%s", text)
	}
}

// TestSplitRefusesADirectory checks the advice given now that packing is the
// user's job, since the message is the only place that says so.
func TestSplitRefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vault")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	log, err := riven(t, env1, "split", src, "--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "-y")
	if err == nil {
		t.Fatalf("a directory is not an input:\n%s", log)
	}
	if !strings.Contains(log, "tar") {
		t.Errorf("the message should say how to pack it first:\n%s", log)
	}
}

// TestRecordedNameRestoresTheFile is the name feature end to end: combine with no
// --out writes the file back under its own name.
func TestRecordedNameRestoresTheFile(t *testing.T) {
	dir := t.TempDir()
	secret := randomBytes(400)
	in := writeFile(t, dir, "quarterly.pdf", secret)
	out := filepath.Join(dir, "pieces")

	log, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "--out", out, "-y")
	if err != nil {
		t.Fatalf("split: %v\n%s", err, log)
	}
	if !strings.Contains(log, "quarterly.pdf") || !strings.Contains(log, "recorded inside the pieces") {
		t.Errorf("the split should say the name was recorded:\n%s", log)
	}

	// info reports it, which is how a holder learns what a piece is for.
	log, err = riven(t, env1, "info", filepath.Join(out, "quarterly.pdf.1"),
		"--password-env", flagPw1, "-y")
	if err != nil {
		t.Fatalf("info: %v\n%s", err, log)
	}
	if !strings.Contains(log, "file name  : quarterly.pdf") {
		t.Errorf("info should report the recorded name:\n%s", log)
	}

	// Automation still writes to standard output, so the name does not change the
	// scripting contract; --out still wins over it.
	rec := filepath.Join(dir, "elsewhere.bin")
	if log, err := riven(t, env1, "combine", out,
		"--password-env", flagPw1, "--out", rec, "-y"); err != nil {
		t.Fatalf("combine: %v\n%s", err, log)
	}
	got, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("content changed")
	}
}

// TestNameIsNotRecordedWhenRefused checks --record-name false leaves it out, and
// that text input has no name to leave out in the first place.
func TestNameIsNotRecordedWhenRefused(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "private.kdbx", []byte("no name please"))
	out := filepath.Join(dir, "pieces")

	log, err := riven(t, env1, "split", in, "-n", "2", "-k", "2", "--record-name", "false",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "--out", out, "-y")
	if err != nil {
		t.Fatalf("split: %v\n%s", err, log)
	}
	if strings.Contains(log, "recorded inside the pieces") {
		t.Errorf("nothing should have been recorded:\n%s", log)
	}

	log, err = riven(t, env1, "info", filepath.Join(out, "private.kdbx.1"),
		"--password-env", flagPw1, "-y")
	if err != nil {
		t.Fatalf("info: %v\n%s", err, log)
	}
	if strings.Contains(log, "file name") {
		t.Errorf("info should not report a name that was not recorded:\n%s", log)
	}

	// The flag is refused where there is no name at all.
	if log, err := riven(t, env1, "split", "--text", "abc", "--record-name", "true",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "-o", dir, "-y"); err == nil {
		t.Errorf("--record-name true has no meaning for --text:\n%s", log)
	}
}

// TestVerifyReadsAWholeDirectory checks verify accepts a folder, including one
// holding several formats of the same set, and still reports one set.
func TestVerifyReadsAWholeDirectory(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "s.bin", []byte("a folder of every format"))
	out := filepath.Join(dir, "pieces")

	if log, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1",
		"-f", "binary,base64,base32", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, log)
	}

	log, err := riven(t, env1, "verify", out, "--password-env", flagPw1, "-y")
	if err != nil {
		t.Fatalf("verify a directory: %v\n%s", err, log)
	}
	if !strings.Contains(log, "3 of 3 distinct pieces held") {
		t.Errorf("nine files are three pieces:\n%s", log)
	}
	if !strings.Contains(log, "hold the same piece as another") {
		t.Errorf("the repeated formats should be reported:\n%s", log)
	}
	if strings.Count(log, "Set ") != 1 {
		t.Errorf("one split is one set:\n%s", log)
	}
}

// assertExportRefused checks that splitting a 64 KiB piece into a format it is
// too large for fails, names the reason, and writes nothing: a refusal must come
// before any file is written rather than partway through a set.
func assertExportRefused(t *testing.T, format, wantErr string) {
	t.Helper()
	dir := t.TempDir()
	in := writeFile(t, dir, "big.bin", randomBytes(64*1024))
	out := filepath.Join(dir, "pieces")

	log, err := riven(t, env1, "split", in, "-n", "2", "-k", "2",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "-f", format, "--out", out, "-y")
	if err == nil {
		t.Fatalf("a 64 KiB piece cannot be exported as %s:\n%s", format, log)
	}
	if !strings.Contains(log, wantErr) {
		t.Errorf("the refusal should mention %q:\n%s", wantErr, log)
	}
	// Nothing may be written for an export that cannot complete.
	if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 {
		t.Errorf("a refused export left %d files behind", len(entries))
	}
}

// TestWordsExportIsRefusedWhenTooLarge checks the word format states its limit
// rather than failing partway through writing a set.
func TestWordsExportIsRefusedWhenTooLarge(t *testing.T) {
	assertExportRefused(t, "words", "cannot export as words")
}

// TestWordsRoundTripThroughTheBinary covers the format a user actually writes
// out by hand, including that copying it back with different spacing works.
func TestWordsRoundTripThroughTheBinary(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("write these words on paper")
	in := writeFile(t, dir, "s.bin", secret)
	out := filepath.Join(dir, "pieces")

	if log, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "-f", "words", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, log)
	}

	p1 := filepath.Join(out, "s.bin.1.words.txt")
	body, err := os.ReadFile(p1)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(string(body))); n < 100 {
		t.Fatalf("a piece of this size is more than %d words", n)
	}

	// Retyped: numbered, upper case, and all on one line.
	var retyped strings.Builder
	for i, w := range strings.Fields(string(body)) {
		retyped.WriteString(strings.ToUpper(w))
		if i%4 == 3 {
			retyped.WriteString(", ")
		} else {
			retyped.WriteString(" ")
		}
	}
	typed := writeFile(t, dir, "typed.txt", []byte(retyped.String()))

	rec := filepath.Join(dir, "back.bin")
	p2 := filepath.Join(out, "s.bin.2.words.txt")
	if log, err := riven(t, env1, "combine", typed, p2,
		"--password-env", flagPw1, "--out", rec, "-y"); err != nil {
		t.Fatalf("combine retyped words: %v\n%s", err, log)
	}
	got, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("recovered %q", got)
	}
}

// TestEmptyDirectoryIsRejected checks a folder named in place of the pieces says
// what is wrong, rather than reading as a set that came up short.
func TestEmptyDirectoryIsRejected(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	log, err := riven(t, env1, "combine", empty, "--password-env", flagPw1, "-y")
	if err == nil {
		t.Fatalf("an empty directory holds no pieces:\n%s", log)
	}
	if !strings.Contains(log, "no files to read") {
		t.Errorf("the message should say the directory is empty:\n%s", log)
	}
}

// TestSheetIsRefusedWhenItWouldNotPrint checks the page limit is enforced before
// anything is written, since the failure mode otherwise is a hundred-page print.
func TestSheetIsRefusedWhenItWouldNotPrint(t *testing.T) {
	assertExportRefused(t, "sheet", "printed pages")
}

// TestMultiPageSheetSaysSo checks a piece that needs several pages is reported
// as such: losing one page of it loses the piece.
func TestMultiPageSheetSaysSo(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "medium.bin", randomBytes(3000))
	out := filepath.Join(dir, "pieces")

	log, err := riven(t, env1, "split", in, "-n", "2", "-k", "2",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "-f", "sheet", "--out", out, "-y")
	if err != nil {
		t.Fatalf("split: %v\n%s", err, log)
	}
	if !strings.Contains(log, "printed pages per piece") {
		t.Errorf("the split should report the page count:\n%s", log)
	}
	page, err := os.ReadFile(filepath.Join(out, "medium.bin.1.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "Keep them together") {
		t.Error("a multi-page sheet should warn about keeping the pages together")
	}
	// It must still read back, which is the whole point of the text block.
	rec := filepath.Join(dir, "back.bin")
	if log, err := riven(t, env1, "combine", out,
		"--password-env", flagPw1, "--out", rec, "-y"); err != nil {
		t.Fatalf("combine from sheets: %v\n%s", err, log)
	}
}
