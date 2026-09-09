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

	"github.com/secu-tools/riven/internal/core"
)

// splitInto runs a split of one input into dir, returning nothing but a failed
// test if it did not work. The cost is kept low: these tests are about the file
// handling, not the derivation.
func splitInto(t *testing.T, input, outDir string, extra ...string) {
	t.Helper()
	args := append([]string{"split", input, "-n", "3", "-k", "2",
		"--password-env", "RIVEN_UNIT_DIR", "--kdf", "m=8,t=1,p=1", "--out", outDir, "-y"}, extra...)
	opts, err := parseArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdSplit(opts); err != nil {
		t.Fatalf("split: %v", err)
	}
}

// TestCombineReadsADirectory is the feature as a user meets it: point at the
// folder the pieces are in instead of naming each one.
func TestCombineReadsADirectory(t *testing.T) {
	t.Setenv("RIVEN_UNIT_DIR", "directory input")
	dir := t.TempDir()
	secret := []byte("named the folder, not the files")
	in := filepath.Join(dir, "s.bin")
	if err := os.WriteFile(in, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	pieces := filepath.Join(dir, "pieces")
	splitInto(t, in, pieces)

	rec := filepath.Join(dir, "back.bin")
	opts, err := parseArgs([]string{"combine", pieces,
		"--password-env", "RIVEN_UNIT_DIR", "--out", rec, "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdCombine(opts); err != nil {
		t.Fatalf("combine from a directory: %v", err)
	}
	got, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("recovered %q", got)
	}
}

// TestVerifyReadsADirectory checks the same path through verify, which reports
// rather than writes.
func TestVerifyReadsADirectory(t *testing.T) {
	t.Setenv("RIVEN_UNIT_DIR", "directory input")
	dir := t.TempDir()
	in := filepath.Join(dir, "s.bin")
	if err := os.WriteFile(in, []byte("verify a whole folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	pieces := filepath.Join(dir, "pieces")
	splitInto(t, in, pieces)

	opts, err := parseArgs([]string{"verify", pieces, "--password-env", "RIVEN_UNIT_DIR", "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdVerify(opts); err != nil {
		t.Fatalf("verify a directory: %v", err)
	}
}

// TestDirectoryIgnoresWhatIsNotAPiece checks the files that sit beside a set are
// stepped over: notes, a recovered copy, and Riven's own key files.
func TestDirectoryIgnoresWhatIsNotAPiece(t *testing.T) {
	t.Setenv("RIVEN_UNIT_DIR", "directory input")
	dir := t.TempDir()
	in := filepath.Join(dir, "s.bin")
	secret := []byte("ignore the rubbish around us")
	if err := os.WriteFile(in, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	pieces := filepath.Join(dir, "pieces")
	splitInto(t, in, pieces)

	for name, body := range map[string]string{
		"notes.txt":     "the password hint is not here",
		"riven-key.pub": "not a piece",
		"riven-key.key": "not a piece either",
		".hidden":       "nor this",
	} {
		if err := os.WriteFile(filepath.Join(pieces, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(pieces, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}

	rec := filepath.Join(dir, "back.bin")
	opts, err := parseArgs([]string{"combine", pieces,
		"--password-env", "RIVEN_UNIT_DIR", "--out", rec, "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdCombine(opts); err != nil {
		t.Fatalf("combine: %v", err)
	}
	got, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("recovered %q", got)
	}
}

// TestDirectoryCountsAPieceOnce checks a set exported in every format is not
// read as five times as many pieces. Opening one costs a key derivation, so the
// repeats are dropped before anything is opened.
func TestDirectoryCountsAPieceOnce(t *testing.T) {
	t.Setenv("RIVEN_UNIT_DIR", "directory input")
	dir := t.TempDir()
	in := filepath.Join(dir, "s.bin")
	if err := os.WriteFile(in, []byte("one piece, several files"), 0o600); err != nil {
		t.Fatal(err)
	}
	pieces := filepath.Join(dir, "pieces")
	splitInto(t, in, pieces, "-f", "binary,base64,base32,words")

	entries, err := os.ReadDir(pieces)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 12 {
		t.Fatalf("expected 3 pieces in 4 formats, found %d files", len(entries))
	}

	items, err := loadInputs(io.Discard, []string{pieces}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("loaded %d pieces from 12 files, want 3", len(items))
	}
}

// TestDirectoryReportsRepeats checks the skipped file is named, so a set that
// looked short is explained rather than silently trimmed.
func TestDirectoryReportsRepeats(t *testing.T) {
	t.Setenv("RIVEN_UNIT_DIR", "directory input")
	dir := t.TempDir()
	in := filepath.Join(dir, "s.bin")
	if err := os.WriteFile(in, []byte("say what was skipped"), 0o600); err != nil {
		t.Fatal(err)
	}
	pieces := filepath.Join(dir, "pieces")
	splitInto(t, in, pieces, "-f", "binary,base32")

	var report strings.Builder
	if _, err := loadInputs(&report, []string{pieces}, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.String(), "hold the same piece as another") {
		t.Fatalf("the repeats should be reported:\n%s", report.String())
	}
}

// TestExpandRejectsAMissingPath checks a mistyped path is an error rather than
// an empty set that later reads as "not enough pieces".
func TestExpandRejectsAMissingPath(t *testing.T) {
	if _, err := expandPieceArgs([]string{filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatal("a path that does not exist must be refused")
	}
	empty := t.TempDir()
	if _, err := expandPieceArgs([]string{empty}); err == nil {
		t.Fatal("an empty directory must be refused")
	}
}

// TestNamedFileMustBeAPiece checks the asymmetry: a file inside a directory is
// skipped when it is not a piece, but one the user typed is an error for
// combine, because they meant that file.
func TestNamedFileMustBeAPiece(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.bin")
	if err := os.WriteFile(junk, []byte("not a piece at all, just some text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInputs(io.Discard, []string{junk}, true); err == nil {
		t.Fatal("a named file that is not a piece must be an error")
	}
	// The same file found inside a directory is skipped, leaving nothing to read.
	if _, err := loadInputs(io.Discard, []string{dir}, true); err == nil {
		t.Fatal("a directory of non-pieces must report that nothing could be read")
	}
}

// TestSplitRefusesADirectory checks the advice, since packing is now the user's
// job and the message is the only place that says so.
func TestSplitRefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := readSplitInput(&cliOptions{files: []string{dir}, yes: true})
	if err == nil {
		t.Fatal("a directory must be refused")
	}
	if !strings.Contains(err.Error(), "tar") {
		t.Fatalf("the message should say how to pack it: %v", err)
	}

	if err := validateSplitOptions(&cliOptions{files: []string{dir, dir}, yes: true}); err == nil {
		t.Fatal("two inputs must be refused")
	}
}

// TestMemoryEstimateGrowsWithThePieceCount checks the figure the large-split
// notice is built on stays honest: shares are one full copy of the input each.
func TestMemoryEstimateGrowsWithThePieceCount(t *testing.T) {
	const mb = 1 << 20
	small := core.MemoryEstimate(mb, 3)
	large := core.MemoryEstimate(mb, 10)
	if small < mb*3 {
		t.Fatalf("3 shares of 1 MiB cannot be under 3 MiB, got %d", small)
	}
	if large <= small {
		t.Fatalf("more pieces must need more memory: %d then %d", small, large)
	}
	var report strings.Builder
	noteLargeSplit(&report, 128<<20, 5)
	if !strings.Contains(report.String(), "MiB of memory") {
		t.Fatalf("a large split should say what it needs:\n%s", report.String())
	}
	report.Reset()
	noteLargeSplit(&report, 1024, 5)
	if report.Len() != 0 {
		t.Fatalf("a small split should say nothing, got %q", report.String())
	}
}

// TestRecordedNameRoundTripsThroughTheCommands is the feature as a user meets it:
// split a file, combine without naming an output, and get the name back.
func TestRecordedNameRoundTripsThroughTheCommands(t *testing.T) {
	t.Setenv("RIVEN_UNIT_DIR", "name recording")
	dir := t.TempDir()
	secret := []byte("the name comes back with it")
	in := filepath.Join(dir, "quarterly.pdf")
	if err := os.WriteFile(in, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	pieces := filepath.Join(dir, "pieces")
	splitInto(t, in, pieces)

	items, err := loadInputs(io.Discard, []string{pieces}, false)
	if err != nil {
		t.Fatal(err)
	}
	_, name, err := core.CombineFile(pieceBytes(items)[:2],
		core.OpenOptions{Passwords: [][]byte{[]byte("name recording")}})
	if err != nil {
		t.Fatal(err)
	}
	if name != "quarterly.pdf" {
		t.Fatalf("the pieces gave back %q", name)
	}
}

// TestRecordedNameIsOptional covers the two ways there is nothing to record and
// the one way it is turned off.
func TestRecordedNameIsOptional(t *testing.T) {
	if got := recordedName(&cliOptions{}, "notes.txt"); got != "notes.txt" {
		t.Errorf("recording is the default, got %q", got)
	}
	if got := recordedName(&cliOptions{recordNameSet: true, recordName: false}, "notes.txt"); got != "" {
		t.Errorf("--record-name false should record nothing, got %q", got)
	}
	if got := recordedName(&cliOptions{}, ""); got != "" {
		t.Errorf("text and standard input have no name, got %q", got)
	}
	// A name that cannot safely be created is not recorded either.
	if got := recordedName(&cliOptions{}, "con"); got != "" {
		t.Errorf("a device name should not be recorded, got %q", got)
	}
}

// TestRecordNameNeedsAFile checks the flag is refused where it would do nothing,
// rather than being accepted and ignored.
func TestRecordNameNeedsAFile(t *testing.T) {
	on := func(o *cliOptions) *cliOptions { o.recordName, o.recordNameSet = true, true; return o }
	if err := validateSplitOptions(on(&cliOptions{text: "x", textSet: true})); err == nil {
		t.Fatal("--record-name true with --text must be refused")
	}
	if err := validateSplitOptions(on(&cliOptions{files: []string{"-"}})); err == nil {
		t.Fatal("--record-name true with standard input must be refused")
	}
	// Turning it off is always allowed: there is simply nothing to record.
	off := &cliOptions{text: "x", textSet: true, recordNameSet: true}
	if err := validateSplitOptions(off); err != nil {
		t.Fatalf("--record-name false should always be allowed: %v", err)
	}
}
