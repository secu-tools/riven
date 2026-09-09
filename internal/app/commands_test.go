// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// TestCommandRoundTripInProcess drives split, info and combine through the
// command functions themselves, which is the layer between the flags and the
// pipeline. It is the same journey the binary makes, without the subprocess.
func TestCommandRoundTripInProcess(t *testing.T) {
	t.Setenv("RIVEN_UNIT_CMD", "command round trip")
	dir := t.TempDir()
	secret := []byte("in-process round trip content")
	in := filepath.Join(dir, "s.bin")
	if err := os.WriteFile(in, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "o")

	splitOpts, err := parseArgs([]string{"split", in, "-n", "3", "-k", "2",
		"--password-env", "RIVEN_UNIT_CMD", "--kdf", "m=8,t=1,p=1", "--out", out, "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdSplit(splitOpts); err != nil {
		t.Fatalf("split: %v", err)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("wrote %d pieces, want 3", len(entries))
	}

	p1 := filepath.Join(out, "s.bin.1")
	p3 := filepath.Join(out, "s.bin.3")

	infoOpts, err := parseArgs([]string{"info", p1, "--password-env", "RIVEN_UNIT_CMD", "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdInfo(infoOpts); err != nil {
		t.Fatalf("info: %v", err)
	}

	rec := filepath.Join(dir, "back.bin")
	combineOpts, err := parseArgs([]string{"combine", p1, p3,
		"--password-env", "RIVEN_UNIT_CMD", "--out", rec, "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdCombine(combineOpts); err != nil {
		t.Fatalf("combine: %v", err)
	}
	got, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatalf("recovered %q", got)
	}

	// A wrong password must fail, and must not leave a file behind.
	t.Setenv("RIVEN_UNIT_WRONG", "not the password")
	badOpts, err := parseArgs([]string{"combine", p1, p3,
		"--password-env", "RIVEN_UNIT_WRONG", "--out", filepath.Join(dir, "no.bin"), "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdCombine(badOpts); err == nil {
		t.Fatal("the wrong password must fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "no.bin")); err == nil {
		t.Fatal("a failed combine must not write a file")
	}
}

// TestCmdKeygenWritesBothFiles covers the command for every key type, including
// that the type reaches the files it writes.
func TestCmdKeygenWritesBothFiles(t *testing.T) {
	dir := t.TempDir()
	for _, s := range kem.All() {
		pub := filepath.Join(dir, s.Name()+".pub")
		priv := filepath.Join(dir, s.Name()+".key")
		opts, err := parseArgs([]string{"keygen", s.Name(), "--pub", pub, "--priv", priv, "-y"})
		if err != nil {
			t.Fatal(err)
		}
		if err := cmdKeygen(opts); err != nil {
			t.Fatalf("%s: %v", s.Name(), err)
		}
		got, err := readPublicKey(pub)
		if err != nil {
			t.Fatalf("%s: %v", s.Name(), err)
		}
		if got.Scheme() != s {
			t.Fatalf("%s file holds a %s key", s.Name(), got.Scheme())
		}
		if _, err := readPrivateKey(priv); err != nil {
			t.Fatalf("%s private: %v", s.Name(), err)
		}
	}
}

// TestResolveFormatsInAutomation checks the format choice without a terminal:
// the flag decides, and binary is the fallback.
func TestResolveFormatsInAutomation(t *testing.T) {
	plan := planFor(t, "--keyless", "-n", "3", "-k", "2")
	pieces := makePieces(t, core.SplitOptions{N: 3, K: 2, Keyless: true}, []byte("formats"))
	size := len(pieces[0])

	got, err := resolveFormats(&cliOptions{yes: true}, plan, size)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != pieceio.Binary {
		t.Fatalf("default is %v, want binary", got)
	}

	got, err = resolveFormats(&cliOptions{yes: true, format: "all"}, plan, size)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(pieceio.All()) {
		t.Fatalf("all gave %v", got)
	}

	if _, err := resolveFormats(&cliOptions{yes: true, format: "pdf"}, plan, size); err == nil {
		t.Fatal("an unknown format must be refused")
	}
}

// TestCheckQRFeasible covers the all-or-nothing rule and the two messages: one
// that blames the padding when padding is on, and one that does not when it is
// already off.
func TestCheckQRFeasible(t *testing.T) {
	t.Setenv("RIVEN_UNIT_QR", "qr feasibility")
	padded := planFor(t, "--password-env", "RIVEN_UNIT_QR", "--pad", "100", "--kdf", "m=8,t=1,p=1")
	unpadded := planFor(t, "--password-env", "RIVEN_UNIT_QR", "--pad", "none", "--kdf", "m=8,t=1,p=1")

	if err := checkQRFeasible(padded, []pieceio.Format{pieceio.QR}, 100, 2); err != nil {
		t.Fatalf("small pieces should fit: %v", err)
	}
	// A format list without QR is never blocked.
	if err := checkQRFeasible(padded, []pieceio.Format{pieceio.Binary}, 99999, 2); err != nil {
		t.Fatalf("a binary export must not be blocked: %v", err)
	}

	err := checkQRFeasible(padded, []pieceio.Format{pieceio.QR}, 99999, 2)
	if err == nil {
		t.Fatal("an oversized piece must block the QR export")
	}
	if !strings.Contains(err.Error(), "2 pieces") {
		t.Fatalf("the message should say how many pieces: %v", err)
	}
	if !strings.Contains(err.Error(), "--pad none") {
		t.Fatalf("with padding on, the message should suggest turning it off: %v", err)
	}

	err = checkQRFeasible(unpadded, []pieceio.Format{pieceio.QR}, 99999, 2)
	if err == nil {
		t.Fatal("an oversized piece must block the QR export")
	}
	if strings.Contains(err.Error(), "--pad none") {
		t.Fatalf("padding is already off, so it must not be blamed: %v", err)
	}
}

// TestFormatNoteWarnsBeforeTheChoice covers the notes on the export menu. They
// exist so a format that cannot work, or that costs far more than it looks,
// is known about while the menu is still open rather than after the export
// fails.
func TestFormatNoteWarnsBeforeTheChoice(t *testing.T) {
	const small = 200
	tooBigForQR := pieceio.QRMaxBytes + 1
	tooBigForWords := pieceio.Bip39MaxPiece + 1

	if note := formatNote(pieceio.Binary, tooBigForQR); note != "" {
		t.Errorf("binary has no limit, so it needs no note: %q", note)
	}
	if note := formatNote(pieceio.QR, small); note != "" {
		t.Errorf("a small piece fits in a QR code: %q", note)
	}

	note := formatNote(pieceio.QR, tooBigForQR)
	if !strings.Contains(note, "NOT AVAILABLE") {
		t.Errorf("an oversized piece must mark QR unavailable: %q", note)
	}
	if !strings.Contains(note, strconv.Itoa(tooBigForQR)) ||
		!strings.Contains(note, strconv.Itoa(pieceio.QRMaxBytes)) {
		t.Errorf("the note should give the size and the limit: %q", note)
	}

	// A sheet still prints its text when the code will not fit, so it is reduced
	// rather than withdrawn.
	note = formatNote(pieceio.Sheet, tooBigForQR)
	if strings.Contains(note, "NOT AVAILABLE") || !strings.Contains(note, "text only") {
		t.Errorf("a sheet without a code is still usable: %q", note)
	}

	note = formatNote(pieceio.Words, small)
	if !strings.Contains(note, strconv.Itoa(pieceio.Bip39Words(small))) {
		t.Errorf("the note should give the word count: %q", note)
	}
	if !strings.Contains(note, "times the size") {
		t.Errorf("the note should say how much larger words are: %q", note)
	}

	note = formatNote(pieceio.Words, tooBigForWords)
	if !strings.Contains(note, "NOT AVAILABLE") {
		t.Errorf("a piece past the word limit must be marked unavailable: %q", note)
	}
}

// TestCheckWordsFeasible checks the same limit is enforced, not only announced,
// so a scripted --format words fails before any file is written.
func TestCheckWordsFeasible(t *testing.T) {
	if err := checkWordsFeasible([]pieceio.Format{pieceio.Words}, 100, 3); err != nil {
		t.Fatalf("a small piece should be fine: %v", err)
	}
	if err := checkWordsFeasible([]pieceio.Format{pieceio.Base32}, 1<<20, 3); err != nil {
		t.Fatalf("only a word export is limited: %v", err)
	}
	err := checkWordsFeasible([]pieceio.Format{pieceio.Words}, pieceio.Bip39MaxPiece+1, 3)
	if err == nil {
		t.Fatal("a piece past the limit must be refused")
	}
	for _, want := range []string{"3 pieces", "base32", strconv.Itoa(pieceio.Bip39MaxPiece)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message should mention %q: %v", want, err)
		}
	}
}

// TestResolveFormatsRefusesWhatWillNotFit checks the flag path is guarded by the
// same limits as the menu.
func TestResolveFormatsRefusesWhatWillNotFit(t *testing.T) {
	plan := planFor(t, "--keyless", "-n", "3", "-k", "2")
	if _, err := resolveFormats(&cliOptions{yes: true, format: "words"}, plan,
		pieceio.Bip39MaxPiece+1); err == nil {
		t.Fatal("--format words must be refused for an oversized piece")
	}
	if _, err := resolveFormats(&cliOptions{yes: true, format: "qr"}, plan,
		pieceio.QRMaxBytes+1); err == nil {
		t.Fatal("--format qr must be refused for an oversized piece")
	}
	if _, err := resolveFormats(&cliOptions{yes: true, format: "words"}, plan, 64); err != nil {
		t.Fatalf("a small piece should be allowed: %v", err)
	}
}

func TestNoteExpensiveOpenIsQuietInAutomation(t *testing.T) {
	pieces := makePieces(t, core.SplitOptions{N: 2, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("p")}}}, []byte("cost"))
	out := capture(t, func() {
		// Not a terminal in tests, so this must print nothing whatever the cost.
		noteExpensiveOpen(pieces, nil)
		expensive := kdf.Params{Memory: 1024 * 1024, Time: 4, Par: 4}
		noteExpensiveOpen(pieces, &expensive)
	})
	if out != "" {
		t.Fatalf("nothing should be printed without a terminal, got %q", out)
	}
}

// TestAskMissingValuesInAutomation checks the two recovery prompts give up
// quietly when there is no terminal, rather than blocking a script.
func TestAskMissingValuesInAutomation(t *testing.T) {
	p, err := askMissingKDF(&cliOptions{yes: true})
	if err != nil || p != nil {
		t.Fatalf("automation should not prompt for a cost: %v %v", p, err)
	}
	ids, err := askMissingAlgos(&cliOptions{yes: true}, 2)
	if err == nil && ids != nil {
		t.Fatal("automation should not invent algorithms")
	}
}

// TestChooseKDFReadsTheAnswer drives the cost chooser with scripted input, since
// it is one of the wizard questions that changes what is written.
func TestChooseKDFReadsTheAnswer(t *testing.T) {
	presets := kdf.PresetNames()
	var got kdf.Params
	withInput(t, "2\n", func() {
		p, err := chooseKDF(kdf.Default())
		if err != nil {
			t.Fatal(err)
		}
		got = p
	})
	want, err := kdf.Parse(presets[1])
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("choice 2 gave %+v, want the second preset %+v", got, want)
	}

	// The custom option takes a specification.
	withInput(t, fmt.Sprintf("%d\nm=8,t=1,p=1\n", len(presets)+1), func() {
		p, err := chooseKDF(kdf.Default())
		if err != nil {
			t.Fatal(err)
		}
		got = p
	})
	if got.Memory != 8*1024 || got.Time != 1 || got.Par != 1 {
		t.Fatalf("custom cost gave %+v", got)
	}
}
