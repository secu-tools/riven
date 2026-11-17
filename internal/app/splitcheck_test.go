// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/pieceio"
)

func TestParseVerify(t *testing.T) {
	for v, want := range map[string]verifyMode{
		"full": verifyFull, "FAST": verifyFast, " off ": verifyOff,
		"true": verifyFull, "on": verifyFull, "false": verifyOff,
	} {
		if got, err := parseVerify(v); err != nil || got != want {
			t.Errorf("%q: %v, %v; want %v", v, got, err, want)
		}
	}
	if _, err := parseVerify("thorough"); err == nil || !strings.Contains(err.Error(), "full, fast or off") {
		t.Errorf("an unknown mode gave %v", err)
	}
}

// uncheckedSplit writes a keyless set of n pieces, any k of which rebuild it, in
// the formats given, without checking it, so a test can spoil a file first.
func uncheckedSplit(t *testing.T, n, k int, formats string) ([]byte, map[pieceio.Format][]string, []pieceio.Format, *splitPlan) {
	t.Helper()
	plan := planFor(t, "--keyless", "-n", strconv.Itoa(n), "-k", strconv.Itoa(k))
	plan.outDir = t.TempDir()
	input := []byte("checked after writing")
	written, chosen, err := exportSplit(&bytes.Buffer{}, plan, &cliOptions{yes: true, format: formats}, input, "doc")
	if err != nil {
		t.Fatal(err)
	}
	return input, written, chosen, plan
}

// TestFullCheckReadsBackEveryFormat covers what the fast check leaves out: it
// reads one format, so a words file holding another piece passes it. The full
// check reads every file against the piece it was written from.
func TestFullCheckReadsBackEveryFormat(t *testing.T) {
	input, written, formats, plan := uncheckedSplit(t, 4, 2, "binary,words")
	words := written[pieceio.Words]
	other, err := os.ReadFile(words[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(words[3], other, 0o600); err != nil {
		t.Fatal(err)
	}

	if got, err := verifySplit(verifyFast, input, written, formats, plan); err != nil || got != verifiedFast {
		t.Fatalf("the fast check reads only the binary pieces, so it should pass: %q, %v", got, err)
	}
	if _, err := verifySplit(verifyFull, input, written, formats, plan); err == nil ||
		!strings.Contains(err.Error(), filepath.Base(words[3])) {
		t.Fatalf("the full check should name the spoiled file: %v", err)
	}
}

// TestFullCheckReadsTheCodeOnASheet checks a sheet's QR code is read as well as
// its text: a combine reads only the text, so a code holding another piece would
// otherwise go unnoticed until someone scanned it.
func TestFullCheckReadsTheCodeOnASheet(t *testing.T) {
	input, written, formats, plan := uncheckedSplit(t, 3, 2, "binary,sheet")
	sheets := written[pieceio.Sheet]
	first, err := os.ReadFile(sheets[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(sheets[1])
	if err != nil {
		t.Fatal(err)
	}
	spoiled := bytes.Replace(second, embeddedQR(t, second), embeddedQR(t, first), 1)
	if err := os.WriteFile(sheets[1], spoiled, 0o600); err != nil {
		t.Fatal(err)
	}

	if got, err := verifySplit(verifyFast, input, written, formats, plan); err != nil || got != verifiedFast {
		t.Fatalf("the fast check does not read sheets, so it should pass: %q, %v", got, err)
	}
	_, err = verifySplit(verifyFull, input, written, formats, plan)
	if err == nil || !strings.Contains(err.Error(), "QR code on") || !strings.Contains(err.Error(), filepath.Base(sheets[1])) {
		t.Fatalf("the full check should name the sheet whose code is wrong: %v", err)
	}
}

// embeddedQR returns the base64 PNG a sheet carries its QR code in.
func embeddedQR(t *testing.T, page []byte) []byte {
	t.Helper()
	const open = "data:image/png;base64,"
	i := bytes.Index(page, []byte(open))
	if i < 0 {
		t.Fatal("the sheet has no QR code")
	}
	rest := page[i+len(open):]
	return rest[:bytes.IndexByte(rest, '"')]
}

// TestTheLastGroupHoldsBorrowedPiecesToTheirDigest checks the pieces the last
// group reads a second time are held to what was written, as the first reading
// was. A file changed between the two readings once went into the rebuild as it
// now was, and was named only as a failed rebuild, if at all.
func TestTheLastGroupHoldsBorrowedPiecesToTheirDigest(t *testing.T) {
	_, other, _, _ := uncheckedSplit(t, 2, 2, "binary")
	foreign, err := os.ReadFile(other[pieceio.Binary][0])
	if err != nil {
		t.Fatal(err)
	}
	input, written, _, plan := uncheckedSplit(t, 3, 2, "binary")
	paths := written[pieceio.Binary]
	c := newGroupCheck(input, plan)
	defer c.wait()
	// The third piece is left over, so the last group borrows the first.
	last, _, err := pieceio.Load(paths[2])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.add(paths[2], last); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[0], foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.finish(paths); err == nil || !strings.Contains(err.Error(), "does not read back as written") ||
		!strings.Contains(err.Error(), filepath.Base(paths[0])) {
		t.Fatalf("a borrowed piece changed since it was read: %v, want it named as not what was written", err)
	}
}

// TestFullCheckPutsEveryPieceInARebuild covers the other gap: the fast check
// rebuilds from the first K pieces, so a later piece that does not open passes
// it. The spoiled piece stands for one made wrong, so its digest is taken as
// written and only a rebuild can tell.
func TestFullCheckPutsEveryPieceInARebuild(t *testing.T) {
	input, written, formats, plan := uncheckedSplit(t, 5, 2, "binary")
	last := written[pieceio.Binary][4]
	body, err := os.ReadFile(last)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 0xFF
	if err := os.WriteFile(last, body, 0o600); err != nil {
		t.Fatal(err)
	}
	plan.pieceSums[4] = sha256.Sum256(body)

	if got, err := verifySplit(verifyFast, input, written, formats, plan); err != nil || got != verifiedFast {
		t.Fatalf("the fast check rebuilds from the first two pieces, so it should pass: %q, %v", got, err)
	}
	if _, err := verifySplit(verifyFull, input, written, formats, plan); err == nil ||
		!strings.Contains(err.Error(), filepath.Base(last)) {
		t.Fatalf("the full check should name the piece that does not open: %v", err)
	}
}
