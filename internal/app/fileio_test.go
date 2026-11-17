// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/pieceio"
)

// TestWorkersStayWithinTheBudget checks small files go several at a time and a
// file as large as the budget alone.
func TestWorkersStayWithinTheBudget(t *testing.T) {
	for size, want := range map[int64]int{0: fileWorkers, 300: fileWorkers, fileBudget / 2: 2, fileBudget: 1, 4 * fileBudget: 1} {
		if got := workersFor(size); got != want {
			t.Errorf("files of %d bytes: %d at a time, want %d", size, got, want)
		}
	}
}

// TestSplitWritesEveryPieceWhereItBelongs checks a split written several files at
// a time puts each piece, in each format, in the file named for it, and records
// each one's path, digest and size by serial, whatever order the files were
// written in.
func TestSplitWritesEveryPieceWhereItBelongs(t *testing.T) {
	const n = 60
	plan := planFor(t, "--keyless", "-n", fmt.Sprint(n), "-k", "2")
	plan.outDir = t.TempDir()
	input := []byte("written several files at a time")
	written, formats, err := exportSplit(io.Discard, plan, &cliOptions{yes: true, format: "binary,base64"}, input, "doc")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range formats {
		if len(written[f]) != n {
			t.Fatalf("%s: %d paths recorded, want %d", f, len(written[f]), n)
		}
		for i, path := range written[f] {
			if want := pieceio.Path(plan.outDir, fmt.Sprintf("doc.%02d", i+1), f); path != want {
				t.Fatalf("%s piece %d recorded as %s, want %s", f, i+1, path, want)
			}
			piece, _, err := pieceio.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(piece) != plan.pieceSums[i] || len(piece) != plan.pieceSize {
				t.Fatalf("%s: %s does not hold the piece recorded for serial %d", f, path, i+1)
			}
			info, err := core.Info(piece, core.OpenOptions{})
			if err != nil || info.Serial != i+1 {
				t.Fatalf("%s: %s holds serial %d, want %d (%v)", f, path, info.Serial, i+1, err)
			}
		}
	}
	if got, err := verifySplit(verifyFull, input, written, formats, plan); err != nil || got != verifiedFull {
		t.Fatalf("the full check: %q, %v", got, err)
	}
}

// TestAFailedWriteStopsTheSplit checks a piece that cannot be written stops the
// split, without hanging the other writers, and that the error names the first
// piece that failed whichever writer got there first.
func TestAFailedWriteStopsTheSplit(t *testing.T) {
	plan := planFor(t, "--keyless", "-n", "200", "-k", "2")
	plan.outDir = t.TempDir()
	// A folder where a piece should go cannot be written over. The pieces after
	// the first of them are with other writers when it fails, so one of those may
	// be the failure the split stops on, and the first is still the one reported.
	for _, serial := range []int{50, 51, 52, 53, 54, 55, 56, 57, 120} {
		if err := os.Mkdir(filepath.Join(plan.outDir, fmt.Sprintf("doc.%03d", serial)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := exportSplit(io.Discard, plan, &cliOptions{yes: true, format: "binary"}, []byte("stopped"), "doc")
	if err == nil || !strings.Contains(err.Error(), "doc.050") {
		t.Fatalf("got %v, want the failure writing doc.050", err)
	}
	entries, err := os.ReadDir(plan.outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) >= 200 {
		t.Fatalf("%d files after a failure at piece 50: the split went on", len(entries))
	}
}

// TestCombineTakesTheFilesInTheOrderGiven checks the pieces read ahead of the one
// being taken still come out in the order the files were named.
func TestCombineTakesTheFilesInTheOrderGiven(t *testing.T) {
	_, written, _, _ := uncheckedSplit(t, 30, 2, "binary")
	paths := slices.Clone(written[pieceio.Binary])
	slices.Reverse(paths)
	items, err := loadInputs(io.Discard, paths, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != len(paths) {
		t.Fatalf("read %d of %d pieces", len(items), len(paths))
	}
	for i, it := range items {
		want, err := os.ReadFile(paths[i])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(it.bytes, want) {
			t.Fatalf("piece %d read is not the file named %d", i, i)
		}
	}
}

// TestGroupsAreRebuiltWithinBudget checks how many groups a full check rebuilds
// at once: several for a threshold of two small pieces, sharing the key
// derivations a combine makes; one for a group as large as the derivations, or
// when the budget for pieces in flight holds just two groups, that one and the
// next being read; and none, each rebuilt where it completes, past that.
func TestGroupsAreRebuiltWithinBudget(t *testing.T) {
	t.Setenv("RIVEN_UNIT_GROUPS", "groups")
	plan := planFor(t, "--password-env", "RIVEN_UNIT_GROUPS", "-n", "100", "-k", "2")
	plan.pieceSize = 300
	want := max(1, core.DerivationsAtOnce(plan.opts.Params)/2)
	if got := cap(newGroupCheck(nil, plan).slots); got != want {
		t.Fatalf("groups of two small pieces: %d at once, want %d", got, want)
	}
	plan.pieceSize = fileBudget / 4
	if got := cap(newGroupCheck(nil, plan).slots); got != 1 {
		t.Fatalf("two groups of two pieces that just fit: %d at once, want 1", got)
	}
	plan.pieceSize = fileBudget/4 + 1
	if c := newGroupCheck(nil, plan); c.slots != nil {
		t.Fatalf("groups of two pieces too large to hold another: %d at once, want each where it completes", cap(c.slots))
	}
	plan.opts.K = core.DerivationsAtOnce(plan.opts.Params)
	plan.pieceSize = 300
	if got := cap(newGroupCheck(nil, plan).slots); got != 1 {
		t.Fatalf("groups as large as the derivations: %d at once, want 1", got)
	}
}

// TestGroupsThatDeriveNoKeyUseEveryCore checks the derivations do not hold back
// a check that makes none: a set with no password, or whose pieces open without
// it, rebuilds as many groups at once as there are cores, however many pieces a
// group is, within the budget for pieces in flight.
func TestGroupsThatDeriveNoKeyUseEveryCore(t *testing.T) {
	t.Setenv("RIVEN_UNIT_GROUPS", "groups")
	cores := runtime.GOMAXPROCS(0)
	for _, args := range [][]string{
		{"--keyless"},
		{"--password-env", "RIVEN_UNIT_GROUPS", "--info", "public"},
		{"--password-env", "RIVEN_UNIT_GROUPS", "--info", "none"},
	} {
		plan := planFor(t, append(args, "-n", "200", "-k", "2")...)
		plan.pieceSize = 300
		if got := cap(newGroupCheck(nil, plan).slots); got != cores {
			t.Fatalf("%v: %d groups at once, want one for each of %d cores", args, got, cores)
		}
		// A threshold past the derivations a combine makes at once is no limit.
		plan.opts.K = 4 * core.DerivationsAtOnce(plan.opts.Params)
		if got := cap(newGroupCheck(nil, plan).slots); got != cores {
			t.Fatalf("%v at K %d: %d groups at once, want %d", args, plan.opts.K, got, cores)
		}
		// The budget for pieces in flight still bounds it.
		plan.opts.K, plan.pieceSize = 2, fileBudget/8
		if got := cap(newGroupCheck(nil, plan).slots); got != min(cores, 3) {
			t.Fatalf("%v with room for four groups: %d at once, want %d", args, got, min(cores, 3))
		}
	}
}

// TestALongGroupIsNamedByItsEnds checks a failing group of many files is named
// by its first and last, not by a list as long as the threshold.
func TestALongGroupIsNamedByItsEnds(t *testing.T) {
	var paths []string
	for i := 1; i <= 5000; i++ {
		paths = append(paths, filepath.Join("out", fmt.Sprintf("doc.%04d", i)))
	}
	if got, want := fileNames(paths), "doc.0001 ... doc.5000 (5000 files)"; got != want {
		t.Fatalf("5000 files named as %q, want %q", got, want)
	}
	if got, want := fileNames(paths[:3]), "doc.0001, doc.0002, doc.0003"; got != want {
		t.Fatalf("3 files named as %q, want %q", got, want)
	}
	if got := fileNames(nil); got != "" {
		t.Fatalf("no files named as %q", got)
	}
}

// TestFullCheckFindsAFaultInAnyGroup checks a group still fails the check, and
// is the one named, when it is the last, both rebuilt alongside the reading,
// where its rebuild ends after every file has been read, and rebuilt where it
// completes, as a group too large for the budget is. A piece of another set
// stands in for a piece the split made wrong, with the digest the split would
// then have recorded, so it reads back as written.
func TestFullCheckFindsAFaultInAnyGroup(t *testing.T) {
	_, other, _, _ := uncheckedSplit(t, 2, 2, "binary")
	foreign, err := os.ReadFile(other[pieceio.Binary][0])
	if err != nil {
		t.Fatal(err)
	}
	for _, large := range []bool{false, true} {
		input, written, formats, plan := uncheckedSplit(t, 12, 2, "binary")
		last := written[pieceio.Binary][10]
		if err := os.WriteFile(last, foreign, 0o600); err != nil {
			t.Fatal(err)
		}
		plan.pieceSums[10] = sha256.Sum256(foreign)
		if large {
			plan.pieceSize = fileBudget
		}
		if _, err := verifySplit(verifyFull, input, written, formats, plan); err == nil ||
			!strings.Contains(err.Error(), filepath.Base(last)) {
			t.Fatalf("large=%v: got %v, want the last group named", large, err)
		}
	}
}

// TestAPieceOfAnotherSizeIsNotWritten checks the writer refuses a piece that is
// not the size it was planned at: the formats were checked against that size,
// and a piece of another would go out under a check it never had.
func TestAPieceOfAnotherSizeIsNotWritten(t *testing.T) {
	plan := planFor(t, "--keyless", "-n", "2", "-k", "2")
	plan.outDir = t.TempDir()
	w := newPieceWriter(plan, []pieceio.Format{pieceio.Binary}, func(s int) string { return fmt.Sprintf("p.%d", s) }, 100, false)
	piece := bytes.Repeat([]byte{7}, 101)
	if err := w.add(1, piece); err == nil || !strings.Contains(err.Error(), "planned") {
		t.Fatalf("a 101-byte piece was taken by a writer planned at 100: %v", err)
	}
	if err := w.wait(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(piece, make([]byte, len(piece))) {
		t.Fatal("the refused piece was not wiped")
	}
	if files, _ := os.ReadDir(plan.outDir); len(files) != 0 {
		t.Fatalf("%d files were written", len(files))
	}
}

// TestFailuresAreReportedByTheFirst checks the writers and the rebuilds keep the
// failure of the earliest piece or group, whatever order they failed in.
func TestFailuresAreReportedByTheFirst(t *testing.T) {
	w := &pieceWriter{}
	c := &groupCheck{}
	for _, at := range []int{5, 3, 9} {
		w.fail(at, fmt.Errorf("piece %d", at))
		c.fail(at, fmt.Errorf("group %d", at))
	}
	if w.failure().Error() != "piece 3" || c.failure().Error() != "group 3" {
		t.Fatalf("kept %v and %v, want the failures at 3", w.failure(), c.failure())
	}
}
