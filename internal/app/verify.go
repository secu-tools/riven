// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/memory"
)

// cmdVerify answers one question: will these pieces rebuild the file?
//
// It reads every piece given, groups them by set, and where a set has enough
// distinct pieces it reconstructs in memory and checks the payload hash. Nothing
// is written. A set that is short of the threshold is reported as such rather
// than treated as a failure, since knowing how many more are needed is the point.
func cmdVerify(opts *cliOptions) error {
	if err := validateOpenOptions(opts); err != nil {
		return err
	}
	if len(opts.files) == 0 {
		return errors.New("verify needs at least one piece: riven verify PIECE...")
	}
	out := msgWriter(opts)

	pieces, err := loadInputs(out, opts.files, false)
	if err != nil {
		return err
	}
	raw := pieceBytes(pieces)
	defer wipeAll(raw)

	open, wipe, err := resolveOpenCredentials(opts, raw)
	if err != nil {
		return err
	}
	defer wipe()

	noteExpensiveOpen(raw, open.Params)

	sets, unreadable := groupBySet(out, pieces, open)
	if len(sets) == 0 {
		return errors.New("no piece could be opened; check the password and the files")
	}
	// A piece that fails while others open cannot be blamed on the password: the
	// same one worked. Saying so turns "wrong password" into "damaged file",
	// which is the difference between retrying and fetching another copy.
	if unreadable > 0 {
		fmt.Fprintf(out, "\n  %d piece(s) failed while others opened with the same password,\n"+
			"  so those files are damaged rather than wrongly keyed.\n", unreadable)
	}

	failed := unreadable > 0
	for _, id := range sortedSetIDs(sets) {
		if !verifySet(out, id, sets[id], open) {
			failed = true
		}
	}
	if failed {
		return errors.New("verification did not pass for every piece")
	}
	return nil
}

// opened pairs a piece with what its manifest says.
type opened struct {
	piece []byte
	info  *core.PieceInfo
}

// groupBySet opens each piece and files it under its set id. It returns the
// number of pieces that could not be opened, which is a failure the caller
// reports even when the sets that did open are complete.
func groupBySet(out io.Writer, items []heldPiece, open core.OpenOptions) (map[string][]opened, int) {
	sets := map[string][]opened{}
	unreadable := 0
	for _, item := range items {
		info, err := core.Info(item.bytes, open)
		if err != nil {
			fmt.Fprintf(out, "  %q: FAILED to open (%v)\n", item.det.Path, err)
			unreadable++
			continue
		}
		status := "intact"
		if !info.Intact {
			status = "DAMAGED"
		}
		checked := ""
		if !item.det.Verified {
			checked = ", no checksum in this format"
		}
		fmt.Fprintf(out, "  %q: piece %d of %d, %s, read as %s%s\n",
			item.det.Path, info.Serial, info.N, status, item.det.Format, checked)
		if !info.Intact {
			unreadable++
			continue
		}
		sets[info.SetID] = append(sets[info.SetID], opened{piece: item.bytes, info: info})
	}
	return sets, unreadable
}

func sortedSetIDs(sets map[string][]opened) []string {
	ids := make([]string, 0, len(sets))
	for id := range sets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// verifySet reports whether one set can be rebuilt, reconstructing it when
// enough distinct pieces are present. It returns false when the set is short or
// the reconstruction fails.
func verifySet(out io.Writer, id string, held []opened, open core.OpenOptions) bool {
	distinct := map[int]bool{}
	for _, h := range held {
		distinct[h.info.Serial] = true
	}
	need, total := held[0].info.K, held[0].info.N
	short := need - len(distinct)

	fmt.Fprintf(out, "\nSet %s: %d of %d distinct pieces held, %d needed of %d.\n",
		id[:8], len(distinct), total, need, total)
	if short > 0 {
		fmt.Fprintf(out, "  NOT ENOUGH: %d more piece(s) required to rebuild.\n", short)
		return false
	}

	// Rebuilding in memory is the only check that covers the shares as well as
	// the envelopes, so it is worth the work when the pieces are there.
	subset := make([][]byte, 0, need)
	used := map[int]bool{}
	for _, h := range held {
		if len(subset) == need {
			break
		}
		if used[h.info.Serial] {
			continue
		}
		used[h.info.Serial] = true
		subset = append(subset, h.piece)
	}
	recovered, err := core.Combine(subset, open)
	if err != nil {
		if errors.Is(err, core.ErrKeyRequired) {
			fmt.Fprintln(out, "  pieces are consistent; a recipient private key is needed to rebuild.")
			return true
		}
		fmt.Fprintf(out, "  FAILED to rebuild: %v\n", err)
		return false
	}
	defer memory.Zero(recovered)
	fmt.Fprintf(out, "  OK: these pieces rebuild %d bytes.\n", len(recovered))
	return true
}
