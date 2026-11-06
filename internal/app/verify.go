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
		return errors.New("verify needs pieces: the piece files, or a folder of them")
	}
	out := msgWriter(opts)

	pieces, err := loadInputs(out, opts.files, false)
	if err != nil {
		return err
	}
	raw := pieceBytes(pieces)
	defer memory.FreeAll(raw)

	open, wipe, err := resolveOpenCredentials(opts, raw)
	if err != nil {
		return err
	}
	defer wipe()

	sets, unreadable := groupBySet(out, pieces, open)
	defer func() {
		for _, set := range sets {
			for _, p := range set {
				p.Wipe()
			}
		}
	}()
	if len(sets) == 0 {
		return errors.New("no piece could be opened; check the password and the files")
	}
	// A piece that fails while others open cannot be blamed on the password: the
	// same one worked. Saying so turns "wrong password" into "damaged file",
	// which is the difference between retrying and fetching another copy.
	if unreadable > 0 {
		fmt.Fprintln(out)
		warn(out, fmt.Sprintf("%d piece(s) did not open although others did with the same answers, "+
			"so those files are damaged rather than wrongly keyed.", unreadable))
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

// groupBySet opens each piece and files it under its set id. The pieces stay
// open, so a rebuild does not derive their keys again; the caller wipes them. It
// returns the number of pieces that could not be opened, which is a failure the
// caller reports even when the sets that did open are complete.
func groupBySet(out io.Writer, items []heldPiece, open core.OpenOptions) (map[string][]*core.Piece, int) {
	sets := map[string][]*core.Piece{}
	unreadable := 0
	for _, item := range items {
		p, err := core.Open(item.bytes, open)
		if err != nil {
			writeWrapped(out, "  ", paint(out, toneError, "FAILED:")+" "+pieceFailure(item.det.Path, err))
			unreadable++
			continue
		}
		info := p.Info
		status := "intact"
		if !info.Intact {
			status = "DAMAGED"
		}
		checked := ""
		if !item.det.Verified {
			checked = ", no checksum in this format"
		}
		which := fmt.Sprintf("piece %d of %d", info.Serial, info.N)
		if info.Hidden {
			which = "piece of a set with hidden details"
		}
		writeWrapped(out, "  ", fmt.Sprintf("%q: %s, %s, read as %s%s",
			item.det.Path, which, status, item.det.Format, checked))
		if !info.Intact {
			p.Wipe()
			unreadable++
			continue
		}
		sets[info.SetID] = append(sets[info.SetID], p)
	}
	return sets, unreadable
}

func sortedSetIDs(sets map[string][]*core.Piece) []string {
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
//
// Rebuilding in memory is the only check that covers the shares as well as the
// envelopes, so it is worth the work when the pieces are there. A set whose
// pieces do not say how many it needs or which piece each is can only be told
// by rebuilding, so its shortfall is reported without a count.
func verifySet(out io.Writer, id string, held []*core.Piece, open core.OpenOptions) bool {
	first := held[0].Info
	if first.Hidden {
		fmt.Fprintln(out)
		heading(out, fmt.Sprintf("Set %s: %d piece(s) held; the set hides how many it needs.", id[:8], len(held)))
		return reportRebuild(out, held, open)
	}
	// One piece per serial: a second copy of a piece adds nothing to a rebuild.
	distinct := map[int]bool{}
	for _, p := range held {
		distinct[p.Info.Serial] = true
	}
	fmt.Fprintln(out)
	heading(out, fmt.Sprintf("Set %s: %d of %d pieces held, %d needed.", id[:8], len(distinct), first.N, first.K))
	if short := first.K - len(distinct); short > 0 {
		fmt.Fprintf(out, "  %s %d more piece(s) required to rebuild.\n", paint(out, toneWarning, "NOT ENOUGH:"), short)
		return false
	}
	return reportRebuild(out, held, open)
}

// reportRebuild rebuilds in memory from pieces already open and says how it
// went.
func reportRebuild(out io.Writer, pieces []*core.Piece, open core.OpenOptions) bool {
	recovered, _, err := core.CombineOpened(pieces, open)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrKeyRequired):
			fmt.Fprintf(out, "  %s the pieces agree; rebuilding needs a recipient private key.\n",
				paint(out, toneGood, "OK:"))
			return true
		case errors.Is(err, core.ErrTooFewPieces):
			fmt.Fprintf(out, "  %s these pieces do not rebuild it; more are required.\n",
				paint(out, toneWarning, "NOT ENOUGH:"))
			return false
		}
		writeWrapped(out, "  ", paint(out, toneError, "FAILED")+" to rebuild: "+humanize(err))
		return false
	}
	defer memory.Zero(recovered)
	fmt.Fprintf(out, "  %s these pieces rebuild %d bytes.\n", paint(out, toneGood, "OK:"), len(recovered))
	return true
}
