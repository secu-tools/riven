// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"sync/atomic"
	"testing"

	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/kdf"
)

// cheap is a cost the tests can afford to actually run.
var cheap = kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}

// pieceDeclaring builds a piece whose recorded Argon2 cost is declared.
//
// The piece is sealed at the cheap cost and the cost byte is then stamped, so
// the test never runs the expensive derivation it is describing -- a gibibyte
// four times over takes minutes on a modest machine. Stamping is also the
// faithful model: the byte is not authenticated before it is used, so it is
// whatever the writer put there, which is the whole reason for the budget.
func pieceDeclaring(t *testing.T, declared kdf.Params) []byte {
	t.Helper()
	piece, err := format.Encode(format.EncodeInput{
		Details: format.Details{
			K:         2,
			N:         3,
			KDFStored: true,
			Params:    cheap,
		},
		SetID:       make([]byte, format.SetIDLen),
		Serial:      1,
		PayloadHash: make([]byte, 32),
		Share:       []byte("xxxxxxxxxx"),
		Passwords:   [][]byte{[]byte("pw")},
	})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := declared.Encode()
	if err != nil {
		t.Fatal(err)
	}
	piece[kdf.SaltLen] = kdf.MaskParams(enc, piece[:kdf.SaltLen])

	if got, ok := format.PeekParams(piece); !ok || got.Memory != declared.Memory {
		t.Fatalf("piece declares %d KiB, want %d", got.Memory, declared.Memory)
	}
	return piece
}

// Opening runs one Argon2 derivation per piece, concurrently. Sizing that pool
// from the first piece alone bounds nothing: a cheap piece 1 would authorise a
// full set of workers that then each meet a piece asking for a gibibyte.
func TestOpenBudgetTakesTheWorstDeclarationInTheSet(t *testing.T) {
	dear := kdf.Params{Memory: 1024 * 1024, Time: 4, Par: 4}

	pieces := [][]byte{
		pieceDeclaring(t, cheap),
		pieceDeclaring(t, dear),
		pieceDeclaring(t, cheap),
	}
	opts := OpenOptions{Passwords: [][]byte{[]byte("pw")}}

	got := openBudget(pieces, opts, cheap)
	if got.Memory != dear.Memory {
		t.Fatalf("budget is %d KiB, want the worst declaration %d KiB",
			got.Memory, dear.Memory)
	}

	// Fewer workers must follow from the larger budget.
	if w := derivationWorkers(got, len(pieces)); w > derivationWorkers(cheap, len(pieces)) {
		t.Errorf("the expensive budget allowed %d workers, no fewer than the cheap one", w)
	}
}

// An explicit --kdf replaces every recorded cost, so it is the only one that runs.
func TestOpenBudgetHonoursAnOverride(t *testing.T) {
	dear := kdf.Params{Memory: 1024 * 1024, Time: 4, Par: 4}
	override := kdf.Params{Memory: 64 * 1024, Time: 3, Par: 4}

	pieces := [][]byte{pieceDeclaring(t, cheap), pieceDeclaring(t, dear)}
	opts := OpenOptions{Passwords: [][]byte{[]byte("pw")}, Params: &override}

	if got := openBudget(pieces, opts, cheap); got.Memory != override.Memory {
		t.Fatalf("budget is %d KiB, want the override %d KiB", got.Memory, override.Memory)
	}
}

// A keyless set derives no key, so there is nothing to budget for and the opens
// should not be serialised against a cost byte that is pure noise.
func TestOpenBudgetIsUnsetWithoutPasswords(t *testing.T) {
	pieces := [][]byte{pieceDeclaring(t, kdf.Params{Memory: 1024 * 1024, Time: 4, Par: 4})}
	got := openBudget(pieces, OpenOptions{}, kdf.Params{})
	if got.Memory != 0 {
		t.Fatalf("budget is %d KiB, want none when no password is derived", got.Memory)
	}
	if w := derivationWorkers(got, 8); w != derivationWorkers(kdf.Params{}, 8) {
		t.Error("a keyless open was bounded by a memory budget it does not spend")
	}
}

// The budget only helps if the open path uses it. A set holding one expensive
// piece must run fewer derivations at once than an all-cheap set of the same
// size, whatever the first piece declares.
func TestOpenWorkersFollowsTheWorstPiece(t *testing.T) {
	dear := kdf.Params{Memory: 1024 * 1024, Time: 4, Par: 4}
	opts := OpenOptions{Passwords: [][]byte{[]byte("pw")}}

	allCheap := [][]byte{pieceDeclaring(t, cheap), pieceDeclaring(t, cheap), pieceDeclaring(t, cheap)}
	oneDear := [][]byte{pieceDeclaring(t, cheap), pieceDeclaring(t, dear), pieceDeclaring(t, cheap)}

	// Both sets declare the same cheap cost on piece 1, which is what the pool
	// used to be sized from.
	got := openWorkers(oneDear, opts, cheap, len(oneDear))
	want := openWorkers(allCheap, opts, cheap, len(allCheap))
	if got >= want {
		t.Fatalf("a set holding a 1 GiB piece ran %d derivations at once, "+
			"no fewer than the %d an all-cheap set does", got, want)
	}
	if got < 1 {
		t.Fatalf("worker count fell to %d", got)
	}
}

// TestTheRestOpenTheWayTheReferenceDid checks the pieces after the reference are
// tried only the way it opened: a strict set's envelope takes every password, so
// trying the first alone on each piece would double what each costs.
func TestTheRestOpenTheWayTheReferenceDid(t *testing.T) {
	const n = 4
	for _, c := range []struct {
		info       InfoMode
		first, all int32
	}{{InfoStrict, 1, n}, {InfoProtected, n, 0}} {
		pieces, err := Split([]byte("two passwords"), SplitOptions{N: n, K: 2, Info: c.info, Params: cheap,
			RecordAlgo: true, RecordKDF: true, Layers: []LayerSpec{
				{Kind: PasswordLayer, Password: []byte("outermost")},
				{Kind: PasswordLayer, Password: []byte("innermost")},
			}})
		if err != nil {
			t.Fatal(err)
		}
		o := OpenOptions{Passwords: [][]byte{[]byte("outermost"), []byte("innermost")}}
		op := &opening{pieces: pieces, o: &o, opened: make([]*format.Manifest, n),
			params: make([]kdf.Params, n), failed: make([]error, n)}
		var tries [2]atomic.Int32
		for w, way := range op.passwordWays() {
			op.ways = append(op.ways, func(p []byte) (*format.Manifest, kdf.Params, error) {
				tries[w].Add(1)
				return way(p)
			})
		}
		if err := op.withPasswords(); err != nil || op.count() != n {
			t.Fatalf("%s: %d of %d opened: %v", c.info, op.count(), n, err)
		}
		if first, all := tries[0].Load(), tries[1].Load(); first != c.first || all != c.all {
			t.Fatalf("%s: the first password alone was tried %d times and every password %d, want %d and %d",
				c.info, first, all, c.first, c.all)
		}
	}
}

// TestTheRestOpenAtTheCostTheReferenceDid checks the pieces after the reference
// are tried at the cost it opened with. A set that did not record its cost has
// noise in every cost byte, and noise that happens to be the cost opens that
// piece alone: the others, tried at their own bytes, would be taken for damaged.
func TestTheRestOpenAtTheCostTheReferenceDid(t *testing.T) {
	const n = 3
	pieces, err := Split([]byte("cost by chance"), SplitOptions{N: n, K: 2, Params: cheap, RecordAlgo: true,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("pw")}}})
	if err != nil {
		t.Fatal(err)
	}
	o := OpenOptions{Passwords: [][]byte{[]byte("pw")}}
	op := &opening{pieces: pieces, o: &o, opened: make([]*format.Manifest, n),
		params: make([]kdf.Params, n), failed: make([]error, n)}
	// Tried at its own cost byte, only the first piece's noise is the cost. The
	// others fail without the derivation their noise asks for, which can be a
	// gibibyte.
	op.ways = []decoder{func(p []byte) (*format.Manifest, kdf.Params, error) {
		cost := o.Params
		if cost == nil {
			if !bytes.Equal(p, pieces[0]) {
				return nil, kdf.Params{}, format.ErrWrongPassword
			}
			cost = &cheap
		}
		return format.DecodePassword(p, o.Passwords, cost)
	}}
	if err := op.withPasswords(); err != nil || op.count() != n {
		t.Fatalf("%d of %d opened once the first opened at its own cost byte: %v", op.count(), n, err)
	}
}
