// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/parallel"
	"github.com/secu-tools/riven/internal/pieceio"
)

// heldPiece is one file that was read successfully.
type heldPiece struct {
	bytes []byte
	det   pieceio.Detected
}

func pieceBytes(items []heldPiece) [][]byte {
	out := make([][]byte, len(items))
	for i, p := range items {
		out[i] = p.bytes
	}
	return out
}

// pieceArg is one input path together with how it was named. A path found inside
// a directory is skipped when it turns out not to be a piece; a path the user
// typed is not, because they meant that file.
type pieceArg struct {
	path    string
	fromDir bool
	size    int64 // what the file system said, for how many to read at once
}

// notPieceExts are the files Riven itself writes that are not pieces, and that
// sit beside a set often enough to be worth stepping over.
var notPieceExts = map[string]bool{extPrivKey: true, extPubKey: true}

// expandPieceArgs turns the paths given on the command line into files to read.
// A directory contributes the files directly inside it, so a whole set can be
// named at once on a shell with no glob, or with one that would not expand it.
func expandPieceArgs(args []string) ([]pieceArg, error) {
	var out []pieceArg
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, pieceArg{path: arg, size: info.Size()})
			continue
		}
		found, err := dirPieceFiles(arg)
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

// dirPieceFiles lists the candidate piece files directly inside dir, in the name
// order os.ReadDir returns. It does not descend: a nested directory is a
// separate set, not part of this one.
func dirPieceFiles(dir string) ([]pieceArg, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []pieceArg
	for _, e := range entries {
		name := e.Name()
		// Only regular files. A symlink to a device or a FIFO left among the
		// pieces would otherwise be read: /dev/zero until memory runs out, a FIFO
		// forever. The user naming a file directly still gets it either way.
		if !e.Type().IsRegular() || strings.HasPrefix(name, ".") ||
			notPieceExts[strings.ToLower(filepath.Ext(name))] {
			continue
		}
		var size int64
		if info, err := e.Info(); err == nil {
			size = info.Size()
		}
		out = append(out, pieceArg{path: filepath.Join(dir, name), fromDir: true, size: size})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no files to read", dir)
	}
	return out, nil
}

// loadPiece reads one piece file. It is a variable so a test can hold a file
// back and see what the command shows while it waits.
var loadPiece = pieceio.Load

// loadInputs reads every file named on the command line, expanding directories.
//
// A file found inside a directory that is not a piece is skipped without
// comment, since the directory was named rather than the file. A file named
// directly is expected to be a piece: strict decides whether that stops the
// command or is only reported.
//
// Repeats are dropped, since one piece exported in several formats decodes to
// the same bytes. Opening a piece costs a full key derivation, so a directory
// written with --format all would otherwise cost six times what it should.
//
// The files are read and decoded several at a time, ahead of the one being
// taken, and taken in the order given.
func loadInputs(out io.Writer, args []string, strict bool) ([]heldPiece, error) {
	inputs, err := expandPieceArgs(args)
	if err != nil {
		return nil, err
	}

	type loaded struct {
		piece []byte
		det   pieceio.Detected
		err   error
	}
	read := make([]loaded, len(inputs))
	defer func() {
		for _, l := range read {
			memory.Zero(l.piece)
		}
	}()
	var largest int64
	for _, in := range inputs {
		largest = max(largest, in.size)
	}

	var items []heldPiece
	seen := map[pieceKey][]int{} // the items with each key
	repeats := 0
	reading := readingFile(progress, len(inputs))
	err = parallel.Ordered(len(inputs), workersFor(largest), func(i int) error {
		l := &read[i]
		l.piece, l.det, l.err = loadPiece(inputs[i].path)
		return nil
	}, func(i int) error {
		in, l := inputs[i], read[i]
		read[i] = loaded{}
		reading(i)
		if l.err != nil {
			progress("", 0, 0)
			switch {
			case in.fromDir:
			case strict:
				return l.err
			default:
				fmt.Fprintf(out, "  %q: cannot read (%v)\n", in.path, l.err)
			}
			return nil
		}
		key := keyOf(l.piece)
		if slices.ContainsFunc(seen[key], func(n int) bool { return bytes.Equal(items[n].bytes, l.piece) }) {
			memory.Zero(l.piece)
			repeats++
			return nil
		}
		seen[key] = append(seen[key], len(items))
		items = append(items, heldPiece{bytes: l.piece, det: l.det})
		return nil
	}, reading)
	progress("", 0, 0)
	if err != nil {
		for _, it := range items {
			memory.Zero(it.bytes)
		}
		return nil, err
	}
	if repeats > 0 {
		fmt.Fprintf(out, "  %d file(s) hold the same piece as another and were skipped\n", repeats)
	}
	if len(items) == 0 {
		return nil, errors.New("no piece could be read")
	}
	return items, nil
}

// pieceKey is what two copies of one piece are first matched by: its length and
// how it starts. A piece starts with a salt and a nonce drawn at random, so two
// different pieces all but never share a key, and telling a repeat costs a
// comparison only when there is one, not a pass over every piece read.
type pieceKey struct {
	size int
	head [48]byte
}

func keyOf(piece []byte) pieceKey {
	k := pieceKey{size: len(piece)}
	copy(k.head[:], piece)
	return k
}

var errSplitDirectory = errors.New(
	"a folder cannot be split: pack it into an archive first, for example " +
		"'tar -czf archive.tar.gz DIR', and split that (see docs/usage.md)")
