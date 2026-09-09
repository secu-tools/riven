// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
			out = append(out, pieceArg{path: arg})
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
		out = append(out, pieceArg{path: filepath.Join(dir, name), fromDir: true})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no files to read", dir)
	}
	return out, nil
}

// loadInputs reads every file named on the command line, expanding directories.
//
// A file found inside a directory that is not a piece is skipped without
// comment, since the directory was named rather than the file. A file named
// directly is expected to be a piece: strict decides whether that stops the
// command or is only reported.
//
// Repeats are dropped, since one piece exported in several formats decodes to
// the same bytes. Opening a piece costs a full key derivation, so a directory
// written with --format all would otherwise cost five times what it should.
func loadInputs(out io.Writer, args []string, strict bool) ([]heldPiece, error) {
	inputs, err := expandPieceArgs(args)
	if err != nil {
		return nil, err
	}

	var items []heldPiece
	seen := map[[sha256.Size]byte]bool{}
	repeats := 0
	for _, in := range inputs {
		piece, det, err := pieceio.Load(in.path)
		if err != nil {
			switch {
			case in.fromDir:
			case strict:
				return nil, err
			default:
				fmt.Fprintf(out, "  %q: cannot read (%v)\n", in.path, err)
			}
			continue
		}
		key := sha256.Sum256(piece)
		if seen[key] {
			repeats++
			continue
		}
		seen[key] = true
		items = append(items, heldPiece{bytes: piece, det: det})
	}
	if repeats > 0 {
		fmt.Fprintf(out, "  %d file(s) hold the same piece as another and were skipped\n", repeats)
	}
	if len(items) == 0 {
		return nil, errors.New("no piece could be read")
	}
	return items, nil
}

var errSplitDirectory = errors.New(
	"riven splits one file: pack the directory into an archive first, for example " +
		"'tar -czf archive.tar.gz DIR', then split that. Compressing as you pack " +
		"shrinks every piece, since each one is the size of the whole input")
