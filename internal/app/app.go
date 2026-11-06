// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package app is the command-line entry point for Riven.
package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/memory"
)

// Run is the process entry point.
func Run() {
	stop := memory.InstallCleanup()
	defer stop()
	defer memory.GuardPanic()

	args := os.Args[1:]
	restore := setupColor(noColorRequested(args))
	err := run(args)
	if err != nil {
		printError(os.Stderr, err)
	}
	restore()
	if err != nil {
		memory.WipeAll()
		os.Exit(1)
	}
}

// printError reports the error a command ended with, folded to the terminal and
// with the internal package names taken out.
func printError(out io.Writer, err error) {
	if errors.Is(err, errAborted) {
		fmt.Fprintln(out, "\nriven: aborted")
		return
	}
	writeLabeled(out, "riven: error:", toneError, humanize(err))
}

// internalPrefix matches the package name the internal packages put before their
// messages, which says where an error came from to a developer and nothing to
// anyone running the tool.
var internalPrefix = regexp.MustCompile(`(^|: )(core|format|cascade|compact|disperse|split|kem|kdf|pieceio|qrcode|wire|ciphers|password|memory): `)

// humanize is the error's message as a user should read it.
func humanize(err error) string {
	s := err.Error()
	for {
		t := internalPrefix.ReplaceAllString(s, "$1")
		if t == s {
			return s
		}
		s = t
	}
}

// pieceFailure says why the piece at path did not open, naming it.
func pieceFailure(path string, err error) string {
	if named := namePiece(err, []string{path}); named != err {
		return humanize(named)
	}
	return fmt.Sprintf("%q: %s", path, humanize(err))
}

// namePiece rewrites an error about one of the pieces given, which core counts
// by position, to name its file instead.
func namePiece(err error, paths []string) error {
	var pe *core.PieceError
	if errors.As(err, &pe) && pe.Piece >= 1 && pe.Piece <= len(paths) {
		return fmt.Errorf("%q %w", paths[pe.Piece-1], pe.Err)
	}
	return err
}
