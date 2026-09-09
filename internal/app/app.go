// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package app is the command-line entry point for Riven.
package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/secu-tools/riven/internal/memory"
)

// Run is the process entry point.
func Run() {
	stop := memory.InstallCleanup()
	defer stop()
	defer memory.GuardPanic()

	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errAborted) {
			fmt.Fprintln(os.Stderr, "\nriven: aborted")
		} else {
			fmt.Fprintln(os.Stderr, "riven:", err)
		}
		memory.WipeAll()
		os.Exit(1)
	}
}
