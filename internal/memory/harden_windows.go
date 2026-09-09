// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build windows

package memory

import (
	"os"
	"os/signal"
)

// DisableCoreDumps is a no-op on Windows: the runtime does not write core dumps
// for uncaught panics, and crash-dump collection is controlled by system policy
// (Windows Error Reporting), not the process.
func DisableCoreDumps() error { return nil }

func notifySignals(ch chan os.Signal) {
	signal.Notify(ch, os.Interrupt)
}
