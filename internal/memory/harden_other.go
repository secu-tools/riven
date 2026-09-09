// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build !unix && !windows

package memory

import (
	"os"
	"os/signal"
)

// DisableCoreDumps is a no-op on platforms without a supported rlimit API.
func DisableCoreDumps() error { return nil }

func notifySignals(ch chan os.Signal) {
	signal.Notify(ch, os.Interrupt)
}
