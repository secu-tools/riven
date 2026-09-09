// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build unix

package memory

import (
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// DisableCoreDumps sets the core-dump size limit to zero so secrets cannot be
// captured in a crash dump, plus any platform-specific hardening.
func DisableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return err
	}
	return extraHarden()
}

func notifySignals(ch chan os.Signal) {
	signal.Notify(ch, os.Interrupt, unix.SIGTERM, unix.SIGHUP)
}
