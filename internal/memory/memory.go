// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package memory provides best-effort protection for secret material: pinned
// off-heap buffers, reliable zeroing, and core-dump suppression.
//
// Bytes and Copy return slices in memory pinned out of swap and registered for
// WipeAll, which the signal and panic handlers run. Passwords go through those;
// Free releases one. Everything else uses Zero, which is unbounded material --
// plaintext and shares can be gigabytes, past any lock limit.
//
// Pure-Go programs cannot make hard guarantees about memory: the runtime may
// keep transient copies the collector later reclaims. This narrows the window
// rather than closing it.
package memory

import (
	"os"
	"os/signal"
	"runtime"
	"sync"
)

// Zero overwrites b with zeros. The trailing runtime.KeepAlive prevents the
// compiler from eliminating the writes as dead stores.
func Zero(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

var (
	regMu   sync.Mutex
	secrets = make(map[*LockedBuffer]struct{})
)

// WipeAll clears every live locked buffer, leaving the memory mapped. It is
// safe to call repeatedly and runs automatically on signal or panic, which is
// what covers the paths os.Exit would skip.
func WipeAll() {
	regMu.Lock()
	bufs := make([]*LockedBuffer, 0, len(secrets))
	for b := range secrets {
		bufs = append(bufs, b)
	}
	regMu.Unlock()
	for _, b := range bufs {
		b.Wipe()
	}
}

var (
	hookMu   sync.Mutex
	hooks    []*hook
	hookNext int
)

// hook is one cleanup registered with OnCleanup.
type hook struct {
	id int
	fn func()
}

// OnCleanup registers fn to run if the process is cut short: by a signal the
// cleanup handler catches, or by a panic GuardPanic sees. It is for undoing what
// must not outlive the process, such as a terminal left in a mode the shell does
// not expect. The returned function removes fn once it is no longer needed; it
// is safe to call more than once.
func OnCleanup(fn func()) (remove func()) {
	hookMu.Lock()
	defer hookMu.Unlock()
	hookNext++
	h := &hook{id: hookNext, fn: fn}
	hooks = append(hooks, h)
	return func() {
		hookMu.Lock()
		defer hookMu.Unlock()
		for i, other := range hooks {
			if other.id == h.id {
				hooks = append(hooks[:i], hooks[i+1:]...)
				return
			}
		}
	}
}

// Cleanup runs every registered hook, newest first and each once, then wipes
// every locked buffer. It is what the signal handler and GuardPanic do before
// the process ends. A hook that panics is passed over so the rest, and the
// wipe, still run.
func Cleanup() {
	hookMu.Lock()
	pending := hooks
	hooks = nil
	hookMu.Unlock()
	for i := len(pending) - 1; i >= 0; i-- {
		func() {
			defer func() { _ = recover() }()
			pending[i].fn()
		}()
	}
	WipeAll()
}

// InstallCleanup suppresses core dumps and installs an interrupt/terminate
// handler that runs Cleanup before exiting. It returns a stop function that
// removes the handler (call it before a normal exit).
func InstallCleanup() (stop func()) {
	_ = DisableCoreDumps()

	ch := make(chan os.Signal, 1)
	notifySignals(ch)
	go func() {
		if _, ok := <-ch; ok {
			Cleanup()
			os.Exit(130)
		}
	}()
	// The stop function is idempotent: a command can return by more than one
	// path, and a cleanup that panicked on a second call would turn an ordinary
	// exit into a crash.
	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(ch)
		})
	}
}

// GuardPanic runs Cleanup if the current goroutine is unwinding a panic, then
// re-raises it. Defer it at the top of any goroutine that touches secrets:
//
//	defer memory.GuardPanic()
func GuardPanic() {
	if r := recover(); r != nil {
		Cleanup()
		panic(r)
	}
}
