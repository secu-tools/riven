// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package parallel runs independent pieces of work across cores. It exists so
// the places that need it, from per-piece key derivation and Shamir splitting
// to reading and writing piece files, report failures the same way: the error of
// the lowest failing index, whatever order the work finished in.
package parallel

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
)

// Workers returns a sensible worker count for n independent items, never more
// than the number of items or the available parallelism.
func Workers(n int) int {
	if n <= 1 {
		return 1
	}
	w := runtime.GOMAXPROCS(0)
	if w > n {
		w = n
	}
	if w < 1 {
		w = 1
	}
	return w
}

// Do runs fn for every index in [0, n) with at most workers running at a time.
// It returns the error from the lowest failing index, so a failure is reported
// identically however the work was scheduled. Every index runs even if an
// earlier one fails, which keeps the work deterministic and side-effect free
// for callers that write into a preallocated slice.
func Do(n, workers int, fn func(i int) error) error {
	if n <= 0 {
		return nil
	}
	if workers <= 1 || n == 1 {
		for i := 0; i < n; i++ {
			if err := fn(i); err != nil {
				return err
			}
		}
		return nil
	}

	errs := make([]error, n)
	next := make(chan int)
	var wg sync.WaitGroup
	var c catcher
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				// The worker carries on after a panic, so the rest of the work
				// is not left blocked.
				func() {
					defer c.catch()
					errs[i] = fn(i)
				}()
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	c.rethrow()

	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// Ordered runs work for every index in [0, n) on up to workers goroutines, and
// use for each index in order, on the caller's goroutine, once its work is done.
// What work makes is made in parallel and taken in order: pieces sealed on every
// core and written out one after another, or files read ahead of the one in use.
// Work runs at most workers indexes ahead of use, which bounds what is held
// between the two. waiting, when it is not nil, is told each index use has to
// wait for, which is when work rather than use is what holds things up.
//
// The first error, from work or from use in index order, stops it: no more work
// starts, the work already running finishes, and Ordered returns that error.
// Whatever work made for an index use never took is the caller's to release once
// Ordered returns. A panic in work is raised again in the caller, as Do does.
func Ordered(n, workers int, work, use func(i int) error, waiting func(i int)) error {
	if n <= 0 {
		return nil
	}
	workers = max(1, min(workers, n))
	// Index i reports in slot i%workers. The work for an index starts only once
	// use is done with the one workers before it, which shared its slot, so the
	// slot is always empty again by then.
	slots := make([]chan error, workers)
	for i := range slots {
		slots[i] = make(chan error, 1)
	}
	var wg sync.WaitGroup
	var c catcher
	// A panic in use is the caller's own and is already on its way; one a worker
	// raised meanwhile would replace it, and name the wrong goroutine.
	returned := false
	defer func() {
		wg.Wait()
		if returned {
			c.rethrow()
		}
	}()
	start := func(i int) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := errWorkerPanic
			defer func() { slots[i%workers] <- err }()
			defer c.catch()
			err = work(i)
		}()
	}
	for i := range workers {
		start(i)
	}

	err := func() error {
		for i := range n {
			var err error
			select {
			case err = <-slots[i%workers]:
			default:
				if waiting != nil {
					waiting(i)
				}
				err = <-slots[i%workers]
			}
			if err == nil {
				err = use(i)
			}
			if err != nil {
				return err
			}
			if next := i + workers; next < n {
				start(next)
			}
		}
		return nil
	}()
	returned = true
	return err
}

// errWorkerPanic stands in for the result of work that panicked, so Ordered
// stops there; the panic itself is raised once every worker has finished.
var errWorkerPanic = errors.New("parallel: a worker panicked")

// catcher keeps the first panic raised in the workers. A panic in a worker would
// end the process from a goroutine with nothing deferred in it, skipping the
// cleanup the caller's goroutine has in place, so it is raised again in the
// caller once every worker has finished.
type catcher struct {
	once  sync.Once
	crash workerPanic
}

// catch is deferred by a worker. It must be deferred itself, not called from
// another deferred function, for recover to see the panic.
func (c *catcher) catch() {
	if r := recover(); r != nil {
		c.once.Do(func() { c.crash = workerPanic{value: r, stack: debug.Stack()} })
	}
}

// rethrow raises the panic caught, if there was one.
func (c *catcher) rethrow() {
	if c.crash.stack != nil {
		panic(c.crash)
	}
}

// workerPanic is a panic raised in a worker, carried to the caller with the
// stack of the goroutine it happened in, which is the one worth reading.
type workerPanic struct {
	value any
	stack []byte
}

func (p workerPanic) Error() string {
	return fmt.Sprintf("%v\n\npanicked in a worker:\n%s", p.value, p.stack)
}
