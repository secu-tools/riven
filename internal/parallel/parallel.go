// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package parallel runs independent pieces of work across cores. It exists so
// the two places that need it, per-piece key derivation and Shamir splitting,
// report failures the same way: the error of the lowest failing index, whatever
// order the work finished in.
package parallel

import (
	"runtime"
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
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				errs[i] = fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
