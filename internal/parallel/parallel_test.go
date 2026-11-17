// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package parallel

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

func TestDoRunsEveryIndexOnce(t *testing.T) {
	for _, n := range []int{0, 1, 2, 7, 64} {
		for _, w := range []int{1, 2, 8} {
			seen := make([]int32, n)
			if err := Do(n, w, func(i int) error {
				atomic.AddInt32(&seen[i], 1)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for i, c := range seen {
				if c != 1 {
					t.Fatalf("n=%d workers=%d: index %d ran %d times", n, w, i, c)
				}
			}
		}
	}
}

// TestDoReportsTheLowestFailure pins the property callers depend on: whatever
// order the work finishes in, the error belongs to the first failing index, so
// messages that name a piece number stay stable.
func TestDoReportsTheLowestFailure(t *testing.T) {
	for _, w := range []int{1, 4, 16} {
		err := Do(16, w, func(i int) error {
			if i == 3 || i == 9 {
				return fmt.Errorf("index %d", i)
			}
			return nil
		})
		if err == nil || err.Error() != "index 3" {
			t.Fatalf("workers=%d: got %v, want the error from index 3", w, err)
		}
	}
}

// TestDoRunsEveryIndexDespiteFailure checks that a failure does not cancel the
// rest, since callers write results into a preallocated slice and a half-filled
// slice would be harder to reason about than a fully attempted one.
func TestDoRunsEveryIndexDespiteFailure(t *testing.T) {
	var ran int32
	err := Do(10, 4, func(i int) error {
		atomic.AddInt32(&ran, 1)
		if i == 0 {
			return errors.New("first")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected the failure to surface")
	}
	if ran != 10 {
		t.Fatalf("%d of 10 indexes ran", ran)
	}
}

// TestDoIsActuallyConcurrent checks the work really overlaps, since a helper
// that quietly serialized would still pass every other test here.
func TestDoIsActuallyConcurrent(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("needs more than one processor")
	}
	const n = 4
	var mu sync.Mutex
	running, peak := 0, 0
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = Do(n, n, func(int) error {
			mu.Lock()
			running++
			if running > peak {
				peak = running
			}
			atPeak := running == n
			mu.Unlock()
			if atPeak {
				close(release)
			}
			<-release
			mu.Lock()
			running--
			mu.Unlock()
			return nil
		})
	}()
	wg.Wait()
	if peak < 2 {
		t.Fatalf("peak concurrency was %d, so the work did not overlap", peak)
	}
}

func TestDoSerialPathStopsAtTheFirstFailure(t *testing.T) {
	var ran int
	err := Do(5, 1, func(i int) error {
		ran++
		if i == 1 {
			return errors.New("stop")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if ran != 2 {
		t.Fatalf("serial path ran %d indexes, want it to stop after the failure", ran)
	}
}

// TestDoPassesAPanicToTheCaller checks a panic in a worker reaches the goroutine
// that called Do, after every worker has stopped, rather than ending the process
// from a goroutine nothing defers in. The caller's own deferred cleanup, which
// restores the terminal and wipes secrets, then runs as it would for any panic.
func TestDoPassesAPanicToTheCaller(t *testing.T) {
	var ran atomic.Int32
	got := func() (r any) {
		defer func() { r = recover() }()
		_ = Do(8, 4, func(i int) error {
			ran.Add(1)
			if i == 3 {
				panic("worker failed")
			}
			return nil
		})
		return nil
	}()
	if got == nil || !strings.Contains(fmt.Sprint(got), "worker failed") {
		t.Fatalf("the caller recovered %v, want the worker's panic", got)
	}
	if ran.Load() != 8 {
		t.Fatalf("%d of 8 indexes ran: the other workers must finish before the panic is passed on", ran.Load())
	}
}

func TestWorkers(t *testing.T) {
	if got := Workers(0); got != 1 {
		t.Fatalf("Workers(0) = %d, want 1", got)
	}
	if got := Workers(1); got != 1 {
		t.Fatalf("Workers(1) = %d, want 1", got)
	}
	if got := Workers(2); got > 2 || got < 1 {
		t.Fatalf("Workers(2) = %d, want 1 or 2", got)
	}
	// Never more than the work available, and never more than the machine has.
	big := Workers(1000)
	if big > runtime.GOMAXPROCS(0) {
		t.Fatalf("Workers(1000) = %d, over GOMAXPROCS %d", big, runtime.GOMAXPROCS(0))
	}
}

// TestOrderedUsesEveryIndexInOrder checks Ordered hands every index to use once
// and in order, however the work finishes, and never runs work more than
// workers indexes ahead of use.
func TestOrderedUsesEveryIndexInOrder(t *testing.T) {
	for _, n := range []int{0, 1, 5, 100} {
		for _, w := range []int{1, 3, 16} {
			var started atomic.Int64
			var used []int
			err := Ordered(n, w, func(i int) error {
				started.Add(1)
				if i%3 == 0 {
					runtime.Gosched() // finish out of order
				}
				return nil
			}, func(i int) error {
				if s := started.Load(); s > int64(i+w) {
					return fmt.Errorf("index %d started while %d was in use, %d workers", s-1, i, w)
				}
				used = append(used, i)
				return nil
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for i, u := range used {
				if u != i {
					t.Fatalf("n=%d w=%d: used %v, want 0 to %d in order", n, w, used, n-1)
				}
			}
			if len(used) != n || started.Load() != int64(n) {
				t.Fatalf("n=%d w=%d: used %d and started %d", n, w, len(used), started.Load())
			}
		}
	}
}

// TestOrderedStopsAtTheFirstError checks an error from work or from use stops
// Ordered there: use sees nothing past it, no work starts long after it, and the
// error is what comes back.
func TestOrderedStopsAtTheFirstError(t *testing.T) {
	const n, w, at = 50, 4, 10
	errAt := errors.New("failed")
	for _, inWork := range []bool{true, false} {
		var started atomic.Int64
		var used []int
		err := Ordered(n, w, func(i int) error {
			started.Add(1)
			if inWork && i == at {
				return errAt
			}
			return nil
		}, func(i int) error {
			used = append(used, i)
			if !inWork && i == at {
				return errAt
			}
			return nil
		}, nil)
		if !errors.Is(err, errAt) {
			t.Fatalf("in work %v: got %v", inWork, err)
		}
		want := at
		if !inWork {
			want++
		}
		if len(used) != want || used[len(used)-1] != want-1 {
			t.Fatalf("in work %v: used %v, want 0 to %d", inWork, used, want-1)
		}
		if s := started.Load(); s > at+w {
			t.Fatalf("in work %v: %d indexes started, at most %d should", inWork, s, at+w)
		}
	}
}

// TestOrderedSaysWhatItWaitsFor checks waiting hears of an index whose work is
// not done when use reaches it, and not of those whose work is.
func TestOrderedSaysWhatItWaitsFor(t *testing.T) {
	// The first index's work finishes only once Ordered says it is waiting for
	// it, so without the call it would never finish. The rest are done by the time
	// use reaches them: use of the first waits until every other goroutine has
	// finished or is blocked, which the workers are only once they have handed
	// their results over.
	synctest.Test(t, func(t *testing.T) {
		const n = 6
		told := make(chan struct{})
		var waited []int
		err := Ordered(n, n, func(i int) error {
			if i == 0 {
				<-told
			}
			return nil
		}, func(i int) error {
			if i == 0 {
				synctest.Wait()
			}
			return nil
		}, func(i int) {
			waited = append(waited, i)
			if i == 0 {
				close(told)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(waited) != 1 || waited[0] != 0 {
			t.Fatalf("waited for %v, want index 0 alone", waited)
		}
	})
}

func TestOrderedPassesAPanicToTheCaller(t *testing.T) {
	var used atomic.Int32
	got := func() (r any) {
		defer func() { r = recover() }()
		_ = Ordered(20, 4, func(i int) error {
			if i == 3 {
				panic("worker failed")
			}
			return nil
		}, func(int) error {
			used.Add(1)
			return nil
		}, nil)
		return nil
	}()
	if got == nil || !strings.Contains(fmt.Sprint(got), "worker failed") {
		t.Fatalf("the caller recovered %v, want the worker's panic", got)
	}
	if used.Load() != 3 {
		t.Fatalf("use took %d indexes, want the 3 before the panic", used.Load())
	}
}

// TestOrderedKeepsAPanicInUse checks a panic in use reaches the caller as it is,
// even when a worker has panicked meanwhile: use runs on the caller's goroutine,
// so its panic is the caller's own, and the worker's once replaced it. The
// worker panics first, and use waits for that before it panics too.
func TestOrderedKeepsAPanicInUse(t *testing.T) {
	workerDone := make(chan struct{})
	got := func() (r any) {
		defer func() { r = recover() }()
		_ = Ordered(4, 2, func(i int) error {
			if i == 1 {
				defer close(workerDone)
				panic("worker failed")
			}
			return nil
		}, func(i int) error {
			<-workerDone
			panic("use failed")
		}, nil)
		return nil
	}()
	if fmt.Sprint(got) != "use failed" {
		t.Fatalf("the caller recovered %v, want use's own panic", got)
	}
}
