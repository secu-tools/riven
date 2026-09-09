// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package parallel

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
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
