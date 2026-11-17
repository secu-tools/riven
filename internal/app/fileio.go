// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/pieceio"
)

// Creating or opening a file costs far more than writing or reading a piece's
// few bytes, on Windows above all, where a virus scanner looks at each one, and
// several files under way at once share that wait. So piece files are written
// and read up to fileWorkers at a time, as long as the pieces in flight fit in
// fileBudget: a set of large pieces goes one file at a time, as the disk would
// take it anyway.
const (
	fileWorkers = 8
	fileBudget  = 64 << 20
)

// workersFor is how many files of size bytes are written or read at once.
func workersFor(size int64) int {
	return int(max(1, min(fileWorkers, fileBudget/max(1, size))))
}

// pieceWriter writes the pieces of a split in every format, on several
// goroutines, so the files are created while the next pieces are sealed. It
// owns each piece it is given and wipes it once written. The first failure stops
// it: the pieces after it are wiped unwritten, and the error comes back from the
// next add and from wait.
type pieceWriter struct {
	plan    *splitPlan
	formats []pieceio.Format
	name    func(serial int) string

	// Each piece's paths and digest, by serial, so the workers fill them in
	// without a lock.
	written map[pieceio.Format][]string
	sums    [][sha256.Size]byte
	size    int // of every piece

	jobs         chan writeJob
	wg           sync.WaitGroup
	firstFailure // by serial
}

type writeJob struct {
	serial int
	piece  []byte
}

// newPieceWriter starts the writers for a split whose pieces are size bytes. It
// takes each piece's digest only when digests says a full check will want them.
func newPieceWriter(plan *splitPlan, formats []pieceio.Format, name func(int) string, size int, digests bool) *pieceWriter {
	n := plan.opts.N
	w := &pieceWriter{
		plan: plan, formats: formats, name: name,
		written: make(map[pieceio.Format][]string, len(formats)),
		size:    size,
		jobs:    make(chan writeJob),
	}
	if digests {
		w.sums = make([][sha256.Size]byte, n)
	}
	for _, f := range formats {
		w.written[f] = make([]string, n)
	}
	for range workersFor(int64(size)) {
		w.wg.Add(1)
		go func() {
			defer memory.GuardPanic()
			defer w.wg.Done()
			for j := range w.jobs {
				if w.failure() != nil {
					memory.Zero(j.piece)
					continue
				}
				if err := w.write(j.serial, j.piece); err != nil {
					w.fail(j.serial, err)
				}
			}
		}()
	}
	return w
}

// add hands piece serial to a writer, waiting for one to be free.
func (w *pieceWriter) add(serial int, piece []byte) error {
	if err := w.failure(); err != nil {
		memory.Zero(piece)
		return err
	}
	// The formats were checked against the size the pieces were planned at, so a
	// piece of another size would be written under a check it never had.
	if len(piece) != w.size {
		memory.Zero(piece)
		return fmt.Errorf("piece %d is %d bytes, not the %d it was planned at", serial, len(piece), w.size)
	}
	w.jobs <- writeJob{serial, piece}
	return nil
}

// wait lets the writers finish what they hold and returns the first failure.
func (w *pieceWriter) wait() error {
	close(w.jobs)
	w.wg.Wait()
	return w.failure()
}

// write writes one piece in every format and wipes it.
func (w *pieceWriter) write(serial int, piece []byte) error {
	defer memory.Zero(piece)
	progress(fmt.Sprintf("writing piece %d of %d", serial, w.plan.opts.N), 0, 0)
	if w.sums != nil {
		w.sums[serial-1] = sha256.Sum256(piece)
	}
	name := w.name(serial)
	for _, f := range w.formats {
		path := pieceio.Path(w.plan.outDir, name, f)
		data := piece
		if f != pieceio.Binary {
			var err error
			if data, err = encodeOne(piece, f, w.plan, serial); err != nil {
				return fmt.Errorf("%s export: %w", f, err)
			}
		}
		err := pieceio.Write(path, data)
		if f != pieceio.Binary {
			memory.Zero(data)
		}
		if err != nil {
			return err
		}
		w.written[f][serial-1] = path
	}
	return nil
}

// firstFailure keeps the failure of the lowest index among work running at once,
// so a failure is reported the same however the work was scheduled.
type firstFailure struct {
	mu  sync.Mutex
	err error
	at  int
}

// fail records err for index at.
func (f *firstFailure) fail(at int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err == nil || at < f.at {
		f.err, f.at = err, at
	}
}

// failure returns the failure kept, if there is one.
func (f *firstFailure) failure() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}
