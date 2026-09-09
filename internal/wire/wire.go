// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package wire is a minimal, allocation-conscious binary codec. Every read is
// bounds-checked and returns an error rather than panicking, so it is safe to
// run against truncated, malformed, or hostile input.
package wire

import (
	"encoding/binary"
	"errors"
)

// ErrShort is returned when a read would go past the end of the buffer.
var ErrShort = errors.New("wire: unexpected end of data")

// ErrTooLarge is returned when a length prefix exceeds the caller's limit or the
// remaining buffer.
var ErrTooLarge = errors.New("wire: length prefix exceeds limit")

// Writer accumulates encoded bytes.
type Writer struct {
	buf []byte
}

// NewWriter returns a Writer with the given initial capacity hint.
func NewWriter(capHint int) *Writer {
	return &Writer{buf: make([]byte, 0, capHint)}
}

func (w *Writer) U8(v uint8) { w.buf = append(w.buf, v) }

func (w *Writer) U16(v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *Writer) U32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *Writer) U64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

// Raw appends bytes with no length prefix.
func (w *Writer) Raw(b []byte) { w.buf = append(w.buf, b...) }

// Bytes appends a uint32 length prefix followed by b.
func (w *Writer) Bytes(b []byte) {
	w.U32(uint32(len(b)))
	w.buf = append(w.buf, b...)
}

// Result returns the accumulated bytes. The Writer must not be used afterward.
func (w *Writer) Result() []byte { return w.buf }

// Reader consumes an encoded buffer.
type Reader struct {
	data []byte
	pos  int
}

// NewReader wraps b. It does not copy; callers keep ownership of b.
func NewReader(b []byte) *Reader { return &Reader{data: b} }

// Remaining returns the number of unread bytes.
func (r *Reader) Remaining() int { return len(r.data) - r.pos }

func (r *Reader) U8() (uint8, error) {
	if r.Remaining() < 1 {
		return 0, ErrShort
	}
	v := r.data[r.pos]
	r.pos++
	return v, nil
}

func (r *Reader) U16() (uint16, error) {
	if r.Remaining() < 2 {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint16(r.data[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *Reader) U32() (uint32, error) {
	if r.Remaining() < 4 {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint32(r.data[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *Reader) U64() (uint64, error) {
	if r.Remaining() < 8 {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint64(r.data[r.pos:])
	r.pos += 8
	return v, nil
}

// Raw reads exactly n bytes and returns a copy.
func (r *Reader) Raw(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrTooLarge
	}
	if r.Remaining() < n {
		return nil, ErrShort
	}
	out := make([]byte, n)
	copy(out, r.data[r.pos:r.pos+n])
	r.pos += n
	return out, nil
}

// Bytes reads a uint32-length-prefixed slice, rejecting lengths above max or
// beyond the remaining buffer. max <= 0 means "only bounded by the buffer".
func (r *Reader) Bytes(max int) ([]byte, error) {
	n, err := r.U32()
	if err != nil {
		return nil, err
	}
	if max > 0 && int64(n) > int64(max) {
		return nil, ErrTooLarge
	}
	if int64(n) > int64(r.Remaining()) {
		return nil, ErrTooLarge
	}
	return r.Raw(int(n))
}

// Rest returns and consumes all remaining bytes (a copy).
func (r *Reader) Rest() []byte {
	out := make([]byte, r.Remaining())
	copy(out, r.data[r.pos:])
	r.pos = len(r.data)
	return out
}
