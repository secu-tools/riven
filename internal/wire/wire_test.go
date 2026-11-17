// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package wire

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	w := NewWriter(0)
	w.U8(0x12)
	w.U16(0x3456)
	w.U32(0x789abcde)
	w.Bytes([]byte("hello"))
	w.Raw([]byte("tail"))
	buf := w.Result()

	r := NewReader(buf)
	if v, _ := r.U8(); v != 0x12 {
		t.Fatal("u8")
	}
	if v, _ := r.U16(); v != 0x3456 {
		t.Fatal("u16")
	}
	if v, _ := r.U32(); v != 0x789abcde {
		t.Fatal("u32")
	}
	b, _ := r.Bytes(1024)
	if !bytes.Equal(b, []byte("hello")) {
		t.Fatal("bytes")
	}
	if !bytes.Equal(r.RestView(), []byte("tail")) {
		t.Fatal("rest")
	}
}

func TestReaderBounds(t *testing.T) {
	r := NewReader([]byte{0x01})
	if _, err := r.U8(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.U8(); err != ErrShort {
		t.Fatalf("expected ErrShort, got %v", err)
	}

	r = NewReader([]byte{0, 0, 0}) // 3 bytes, ask for u32
	if _, err := r.U32(); err != ErrShort {
		t.Fatalf("expected ErrShort, got %v", err)
	}
}

func TestBytesTooLarge(t *testing.T) {
	// Length prefix claims 1000 bytes but only a few remain.
	buf := []byte{0x00, 0x00, 0x03, 0xE8, 0x01, 0x02}
	r := NewReader(buf)
	if _, err := r.Bytes(0); err != ErrTooLarge {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
	// Exceeds explicit max.
	r = NewReader([]byte{0x00, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5})
	if _, err := r.Bytes(4); err != ErrTooLarge {
		t.Fatalf("expected ErrTooLarge for over-max, got %v", err)
	}
}

// FuzzReader ensures no sequence of reads over arbitrary input can panic.
func FuzzReader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, 9, 9, 1, 2, 3})
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 3, 1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(data)
		for i := 0; i < 8; i++ {
			_, _ = r.U8()
			_, _ = r.U16()
			_, _ = r.U32()
			_, _ = r.Bytes(1 << 20)
			_, _ = r.View64()
			_, _ = r.Raw(3)
		}
		_ = r.RestView()
	})
}

// TestViewsShareTheBuffer checks View and RestView return the bytes in place
// rather than copies, and that a view cannot grow over the field after it.
func TestViewsShareTheBuffer(t *testing.T) {
	w := NewWriter(0)
	w.Bytes([]byte("first"))
	w.Bytes([]byte("second"))
	w.Raw([]byte("rest"))
	buf := w.Result()

	r := NewReader(buf)
	first, err := r.View(0)
	if err != nil || string(first) != "first" {
		t.Fatalf("view %q, %v", first, err)
	}
	first[0] = 'F'
	if !bytes.Contains(buf, []byte("First")) {
		t.Fatal("a view is a copy")
	}
	_ = append(first, 'X')
	second, err := r.View(6)
	if err != nil || string(second) != "second" {
		t.Fatalf("appending to a view changed the next field: %q, %v", second, err)
	}
	if rest := r.RestView(); string(rest) != "rest" || r.Remaining() != 0 {
		t.Fatalf("rest view %q", rest)
	}
	if _, err := NewReader([]byte{0, 0, 0, 3, 1, 2}).View(0); err != ErrTooLarge {
		t.Fatalf("a view past the buffer: %v", err)
	}
}

// TestView64ReadsALongPrefix checks a field behind a uint64 length prefix, the
// way format writes a fragment, reads back whole and empty.
func TestView64ReadsALongPrefix(t *testing.T) {
	w := NewWriter(0)
	w.U64(5)
	w.Raw([]byte("large"))
	w.U64(0)
	w.Raw([]byte("rest"))
	buf := w.Result()
	if len(buf) != 8+5+8+4 {
		t.Fatalf("encoded %d bytes, want two 8-byte prefixes", len(buf))
	}

	r := NewReader(buf)
	if v, err := r.View64(); err != nil || string(v) != "large" {
		t.Fatalf("view %q, %v", v, err)
	}
	if v, err := r.View64(); err != nil || len(v) != 0 {
		t.Fatalf("empty view %q, %v", v, err)
	}
	if rest := r.RestView(); string(rest) != "rest" {
		t.Fatalf("rest %q", rest)
	}
}

// TestView64ReadsTheWholeLength shows a length past 4 GiB is read whole, with no
// 4 GiB buffer: the claim is 2^32+3 with 3 bytes behind it, which a reader that
// kept only the low 32 bits would take as a 3-byte field.
func TestView64ReadsTheWholeLength(t *testing.T) {
	for _, n := range []uint64{1<<32 + 3, math.MaxInt64 + 1, math.MaxUint64} {
		buf := binary.BigEndian.AppendUint64(nil, n)
		buf = append(buf, 1, 2, 3)
		if v, err := NewReader(buf).View64(); err != ErrTooLarge {
			t.Errorf("a length of %d over 3 bytes gave %d bytes, %v; want ErrTooLarge", n, len(v), err)
		}
	}
	if _, err := NewReader([]byte{0, 0, 0, 0, 0, 0, 0}).View64(); err != ErrShort {
		t.Errorf("a 7-byte prefix: %v, want ErrShort", err)
	}
}

// TestBytesRefusesALengthItWouldWrap covers the writer side of the same limit: a
// u32 prefix cannot hold 4 GiB, so the length is refused rather than wrapped.
func TestBytesRefusesALengthItWouldWrap(t *testing.T) {
	if got := prefixLen(math.MaxUint32); got != math.MaxUint32 {
		t.Fatalf("the longest field got a prefix of %d", got)
	}
	if uint64(math.MaxInt) <= math.MaxUint32 {
		t.Skip("an int here cannot hold a length past a u32")
	}
	over := uint64(math.MaxUint32) + 1
	defer func() {
		if recover() == nil {
			t.Fatal("a 4 GiB field was given a wrapped prefix")
		}
	}()
	prefixLen(int(over))
}
