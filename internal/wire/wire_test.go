// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package wire

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	w := NewWriter(0)
	w.U8(0x12)
	w.U16(0x3456)
	w.U32(0x789abcde)
	w.U64(0x0102030405060708)
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
	if v, _ := r.U64(); v != 0x0102030405060708 {
		t.Fatal("u64")
	}
	b, _ := r.Bytes(1024)
	if !bytes.Equal(b, []byte("hello")) {
		t.Fatal("bytes")
	}
	if !bytes.Equal(r.Rest(), []byte("tail")) {
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
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(data)
		for i := 0; i < 8; i++ {
			_, _ = r.U8()
			_, _ = r.U16()
			_, _ = r.U32()
			_, _ = r.U64()
			_, _ = r.Bytes(1 << 20)
			_, _ = r.Raw(3)
		}
		_ = r.Rest()
	})
}
