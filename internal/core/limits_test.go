// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"testing"

	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/split"
)

// TestLargeSplitsPlanExactly runs the size arithmetic of a full-method split past
// the 4 GiB a u32 holds, which a unit test cannot afford to allocate: a piece
// takes the share, the fill still brings the piece to its size class, and the
// memory estimate does not wrap. tests/large splits such an input for real.
func TestLargeSplitsPlanExactly(t *testing.T) {
	for _, payloadLen := range []int{1<<32 - 64, 1<<32 + 1, 37<<30 + 12345, 64 << 30} {
		for _, k := range []int{1, 2, 3} {
			for _, w := range []int{MinPadPercent, 10, MaxPadPercent} {
				shape := format.Shape{Layers: 3, Meta: 40}
				natural, padded := shape, shape
				natural.Share = split.ShareLen(format.SharedLen(payloadLen, format.MinFill), k)
				want := BucketFor(format.PieceLen(natural), w)

				fill, pad := fillLen(payloadLen, SplitOptions{N: 5, K: k, Padding: PadPercent(w)}, shape)
				padded.Share = split.ShareLen(format.SharedLen(payloadLen, fill), k)
				padded.Pad = pad
				if got := format.PieceLen(padded); got != want {
					t.Fatalf("%d bytes at K=%d, width %d: a piece of %d bytes, want the class of %d",
						payloadLen, k, w, got, want)
				}
				if err := fitsPiece(padded); err != nil {
					t.Fatalf("%d bytes at K=%d: %v", payloadLen, k, err)
				}
			}
		}
	}
	if err := fitsPiece(format.Shape{Share: int(format.MaxCarriedLen) + 1}); err == nil {
		t.Fatal("a share past what a piece carries was accepted")
	}
	// The limit is on all a piece carries, as the format applies it: a share that
	// fits alone does not with a details share, or a fragment, that takes it past.
	most := int(format.MaxCarriedLen)
	for _, c := range []struct {
		shape format.Shape
		fits  bool
	}{
		{format.Shape{Share: most}, true},
		{format.Shape{Share: most - 258, Details: 258}, true},
		{format.Shape{Share: most - 257, Details: 258}, false},
		{format.Shape{Share: 100, Fragment: most - 100}, true},
		{format.Shape{Share: 100, Fragment: most - 99}, false},
		{format.Shape{Share: 100, Fragment: most - 358, Details: 258}, true},
		{format.Shape{Share: 100, Fragment: most - 357, Details: 258}, false},
	} {
		if err := fitsPiece(c.shape); (err == nil) != c.fits {
			t.Fatalf("a piece carrying %d bytes of %d: %v, want fits=%v", c.shape.Carried(), most, err, c.fits)
		}
	}
	if got, want := MemoryEstimate(64<<30, 255, 2, MethodFull), int64(257)<<36; got != want {
		t.Fatalf("a 64 GiB split into 255 pieces estimates %d bytes, want %d", got, want)
	}
}
