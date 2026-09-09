// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/secu-tools/riven/internal/kem"
)

// widths covers the offered class widths plus the extremes of the range.
var widths = []int{MinPadPercent, 5, 10, 100, MaxPadPercent}

func pwLayers(n int) ([]LayerSpec, [][]byte) {
	specs := make([]LayerSpec, n)
	pws := make([][]byte, n)
	for i := range specs {
		pws[i] = []byte(fmt.Sprintf("layer-%d", i))
		specs[i] = LayerSpec{Kind: PasswordLayer, Password: pws[i]}
	}
	return specs, pws
}

// pieceSize splits input with the given padding and returns the common piece
// size, failing if the pieces of one set do not agree.
func pieceSize(t *testing.T, input []byte, pad Padding, layers int) int {
	t.Helper()
	specs, _ := pwLayers(layers)
	pieces := mustSplit(t, input, SplitOptions{N: 4, K: 2, Layers: specs, Padding: pad})
	for i, p := range pieces {
		if len(p) != len(pieces[0]) {
			t.Fatalf("piece %d is %d bytes, piece 1 is %d", i+1, len(p), len(pieces[0]))
		}
	}
	return len(pieces[0])
}

// TestPaddingOffGivesTheNaturalSize checks that switching padding off produces
// one exact size, repeatable across runs, which is what makes piece sizes
// predictable enough to plan a QR export around.
func TestPaddingOffGivesTheNaturalSize(t *testing.T) {
	input := bytes.Repeat([]byte("j"), 500)
	first := pieceSize(t, input, PadNone(), 1)
	for run := 0; run < 3; run++ {
		if got := pieceSize(t, input, PadNone(), 1); got != first {
			t.Fatalf("padding off gave %d bytes, want %d", got, first)
		}
	}
}

// TestPaddingIsUniformWithinAndAcrossSplits is the property bucketed padding is
// chosen for. Every piece of a set is the same size, so holding more pieces
// reveals no more than holding one; and the same content split again gives the
// same size, so a repeat split adds nothing either.
func TestPaddingIsUniformWithinAndAcrossSplits(t *testing.T) {
	input := bytes.Repeat([]byte("b"), 1500)
	for _, w := range widths {
		t.Run(fmt.Sprintf("%d%%", w), func(t *testing.T) {
			want := pieceSize(t, input, PadPercent(w), 1)
			for run := 0; run < 3; run++ {
				if got := pieceSize(t, input, PadPercent(w), 1); got != want {
					t.Fatalf("run %d gave %d bytes, want %d", run, got, want)
				}
			}
			if want != BucketFor(want, w) {
				t.Fatalf("padded size %d is not a class boundary at %d percent", want, w)
			}
		})
	}
}

// TestPaddingIsIndependentOfContent checks the size depends on the length alone.
// A size that varied with the bytes would leak something about them.
func TestPaddingIsIndependentOfContent(t *testing.T) {
	const n = 777
	a := bytes.Repeat([]byte{0x00}, n)
	b := bytes.Repeat([]byte{0xFF}, n)
	c := make([]byte, n)
	if _, err := rand.Read(c); err != nil {
		t.Fatal(err)
	}
	for _, w := range widths {
		sa := pieceSize(t, a, PadPercent(w), 1)
		sb := pieceSize(t, b, PadPercent(w), 1)
		sc := pieceSize(t, c, PadPercent(w), 1)
		if sa != sb || sa != sc {
			t.Fatalf("%d percent: sizes %d, %d, %d differ for equal-length inputs", w, sa, sb, sc)
		}
	}
}

// TestZeroValuePadsAtTheDefault checks the zero value of SplitOptions pads, and
// pads at the documented default, so forgetting the field cannot expose a length.
func TestZeroValuePadsAtTheDefault(t *testing.T) {
	input := bytes.Repeat([]byte("d"), 1000)
	zero := pieceSize(t, input, Padding{}, 1)
	explicit := pieceSize(t, input, PadPercent(DefaultPadPercent), 1)
	natural := pieceSize(t, input, PadNone(), 1)
	if zero != explicit {
		t.Fatalf("the zero value gave %d bytes, the default width gives %d", zero, explicit)
	}
	if zero <= natural {
		t.Fatalf("the zero value did not pad: %d bytes against a natural %d", zero, natural)
	}
}

// TestWiderClassesHideMore checks the ordering that gives the width its meaning:
// over a run of input lengths, a wider class must map them onto no more distinct
// sizes than a narrower one, and the widest must be strictly better than the
// narrowest. Individual sizes are not comparable across widths, because the two
// ladders of boundaries are not nested.
func TestWiderClassesHideMore(t *testing.T) {
	const from, span = 600, 60
	counts := make([]int, len(widths))
	for i, w := range widths {
		sizes := map[int]bool{}
		for n := from; n < from+span; n++ {
			sizes[pieceSize(t, bytes.Repeat([]byte("x"), n), PadPercent(w), 1)] = true
		}
		counts[i] = len(sizes)
		if i > 0 && counts[i] > counts[i-1] {
			t.Fatalf("%d percent classes gave %d sizes for %d lengths, more than the %d at %d percent",
				w, counts[i], span, counts[i-1], widths[i-1])
		}
	}
	if counts[len(counts)-1] >= counts[0] {
		t.Fatalf("the widest class gave %d sizes, no better than the %d of the narrowest",
			counts[len(counts)-1], counts[0])
	}
}

// TestPaddingHidesNearbyLengths checks that a run of different input lengths
// collapses onto few padded sizes: seeing a piece narrows the content to a class,
// not to a length. The bound comes from the class width at that size rather than
// a fixed number, since a span can straddle a boundary.
func TestPaddingHidesNearbyLengths(t *testing.T) {
	const from, span = 600, 60
	for _, w := range widths {
		sizes := map[int]bool{}
		for n := from; n < from+span; n++ {
			sizes[pieceSize(t, bytes.Repeat([]byte("x"), n), PadPercent(w), 1)] = true
		}
		// A class at this size is at least (from * w / 100) bytes wide, so the span
		// can cross at most that many boundaries, plus the class it starts in.
		classWidth := from * w / 100
		if classWidth < 1 {
			classWidth = 1
		}
		limit := span/classWidth + 1
		if len(sizes) > limit {
			t.Fatalf("%d percent: %d lengths gave %d sizes, more than the %d a class of %d bytes allows",
				w, span, len(sizes), limit, classWidth)
		}
		if len(sizes) == span {
			t.Fatalf("%d percent: every length got its own size, so nothing is hidden", w)
		}
	}
}

// TestPaddedSizeMatchesThePredictedBucket checks the length formula the padding
// is computed from against real encodings across widths, layer counts and input
// sizes. A drift between formula and encoder would put pieces in the wrong class
// or overshoot it.
func TestPaddedSizeMatchesThePredictedBucket(t *testing.T) {
	for _, w := range widths {
		for _, layers := range []int{1, 2, 3} {
			for _, size := range []int{0, 1, 100, 900, 5000} {
				input := bytes.Repeat([]byte("m"), size)
				natural := pieceSize(t, input, PadNone(), layers)
				padded := pieceSize(t, input, PadPercent(w), layers)
				if want := BucketFor(natural, w); padded != want {
					t.Fatalf("width=%d layers=%d size=%d: natural %d padded to %d, want %d",
						w, layers, size, natural, padded, want)
				}
			}
		}
	}
}

// TestPaddingOverheadIsBounded checks the storage cost stays inside the class
// width, which is the whole reason the width is the knob the user turns.
func TestPaddingOverheadIsBounded(t *testing.T) {
	for _, w := range widths {
		for _, size := range []int{1000, 4000, 20000} {
			input := bytes.Repeat([]byte("o"), size)
			natural := pieceSize(t, input, PadNone(), 1)
			padded := pieceSize(t, input, PadPercent(w), 1)
			if limit := natural + natural*w/100 + 1; padded > limit {
				t.Fatalf("width=%d size=%d: padded to %d bytes, over the %d bound on a natural %d",
					w, size, padded, limit, natural)
			}
		}
	}
}

// TestBucketForProperties pins the size-class function itself: never shrinking,
// never below the floor, monotone, deterministic, and never more than one class
// width above the value it pads.
func TestBucketForProperties(t *testing.T) {
	for _, w := range widths {
		prev := 0
		for n := 0; n < 20000; n++ {
			got := BucketFor(n, w)
			if got < n {
				t.Fatalf("width=%d: BucketFor(%d) = %d, smaller than the input", w, n, got)
			}
			if got < bucketFloor {
				t.Fatalf("width=%d: BucketFor(%d) = %d, below the floor %d", w, n, got, bucketFloor)
			}
			if got < prev {
				t.Fatalf("width=%d: BucketFor is not monotone at %d: %d after %d", w, n, got, prev)
			}
			if again := BucketFor(n, w); again != got {
				t.Fatalf("width=%d: BucketFor(%d) is not deterministic", w, n)
			}
			prev = got
			if n > bucketFloor {
				if limit := n + n*w/100 + 1; got > limit {
					t.Fatalf("width=%d: BucketFor(%d) = %d, over the %d bound", w, n, got, limit)
				}
			}
		}
	}
}

// TestBucketForResolvesTheDefaultWidth checks the zero and out-of-range widths
// fall back to the default rather than producing a degenerate class.
func TestBucketForResolvesTheDefaultWidth(t *testing.T) {
	for _, n := range []int{0, 1, 255, 256, 257, 1000, 9999} {
		want := BucketFor(n, DefaultPadPercent)
		for _, w := range []int{0, -1, -100} {
			if got := BucketFor(n, w); got != want {
				t.Fatalf("BucketFor(%d, %d) = %d, want the default %d", n, w, got, want)
			}
		}
	}
}

// TestPaddingWidthValidated checks a width outside the supported range is
// refused rather than quietly clamped, since a clamp would pad differently from
// what was asked.
func TestPaddingWidthValidated(t *testing.T) {
	specs, _ := pwLayers(1)
	for _, bad := range []int{-1, MaxPadPercent + 1, 100000} {
		_, err := Split([]byte("x"), SplitOptions{
			N: 2, K: 2, Layers: specs, Padding: PadPercent(bad),
			Params: testParams, RecordAlgo: true, RecordKDF: true,
		})
		if err == nil {
			t.Fatalf("width %d should be refused", bad)
		}
	}
	for _, ok := range widths {
		if _, err := Split([]byte("x"), SplitOptions{
			N: 2, K: 2, Layers: specs, Padding: PadPercent(ok),
			Params: testParams, RecordAlgo: true, RecordKDF: true,
		}); err != nil {
			t.Fatalf("width %d should be accepted: %v", ok, err)
		}
	}
}

// TestPaddingSkippedWithoutAPassword covers the case where padding would be
// theatre. A split with no password seals its metadata with the public keyless
// key, so anyone holding this tool reads the content length out of any piece;
// padding would cost storage and hide nothing, so it is not applied.
func TestPaddingSkippedWithoutAPassword(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.Repeat([]byte("k"), 1000)

	cases := []struct {
		name string
		so   SplitOptions
	}{
		{"keyless", SplitOptions{N: 4, K: 2, Keyless: true}},
		{"recipient only", SplitOptions{N: 4, K: 2,
			Layers: []LayerSpec{{Kind: RecipientLayer, Recipient: priv.Public()}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			so := c.so
			so.Padding = PadPercent(500)
			padded := mustSplit(t, input, so)
			so.Padding = PadNone()
			natural := mustSplit(t, input, so)
			if len(padded[0]) != len(natural[0]) {
				t.Fatalf("padding was applied without a password: %d bytes against a natural %d",
					len(padded[0]), len(natural[0]))
			}
		})
	}

	// A password layer alongside a recipient layer does seal the metadata, so
	// padding applies again.
	so := SplitOptions{N: 4, K: 2, Layers: []LayerSpec{
		{Kind: PasswordLayer, Password: []byte("pw")},
		{Kind: RecipientLayer, Recipient: priv.Public()},
	}}
	so.Padding = PadPercent(500)
	padded := mustSplit(t, input, so)
	so.Padding = PadNone()
	natural := mustSplit(t, input, so)
	if len(padded[0]) <= len(natural[0]) {
		t.Fatalf("a password layer should restore padding: %d bytes against a natural %d",
			len(padded[0]), len(natural[0]))
	}
}

// TestPaddingApplies states the rule directly, so a change to it is deliberate.
func TestPaddingApplies(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	pw := LayerSpec{Kind: PasswordLayer, Password: []byte("p")}
	key := LayerSpec{Kind: RecipientLayer, Recipient: priv.Public()}

	cases := []struct {
		name string
		so   SplitOptions
		want bool
	}{
		{"password", SplitOptions{Layers: []LayerSpec{pw}}, true},
		{"password and key", SplitOptions{Layers: []LayerSpec{pw, key}}, true},
		{"password, padding off", SplitOptions{Layers: []LayerSpec{pw}, Padding: PadNone()}, false},
		{"key only", SplitOptions{Layers: []LayerSpec{key}}, false},
		{"keyless", SplitOptions{Keyless: true}, false},
	}
	for _, c := range cases {
		if got := PaddingApplies(c.so); got != c.want {
			t.Fatalf("%s: PaddingApplies = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestPaddingNeverBreaksRecovery checks the padded bytes stay padding: every
// width must still reconstruct the exact input, including the sizes where the
// padding is much larger than the content.
func TestPaddingNeverBreaksRecovery(t *testing.T) {
	for _, w := range append([]int{}, widths...) {
		for _, size := range []int{0, 1, 2, 255, 1000, 9000} {
			input := make([]byte, size)
			if _, err := rand.Read(input); err != nil {
				t.Fatal(err)
			}
			specs, pws := pwLayers(2)
			pieces := mustSplit(t, input, SplitOptions{
				N: 5, K: 3, Layers: specs, Padding: PadPercent(w),
			})
			got, err := Combine(pieces[1:4], OpenOptions{Passwords: pws})
			if err != nil {
				t.Fatalf("width=%d size=%d: combine: %v", w, size, err)
			}
			if !bytes.Equal(got, input) {
				t.Fatalf("width=%d size=%d: content changed", w, size)
			}
		}
	}
}

// TestPaddingSurvivesInfo checks a padded piece still describes itself, since
// the padding sits inside the same authenticated manifest as the metadata.
func TestPaddingSurvivesInfo(t *testing.T) {
	specs, pws := pwLayers(1)
	for _, w := range widths {
		pieces := mustSplit(t, bytes.Repeat([]byte("i"), 2000), SplitOptions{
			N: 6, K: 4, Layers: specs, Padding: PadPercent(w),
		})
		info, err := Info(pieces[2], OpenOptions{Passwords: pws})
		if err != nil {
			t.Fatalf("width=%d: info: %v", w, err)
		}
		if info.Serial != 3 || info.K != 4 || info.N != 6 {
			t.Fatalf("width=%d: piece describes itself as %d of %d, threshold %d",
				w, info.Serial, info.N, info.K)
		}
	}
}
