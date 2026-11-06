// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package disperse

import (
	"bytes"
	"crypto/rand"
	mathrand "math/rand/v2"
	"strconv"
	"testing"

	"github.com/secu-tools/riven/internal/testkit"
)

// split disperses data into n fragments, any k of which rebuild it, all at once.
func split(data []byte, n, k int) ([][]byte, error) {
	d, err := New(data, n, k)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, n)
	for i := range out {
		out[i] = d.Fragment(i)
	}
	return out, nil
}

func randomData(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestFieldTables checks every product and inverse against shift-and-add, so the
// tables cannot drift from the field docs/format.md names.
func TestFieldTables(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if got, want := mulTable[a][b], slowMul(byte(a), byte(b)); got != want {
				t.Fatalf("%d * %d = %d, want %d", a, b, got, want)
			}
		}
		if a != 0 && slowMul(byte(a), inverse(byte(a))) != 1 {
			t.Fatalf("inverse(%d) is wrong", a)
		}
	}
}

// TestEveryThresholdSubsetRebuilds covers the promise the format makes: any k
// fragments, in any order, rebuild the data, for every k of n up to 6.
func TestEveryThresholdSubsetRebuilds(t *testing.T) {
	for n := 1; n <= 6; n++ {
		for k := 1; k <= n; k++ {
			data := randomData(t, 7*k)
			frags, err := split(data, n, k)
			if err != nil {
				t.Fatalf("n=%d k=%d: %v", n, k, err)
			}
			for _, f := range frags {
				if len(f) != FragmentLen(len(data), k) {
					t.Fatalf("n=%d k=%d: fragment is %d bytes, want %d", n, k, len(f), FragmentLen(len(data), k))
				}
			}
			testkit.Subsets(n, k, func(idx []int) {
				pick := make([][]byte, len(idx))
				for i, j := range idx {
					pick[len(idx)-1-i] = frags[j] // reversed, so order cannot matter
				}
				got, err := Combine(pick, k)
				if err != nil {
					t.Fatalf("n=%d k=%d subset %v: %v", n, k, idx, err)
				}
				if !bytes.Equal(got, data) {
					t.Fatalf("n=%d k=%d subset %v rebuilt different data", n, k, idx)
				}
			})
		}
	}
}

// TestLargeThresholds covers the top of the range, where the matrix is largest.
func TestLargeThresholds(t *testing.T) {
	for _, c := range []struct{ n, k int }{{255, 255}, {255, 128}, {200, 2}, {255, 1}} {
		data := randomData(t, c.k*3)
		frags, err := split(data, c.n, c.k)
		if err != nil {
			t.Fatalf("n=%d k=%d: %v", c.n, c.k, err)
		}
		mathrand.Shuffle(len(frags), func(i, j int) { frags[i], frags[j] = frags[j], frags[i] })
		got, err := Combine(frags, c.k)
		if err != nil {
			t.Fatalf("n=%d k=%d: %v", c.n, c.k, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("n=%d k=%d rebuilt different data", c.n, c.k)
		}
	}
}

// TestFragmentsOnDemand checks a Disperser gives the same fragment every time it
// is asked, so a split can compute each as its piece is written, and that any k
// of its fragments rebuild the data.
func TestFragmentsOnDemand(t *testing.T) {
	data := randomData(t, (blockGroups+5)*4)
	d, err := New(data, 6, 4)
	if err != nil {
		t.Fatal(err)
	}
	frags := make([][]byte, 6)
	for i := range frags {
		frags[i] = d.Fragment(i)
		if !bytes.Equal(frags[i], d.Fragment(i)) {
			t.Fatalf("fragment %d changed between two calls", i)
		}
	}
	got, err := Combine([][]byte{frags[5], frags[0], frags[3], frags[2]}, 4)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("on-demand fragments did not rebuild the data: %v", err)
	}
	if _, err := New(data, 6, 7); err == nil {
		t.Fatal("a threshold above the parts was accepted")
	}
}

// TestManyBlocks crosses the parallel block boundary, so a block computed with
// the wrong offsets would show.
func TestManyBlocks(t *testing.T) {
	const k = 3
	data := randomData(t, (2*blockGroups+17)*k)
	frags, err := split(data, 5, k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine([][]byte{frags[4], frags[1], frags[2]}, k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("rebuilt different data across blocks")
	}
}

// TestCoordinatesAreDistinctAndRandom checks a fragment does not say which piece
// it is: coordinates differ within a set and change from one dispersal to the next.
func TestCoordinatesAreDistinctAndRandom(t *testing.T) {
	data := randomData(t, 8)
	first := map[byte]bool{}
	changed := false
	for run := 0; run < 20; run++ {
		frags, err := split(data, 255, 2)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[byte]bool{}
		for i, f := range frags {
			if f[0] == 0 || seen[f[0]] {
				t.Fatalf("run %d: fragment %d has coordinate %d, zero or repeated", run, i, f[0])
			}
			seen[f[0]] = true
		}
		if run == 0 {
			first[frags[0][0]] = true
		} else if !first[frags[0][0]] {
			changed = true
		}
	}
	if !changed {
		t.Fatal("the first fragment always gets the same coordinate")
	}
}

// TestFewerThanThresholdDoesNotRebuild checks that k-1 fragments are refused, and
// that padding them out with a forged fragment gives wrong bytes rather than the
// data, which is why the caller authenticates the result.
func TestFewerThanThresholdDoesNotRebuild(t *testing.T) {
	data := randomData(t, 30)
	frags, err := split(data, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Combine(frags[:2], 3); err != ErrTooFew {
		t.Fatalf("two of three fragments: got %v, want ErrTooFew", err)
	}
	forged := append([]byte{frags[2][0]}, randomData(t, len(frags[2])-1)...)
	got, err := Combine([][]byte{frags[0], frags[1], forged}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, data) {
		t.Fatal("a forged fragment still rebuilt the data")
	}
}

func TestSplitRejectsBadParameters(t *testing.T) {
	cases := []struct {
		name    string
		dataLen int
		n, k    int
	}{
		{"zero threshold", 6, 3, 0},
		{"threshold above parts", 6, 2, 3},
		{"too many parts", 6, 256, 2},
		{"empty data", 0, 3, 2},
		{"length not a multiple", 7, 3, 2},
	}
	for _, c := range cases {
		if _, err := split(make([]byte, c.dataLen), c.n, c.k); err == nil {
			t.Fatalf("%s: accepted", c.name)
		}
	}
}

func TestCombineRejectsMalformedFragments(t *testing.T) {
	data := randomData(t, 12)
	frags, err := split(data, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	short := frags[1][:len(frags[1])-1]
	zero := append([]byte{0}, frags[1][1:]...)
	cases := map[string][][]byte{
		"different lengths":  {frags[0], short},
		"repeated fragment":  {frags[0], frags[0]},
		"coordinate zero":    {frags[0], zero},
		"coordinate only":    {frags[0][:1], frags[1][:1]},
		"no fragments at k1": {},
	}
	for name, use := range cases {
		k := 2
		if name == "no fragments at k1" {
			k = 1
		}
		if _, err := Combine(use, k); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := Combine(frags, 0); err == nil {
		t.Fatal("threshold zero: accepted")
	}
}

// TestThresholdOneIsACopy pins the degenerate case: with k of 1 every fragment is
// the data itself behind its coordinate.
func TestThresholdOneIsACopy(t *testing.T) {
	data := randomData(t, 9)
	frags, err := split(data, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range frags {
		if !bytes.Equal(f[1:], data) {
			t.Fatalf("fragment %d is not a copy of the data", i)
		}
	}
}

// TestDispersalHidesNothingOnItsOwn shows why the data must be encrypted first:
// all-zero data disperses to all-zero fragments, so the mix is linear and a
// fragment says something about the data it came from.
func TestDispersalHidesNothingOnItsOwn(t *testing.T) {
	frags, err := split(make([]byte, 30), 4, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range frags {
		if !bytes.Equal(f[1:], make([]byte, 10)) {
			t.Fatalf("fragment %d of zeros is not zeros: dispersal is meant to be linear", i)
		}
	}
}

func FuzzCombine(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6}, uint8(3), uint8(2))
	f.Fuzz(func(t *testing.T, data []byte, n, k uint8) {
		if k == 0 || n < k || len(data) == 0 {
			return
		}
		data = data[:len(data)-len(data)%int(k)]
		if len(data) == 0 {
			return
		}
		frags, err := split(data, int(n), int(k))
		if err != nil {
			return
		}
		got, err := Combine(frags[len(frags)-int(k):], int(k))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("round trip failed")
		}
	})
}

// BenchmarkCombine measures the rebuild of 64 MiB at the default threshold and
// at a wide one, which is where the inner loop matters.
func BenchmarkCombine(b *testing.B) {
	for _, k := range []int{3, 10} {
		data := make([]byte, 64<<20/k*k)
		if _, err := rand.Read(data); err != nil {
			b.Fatal(err)
		}
		frags, err := split(data, k+2, k)
		if err != nil {
			b.Fatal(err)
		}
		b.Run("k="+strconv.Itoa(k), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				if _, err := Combine(frags[2:], k); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
