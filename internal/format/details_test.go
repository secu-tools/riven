// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package format

import (
	"testing"

	"github.com/secu-tools/riven/internal/cascade"
	"github.com/secu-tools/riven/internal/kdf"
)

func sampleDetails() Details {
	return Details{
		K: 2, N: 3, Encrypted: true, Hybrid: true, AlgoStored: true, KDFStored: true,
		Params: kdf.Params{Memory: 32 * 1024, Time: 3, Par: 2},
		Layers: []cascade.Descriptor{
			{Kind: cascade.Password, SchemeID: 1, Recorded: true},
			{Kind: cascade.KEM, SchemeID: 3, Recorded: true},
		},
		Name: "wallet.txt", CreatorVersion: "1.0.0", CreatorCommit: "abc123",
	}
}

func TestDetailsRoundTrip(t *testing.T) {
	d := sampleDetails()
	b, err := EncodeDetails(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != DetailsLen(len(d.Layers), len(d.Name)+len(d.CreatorVersion)+len(d.CreatorCommit)) {
		t.Fatalf("details are %d bytes, DetailsLen says otherwise", len(b))
	}
	got, ok := DecodeDetails(b)
	if !ok {
		t.Fatal("details did not decode")
	}
	if got.K != 2 || got.N != 3 || !got.Encrypted || !got.Hybrid || !got.AlgoStored || !got.KDFStored ||
		got.Params != d.Params || got.Name != d.Name || got.CreatorVersion != d.CreatorVersion ||
		got.CreatorCommit != d.CreatorCommit || len(got.Layers) != 2 || got.Layers[1].Kind != cascade.KEM ||
		got.Layers[1].SchemeID != 3 {
		t.Fatalf("details changed on the way: %+v", got)
	}
}

// TestDetailsWithoutRecording checks unrecorded algorithms and cost stay out of
// the shared details too, so hiding the details never records more than showing
// them would.
func TestDetailsWithoutRecording(t *testing.T) {
	d := sampleDetails()
	d.AlgoStored, d.KDFStored = false, false
	b, err := EncodeDetails(d)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := DecodeDetails(b)
	if !ok {
		t.Fatal("details did not decode")
	}
	if got.KDFStored || got.Params != (kdf.Params{}) || got.AlgoStored || got.Layers[0].SchemeID != 0 {
		t.Fatalf("unrecorded settings were shared: %+v", got)
	}
}

// TestDetailsRejectDamage checks the closing hash: any change to the bytes, which
// is what interpolating too few shares produces, is refused rather than read.
func TestDetailsRejectDamage(t *testing.T) {
	b, err := EncodeDetails(sampleDetails())
	if err != nil {
		t.Fatal(err)
	}
	for i := range b {
		bad := append([]byte(nil), b...)
		bad[i] ^= 0x10
		if _, ok := DecodeDetails(bad); ok {
			t.Fatalf("a change at byte %d was not noticed", i)
		}
	}
	for _, n := range []int{0, 1, detailsFixedLen - 1, len(b) - 1} {
		if _, ok := DecodeDetails(b[:n]); ok {
			t.Fatalf("details cut to %d bytes were read", n)
		}
	}
}

// FuzzDecodeDetails feeds arbitrary bytes to the details parser, which reads
// whatever too few shares interpolate to: it must refuse, never panic.
func FuzzDecodeDetails(f *testing.F) {
	good, _ := EncodeDetails(sampleDetails())
	f.Add(good)
	f.Add([]byte{})
	f.Add(make([]byte, detailsFixedLen))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeDetails(b)
	})
}

func TestEncodeDetailsRejectsBadInput(t *testing.T) {
	d := sampleDetails()
	d.K = 0
	if _, err := EncodeDetails(d); err == nil {
		t.Fatal("k of zero was accepted")
	}
	d = sampleDetails()
	d.N = 1
	if _, err := EncodeDetails(d); err == nil {
		t.Fatal("n under k was accepted")
	}
	d = sampleDetails()
	d.Name = string(make([]byte, MaxNameLen+1))
	if _, err := EncodeDetails(d); err == nil {
		t.Fatal("an over-long name was accepted")
	}
}
