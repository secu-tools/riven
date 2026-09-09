// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
)

var testParams = kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}

func mustSplit(t *testing.T, input []byte, opts SplitOptions) [][]byte {
	t.Helper()
	opts.Params = testParams
	opts.RecordAlgo = true
	opts.RecordKDF = true
	pieces, err := Split(input, opts)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	return pieces
}

// allSubsetsOfSize invokes fn with every k-sized subset of pieces.
func allSubsetsOfSize(pieces [][]byte, k int, fn func(subset [][]byte)) {
	n := len(pieces)
	idx := make([]int, k)
	var rec func(start, depth int)
	rec = func(start, depth int) {
		if depth == k {
			sub := make([][]byte, k)
			for i, j := range idx {
				sub[i] = pieces[j]
			}
			fn(sub)
			return
		}
		for i := start; i < n; i++ {
			idx[depth] = i
			rec(i+1, depth+1)
		}
	}
	rec(0, 0)
}

func TestSplitCombine_PureSSS(t *testing.T) {
	input := []byte("top secret pure shamir content")
	pieces := mustSplit(t, input, SplitOptions{N: 4, K: 3, Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("envelope")}}})

	opts := OpenOptions{Passwords: [][]byte{[]byte("envelope")}}

	// Every 3-of-4 subset reconstructs.
	allSubsetsOfSize(pieces, 3, func(sub [][]byte) {
		got, err := Combine(sub, opts)
		if err != nil {
			t.Fatalf("Combine 3-of-4: %v", err)
		}
		if !bytes.Equal(got, input) {
			t.Fatalf("mismatch")
		}
	})

	// Any 2-of-4 subset must fail (below threshold).
	allSubsetsOfSize(pieces, 2, func(sub [][]byte) {
		if _, err := Combine(sub, opts); err == nil {
			t.Fatalf("2-of-4 should not reconstruct")
		}
	})
}

func TestSplitCombine_Cascade(t *testing.T) {
	input := bytes.Repeat([]byte("cascade!"), 50)
	layers := []LayerSpec{
		{SchemeID: 1, Password: []byte("alpha")},
		{SchemeID: 2, Password: []byte("bravo")},
	}
	pieces := mustSplit(t, input, SplitOptions{N: 5, K: 3, Layers: layers})

	good := OpenOptions{Passwords: [][]byte{[]byte("alpha"), []byte("bravo")}}
	got, err := Combine(pieces[:3], good)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("mismatch")
	}

	// Wrong password fails at envelope.
	bad := OpenOptions{Passwords: [][]byte{[]byte("alpha"), []byte("WRONG")}}
	if _, err := Combine(pieces[:3], bad); err == nil {
		t.Fatalf("expected failure with wrong password")
	}
}

func TestSplitCombine_Hybrid(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("hybrid post-quantum + password")
	layers := []LayerSpec{{SchemeID: 3, Password: []byte("pw")}}
	pieces := mustSplit(t, input, SplitOptions{N: 3, K: 2,
		Layers: append(layers, LayerSpec{Kind: RecipientLayer, Recipient: priv.Public()})})

	opts := OpenOptions{Passwords: [][]byte{[]byte("pw")}, PrivateKeys: []*kem.PrivateKey{priv}}
	got, err := Combine(pieces[:2], opts)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("mismatch")
	}

	// Missing private key fails.
	noKey := OpenOptions{Passwords: [][]byte{[]byte("pw")}}
	if _, err := Combine(pieces[:2], noKey); err == nil {
		t.Fatalf("expected failure without private key")
	}
}

func TestSinglePiece_Encryption(t *testing.T) {
	// N=1,K=1 is pure encryption: one self-sufficient piece, no real split.
	input := []byte("just encrypt me, no real split")
	pieces := mustSplit(t, input, SplitOptions{N: 1, K: 1, Layers: []LayerSpec{{SchemeID: 5, Password: []byte("solo")}}})
	if len(pieces) != 1 {
		t.Fatalf("expected 1 piece")
	}
	got, err := Combine(pieces, OpenOptions{Passwords: [][]byte{[]byte("solo")}})
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("mismatch")
	}
}

// TestInfoReportsCreatorFields checks the build identity recorded at split time
// is surfaced by Info, which is what lets a version mismatch be diagnosed later.
func TestInfoReportsCreatorFields(t *testing.T) {
	input := []byte("stamped by a build")
	pieces := mustSplit(t, input, SplitOptions{N: 3, K: 2,
		Layers:         []LayerSpec{{Kind: PasswordLayer, Password: []byte("pw")}},
		CreatorVersion: "9.9.9.9", CreatorCommit: "cafef00d"})

	info, err := Info(pieces[0], OpenOptions{Passwords: [][]byte{[]byte("pw")}})
	if err != nil {
		t.Fatal(err)
	}
	if info.CreatorVersion != "9.9.9.9" || info.CreatorCommit != "cafef00d" {
		t.Fatalf("creator fields: version %q commit %q", info.CreatorVersion, info.CreatorCommit)
	}
}

func TestTinyAndEmptyAndBinary(t *testing.T) {
	cases := map[string][]byte{
		"one-byte":    {0x00}, // smallest addressable file
		"one-bit-ish": {0x01}, // a single set bit
		"empty":       {},     // zero-length
		"binary":      nil,    // filled below
	}
	bin := make([]byte, 777)
	rand.Read(bin)
	cases["binary"] = bin

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			opts := SplitOptions{N: 10, K: 8, Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("p")}}}
			pieces, err := func() ([][]byte, error) {
				o := opts
				o.Params = testParams
				o.RecordAlgo = true
				o.RecordKDF = true
				return Split(input, o)
			}()
			if err != nil {
				t.Fatalf("Split: %v", err)
			}
			got, err := Combine(pieces[:8], OpenOptions{Passwords: [][]byte{[]byte("p")}})
			if err != nil {
				t.Fatalf("Combine: %v", err)
			}
			if !bytes.Equal(got, input) {
				t.Fatalf("mismatch for %s: got %v want %v", name, got, input)
			}
		})
	}
}

func TestInfo(t *testing.T) {
	input := []byte("metadata check")
	layers := []LayerSpec{{SchemeID: 1, Password: []byte("a")}, {SchemeID: 4, Password: []byte("b")}}
	pieces := mustSplit(t, input, SplitOptions{N: 5, K: 3, Layers: layers})

	info, err := Info(pieces[2], OpenOptions{Passwords: [][]byte{[]byte("a"), []byte("b")}})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Serial != 3 || info.K != 3 || info.N != 5 {
		t.Fatalf("bad info: %+v", info)
	}
	if !info.Encrypted || info.Hybrid {
		t.Fatalf("bad flags: %+v", info)
	}
	if len(info.Algorithms) != 2 {
		t.Fatalf("expected 2 algorithms, got %v", info.Algorithms)
	}

	// Two pieces from the same set share a SetID; a different split does not.
	info2, _ := Info(pieces[0], OpenOptions{Passwords: [][]byte{[]byte("a"), []byte("b")}})
	if info.SetID != info2.SetID {
		t.Fatalf("same-set pieces should share SetID")
	}
	other := mustSplit(t, input, SplitOptions{N: 5, K: 3, Layers: layers})
	infoOther, _ := Info(other[0], OpenOptions{Passwords: [][]byte{[]byte("a"), []byte("b")}})
	if info.SetID == infoOther.SetID {
		t.Fatalf("different splits must have different SetIDs")
	}
}

func TestAdjacentSameAlgoRejected(t *testing.T) {
	layers := []LayerSpec{
		{SchemeID: 1, Password: []byte("a")},
		{SchemeID: 1, Password: []byte("b")},
	}
	_, err := Split([]byte("x"), SplitOptions{N: 3, K: 2, Layers: layers, Params: testParams, RecordAlgo: true, RecordKDF: true})
	if err == nil {
		t.Fatal("expected rejection when adjacent layers share an algorithm")
	}
}

// TestHiddenAlgoRoundTrip covers a set that does not record its algorithms: the
// caller must supply them, and wrong ones must fail.
func TestHiddenAlgoRoundTrip(t *testing.T) {
	input := []byte("algorithms kept out of the pieces")
	layers := []LayerSpec{
		{SchemeID: 1, Password: []byte("a")},
		{SchemeID: 2, Password: []byte("b")},
	}
	pieces, err := Split(input, SplitOptions{
		N: 4, K: 2, Layers: layers,
		Params: testParams, RecordAlgo: false, RecordKDF: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pws := [][]byte{[]byte("a"), []byte("b")}

	// info still works and reports that the algorithms are absent.
	info, err := Info(pieces[0], OpenOptions{Passwords: pws})
	if err != nil {
		t.Fatal(err)
	}
	if info.AlgoStored || len(info.Algorithms) != 0 || info.LayerCount != 2 {
		t.Fatalf("algorithms leaked or layer count lost: %+v", info)
	}

	if _, err := Combine(pieces[:2], OpenOptions{Passwords: pws}); !errors.Is(err, ErrSchemesRequired) {
		t.Fatalf("expected ErrSchemesRequired, got %v", err)
	}
	got, err := Combine(pieces[:2], OpenOptions{Passwords: pws, Schemes: []uint8{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}
	if _, err := Combine(pieces[:2], OpenOptions{Passwords: pws, Schemes: []uint8{2, 1}}); err == nil {
		t.Fatal("wrong algorithms should fail")
	}
}

// TestHiddenKDFRoundTrip covers a set that does not record its cost parameters.
func TestHiddenKDFRoundTrip(t *testing.T) {
	input := []byte("cost kept out of the pieces")
	custom := kdf.Params{Memory: 16 * 1024, Time: 5, Par: 2}
	pieces, err := Split(input, SplitOptions{
		N: 3, K: 2, Layers: []LayerSpec{{SchemeID: 2, Password: []byte("p")}},
		Params: custom, RecordAlgo: true, RecordKDF: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	pws := [][]byte{[]byte("p")}
	got, err := Combine(pieces[:2], OpenOptions{Passwords: pws, Params: &custom})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}
	wrong := kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}
	if _, err := Combine(pieces[:2], OpenOptions{Passwords: pws, Params: &wrong}); err == nil {
		t.Fatal("wrong cost should fail")
	}
}

// TestHideBothRoundTrip covers omitting algorithms and cost together.
func TestHideBothRoundTrip(t *testing.T) {
	input := []byte("nothing recorded at all")
	custom := kdf.Params{Memory: 8 * 1024, Time: 3, Par: 1}
	pieces, err := Split(input, SplitOptions{
		N: 3, K: 2, Layers: []LayerSpec{{SchemeID: 5, Password: []byte("p")}},
		Params: custom, RecordAlgo: false, RecordKDF: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine(pieces[:2], OpenOptions{
		Passwords: [][]byte{[]byte("p")}, Params: &custom, Schemes: []uint8{5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}
}

// TestEveryRegisteredSchemeWorks means a newly registered algorithm is covered
// automatically, without editing this test.
func TestEveryRegisteredSchemeWorks(t *testing.T) {
	input := bytes.Repeat([]byte("registry"), 20)
	for _, s := range ciphers.All() {
		t.Run(s.Name, func(t *testing.T) {
			pieces := mustSplit(t, input, SplitOptions{
				N: 3, K: 2, Layers: []LayerSpec{{SchemeID: s.ID, Password: []byte("pw")}},
			})
			got, err := Combine(pieces[:2], OpenOptions{Passwords: [][]byte{[]byte("pw")}})
			if err != nil {
				t.Fatalf("%s: %v", s.Name, err)
			}
			if !bytes.Equal(got, input) {
				t.Fatalf("%s: mismatch", s.Name)
			}
		})
	}
}

// TestFullCascadeOfEveryScheme stacks one layer per registered algorithm.
func TestFullCascadeOfEveryScheme(t *testing.T) {
	all := ciphers.All()
	input := []byte("stacked")
	layers := make([]LayerSpec, 0, len(all))
	pws := make([][]byte, 0, len(all))
	for i, s := range all {
		pw := []byte(fmt.Sprintf("password-%d", i))
		layers = append(layers, LayerSpec{SchemeID: s.ID, Password: pw})
		pws = append(pws, pw)
	}
	pieces := mustSplit(t, input, SplitOptions{N: 3, K: 2, Layers: layers})
	got, err := Combine(pieces[:2], OpenOptions{Passwords: pws})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}
}

// TestKeylessRoundTrip covers split-only mode: no password anywhere, and any K
// pieces rebuild the file with nothing else supplied.
func TestKeylessRoundTrip(t *testing.T) {
	input := []byte("no password protects this, only the threshold does")
	pieces, err := Split(input, SplitOptions{N: 5, K: 3, Keyless: true})
	if err != nil {
		t.Fatal(err)
	}

	// Nothing supplied at all.
	got, err := Combine(pieces[:3], OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}

	// Every 3-of-5 subset works.
	allSubsetsOfSize(pieces, 3, func(sub [][]byte) {
		out, err := Combine(sub, OpenOptions{})
		if err != nil || !bytes.Equal(out, input) {
			t.Fatalf("subset failed: %v", err)
		}
	})

	// Below the threshold still reveals nothing, exactly as with a password.
	allSubsetsOfSize(pieces, 2, func(sub [][]byte) {
		if _, err := Combine(sub, OpenOptions{}); err == nil {
			t.Fatal("2 of 5 should not reconstruct")
		}
	})

	info, err := Info(pieces[0], OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !info.Keyless || info.Encrypted || info.Hybrid {
		t.Fatalf("bad flags: %+v", info)
	}
	if info.Serial != 1 || info.K != 3 || info.N != 5 {
		t.Fatalf("bad info: %+v", info)
	}
}

func TestKeylessRejectsConflictingOptions(t *testing.T) {
	in := []byte("x")
	cases := map[string]SplitOptions{
		"with layers":   {N: 3, K: 2, Keyless: true, Layers: []LayerSpec{{SchemeID: 1, Password: []byte("p")}}},
		"with password": {N: 3, K: 2, Keyless: true, Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("p")}}},
		"threshold one": {N: 3, K: 1, Keyless: true},
	}
	for name, opts := range cases {
		if _, err := Split(in, opts); err == nil {
			t.Fatalf("%s should be rejected", name)
		}
	}
}

// TestKeylessAndPasswordSetsAreDistinct checks the two pure-Shamir modes do not
// open each other: a password set must not open keyless, and the reverse.
func TestKeylessAndPasswordSetsAreDistinct(t *testing.T) {
	in := []byte("distinct modes")
	keyless, err := Split(in, SplitOptions{N: 3, K: 2, Keyless: true})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Split(in, SplitOptions{
		N: 3, K: 2, Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("pw")}},
		Params: testParams, RecordAlgo: true, RecordKDF: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A password-sealed set must not open with no password.
	if _, err := Combine(sealed[:2], OpenOptions{}); err == nil {
		t.Fatal("sealed set should not open without its password")
	}
	// A keyless set must not open when a password is offered.
	if _, err := Combine(keyless[:2], OpenOptions{Passwords: [][]byte{[]byte("pw")}}); err == nil {
		t.Fatal("keyless set should not open with a password")
	}
	// And each opens its own way.
	if _, err := Combine(keyless[:2], OpenOptions{}); err != nil {
		t.Fatalf("keyless: %v", err)
	}
	if _, err := Combine(sealed[:2], OpenOptions{Passwords: [][]byte{[]byte("pw")}}); err != nil {
		t.Fatalf("sealed: %v", err)
	}
}

// TestHybridWithHiddenAlgorithms covers the two features together: the KEM layer
// counts as a layer, so its algorithm must be supplied along with the others.
func TestHybridWithHiddenAlgorithms(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("hybrid with nothing recorded")
	layers := []LayerSpec{{SchemeID: ciphers.Default().ID, Password: []byte("pw")}}

	pieces, err := Split(input, SplitOptions{
		N: 3, K: 2, Layers: append(layers, LayerSpec{Kind: RecipientLayer, Recipient: priv.Public()}),
		Params: testParams, RecordAlgo: false, RecordKDF: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The algorithms are resolved the same way the split resolved them.
	all := append(layers, LayerSpec{Kind: RecipientLayer, Recipient: priv.Public()})
	ids, err := AssignSchemes(all)
	if err != nil {
		t.Fatal(err)
	}
	open := OpenOptions{
		Passwords:   [][]byte{[]byte("pw")},
		PrivateKeys: []*kem.PrivateKey{priv},
		Schemes:     ids,
	}
	got, err := Combine(pieces[:2], open)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}

	// Naming only the password layer is not enough.
	short := open
	short.Schemes = []uint8{layers[0].SchemeID}
	if _, err := Combine(pieces[:2], short); err == nil {
		t.Fatal("supplying too few algorithms should fail")
	}
}

// TestRecipientOnly covers encrypting to a recipient key with no password at
// all: the private key alone decrypts, which is the point of public-key mode.
func TestRecipientOnly(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("only the holder of the private key may read this")

	pieces, err := Split(input, SplitOptions{
		N: 4, K: 2, Layers: []LayerSpec{{Kind: RecipientLayer, Recipient: priv.Public()}},
		Params: testParams, RecordAlgo: true, RecordKDF: true,
	})
	if err != nil {
		t.Fatalf("recipient-only split should be allowed: %v", err)
	}

	// No password, just the key.
	got, err := Combine(pieces[:2], OpenOptions{PrivateKeys: []*kem.PrivateKey{priv}})
	if err != nil {
		t.Fatalf("combine with the key alone: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}

	// Without the key it must fail, even though the envelope opens.
	if _, err := Combine(pieces[:2], OpenOptions{}); err == nil {
		t.Fatal("combine without the private key should fail")
	}
	// The wrong key must fail.
	other, _ := kem.Generate(kem.Default())
	if _, err := Combine(pieces[:2], OpenOptions{PrivateKeys: []*kem.PrivateKey{other}}); err == nil {
		t.Fatal("combine with the wrong private key should fail")
	}
	// Below the threshold still reveals nothing, key or not.
	if _, err := Combine(pieces[:1], OpenOptions{PrivateKeys: []*kem.PrivateKey{priv}}); err == nil {
		t.Fatal("one piece should not reconstruct")
	}

	// Metadata is readable without the key, and reports the situation.
	info, err := Info(pieces[0], OpenOptions{})
	if err != nil {
		t.Fatalf("info without a password: %v", err)
	}
	if !info.Encrypted || !info.Hybrid || !info.Keyless {
		t.Fatalf("expected an encrypted, hybrid, password-free piece: %+v", info)
	}
}

// TestRecipientOnlyWithPasswordIsHybrid checks that adding a password to a
// recipient key keeps both requirements.
func TestRecipientOnlyWithPasswordIsHybrid(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("needs both")
	pieces, err := Split(input, SplitOptions{
		N: 3, K: 2,
		Layers: []LayerSpec{
			{Kind: PasswordLayer, SchemeID: ciphers.Default().ID, Password: []byte("pw")},
			{Kind: RecipientLayer, Recipient: priv.Public()},
		},
		Params: testParams, RecordAlgo: true, RecordKDF: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pw := [][]byte{[]byte("pw")}

	// Both are required.
	if _, err := Combine(pieces[:2], OpenOptions{Passwords: pw}); err == nil {
		t.Fatal("password alone should not be enough")
	}
	if _, err := Combine(pieces[:2], OpenOptions{PrivateKeys: []*kem.PrivateKey{priv}}); err == nil {
		t.Fatal("key alone should not be enough")
	}
	got, err := Combine(pieces[:2], OpenOptions{Passwords: pw, PrivateKeys: []*kem.PrivateKey{priv}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("mismatch")
	}

	// A password-sealed envelope must not open without the password.
	if info, err := Info(pieces[0], OpenOptions{}); err == nil {
		t.Fatalf("envelope should be password protected, got %+v", info)
	}
}

// TestEveryRecipientScheme runs the whole pipeline for each recipient key type,
// so registering one in the kem package is enough to have it covered here.
func TestEveryRecipientScheme(t *testing.T) {
	input := []byte("works with every recipient key type")
	for _, v := range kem.All() {
		t.Run(v.Name(), func(t *testing.T) {
			priv, err := kem.Generate(v)
			if err != nil {
				t.Fatal(err)
			}
			// Recipient only.
			pieces, err := Split(input, SplitOptions{
				N: 3, K: 2, Layers: []LayerSpec{{Kind: RecipientLayer, Recipient: priv.Public()}},
				Params: testParams, RecordAlgo: true, RecordKDF: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := Combine(pieces[:2], OpenOptions{PrivateKeys: []*kem.PrivateKey{priv}})
			if err != nil {
				t.Fatalf("recipient-only combine: %v", err)
			}
			if !bytes.Equal(got, input) {
				t.Fatal("mismatch")
			}

			// Hybrid.
			pieces, err = Split(input, SplitOptions{
				N: 3, K: 2,
				Layers: []LayerSpec{
					{Kind: PasswordLayer, SchemeID: ciphers.Default().ID, Password: []byte("pw")},
					{Kind: RecipientLayer, Recipient: priv.Public()},
				},
				Params: testParams, RecordAlgo: true, RecordKDF: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err = Combine(pieces[:2], OpenOptions{
				Passwords: [][]byte{[]byte("pw")}, PrivateKeys: []*kem.PrivateKey{priv},
			})
			if err != nil {
				t.Fatalf("hybrid combine: %v", err)
			}
			if !bytes.Equal(got, input) {
				t.Fatal("hybrid mismatch")
			}
		})
	}
}

// TestRecipientSchemeMismatch checks a key of another type is refused rather
// than silently producing garbage.
func TestRecipientSchemeMismatch(t *testing.T) {
	small, err := kem.Generate(kem.MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	large, err := kem.Generate(kem.MLKEM1024)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("size matters")

	for _, c := range []struct {
		name       string
		to, opened *kem.PrivateKey
	}{
		{"1024 set opened with a 768 key", large, small},
		{"768 set opened with a 1024 key", small, large},
	} {
		t.Run(c.name, func(t *testing.T) {
			pieces, err := Split(input, SplitOptions{
				N: 2, K: 2,
				Layers: []LayerSpec{{Kind: RecipientLayer, Recipient: c.to.Public()}},
				Params: testParams, RecordAlgo: true, RecordKDF: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Combine(pieces, OpenOptions{PrivateKeys: []*kem.PrivateKey{c.opened}}); err == nil {
				t.Fatal("the wrong parameter set should be refused")
			}
			// The right key still works.
			got, err := Combine(pieces, OpenOptions{PrivateKeys: []*kem.PrivateKey{c.to}})
			if err != nil || !bytes.Equal(got, input) {
				t.Fatalf("the matching key should work: %v", err)
			}
		})
	}
}

// TestKEMCiphertextSizeShowsInPieces documents the cost of the larger parameter
// set: the ciphertext rides inside the split payload, so every piece grows.
func TestKEMCiphertextSizeShowsInPieces(t *testing.T) {
	input := []byte("x")
	size := func(v kem.Scheme) int {
		priv, err := kem.Generate(v)
		if err != nil {
			t.Fatal(err)
		}
		pieces, err := Split(input, SplitOptions{
			N: 2, K: 2, Layers: []LayerSpec{{Kind: RecipientLayer, Recipient: priv.Public()}}, Padding: PadNone(),
			Params: testParams, RecordAlgo: true, RecordKDF: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return len(pieces[0])
	}
	small, large := size(kem.MLKEM768), size(kem.MLKEM1024)
	grew := large - small
	want := kem.MLKEM1024.CiphertextSize() - kem.MLKEM768.CiphertextSize()
	// Padding varies, so allow slack while confirming the growth is real.
	if grew < want-64 || grew > want+256 {
		t.Fatalf("piece grew by %d bytes, expected about %d", grew, want)
	}
}

// TestHybridRejectsDuplicateAdjacentScheme checks the distinctness rule covers
// the KEM layer, not just the password layers.
func TestHybridRejectsDuplicateAdjacentScheme(t *testing.T) {
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	same := ciphers.Default().ID
	_, err = Split([]byte("x"), SplitOptions{
		N: 3, K: 2,
		Layers: []LayerSpec{
			{Kind: PasswordLayer, SchemeID: same, Password: []byte("pw")},
			// Deliberately the same algorithm as the layer above.
			{Kind: RecipientLayer, SchemeID: same, Recipient: priv.Public()},
		},
		Params: testParams, RecordAlgo: true, RecordKDF: true,
	})
	if err == nil {
		t.Fatal("a KEM layer repeating the adjacent algorithm should be rejected")
	}
}

// TestSchemeName covers the name lookup the summaries use, including an id that
// was never registered.
func TestSchemeName(t *testing.T) {
	for _, s := range ciphers.All() {
		if SchemeName(s.ID) != s.Name {
			t.Fatalf("id %d named %q, want %q", s.ID, SchemeName(s.ID), s.Name)
		}
	}
	if SchemeName(0) == "" {
		t.Fatal("an unknown id should still produce a name")
	}
}
