// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/compact"
	"github.com/secu-tools/riven/internal/disperse"
	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/split"
)

// This file covers the two split methods and the three info modes: that every
// combination rebuilds, what one piece shows in each, and that the modes which
// take the password off the envelope leave nothing on a piece to test it with.

var (
	methods   = []Method{MethodFull, MethodCompact}
	infoModes = []InfoMode{InfoAuto, InfoProtected, InfoStrict, InfoPublic, InfoHidden}
)

// credentialSetup is one way a set can be protected, with what opens it.
type credentialSetup struct {
	name   string
	layers []LayerSpec
	open   OpenOptions
	none   bool // keyless: no layers at all
}

func credentialSetups(t *testing.T) []credentialSetup {
	t.Helper()
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	keys := []*kem.PrivateKey{priv}
	return []credentialSetup{
		{name: "password", layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("one")}},
			open: OpenOptions{Passwords: [][]byte{[]byte("one")}}},
		{name: "two passwords", layers: []LayerSpec{
			{Kind: PasswordLayer, Password: []byte("one")},
			{Kind: PasswordLayer, Password: []byte("two")},
		}, open: OpenOptions{Passwords: [][]byte{[]byte("one"), []byte("two")}}},
		{name: "password and recipient", layers: []LayerSpec{
			{Kind: PasswordLayer, Password: []byte("one")},
			{Kind: RecipientLayer, Recipient: priv.Public()},
		}, open: OpenOptions{Passwords: [][]byte{[]byte("one")}, PrivateKeys: keys}},
		{name: "recipient", layers: []LayerSpec{{Kind: RecipientLayer, Recipient: priv.Public()}},
			open: OpenOptions{PrivateKeys: keys}},
		{name: "keyless", none: true},
	}
}

func (c credentialSetup) options(n, k int, m Method, info InfoMode) SplitOptions {
	return SplitOptions{N: n, K: k, Layers: c.layers, Keyless: c.none, Method: m, Info: info,
		Name: "file.bin", CreatorVersion: "1.2.3", CreatorCommit: "abcdef0"}
}

// TestEveryMethodAndInfoModeRoundTrips rebuilds every combination of method,
// info mode and protection, from every subset of exactly K pieces and from all
// of them, across a 512 KiB share chunk so both share layouts are crossed.
func TestEveryMethodAndInfoModeRoundTrips(t *testing.T) {
	small := []byte("a short secret")
	large := make([]byte, 600<<10)
	if _, err := rand.Read(large); err != nil {
		t.Fatal(err)
	}
	for _, c := range credentialSetups(t) {
		for _, m := range methods {
			for _, info := range infoModes {
				if (info == InfoProtected || info == InfoStrict) && c.none {
					continue
				}
				name := fmt.Sprintf("%s/%s/%s", c.name, m, info)
				for _, input := range [][]byte{small, large} {
					const n, k = 4, 3
					pieces := mustSplit(t, input, c.options(n, k, m, info))
					check := func(sub [][]byte) {
						got, file, err := CombineFile(sub, c.open)
						if err != nil {
							t.Fatalf("%s, %d bytes, %d pieces: %v", name, len(input), len(sub), err)
						}
						if !bytes.Equal(got, input) || file != "file.bin" {
							t.Fatalf("%s, %d bytes: rebuilt different content or name %q", name, len(input), file)
						}
					}
					if len(input) == len(small) {
						allSubsetsOfSize(pieces, k, check)
					}
					check(reversed(pieces))
				}
			}
		}
	}
}

// TestInfoProtectedNeedsASecret refuses protected or strict details for a set
// with neither a password nor a recipient key, and resolves the automatic mode
// by whether it has one.
func TestInfoProtectedNeedsASecret(t *testing.T) {
	for _, c := range credentialSetups(t) {
		for _, mode := range []InfoMode{InfoProtected, InfoStrict} {
			opts := c.options(3, 2, MethodFull, mode)
			opts.Params = testParams
			_, err := Split([]byte("x"), opts)
			if c.none == (err == nil) {
				t.Fatalf("%s: info %s gave %v", c.name, mode, err)
			}
		}
		got, err := EffectiveInfo(c.options(3, 2, MethodFull, InfoAuto))
		want := InfoProtected
		if c.none {
			want = InfoPublic
		}
		if err != nil || got != want {
			t.Fatalf("%s: auto resolved to %v (%v), want %v", c.name, got, err, want)
		}
	}
	if _, err := Split([]byte("x"), SplitOptions{N: 3, K: 2, Keyless: true, Info: InfoMode(9)}); err == nil {
		t.Fatal("an unknown info mode was accepted")
	}
	if _, err := Split([]byte("x"), SplitOptions{N: 3, K: 2, Keyless: true, Method: Method(9)}); err == nil {
		t.Fatal("an unknown method was accepted")
	}
}

// TestWhatOnePieceShows checks Info in each mode: the details need the password,
// need nothing, or are not there at all.
func TestWhatOnePieceShows(t *testing.T) {
	pw := [][]byte{[]byte("one")}
	layers := []LayerSpec{{Kind: PasswordLayer, Password: pw[0]}}
	for _, m := range methods {
		opts := SplitOptions{N: 3, K: 2, Layers: layers, Method: m, Name: "wallet.txt",
			CreatorVersion: "1.2.3", CreatorCommit: "abcdef0"}

		opts.Info = InfoProtected
		piece := mustSplit(t, []byte("content"), opts)[0]
		if _, err := Info(piece, OpenOptions{}); err == nil {
			t.Fatalf("%s: details behind the password were read without it", m)
		}
		info, err := Info(piece, OpenOptions{Passwords: pw})
		if err != nil || info.K != 2 || info.Name != "wallet.txt" || info.Keyless || info.Compact != (m == MethodCompact) {
			t.Fatalf("%s: password details: %+v, %v", m, info, err)
		}

		opts.Info = InfoPublic
		piece = mustSplit(t, []byte("content"), opts)[0]
		info, err = Info(piece, OpenOptions{})
		if err != nil || info.K != 2 || info.N != 3 || info.Name != "wallet.txt" || !info.Keyless ||
			!info.Encrypted || info.PasswordLayers() != 1 || info.Params != testParams || info.CreatorVersion != "1.2.3" {
			t.Fatalf("%s: public details: %+v, %v", m, info, err)
		}

		opts.Info = InfoHidden
		piece = mustSplit(t, []byte("content"), opts)[0]
		info, err = Info(piece, OpenOptions{})
		if err != nil || !info.Hidden || info.K != 0 || info.N != 0 || info.Serial != 0 || info.Name != "" ||
			info.Encrypted || info.LayerCount != 0 || info.CreatorVersion != "" || info.Params != (kdf.Params{}) {
			t.Fatalf("%s: hidden details: %+v, %v", m, info, err)
		}
		for _, s := range []string{"wallet.txt", "1.2.3", "abcdef0"} {
			if bytes.Contains(piece, []byte(s)) {
				t.Fatalf("%s: a hidden piece carries %q in the clear", m, s)
			}
		}
		withPw, err := Info(piece, OpenOptions{Passwords: pw})
		if err != nil || !withPw.Hidden || withPw.Name != "" {
			t.Fatalf("%s: the password showed hidden details: %+v, %v", m, withPw, err)
		}
	}
}

// TestOnePieceCannotTestAPassword is the reason for the public and hidden modes:
// with the password off the envelope, nothing a single piece holds answers
// differently to the right password and a wrong one. The password mode is the
// contrast, and keeps that oracle by design.
func TestOnePieceCannotTestAPassword(t *testing.T) {
	right, wrong := [][]byte{[]byte("right")}, [][]byte{[]byte("wrong")}
	layers := []LayerSpec{{Kind: PasswordLayer, Password: right[0]}}
	for _, m := range methods {
		for _, info := range []InfoMode{InfoPublic, InfoHidden} {
			pieces := mustSplit(t, []byte("guess me"), SplitOptions{N: 3, K: 2, Layers: layers, Method: m, Info: info})
			a, _, errA := format.Decode(pieces[0], right, nil)
			b, _, errB := format.Decode(pieces[0], wrong, nil)
			if errA != nil || errB != nil || !bytes.Equal(a.Share, b.Share) || !bytes.Equal(a.DetailsShare, b.DetailsShare) {
				t.Fatalf("%s/%s: one piece answers the right and wrong password differently", m, info)
			}
			_, errRight := Combine(pieces[:1], OpenOptions{Passwords: right})
			_, errWrong := Combine(pieces[:1], OpenOptions{Passwords: wrong})
			if errRight == nil || errWrong == nil || errRight.Error() != errWrong.Error() {
				t.Fatalf("%s/%s: one piece told the passwords apart: %v / %v", m, info, errRight, errWrong)
			}
			if !errors.Is(errRight, ErrTooFewPieces) {
				t.Fatalf("%s/%s: one piece of two should be too few: %v", m, info, errRight)
			}
			// With K pieces the password matters again, as it must.
			if _, err := Combine(pieces[:2], OpenOptions{Passwords: wrong}); err == nil {
				t.Fatalf("%s/%s: a wrong password rebuilt the set", m, info)
			}
		}
		pieces := mustSplit(t, []byte("guess me"), SplitOptions{N: 3, K: 2, Layers: layers, Method: m, Info: InfoProtected})
		if _, _, err := format.Decode(pieces[0], wrong, nil); !errors.Is(err, format.ErrWrongPassword) {
			t.Fatalf("%s/password: a wrong password should not open the envelope: %v", m, err)
		}
	}
}

// TestFewerThanThresholdIsRefused checks K-1 distinct pieces never rebuild, in
// any mode, and say why in a way callers can test for.
func TestFewerThanThresholdIsRefused(t *testing.T) {
	for _, m := range methods {
		for _, info := range []InfoMode{InfoAuto, InfoPublic, InfoHidden} {
			pieces := mustSplit(t, []byte("threshold"), SplitOptions{N: 5, K: 3, Keyless: true, Method: m, Info: info})
			allSubsetsOfSize(pieces, 2, func(sub [][]byte) {
				_, err := Combine(sub, OpenOptions{})
				if !errors.Is(err, ErrTooFewPieces) {
					t.Fatalf("%s/%s: two of a 3-of-5 set gave %v", m, info, err)
				}
			})
			// Repeating a piece does not make it two.
			if _, err := Combine([][]byte{pieces[0], pieces[0], pieces[1]}, OpenOptions{}); !errors.Is(err, ErrTooFewPieces) {
				t.Fatalf("%s/%s: a repeated piece counted twice: %v", m, info, err)
			}
		}
	}
}

// TestAskPasswordsGetsTheCount checks a set whose envelopes take no password
// asks for exactly as many as it has layers, once it knows, and that without the
// callback the shortfall is an error rather than a wrong rebuild.
func TestAskPasswordsGetsTheCount(t *testing.T) {
	specs, pws := pwLayers(2)
	for _, m := range methods {
		for _, info := range []InfoMode{InfoPublic, InfoHidden} {
			pieces := mustSplit(t, []byte("asked"), SplitOptions{N: 3, K: 2, Layers: specs, Method: m, Info: info})
			asked := 0
			got, err := Combine(pieces[:2], OpenOptions{AskPasswords: func(n int) ([][]byte, error) {
				asked = n
				return [][]byte{append([]byte(nil), pws[0]...), append([]byte(nil), pws[1]...)}, nil
			}})
			if err != nil || string(got) != "asked" || asked != 2 {
				t.Fatalf("%s/%s: asked for %d, rebuilt %q, %v", m, info, asked, got, err)
			}
			if _, err := Combine(pieces[:2], OpenOptions{}); err == nil || !strings.Contains(err.Error(), "needs 2 password") {
				t.Fatalf("%s/%s: no passwords and no callback gave %v", m, info, err)
			}
			stop := errors.New("cancelled")
			if _, err := Combine(pieces[:2], OpenOptions{AskPasswords: func(int) ([][]byte, error) { return nil, stop }}); !errors.Is(err, stop) {
				t.Fatalf("%s/%s: a refused prompt gave %v", m, info, err)
			}
		}
	}
}

// TestUnrecordedSettingsInHiddenSets checks a hidden set that withheld its cost
// or algorithms asks for them the same way a visible one does, and says how many
// algorithms, which only the rebuilt details can tell.
func TestUnrecordedSettingsInHiddenSets(t *testing.T) {
	specs, pws := pwLayers(2)
	for _, m := range methods {
		opts := SplitOptions{N: 3, K: 2, Layers: specs, Method: m, Info: InfoHidden, Params: testParams}
		pieces, err := Split([]byte("withheld"), opts)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Combine(pieces[:2], OpenOptions{Passwords: pws})
		var se *SchemesRequiredError
		if !errors.As(err, &se) || se.Layers != 2 || !errors.Is(err, ErrSchemesRequired) {
			t.Fatalf("%s: unrecorded algorithms gave %v", m, err)
		}
		ids, _ := AssignSchemes(specs)
		_, err = Combine(pieces[:2], OpenOptions{Passwords: pws, Schemes: ids})
		if !errors.Is(err, ErrParamsRequired) {
			t.Fatalf("%s: an unrecorded cost gave %v", m, err)
		}
		cost := testParams
		got, err := Combine(pieces[:2], OpenOptions{Passwords: pws, Schemes: ids, Params: &cost})
		if err != nil || string(got) != "withheld" {
			t.Fatalf("%s: with everything supplied: %q, %v", m, got, err)
		}
	}
}

// TestPublicSetWithheldCost covers the public mode's version of the same: the
// cost byte is noise, so the cost has to be supplied.
func TestPublicSetWithheldCost(t *testing.T) {
	specs, pws := pwLayers(1)
	pieces, err := Split([]byte("public"), SplitOptions{N: 3, K: 2, Layers: specs, Info: InfoPublic,
		Params: testParams, RecordAlgo: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Combine(pieces[:2], OpenOptions{Passwords: pws}); !errors.Is(err, ErrParamsRequired) {
		t.Fatalf("an unrecorded cost gave %v", err)
	}
	cost := testParams
	if got, err := Combine(pieces[:2], OpenOptions{Passwords: pws, Params: &cost}); err != nil || string(got) != "public" {
		t.Fatalf("with the cost: %q, %v", got, err)
	}
}

// TestDamagedPieceIsSetAside checks a spare piece covers a damaged one in the new
// modes too, and that the damage is reported rather than silently skipped.
func TestDamagedPieceIsSetAside(t *testing.T) {
	for _, m := range methods {
		for _, info := range []InfoMode{InfoProtected, InfoPublic, InfoHidden} {
			specs, pws := pwLayers(1)
			pieces := mustSplit(t, []byte("spare"), SplitOptions{N: 4, K: 2, Layers: specs, Method: m, Info: info})
			bad := append([]byte(nil), pieces[1]...)
			bad[len(bad)/2] ^= 0xFF
			reported := -1
			got, err := Combine([][]byte{pieces[0], bad, pieces[2]}, OpenOptions{Passwords: pws,
				Damaged: func(i int, _ error) { reported = i }})
			if err != nil || string(got) != "spare" || reported != 1 {
				t.Fatalf("%s/%s: rebuilt %q, reported %d, %v", m, info, got, reported, err)
			}
			// With no spare, the damaged file is the error.
			if _, err := Combine([][]byte{pieces[0], bad}, OpenOptions{Passwords: pws}); err == nil ||
				!strings.Contains(err.Error(), "damaged") {
				t.Fatalf("%s/%s: no spare gave %v", m, info, err)
			}
		}
	}
}

// TestPiecesOfAnotherSetAreRefused mixes two sets of the same mode.
func TestPiecesOfAnotherSetAreRefused(t *testing.T) {
	for _, m := range methods {
		for _, info := range []InfoMode{InfoPublic, InfoHidden} {
			opts := SplitOptions{N: 3, K: 2, Keyless: true, Method: m, Info: info}
			a := mustSplit(t, []byte("set a"), opts)
			b := mustSplit(t, []byte("set b"), opts)
			if _, err := Combine([][]byte{a[0], b[1]}, OpenOptions{}); err == nil || !strings.Contains(err.Error(), "different set") {
				t.Fatalf("%s/%s: mixed sets gave %v", m, info, err)
			}
		}
	}
	full := mustSplit(t, []byte("set a"), SplitOptions{N: 3, K: 2, Keyless: true})
	small := mustSplit(t, []byte("set a"), SplitOptions{N: 3, K: 2, Keyless: true, Method: MethodCompact})
	if _, err := Combine([][]byte{full[0], small[1]}, OpenOptions{}); err == nil {
		t.Fatal("pieces of a full and a compact set were combined")
	}
}

// TestCompactPiecesAreAFractionOfTheInput is the point of the method: a piece is
// about 1/K of the input, against the whole input for the full method.
func TestCompactPiecesAreAFractionOfTheInput(t *testing.T) {
	input := make([]byte, 300<<10)
	if _, err := rand.Read(input); err != nil {
		t.Fatal(err)
	}
	specs, _ := pwLayers(1)
	for _, k := range []int{1, 2, 3, 5} {
		full := mustSplit(t, input, SplitOptions{N: 5, K: k, Layers: specs, Padding: PadNone()})
		small := mustSplit(t, input, SplitOptions{N: 5, K: k, Layers: specs, Padding: PadNone(), Method: MethodCompact})
		if want := len(input)/k + 1024; len(small[0]) > want {
			t.Fatalf("k=%d: compact piece is %d bytes, over %d", k, len(small[0]), want)
		}
		if len(full[0]) < len(input) {
			t.Fatalf("k=%d: a full piece is %d bytes, under the input", k, len(full[0]))
		}
	}
}

// TestNewModesReachTheSizeClass checks padding lands every compact and hidden
// piece exactly on a size class, so their sizes say no more than full pieces do.
func TestNewModesReachTheSizeClass(t *testing.T) {
	specs, _ := pwLayers(1)
	for _, m := range methods {
		for _, info := range []InfoMode{InfoProtected, InfoPublic, InfoHidden} {
			for _, w := range []int{1, 10} {
				for _, n := range []int{1, 300, 5000, 70000} {
					pieces := mustSplit(t, make([]byte, n), SplitOptions{N: 3, K: 2, Layers: specs,
						Method: m, Info: info, Padding: PadPercent(w)})
					size := len(pieces[0])
					for _, p := range pieces {
						if len(p) != size {
							t.Fatalf("%s/%s: pieces of one set differ in size", m, info)
						}
					}
					if BucketFor(size, w) != size {
						t.Fatalf("%s/%s at %d percent, %d bytes: piece of %d is not a class", m, info, w, n, size)
					}
				}
			}
		}
	}
}

// TestCompactThresholdOne checks the degenerate threshold: every compact piece
// rebuilds the set alone.
func TestCompactThresholdOne(t *testing.T) {
	specs, pws := pwLayers(1)
	pieces := mustSplit(t, []byte("alone"), SplitOptions{N: 3, K: 1, Layers: specs, Method: MethodCompact})
	for i, p := range pieces {
		if got, err := Combine([][]byte{p}, OpenOptions{Passwords: pws}); err != nil || string(got) != "alone" {
			t.Fatalf("piece %d: %q, %v", i+1, got, err)
		}
	}
}

// TestSplitToCompactAndHidden checks the streaming path builds the same sets.
func TestSplitToCompactAndHidden(t *testing.T) {
	input := bytes.Repeat([]byte("stream "), 5000)
	for _, info := range []InfoMode{InfoPublic, InfoHidden} {
		opts := SplitOptions{N: 4, K: 2, Keyless: true, Method: MethodCompact, Info: info, Params: testParams}
		var pieces [][]byte
		if err := SplitTo(input, opts, func(_ int, p []byte) error {
			pieces = append(pieces, append([]byte(nil), p...))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if got, err := Combine(pieces[2:], OpenOptions{}); err != nil || !bytes.Equal(got, input) {
			t.Fatalf("%s: %v", info, err)
		}
	}
}

// TestSharesAreDroppedAfterTheRebuild checks forget wipes and drops what the
// opened manifests carry, so a combine does not hold K input-sized shares through
// the decryption.
func TestSharesAreDroppedAfterTheRebuild(t *testing.T) {
	pieces := mustSplit(t, []byte("forgotten"), SplitOptions{N: 3, K: 2, Keyless: true, Info: InfoHidden, Method: MethodCompact})
	o := OpenOptions{}
	_, _, opened, _, err := openPieces(pieces, &o)
	if err != nil {
		t.Fatal(err)
	}
	shares := make([][]byte, len(opened))
	for i, m := range opened {
		shares[i] = m.Share
	}
	forget(opened)
	for i, m := range opened {
		if m.Share != nil || m.Fragment != nil || m.DetailsShare != nil {
			t.Fatalf("piece %d still holds its shares", i+1)
		}
		for _, b := range shares[i] {
			if b != 0 {
				t.Fatalf("piece %d's share was dropped without being wiped", i+1)
			}
		}
	}
	forget([]*format.Manifest{nil})
}

// TestCompactFragmentsAreAllOrNothing reaches inside a compact set to play an
// attacker who has the shared keys, which takes K pieces, but is one fragment
// short: the fragments they hold still decrypt to nothing, because the package
// opens only whole. That is what the all-or-nothing transform adds over the two
// keyed layers.
func TestCompactFragmentsAreAllOrNothing(t *testing.T) {
	marker := []byte("CONFIDENTIAL-")
	input := bytes.Repeat(append(append([]byte(nil), marker...), "a very regular line\n"...), 3000)
	const n, k = 5, 3
	prep, err := prepare(input, SplitOptions{N: n, K: k, Keyless: true, Method: MethodCompact, Params: testParams})
	if err != nil {
		t.Fatal(err)
	}
	defer prep.cleanup()

	shared, err := split.Combine(prep.shares[:k], k)
	if err != nil {
		t.Fatal(err)
	}
	secret, ok := format.UnwrapPayload(shared, prep.payloadHash)
	if !ok {
		t.Fatal("the shared secret did not unwrap")
	}
	fragments := make([][]byte, n)
	for i := range fragments {
		fragments[i] = prep.disp.Fragment(i)
		if bytes.Contains(fragments[i], marker) {
			t.Fatalf("fragment %d carries the content", i+1)
		}
	}
	forged := append([]byte{fragments[k-1][0]}, make([]byte, len(fragments[0])-1)...)
	if _, err := rand.Read(forged[1:]); err != nil {
		t.Fatal(err)
	}
	data, err := disperse.Combine([][]byte{fragments[0], fragments[1], forged}, k)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, marker) {
		t.Fatal("K-1 fragments and the keys exposed the content")
	}
	if _, err := compact.Open(data, secret); !errors.Is(err, compact.ErrIntegrity) {
		t.Fatalf("K-1 fragments and the keys opened the package: %v", err)
	}

	// And the genuine K fragments do open, so the check above is meaningful.
	data, err = disperse.Combine(fragments[:k], k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compact.Open(data, secret); err != nil {
		t.Fatalf("K genuine fragments did not open: %v", err)
	}
}
