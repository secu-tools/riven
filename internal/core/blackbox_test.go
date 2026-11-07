// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
)

// These tests use only what the package exports, the way a caller or an attacker
// meets it: split a set, then do what the documentation allows to its pieces. A
// keyless envelope can be opened and sealed again by anyone, so those tests also
// rewrite pieces the way docs/format.md says they can be rewritten.

var cheap = kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}

// publicEnvelopes are the info modes that seal every envelope with the public
// key, so anyone can open a piece and seal it again.
var publicEnvelopes = []core.InfoMode{core.InfoPublic, core.InfoHidden}

func split(t *testing.T, input []byte, opts core.SplitOptions) [][]byte {
	t.Helper()
	if opts.Params == (kdf.Params{}) {
		opts.Params = cheap
	}
	pieces, err := core.Split(input, opts)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	return pieces
}

func password(pw string) []core.LayerSpec {
	return []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte(pw)}}
}

// reseal opens a keyless piece with the public key, lets edit change the
// manifest, and seals it again: anything a holder of the piece can do.
func reseal(t *testing.T, piece []byte, edit func(m *format.Manifest)) []byte {
	t.Helper()
	m, _, err := format.Decode(piece, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	edit(m)
	// The cost a piece records is kept, as anyone resealing it can.
	params := cheap
	if m.KDFStored {
		params = m.Params
	}
	in := format.EncodeInput{
		Details: format.Details{
			K:              max(m.K, 1),
			N:              max(m.N, 1),
			Encrypted:      m.Encrypted,
			Hybrid:         m.Hybrid,
			AlgoStored:     m.AlgoStored,
			KDFStored:      m.KDFStored,
			Params:         params,
			Layers:         m.Layers,
			Name:           m.Name,
			CreatorVersion: m.CreatorVersion,
			CreatorCommit:  m.CreatorCommit,
		},
		SetID:        m.SetID,
		Serial:       max(m.Serial, 1),
		Keyless:      true,
		Stretched:    true,
		PayloadHash:  m.PayloadHash,
		Share:        m.Share,
		Fragment:     m.Fragment,
		DetailsShare: m.DetailsShare,
	}
	out, err := format.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCostIsAskedForBeforeThePasswords: a set whose envelopes take no password
// and which withheld its cost must say so before asking for any password, or a
// caller that asks for the cost and tries again has to ask for every password a
// second time.
func TestCostIsAskedForBeforeThePasswords(t *testing.T) {
	for _, info := range publicEnvelopes {
		pieces, err := core.Split([]byte("cost first"), core.SplitOptions{N: 3, K: 2, Info: info,
			Layers: password("pw"), Params: cheap, RecordAlgo: true})
		if err != nil {
			t.Fatal(err)
		}
		asked := 0
		_, err = core.Combine(pieces[:2], core.OpenOptions{AskPasswords: func(n int) ([][]byte, error) {
			asked++
			return [][]byte{[]byte("pw")}, nil
		}})
		if !errors.Is(err, core.ErrParamsRequired) || asked != 0 {
			t.Fatalf("%v: got %v after asking for passwords %d time(s), want the cost error first", info, err, asked)
		}
	}
}

// TestAskedPasswordsAreCanonical checks a password typed at the prompt goes
// through the same normalisation as one given up front, so a set split with
// one Unicode form opens with the other.
func TestAskedPasswordsAreCanonical(t *testing.T) {
	decomposed := "cafe" + string(rune(0x0301))
	composed := "caf" + string(rune(0x00E9))
	pieces := split(t, []byte("canonical"), core.SplitOptions{N: 2, K: 2, Info: core.InfoPublic,
		Layers: password(decomposed), RecordAlgo: true, RecordKDF: true})
	got, err := core.Combine(pieces, core.OpenOptions{AskPasswords: func(int) ([][]byte, error) {
		return [][]byte{[]byte(composed)}, nil
	}})
	if err != nil || string(got) != "canonical" {
		t.Fatalf("the composed form did not open a set split with the decomposed one: %q, %v", got, err)
	}
}

// TestAskedPasswordsMustMatchTheCount checks a prompt that returns too few or
// too many passwords is an error rather than a wrong key.
func TestAskedPasswordsMustMatchTheCount(t *testing.T) {
	layers := append(password("one"), core.LayerSpec{Kind: core.PasswordLayer, Password: []byte("two"), SchemeID: 3})
	pieces := split(t, []byte("count"), core.SplitOptions{N: 2, K: 2, Info: core.InfoHidden,
		Layers: layers, RecordAlgo: true, RecordKDF: true})
	for _, give := range [][][]byte{{[]byte("one")}, {[]byte("one"), []byte("two"), []byte("three")}} {
		_, err := core.Combine(pieces, core.OpenOptions{AskPasswords: func(int) ([][]byte, error) { return give, nil }})
		if err == nil || !strings.Contains(err.Error(), "needs 2 password") {
			t.Fatalf("%d passwords for a 2-layer set: %v", len(give), err)
		}
	}
}

// TestKeylessCompactRefusesAPassword keeps a set with no password from looking
// as though a password unlocked it, in the new modes too.
func TestKeylessCompactRefusesAPassword(t *testing.T) {
	for _, info := range []core.InfoMode{core.InfoAuto, core.InfoHidden} {
		pieces := split(t, []byte("no password"), core.SplitOptions{N: 3, K: 2, Keyless: true,
			Method: core.MethodCompact, Info: info})
		if _, err := core.Combine(pieces[:2], core.OpenOptions{Passwords: [][]byte{[]byte("stray")}}); err == nil {
			t.Fatalf("%v: a keyless set accepted a password", info)
		}
		if got, err := core.Combine(pieces[:2], core.OpenOptions{}); err != nil || string(got) != "no password" {
			t.Fatalf("%v: %q, %v", info, got, err)
		}
	}
}

// TestHiddenNeedsAThresholdAboveOne refuses --info none at K of 1. A share at
// that threshold is a plain copy, so each piece would carry its details in the
// clear under the public envelope: hiding them is impossible, and pretending
// otherwise would leave the name less protected than the default mode does.
func TestHiddenNeedsAThresholdAboveOne(t *testing.T) {
	for _, m := range []core.Method{core.MethodFull, core.MethodCompact} {
		_, err := core.Split([]byte("one is enough"), core.SplitOptions{N: 3, K: 1, Info: core.InfoHidden, Method: m,
			Layers: password("pw"), Name: "one.txt", Params: cheap, RecordAlgo: true, RecordKDF: true})
		if err == nil {
			t.Fatalf("%v: hidden details at a threshold of one were accepted", m)
		}
	}
}

// TestHiddenDetailsGiveNoLength checks the one thing a hidden piece shows of its
// details, the length of their share, says nothing about them: a long name and
// more layers give a share as long as a short name and one layer.
func TestHiddenDetailsGiveNoLength(t *testing.T) {
	layers := []core.LayerSpec{
		{Kind: core.PasswordLayer, Password: []byte("one")},
		{Kind: core.PasswordLayer, Password: []byte("two"), SchemeID: 3},
		{Kind: core.PasswordLayer, Password: []byte("three"), SchemeID: 1},
	}
	short := split(t, []byte("x"), core.SplitOptions{N: 2, K: 2, Info: core.InfoHidden, Layers: password("one"),
		Name: "a", RecordAlgo: true, RecordKDF: true})
	long := split(t, []byte("x"), core.SplitOptions{N: 2, K: 2, Info: core.InfoHidden, Layers: layers,
		Name: strings.Repeat("n", 120), CreatorVersion: "1.2.3", CreatorCommit: "abcdef0", RecordAlgo: true, RecordKDF: true})
	a, _, err := format.Decode(short[0], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := format.Decode(long[0], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.DetailsShare) != len(b.DetailsShare) {
		t.Fatalf("details shares of %d and %d bytes tell the sets apart", len(a.DetailsShare), len(b.DetailsShare))
	}
}

// TestPublicDetailsMustAgree rewrites the name on one piece of a public password
// set, which its keyless envelope allows. The pieces then disagree, and the set
// must refuse rather than offer the rewritten name.
func TestPublicDetailsMustAgree(t *testing.T) {
	pieces := split(t, []byte("named"), core.SplitOptions{N: 3, K: 2, Info: core.InfoPublic, Layers: password("pw"),
		Name: "report.pdf", RecordAlgo: true, RecordKDF: true})
	forged := reseal(t, pieces[0], func(m *format.Manifest) { m.Name = "report.pdf.exe" })
	_, name, err := core.CombineFile([][]byte{forged, pieces[1]}, core.OpenOptions{Passwords: [][]byte{[]byte("pw")}})
	if err == nil {
		t.Fatalf("a rewritten name was accepted and offered as %q", name)
	}
	if !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("a rewritten name gave %v", err)
	}
}

// TestKeylessPieceCannotStandInForAPasswordSet puts a crafted keyless piece of
// threshold one among the pieces of a password set. Wherever it sits, the
// password set's content comes back or the combine fails; the crafted content
// never does.
func TestKeylessPieceCannotStandInForAPasswordSet(t *testing.T) {
	genuine := split(t, []byte("the real content"), core.SplitOptions{N: 3, K: 2, Layers: password("pw"),
		RecordAlgo: true, RecordKDF: true})
	crafted, err := core.Split([]byte("attacker content"), core.SplitOptions{N: 2, K: 2, Keyless: true})
	if err != nil {
		t.Fatal(err)
	}
	pw := core.OpenOptions{Passwords: [][]byte{[]byte("pw")}}
	for _, order := range [][][]byte{
		{crafted[0], genuine[0], genuine[1]},
		{genuine[0], crafted[0], genuine[1]},
	} {
		got, err := core.Combine(order, pw)
		if err == nil && string(got) != "the real content" {
			t.Fatalf("a crafted keyless piece replaced the content with %q", got)
		}
	}
}

// TestHiddenWithoutARecordedName checks --record-name false holds when the
// details are hidden: nothing comes back.
func TestHiddenWithoutARecordedName(t *testing.T) {
	pieces := split(t, []byte("nameless"), core.SplitOptions{N: 3, K: 2, Info: core.InfoHidden, Keyless: true})
	if _, name, err := core.CombineFile(pieces[1:], core.OpenOptions{}); err != nil || name != "" {
		t.Fatalf("name %q, %v", name, err)
	}
}

// TestDamagedFirstPieceInTheNewModes damages the piece every other is measured
// against; the second opens instead and the set rebuilds from the rest.
func TestDamagedFirstPieceInTheNewModes(t *testing.T) {
	for _, m := range []core.Method{core.MethodFull, core.MethodCompact} {
		for _, info := range publicEnvelopes {
			pieces := split(t, []byte("first is broken"), core.SplitOptions{N: 4, K: 3, Info: info, Method: m,
				Layers: password("pw"), RecordAlgo: true, RecordKDF: true})
			bad := append([]byte(nil), pieces[0]...)
			bad[len(bad)-1] ^= 1
			damaged := -1
			got, err := core.Combine([][]byte{bad, pieces[1], pieces[2], pieces[3]}, core.OpenOptions{
				Passwords: [][]byte{[]byte("pw")}, Damaged: func(i int, _ error) { damaged = i }})
			if err != nil || string(got) != "first is broken" || damaged != 0 {
				t.Fatalf("%v/%v: %q, damaged %d, %v", m, info, got, damaged, err)
			}
		}
	}
}

// TestCompactAtTheTopOfTheRange checks the largest thresholds rebuild, from a
// subset that is not the first K.
func TestCompactAtTheTopOfTheRange(t *testing.T) {
	input := []byte("two hundred of two hundred and fifty five")
	pieces := split(t, input, core.SplitOptions{N: 255, K: 200, Keyless: true, Method: core.MethodCompact, Info: core.InfoHidden})
	got, err := core.Combine(pieces[55:], core.OpenOptions{})
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("%q, %v", got, err)
	}
	if _, err := core.Combine(pieces[56:], core.OpenOptions{}); !errors.Is(err, core.ErrTooFewPieces) {
		t.Fatalf("199 of a 200-piece threshold: %v", err)
	}
}

// TestRecipientOnlyDetailsArePublic checks a set with only a recipient key shows
// its details to anyone and names the key it needs.
func TestRecipientOnlyDetailsArePublic(t *testing.T) {
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	pieces := split(t, []byte("for the key"), core.SplitOptions{N: 2, K: 2, Method: core.MethodCompact, Info: core.InfoPublic,
		Layers: []core.LayerSpec{{Kind: core.RecipientLayer, Recipient: priv.Public()}}, RecordAlgo: true})
	info, err := core.Info(pieces[0], core.OpenOptions{})
	if err != nil || !info.Keyless || info.KEMLayers != 1 || info.PasswordLayers() != 0 || !info.Compact {
		t.Fatalf("%+v, %v", info, err)
	}
	if _, err := core.Combine(pieces, core.OpenOptions{}); !errors.Is(err, core.ErrKeyRequired) {
		t.Fatalf("no key: %v", err)
	}
	got, err := core.Combine(pieces, core.OpenOptions{PrivateKeys: []*kem.PrivateKey{priv}})
	if err != nil || string(got) != "for the key" {
		t.Fatalf("%q, %v", got, err)
	}
}

// TestStrictDetailsTakeEverySecret checks a strict piece shows its details only
// to someone holding every password and every private key the set takes, and
// that a set protected by keys alone never asks for a password.
func TestStrictDetailsTakeEverySecret(t *testing.T) {
	a, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	b, err := kem.Generate(kem.P256)
	if err != nil {
		t.Fatal(err)
	}
	other, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	pw := [][]byte{[]byte("the password")}
	noAsk := func(bool) ([][]byte, error) {
		t.Fatal("a password was asked for")
		return nil, nil
	}

	t.Run("keys", func(t *testing.T) {
		pieces := split(t, []byte("for two keys"), core.SplitOptions{N: 3, K: 2, Info: core.InfoStrict,
			RecordAlgo: true, RecordKDF: true, Layers: []core.LayerSpec{
				{Kind: core.RecipientLayer, Recipient: a.Public()},
				{Kind: core.RecipientLayer, Recipient: b.Public()},
			}})
		for _, keys := range [][]*kem.PrivateKey{nil, {a}, {b}, {a, other}} {
			if _, err := core.Info(pieces[0], core.OpenOptions{PrivateKeys: keys}); err == nil {
				t.Fatalf("%d of the keys read the details", len(keys))
			}
		}
		// The keys in either order, alongside one the set does not take.
		keys := []*kem.PrivateKey{b, other, a}
		info, err := core.Info(pieces[0], core.OpenOptions{PrivateKeys: keys, EnvelopePasswords: noAsk})
		if err != nil || !info.SealedToKeys || info.KEMLayers != 2 {
			t.Fatalf("%+v, %v", info, err)
		}
		got, err := core.Combine(pieces[1:], core.OpenOptions{PrivateKeys: keys, EnvelopePasswords: noAsk})
		if err != nil || string(got) != "for two keys" {
			t.Fatalf("%q, %v", got, err)
		}
		p, err := core.Open(pieces[0], core.OpenOptions{PrivateKeys: keys})
		if err != nil {
			t.Fatal(err)
		}
		q, err := core.Open(pieces[2], core.OpenOptions{PrivateKeys: keys})
		if err != nil {
			t.Fatal(err)
		}
		got, _, err = core.CombineOpened([]*core.Piece{p, q}, core.OpenOptions{PrivateKeys: keys, EnvelopePasswords: noAsk})
		if err != nil || string(got) != "for two keys" {
			t.Fatalf("opened: %q, %v", got, err)
		}
	})

	t.Run("password and key", func(t *testing.T) {
		pieces := split(t, []byte("for both"), core.SplitOptions{N: 3, K: 2, Info: core.InfoStrict,
			RecordAlgo: true, RecordKDF: true, Layers: []core.LayerSpec{
				{Kind: core.PasswordLayer, Password: pw[0]},
				{Kind: core.RecipientLayer, Recipient: a.Public()},
			}})
		for name, o := range map[string]core.OpenOptions{
			"password":       {Passwords: pw},
			"key":            {PrivateKeys: []*kem.PrivateKey{a}},
			"wrong password": {Passwords: [][]byte{[]byte("not it")}, PrivateKeys: []*kem.PrivateKey{a}},
		} {
			if _, err := core.Info(pieces[0], o); err == nil {
				t.Fatalf("the %s alone read the details", name)
			}
		}
		info, err := core.Info(pieces[0], core.OpenOptions{Passwords: pw, PrivateKeys: []*kem.PrivateKey{a}})
		if err != nil || !info.SealedToKeys || info.PasswordLayers() != 1 || info.KEMLayers != 1 {
			t.Fatalf("%+v, %v", info, err)
		}
		// Passwords asked for once the keys alone have not opened anything.
		asked := 0
		ask := func(bool) ([][]byte, error) { asked++; return pw, nil }
		got, err := core.Combine(pieces, core.OpenOptions{PrivateKeys: []*kem.PrivateKey{a}, EnvelopePasswords: ask})
		if err != nil || string(got) != "for both" || asked != 1 {
			t.Fatalf("%q, %v, asked %d times", got, err, asked)
		}
	})
}

// TestProtectedDetailsTakeTheFirstLayer checks the default: a piece shows its
// details to whoever holds the first layer's password or key, whatever the
// layers under it take, and to nobody without it. The rest are needed only to
// rebuild, and are asked for then.
func TestProtectedDetailsTakeTheFirstLayer(t *testing.T) {
	key, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	first, second := []byte("outermost"), []byte("innermost")

	t.Run("password first", func(t *testing.T) {
		pieces := split(t, []byte("password first"), core.SplitOptions{N: 3, K: 2, RecordAlgo: true, RecordKDF: true,
			Layers: []core.LayerSpec{
				{Kind: core.PasswordLayer, Password: first},
				{Kind: core.RecipientLayer, Recipient: key.Public()},
				{Kind: core.PasswordLayer, Password: second},
			}})
		info, err := core.Info(pieces[0], core.OpenOptions{Passwords: [][]byte{first}})
		if err != nil || info.SealedToKeys || info.LayerCount != 3 {
			t.Fatalf("the first password alone: %+v, %v", info, err)
		}
		for name, o := range map[string]core.OpenOptions{
			"key":             {PrivateKeys: []*kem.PrivateKey{key}},
			"second password": {Passwords: [][]byte{second}},
		} {
			if _, err := core.Info(pieces[0], o); err == nil {
				t.Fatalf("the %s read the details", name)
			}
		}
		// Every password given opens it too, the first tried alone.
		all := core.OpenOptions{Passwords: [][]byte{first, second}, PrivateKeys: []*kem.PrivateKey{key}}
		got, err := core.Combine(pieces[1:], all)
		if err != nil || string(got) != "password first" {
			t.Fatalf("%q, %v", got, err)
		}
		// Opened with the first password, a rebuild asks for every one.
		p, err := core.Open(pieces[0], core.OpenOptions{Passwords: [][]byte{first}})
		if err != nil {
			t.Fatal(err)
		}
		q, err := core.Open(pieces[1], core.OpenOptions{Passwords: [][]byte{first}})
		if err != nil {
			t.Fatal(err)
		}
		asked := 0
		got, _, err = core.CombineOpened([]*core.Piece{p, q}, core.OpenOptions{PrivateKeys: []*kem.PrivateKey{key},
			EnvelopePasswords: func(bool) ([][]byte, error) { return [][]byte{[]byte("outermost")}, nil },
			AskPasswords: func(n int) ([][]byte, error) {
				asked = n
				return [][]byte{[]byte("outermost"), []byte("innermost")}, nil
			}})
		if err != nil || string(got) != "password first" || asked != 2 {
			t.Fatalf("%q, %v, asked for %d", got, err, asked)
		}
	})

	t.Run("key first", func(t *testing.T) {
		// The cost is not recorded, so nothing the envelope opened with can
		// stand in for it: the password layer under the key needs it supplied.
		pieces := split(t, []byte("key first"), core.SplitOptions{N: 3, K: 2, RecordAlgo: true,
			Layers: []core.LayerSpec{
				{Kind: core.RecipientLayer, Recipient: key.Public()},
				{Kind: core.PasswordLayer, Password: second},
			}})
		info, err := core.Info(pieces[0], core.OpenOptions{PrivateKeys: []*kem.PrivateKey{key},
			EnvelopePasswords: func(bool) ([][]byte, error) {
				t.Fatal("the key alone should open a piece sealed to it")
				return nil, nil
			}})
		if err != nil || !info.SealedToKeys || info.PasswordLayers() != 1 {
			t.Fatalf("the key alone: %+v, %v", info, err)
		}
		if _, err := core.Info(pieces[0], core.OpenOptions{Passwords: [][]byte{second}}); err == nil {
			t.Fatal("the password read details sealed to the key")
		}
		_, err = core.Combine(pieces[:2], core.OpenOptions{Passwords: [][]byte{second},
			PrivateKeys: []*kem.PrivateKey{key}})
		if !errors.Is(err, core.ErrParamsRequired) {
			t.Fatalf("an unrecorded cost was not asked for: %v", err)
		}
		cost := cheap
		got, err := core.Combine(pieces[:2], core.OpenOptions{Passwords: [][]byte{second},
			PrivateKeys: []*kem.PrivateKey{key}, Params: &cost})
		if err != nil || string(got) != "key first" {
			t.Fatalf("%q, %v", got, err)
		}
	})
}

// TestRewrittenPiecesNeverRebuildWrongContent plays a holder of a keyless piece
// who rewrites what it carries. Whatever is changed, the set either fails or
// rebuilds the true content; it never rebuilds something else.
func TestRewrittenPiecesNeverRebuildWrongContent(t *testing.T) {
	input := []byte("only this, or nothing")
	edits := map[string]func(m *format.Manifest){
		"share byte":    func(m *format.Manifest) { m.Share[0] ^= 1 },
		"fragment byte": func(m *format.Manifest) { m.Fragment[len(m.Fragment)-1] ^= 1 },
		"fragment x":    func(m *format.Manifest) { m.Fragment[0] ^= 1 },
		"details byte":  func(m *format.Manifest) { m.DetailsShare[0] ^= 1 },
		"hash":          func(m *format.Manifest) { m.PayloadHash[0] ^= 1 },
	}
	for _, info := range publicEnvelopes {
		pieces := split(t, input, core.SplitOptions{N: 3, K: 3, Keyless: true, Method: core.MethodCompact, Info: info})
		for name, edit := range edits {
			if name == "details byte" && info != core.InfoHidden {
				continue
			}
			forged := reseal(t, pieces[1], edit)
			got, err := core.Combine([][]byte{pieces[0], forged, pieces[2]}, core.OpenOptions{})
			if err == nil && !bytes.Equal(got, input) {
				t.Fatalf("%v, %s: rebuilt different content %q", info, name, got)
			}
			if err == nil {
				t.Fatalf("%v, %s: a rewritten piece went unnoticed", info, name)
			}
		}
	}
}

// TestForeignDetailsShareIsNamed adds a piece that claims the set id of a hidden
// set but carries a details share of another length. The error must say a piece
// does not fit the set, not that more pieces are needed: three genuine pieces of
// a 3-of-4 set are there.
func TestForeignDetailsShareIsNamed(t *testing.T) {
	pieces := split(t, []byte("hidden"), core.SplitOptions{N: 4, K: 3, Keyless: true, Info: core.InfoHidden})
	forged := reseal(t, pieces[3], func(m *format.Manifest) { m.DetailsShare = append(m.DetailsShare, 0) })
	_, err := core.Combine([][]byte{pieces[0], pieces[1], pieces[2], forged}, core.OpenOptions{})
	if err == nil || errors.Is(err, core.ErrTooFewPieces) || !strings.Contains(err.Error(), "piece 4") {
		t.Fatalf("a piece that does not fit the set gave %v", err)
	}
}

// TestEnvelopePasswordsAreAskedOnlyWhenNeeded checks when the open asks for the
// envelope passwords: never for a set that opens without one, with mixed false
// when nothing opened, and with mixed true when some pieces did, which is how a
// crafted keyless piece in front of a password set shows itself.
func TestEnvelopePasswordsAreAskedOnlyWhenNeeded(t *testing.T) {
	keyless := split(t, []byte("keyless"), core.SplitOptions{N: 3, K: 2, Keyless: true})
	sealed := split(t, []byte("sealed"), core.SplitOptions{N: 3, K: 2, Layers: password("pw"),
		RecordAlgo: true, RecordKDF: true})
	type call struct{ mixed bool }
	cases := []struct {
		name   string
		pieces [][]byte
		calls  []call
		want   string
	}{
		{"keyless", keyless[:2], nil, "keyless"},
		{"sealed", sealed[:2], []call{{false}}, "sealed"},
		{"crafted in front", [][]byte{keyless[0], sealed[0], sealed[1]}, []call{{true}}, ""},
	}
	for _, c := range cases {
		var calls []call
		got, err := core.Combine(c.pieces, core.OpenOptions{EnvelopePasswords: func(mixed bool) ([][]byte, error) {
			calls = append(calls, call{mixed})
			return [][]byte{[]byte("pw")}, nil
		}})
		if len(calls) != len(c.calls) || (len(calls) > 0 && calls[0] != c.calls[0]) {
			t.Fatalf("%s: asked %v, want %v", c.name, calls, c.calls)
		}
		if c.want != "" && (err != nil || string(got) != c.want) {
			t.Fatalf("%s: %q, %v", c.name, got, err)
		}
		if c.want == "" && err == nil && string(got) != "sealed" {
			t.Fatalf("%s: the crafted content came back: %q", c.name, got)
		}
	}
	// Answering with no password treats the set as keyless: the pieces that did
	// not open are damaged, and the rest rebuild if there are enough.
	damaged := 0
	got, err := core.Combine([][]byte{keyless[0], sealed[0], keyless[1]}, core.OpenOptions{
		EnvelopePasswords: func(bool) ([][]byte, error) { return nil, nil },
		Damaged:           func(int, error) { damaged++ },
	})
	if err != nil || string(got) != "keyless" || damaged != 1 {
		t.Fatalf("no password for a mixed set: %q, %d damaged, %v", got, damaged, err)
	}
}

// TestCostAndAlgorithmsAreAskedForOnce covers a password set that recorded
// neither: its pieces do not open at the noise in the cost byte, so AskParams is
// asked with certain false, then the algorithms are asked for with the layer
// count, and each once.
func TestCostAndAlgorithmsAreAskedForOnce(t *testing.T) {
	// Noise that is the cost, one time in 256, opens the first piece tried
	// without asking, which is a test of its own in the core package. Other
	// noise is derived at, up to 1 GiB and 8 passes, so dear noise is split
	// again too, to keep the time from depending on chance.
	var pieces [][]byte
	for pieces == nil || noiseUnfit(pieces[:2], cheap) {
		var err error
		pieces, err = core.Split([]byte("withheld"), core.SplitOptions{N: 3, K: 2, Params: cheap,
			Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("pw"), SchemeID: 2}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	var params, schemes []string
	cost := cheap
	got, err := core.Combine(pieces, core.OpenOptions{
		Passwords: [][]byte{[]byte("pw")},
		AskParams: func(certain bool) (*kdf.Params, error) {
			params = append(params, map[bool]string{true: "certain", false: "maybe"}[certain])
			return &cost, nil
		},
		AskSchemes: func(layers int) ([]uint8, error) {
			schemes = append(schemes, strings.Repeat("x", layers))
			return []uint8{2}, nil
		},
	})
	if err != nil || string(got) != "withheld" {
		t.Fatalf("%q, %v", got, err)
	}
	if strings.Join(params, ",") != "maybe" || strings.Join(schemes, ",") != "x" {
		t.Fatalf("asked for the cost %v and the algorithms %v", params, schemes)
	}
	// A callback that gives up leaves the error as it was.
	_, err = core.Combine(pieces, core.OpenOptions{Passwords: [][]byte{[]byte("pw")},
		AskParams: func(bool) (*kdf.Params, error) { return nil, nil }})
	if !errors.Is(err, format.ErrWrongPassword) {
		t.Fatalf("a declined cost question gave %v", err)
	}
}

// noiseUnfit reports whether a cost byte among pieces, noise in a set that did
// not record its cost, decodes to cost itself or to more work than 128 MiB at
// one pass, which a combine without the cost spends deriving.
func noiseUnfit(pieces [][]byte, cost kdf.Params) bool {
	for _, p := range pieces {
		d, ok := format.PeekParams(p)
		if ok && (d == cost || uint64(d.Memory)*uint64(d.Time) > 128*1024) {
			return true
		}
	}
	return false
}

// TestBeforeDeriveOnlyWhenAKeyIsDerived checks the slow-open notice is given
// once for a password set, with the cost it declares, and never for a set whose
// envelopes take no password, whose cost bytes may be noise.
func TestBeforeDeriveOnlyWhenAKeyIsDerived(t *testing.T) {
	sealed := split(t, []byte("sealed"), core.SplitOptions{N: 3, K: 2, Layers: password("pw"),
		RecordAlgo: true, RecordKDF: true})
	hidden := split(t, []byte("hidden"), core.SplitOptions{N: 3, K: 2, Layers: password("pw"), Info: core.InfoHidden,
		RecordAlgo: true, RecordKDF: true})
	for name, c := range map[string]struct {
		pieces [][]byte
		calls  int
	}{"sealed": {sealed, 1}, "hidden": {hidden, 0}} {
		calls := 0
		var seen kdf.Params
		_, err := core.Combine(c.pieces, core.OpenOptions{Passwords: [][]byte{[]byte("pw")},
			BeforeDerive: func(p kdf.Params) { calls++; seen = p }})
		if err != nil || calls != c.calls {
			t.Fatalf("%s: told %d times, want %d (%v)", name, calls, c.calls, err)
		}
		if calls == 1 && seen != cheap {
			t.Fatalf("%s: told %+v, want the declared %+v", name, seen, cheap)
		}
	}
}

// TestInfoUsesTheCallbacks checks a single piece asks the same way a set does.
func TestInfoUsesTheCallbacks(t *testing.T) {
	sealed := split(t, []byte("sealed"), core.SplitOptions{N: 2, K: 2, Layers: password("pw"),
		RecordAlgo: true, RecordKDF: true})
	asked := 0
	info, err := core.Info(sealed[0], core.OpenOptions{EnvelopePasswords: func(mixed bool) ([][]byte, error) {
		asked++
		return [][]byte{[]byte("pw")}, nil
	}})
	if err != nil || asked != 1 || info.K != 2 {
		t.Fatalf("asked %d times: %+v, %v", asked, info, err)
	}
	if _, err := core.Info(sealed[0], core.OpenOptions{}); !errors.Is(err, format.ErrWrongPassword) {
		t.Fatalf("no password and no callback: %v", err)
	}
}

// FuzzCraftedKeylessPieces builds two keyless pieces of one set from whatever the
// fuzzer chooses, in both methods and with hidden details, and combines them.
// Nothing an attacker writes into a piece may panic the reader.
func FuzzCraftedKeylessPieces(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4}, []byte{5, 6, 7}, []byte{9, 9, 9}, uint8(2), true, true)
	f.Add([]byte{0}, []byte{0, 0}, []byte{}, uint8(1), false, false)
	f.Fuzz(func(t *testing.T, share, fragment, details []byte, k uint8, compact, hidden bool) {
		if k == 0 || len(share) == 0 {
			return
		}
		setID := make([]byte, format.SetIDLen)
		hash := make([]byte, 32)
		rand.Read(setID)
		if !compact {
			fragment = nil
		} else if len(fragment) == 0 {
			fragment = []byte{1}
		}
		if !hidden {
			details = nil
		} else if len(details) == 0 {
			details = []byte{1}
		}
		var pieces [][]byte
		for serial := 1; serial <= 2; serial++ {
			p, err := format.Encode(format.EncodeInput{
				Details: format.Details{
					K: int(min(k, 2)),
					N: 2,
				},
				SetID:        setID,
				Serial:       serial,
				Keyless:      true,
				PayloadHash:  hash,
				Share:        share,
				Fragment:     fragment,
				DetailsShare: details,
			})
			if err != nil {
				return
			}
			pieces = append(pieces, p)
		}
		_, _ = core.Combine(pieces, core.OpenOptions{})
		_, _ = core.Info(pieces[0], core.OpenOptions{})
	})
}

// openAll opens every piece with Open, failing the test on any error.
func openAll(t *testing.T, pieces [][]byte, opts core.OpenOptions) []*core.Piece {
	t.Helper()
	out := make([]*core.Piece, len(pieces))
	for i, p := range pieces {
		var err error
		if out[i], err = core.Open(p, opts); err != nil {
			t.Fatalf("piece %d: %v", i+1, err)
		}
	}
	return out
}

// TestCombineOpenedDerivesNothing checks pieces opened once rebuild without any
// key being derived again, for every method and info mode, and that they are
// spent: the same pieces do not rebuild a second time.
func TestCombineOpenedDerivesNothing(t *testing.T) {
	input := []byte("opened once, rebuilt once")
	for _, method := range []core.Method{core.MethodFull, core.MethodCompact} {
		for _, info := range []core.InfoMode{core.InfoProtected, core.InfoPublic, core.InfoHidden} {
			pieces := split(t, input, core.SplitOptions{N: 3, K: 2, Method: method, Info: info,
				Layers: password("pw"), RecordAlgo: true, RecordKDF: true})
			opts := core.OpenOptions{Passwords: [][]byte{[]byte("pw")}}
			opened := openAll(t, pieces[1:], opts)
			derived := 0
			opts.BeforeDerive = func(kdf.Params) { derived++ }
			got, _, err := core.CombineOpened(opened, opts)
			if err != nil || !bytes.Equal(got, input) {
				t.Fatalf("%v/%v: %q, %v", method, info, got, err)
			}
			if derived != 0 {
				t.Fatalf("%v/%v: an envelope key was derived again", method, info)
			}
			if opened[0].Info.SetID == "" {
				t.Fatalf("%v/%v: the description did not survive the rebuild", method, info)
			}
			if _, _, err := core.CombineOpened(opened, opts); err == nil {
				t.Fatalf("%v/%v: spent pieces rebuilt again", method, info)
			}
		}
	}
}

// TestCombineOpenedAsksForTheEnvelopePassword checks a password set opened
// through the envelope callback gets the same callback asked again for its
// layers, rather than needing the passwords given twice.
func TestCombineOpenedAsksForTheEnvelopePassword(t *testing.T) {
	input := []byte("one answer")
	pieces := split(t, input, core.SplitOptions{N: 2, K: 2, Layers: password("pw"), RecordAlgo: true, RecordKDF: true})
	asked := 0
	opts := core.OpenOptions{EnvelopePasswords: func(bool) ([][]byte, error) {
		asked++
		return [][]byte{[]byte("pw")}, nil
	}}
	opened := openAll(t, pieces, opts)
	got, _, err := core.CombineOpened(opened, opts)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("%q, %v", got, err)
	}
	if asked != 3 {
		t.Fatalf("the callback was asked %d times, once per open and once for the rebuild", asked)
	}
	// Without a callback the rebuild says how many passwords it needs.
	opened = openAll(t, pieces, core.OpenOptions{Passwords: [][]byte{[]byte("pw")}})
	if _, _, err := core.CombineOpened(opened, core.OpenOptions{}); err == nil ||
		!strings.Contains(err.Error(), "needs 1 password") {
		t.Fatalf("no password for the rebuild: %v", err)
	}
}

// TestCombineOpenedRefusesTwoSets checks pieces of different sets, each opened on
// its own, are not rebuilt together.
func TestCombineOpenedRefusesTwoSets(t *testing.T) {
	a := split(t, []byte("set a"), core.SplitOptions{N: 2, K: 2, Keyless: true})
	b := split(t, []byte("set b"), core.SplitOptions{N: 2, K: 2, Keyless: true})
	opened := openAll(t, [][]byte{a[0], b[1]}, core.OpenOptions{})
	if _, _, err := core.CombineOpened(opened, core.OpenOptions{}); err == nil ||
		!strings.Contains(err.Error(), "different set") {
		t.Fatalf("two sets combined: %v", err)
	}
	if _, _, err := core.CombineOpened(nil, core.OpenOptions{}); err == nil {
		t.Fatal("no pieces combined")
	}
}

// TestPasswordPieceAmongKeylessOnesWithAPassword checks the path a keyless set
// takes when a password is given anyway: the pieces open with the public key, and
// a piece sealed with the password among them still opens, to be refused as not
// belonging, rather than being skipped as damaged.
func TestPasswordPieceAmongKeylessOnesWithAPassword(t *testing.T) {
	pieces := split(t, []byte("keyless set"), core.SplitOptions{N: 3, K: 2, Keyless: true})
	m, _, err := format.Decode(pieces[2], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	details := m.Details
	details.Params = cheap // the cost the password is stretched with; not recorded
	crafted, err := format.Encode(format.EncodeInput{
		Details: details, SetID: m.SetID, Serial: m.Serial, PayloadHash: m.PayloadHash, Share: m.Share,
		Passwords: [][]byte{[]byte("pw")},
	})
	if err != nil {
		t.Fatal(err)
	}
	m.Wipe()
	opts := core.OpenOptions{Passwords: [][]byte{[]byte("pw")}, Params: &cheap}
	if _, err := core.Combine([][]byte{pieces[0], pieces[1], crafted}, opts); err == nil ||
		!strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("a password piece among keyless ones: %v", err)
	}
}

// TestRewrittenCostIsInconsistent checks a piece of a public password set that
// was sealed again recording a different cost is refused, rather than its cost
// or the first piece's being taken on trust.
func TestRewrittenCostIsInconsistent(t *testing.T) {
	pieces := split(t, []byte("one cost per set"), core.SplitOptions{N: 3, K: 2, Info: core.InfoPublic,
		Layers: password("pw"), RecordAlgo: true, RecordKDF: true})
	other := kdf.Params{Memory: 16 * 1024, Time: 1, Par: 1}
	forged := reseal(t, pieces[1], func(m *format.Manifest) { m.Params = other })
	_, err := core.Combine([][]byte{pieces[0], forged}, core.OpenOptions{Passwords: [][]byte{[]byte("pw")}})
	if err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("a piece recording another cost: %v", err)
	}
}

// TestCombineAsksForThePasswordsTheEnvelopeDidNotTake checks a protected set,
// opened with the first password alone as the envelope question allows, then
// asks for every password rather than failing on the count, as CombineOpened
// does. Passwords given up front are the caller's whole answer, and a short
// count is refused.
func TestCombineAsksForThePasswordsTheEnvelopeDidNotTake(t *testing.T) {
	pieces := split(t, []byte("two passwords"), core.SplitOptions{N: 3, K: 2, RecordAlgo: true, RecordKDF: true,
		Layers: []core.LayerSpec{
			{Kind: core.PasswordLayer, Password: []byte("outermost")},
			{Kind: core.PasswordLayer, Password: []byte("innermost")},
		}})
	asked := 0
	got, err := core.Combine(pieces[:2], core.OpenOptions{
		EnvelopePasswords: func(bool) ([][]byte, error) { return [][]byte{[]byte("outermost")}, nil },
		AskPasswords: func(n int) ([][]byte, error) {
			asked = n
			return [][]byte{[]byte("outermost"), []byte("innermost")}, nil
		}})
	if err != nil || string(got) != "two passwords" || asked != 2 {
		t.Fatalf("%q, %v, asked for %d", got, err, asked)
	}
	if _, err := core.Combine(pieces[:2], core.OpenOptions{Passwords: [][]byte{[]byte("outermost")}}); err == nil {
		t.Fatal("one password given for a set of two was accepted")
	}
}

// TestADamagedPieceDoesNotAskForTheCost checks a piece that fails once others
// have opened is set aside as damaged, without asking for an Argon2 cost: an
// answer there could only replace the cost the open pieces recorded.
func TestADamagedPieceDoesNotAskForTheCost(t *testing.T) {
	pieces := split(t, []byte("public details"), core.SplitOptions{N: 3, K: 2, Info: core.InfoPublic,
		RecordAlgo: true, RecordKDF: true, Layers: password("password")})
	pieces[2] = bytes.Clone(pieces[2])
	pieces[2][len(pieces[2])-1] ^= 1
	damaged := 0
	got, err := core.Combine(pieces, core.OpenOptions{Passwords: [][]byte{[]byte("password")},
		AskParams: func(bool) (*kdf.Params, error) {
			t.Error("asked for the cost of a damaged piece")
			return nil, nil
		},
		Damaged: func(int, error) { damaged++ }})
	if err != nil || string(got) != "public details" || damaged != 1 {
		t.Fatalf("%q, %v, %d damaged", got, err, damaged)
	}
}
