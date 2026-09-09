// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

var fastKDF = kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}

// makePieces produces a small set for the open-side helpers to work on.
func makePieces(t *testing.T, opts core.SplitOptions, input []byte) [][]byte {
	t.Helper()
	opts.Params = fastKDF
	opts.RecordAlgo = true
	opts.RecordKDF = true
	pieces, err := core.Split(input, opts)
	if err != nil {
		t.Fatal(err)
	}
	return pieces
}

// TestLooksKeylessTellsTheModes checks the probe used to decide whether to ask
// for a password: a keyless set needs none, a password set does.
func TestLooksKeylessTellsTheModes(t *testing.T) {
	keyless := makePieces(t, core.SplitOptions{N: 3, K: 2, Keyless: true}, []byte("open"))
	if !looksKeyless(keyless) {
		t.Fatal("a keyless set should be recognised")
	}
	sealed := makePieces(t, core.SplitOptions{N: 3, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("pw")}}}, []byte("open"))
	if looksKeyless(sealed) {
		t.Fatal("a password set must not look keyless")
	}
	if looksKeyless(nil) {
		t.Fatal("no pieces cannot look keyless")
	}
	if looksKeyless([][]byte{[]byte("not a piece")}) {
		t.Fatal("junk must not look keyless")
	}
}

// TestGatherOpenPasswords covers where passwords come from when opening: the
// environment in automation, nothing at all for a keyless set, and a clear
// refusal when automation has no source.
func TestGatherOpenPasswords(t *testing.T) {
	t.Setenv("RIVEN_UNIT_OPEN1", "one")
	t.Setenv("RIVEN_UNIT_OPEN2", "two")
	sealed := makePieces(t, core.SplitOptions{N: 2, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("one")}}}, []byte("open"))

	opts, err := parseArgs([]string{"combine", "a",
		"--password-env", "RIVEN_UNIT_OPEN1", "--password-env", "RIVEN_UNIT_OPEN2"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := gatherOpenPasswords(opts, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got[0]) != "one" || string(got[1]) != "two" {
		t.Fatalf("passwords are %q, want them in flag order", got)
	}

	keyless := makePieces(t, core.SplitOptions{N: 3, K: 2, Keyless: true}, []byte("open"))
	pws, err := gatherOpenPasswords(&cliOptions{yes: true}, keyless)
	if err != nil {
		t.Fatalf("a keyless set should need no password: %v", err)
	}
	if len(pws) != 0 {
		t.Fatal("a keyless set should return no passwords")
	}

	if _, err := gatherOpenPasswords(&cliOptions{yes: true}, sealed); err == nil {
		t.Fatal("automation with no password source must fail")
	}

	missing, err := parseArgs([]string{"combine", "a", "--password-env", "RIVEN_UNIT_NOT_SET"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gatherOpenPasswords(missing, sealed); err == nil {
		t.Fatal("an unset environment variable must fail")
	}
}

func TestResolveOpenKeys(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, s := range []kem.Scheme{kem.X25519, kem.MLKEM768} {
		priv, err := kem.Generate(s)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, s.Name()+".key")
		if err := writePrivateKey(p, priv); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	keys, err := resolveOpenKeys(&cliOptions{identities: paths})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].Scheme() != kem.X25519 || keys[1].Scheme() != kem.MLKEM768 {
		t.Fatalf("keys resolved to %v", keys)
	}
	if _, err := resolveOpenKeys(&cliOptions{identities: []string{filepath.Join(dir, "absent")}}); err == nil {
		t.Fatal("a missing key file must fail")
	}
}

func TestLayerCountReadsTheSet(t *testing.T) {
	pieces := makePieces(t, core.SplitOptions{N: 3, K: 2, Layers: []core.LayerSpec{
		{Kind: core.PasswordLayer, Password: []byte("a")},
		{Kind: core.PasswordLayer, Password: []byte("b")},
	}}, []byte("layers"))
	open := core.OpenOptions{Passwords: [][]byte{[]byte("a"), []byte("b")}}
	n, err := layerCount(pieces, open)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("layer count is %d, want 2", n)
	}
	if _, err := layerCount(pieces, core.OpenOptions{Passwords: [][]byte{[]byte("wrong")}}); err == nil {
		t.Fatal("a wrong password must not yield a layer count")
	}
}

// TestCombineWithRecoveryNeedsTheHiddenAlgorithms checks that a set which did
// not record its algorithms fails in automation with the error naming that
// cause, and succeeds once the algorithms are supplied.
func TestCombineWithRecoveryNeedsTheHiddenAlgorithms(t *testing.T) {
	ids := ciphers.Cascade(2)
	pws := [][]byte{[]byte("a"), []byte("b")}
	pieces, err := core.Split([]byte("hidden algorithms"), core.SplitOptions{
		N: 3, K: 2, Params: fastKDF, RecordAlgo: false, RecordKDF: true,
		Layers: []core.LayerSpec{
			{Kind: core.PasswordLayer, SchemeID: ids[0], Password: pws[0]},
			{Kind: core.PasswordLayer, SchemeID: ids[1], Password: pws[1]},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	open := core.OpenOptions{Passwords: pws}
	if _, _, err := combineWithRecovery(&cliOptions{yes: true}, pieces[:2], open); err == nil {
		t.Fatal("automation cannot guess the algorithms")
	}

	open.Schemes = ids
	got, _, err := combineWithRecovery(&cliOptions{yes: true}, pieces[:2], open)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hidden algorithms" {
		t.Fatalf("got %q", got)
	}
}

// TestWriteRecovered covers both destinations: a file, and standard output with
// nothing else mixed into it.
func TestWriteRecovered(t *testing.T) {
	dir := t.TempDir()
	data := []byte("recovered bytes")

	path := filepath.Join(dir, "out.bin")
	if err := writeRecovered(&cliOptions{outDir: path, yes: true}, data, ""); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("file holds %q", got)
	}

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	err = writeRecovered(&cliOptions{yes: true}, data, "")
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if !bytes.Equal(buf.Bytes(), data) {
		t.Fatalf("standard output carried %q, want exactly the data", buf.Bytes())
	}
}

// TestPrintPieceInfoStatesWhatOnePieceReveals is the single-piece requirement:
// serial, total, threshold, set identity and integrity, and nothing about the
// content itself.
func TestPrintPieceInfoStatesWhatOnePieceReveals(t *testing.T) {
	secret := []byte("the quick brown fox jumps over the lazy dog")
	pieces := makePieces(t, core.SplitOptions{N: 5, K: 3,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("pw")}}}, secret)
	info, err := core.Info(pieces[2], core.OpenOptions{Passwords: [][]byte{[]byte("pw")}})
	if err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	printPieceInfo("piece.3", pieceio.Detected{Format: pieceio.Binary}, info)
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	for _, want := range []string{"3 of 5", "need any 3", "intact", "set id", "chacha20-poly1305"} {
		if !strings.Contains(out, want) {
			t.Fatalf("info is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "quick brown fox") {
		t.Fatalf("info leaked the content:\n%s", out)
	}
}
