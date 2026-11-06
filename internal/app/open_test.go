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

// TestKeylessSetOpensWithoutAQuestion checks the open side tells the modes apart
// by opening: a keyless set rebuilds with nothing asked and nothing given, and a
// password set run without a terminal fails naming the flag.
func TestKeylessSetOpensWithoutAQuestion(t *testing.T) {
	keyless := makePieces(t, core.SplitOptions{N: 3, K: 2, Keyless: true}, []byte("open"))
	got, _, err := combinePieces(&cliOptions{yes: true}, keyless, nil)
	if err != nil || string(got) != "open" {
		t.Fatalf("a keyless set: %q, %v", got, err)
	}
	sealed := makePieces(t, core.SplitOptions{N: 3, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("pw")}}}, []byte("open"))
	if _, _, err := combinePieces(&cliOptions{yes: true}, sealed, nil); err == nil ||
		!strings.Contains(err.Error(), "--password-env") {
		t.Fatalf("a password set without a password: %v", err)
	}
	if _, _, err := combinePieces(&cliOptions{yes: true}, [][]byte{[]byte("not a piece")}, nil); err == nil {
		t.Fatal("junk was combined")
	}
}

// TestGatherOpenPasswords covers where passwords come from up front: the
// environment, in flag order, or nothing, leaving the question to the open.
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
	got, err := gatherOpenPasswords(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got[0]) != "one" || string(got[1]) != "two" {
		t.Fatalf("passwords are %q, want them in flag order", got)
	}
	if got, _, err := combinePieces(opts, sealed, nil); err == nil {
		t.Fatalf("two passwords for a one-layer set rebuilt %q", got)
	}

	pws, err := gatherOpenPasswords(&cliOptions{yes: true})
	if err != nil || len(pws) != 0 {
		t.Fatalf("no flag should give no password and no error: %q, %v", pws, err)
	}

	missing, err := parseArgs([]string{"combine", "a", "--password-env", "RIVEN_UNIT_NOT_SET"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gatherOpenPasswords(missing); err == nil {
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

// TestCombineNeedsTheHiddenAlgorithms checks that a set which did not record its
// algorithms fails in automation with the error naming the flag and the layer
// count, and succeeds once the algorithms are supplied.
func TestCombineNeedsTheHiddenAlgorithms(t *testing.T) {
	t.Setenv("RIVEN_UNIT_HA1", "a")
	t.Setenv("RIVEN_UNIT_HA2", "b")
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

	args := []string{"combine", "p", "--password-env", "RIVEN_UNIT_HA1", "--password-env", "RIVEN_UNIT_HA2", "-y"}
	opts, err := parseArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := combinePieces(opts, pieces[:2], nil); err == nil ||
		!strings.Contains(err.Error(), "--algo") || !strings.Contains(err.Error(), "2 needed") {
		t.Fatalf("automation cannot guess the algorithms: %v", err)
	}

	opts, err = parseArgs(append(args, "--algo", ciphers.Name(ids[0])+","+ciphers.Name(ids[1])))
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := combinePieces(opts, pieces[:2], nil)
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

	for _, want := range []string{"3 of 5", "need any 3", "intact", "set id", ciphers.Default().Name} {
		if !strings.Contains(out, want) {
			t.Fatalf("info is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "quick brown fox") {
		t.Fatalf("info leaked the content:\n%s", out)
	}
}
