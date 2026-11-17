// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// writeSet splits input and writes the pieces in the given format, returning the
// paths in order.
func writeSet(t *testing.T, dir string, opts core.SplitOptions, input []byte, f pieceio.Format) []string {
	t.Helper()
	pieces := makePieces(t, opts, input)
	var paths []string
	for i, p := range pieces {
		data, err := pieceio.Encode(p, f, 4)
		if err != nil {
			t.Fatal(err)
		}
		path := pieceio.Path(dir, "s."+string(rune('0'+i+1)), f)
		if err := pieceio.Write(path, data); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

func verifyOpts(t *testing.T, paths []string, extra ...string) *cliOptions {
	t.Helper()
	args := append(append([]string{"verify"}, paths...), extra...)
	opts, err := parseArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	opts.yes = true
	return opts
}

// TestVerifyPassesForACompleteSet is the question the command answers: will
// these pieces rebuild the file?
func TestVerifyPassesForACompleteSet(t *testing.T) {
	t.Setenv("RIVEN_UNIT_VER", "verify password")
	dir := t.TempDir()
	paths := writeSet(t, dir, core.SplitOptions{N: 3, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("verify password")}}},
		[]byte("verify me"), pieceio.Binary)

	opts := verifyOpts(t, paths[:2], "--password-env", "RIVEN_UNIT_VER")
	if err := cmdVerify(opts); err != nil {
		t.Fatalf("a complete set should verify: %v", err)
	}
}

// TestVerifyAsksForThePasswordOnce checks an interactive verify of a password set
// asks for the password once: the answer that opened the pieces also rebuilds
// them, rather than the rebuild asking for it again.
func TestVerifyAsksForThePasswordOnce(t *testing.T) {
	dir := t.TempDir()
	paths := writeSet(t, dir, core.SplitOptions{N: 3, K: 2, Params: fastKDF,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("asked once")}}},
		[]byte("verify me"), pieceio.Binary)

	opts := verifyOpts(t, paths[:2])
	opts.yes = false
	var err error
	out := withTerminal(t, "asked once\n\n", func() { err = cmdVerify(opts) })
	if err != nil || strings.Contains(out, "This set needs") || !strings.Contains(out, "OK: these pieces rebuild") {
		t.Fatalf("the password was not enough once: %v\n%s", err, out)
	}
}

// TestVerifyReportsAShortSet checks the useful case: not a failure of the
// pieces, but a count of what is missing.
func TestVerifyReportsAShortSet(t *testing.T) {
	t.Setenv("RIVEN_UNIT_VER", "verify password")
	dir := t.TempDir()
	paths := writeSet(t, dir, core.SplitOptions{N: 5, K: 3,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("verify password")}}},
		[]byte("not enough"), pieceio.Binary)

	opts := verifyOpts(t, paths[:1], "--password-env", "RIVEN_UNIT_VER")
	err := cmdVerify(opts)
	if err == nil {
		t.Fatal("one piece of a 3-of-5 set must not verify")
	}

	// Standard error carries the detail, so check the message a user sees.
	out := captureStderr(t, func() {
		_ = cmdVerify(verifyOpts(t, paths[:1], "--password-env", "RIVEN_UNIT_VER"))
	})
	if !strings.Contains(out, "NOT ENOUGH") || !strings.Contains(out, "2 more piece") {
		t.Fatalf("the report should say how many more are needed:\n%s", out)
	}
}

// TestVerifyDetectsDamage checks a corrupted piece is named, rather than the set
// silently coming up short.
func TestVerifyDetectsDamage(t *testing.T) {
	t.Setenv("RIVEN_UNIT_VER", "verify password")
	dir := t.TempDir()
	paths := writeSet(t, dir, core.SplitOptions{N: 3, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("verify password")}}},
		[]byte("damage me"), pieceio.Binary)

	body, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0xFF
	if err := os.WriteFile(paths[0], body, 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStderr(t, func() {
		if err := cmdVerify(verifyOpts(t, paths, "--password-env", "RIVEN_UNIT_VER")); err == nil {
			t.Error("a damaged piece must fail verification")
		}
	})
	if !strings.Contains(out, "FAILED") {
		t.Fatalf("the damaged piece should be named:\n%s", out)
	}
}

// TestVerifyReadsEveryTransport checks the command accepts the same forms as
// combine, including a saved recovery sheet.
func TestVerifyReadsEveryTransport(t *testing.T) {
	t.Setenv("RIVEN_UNIT_VER", "verify password")
	input := []byte("every transport verifies")
	opts := core.SplitOptions{N: 2, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("verify password")}}}
	pieces := makePieces(t, opts, input)

	for _, f := range pieceio.All() {
		t.Run(string(f), func(t *testing.T) {
			dir := t.TempDir()
			var paths []string
			for i, p := range pieces {
				var data []byte
				var err error
				if f == pieceio.Sheet {
					data, err = pieceio.EncodeSheet(p,
						pieceio.SheetInfo{Serial: i + 1, Total: 2, Needed: 2, Name: "s"}, 4)
				} else {
					data, err = pieceio.Encode(p, f, 4)
				}
				if err != nil {
					t.Fatal(err)
				}
				path := pieceio.Path(dir, "s."+string(rune('1'+i)), f)
				if err := pieceio.Write(path, data); err != nil {
					t.Fatal(err)
				}
				paths = append(paths, path)
			}
			if err := cmdVerify(verifyOpts(t, paths, "--password-env", "RIVEN_UNIT_VER")); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		})
	}
}

// TestVerifyKeylessNeedsNoPassword checks a split-only set verifies with nothing
// supplied, as it opens with nothing supplied.
func TestVerifyKeylessNeedsNoPassword(t *testing.T) {
	dir := t.TempDir()
	paths := writeSet(t, dir, core.SplitOptions{N: 3, K: 2, Keyless: true},
		[]byte("no password here"), pieceio.Binary)
	if err := cmdVerify(verifyOpts(t, paths[:2])); err != nil {
		t.Fatalf("a keyless set should verify with no password: %v", err)
	}
}

// TestVerifyRejectsBadInput covers the ways the command is misused.
func TestVerifyRejectsBadInput(t *testing.T) {
	if err := cmdVerify(&cliOptions{yes: true}); err == nil {
		t.Fatal("verify with no files must fail")
	}
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.bin")
	if err := os.WriteFile(junk, []byte("not a piece at all, just some text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdVerify(verifyOpts(t, []string{junk})); err == nil {
		t.Fatal("a file that is not a piece must fail")
	}
	// Split-only flags do not belong here.
	opts := verifyOpts(t, []string{junk})
	opts.keyless = true
	if err := cmdVerify(opts); err == nil {
		t.Fatal("--keyless must be refused when opening pieces")
	}
}

// TestResolveFormatAnswer covers the export answer in every shape the prompt
// accepts: names, numbers, a mix, and "all".
func TestResolveFormatAnswer(t *testing.T) {
	all := pieceio.All()
	cases := map[string][]pieceio.Format{
		"1":                {pieceio.Binary},
		"2,3":              {pieceio.Base64, pieceio.Base32},
		"base64":           {pieceio.Base64},
		"base64,3,qr":      {pieceio.Base64, pieceio.Base32, pieceio.QR},
		"all":              all,
		"ALL":              all,
		" b32 , 1 ":        {pieceio.Base32, pieceio.Binary},
		"qr,qr":            {pieceio.QR},
		"sheet":            {pieceio.Sheet},
		"1,2,3,4,5,6":      all,
		"words":            {pieceio.Words},
		"bip39,1":          {pieceio.Words, pieceio.Binary},
		"paper,png,b64":    {pieceio.Sheet, pieceio.QR, pieceio.Base64},
		"binary base64 qr": {pieceio.Binary, pieceio.Base64, pieceio.QR},
	}
	for answer, want := range cases {
		got, err := resolveFormatAnswer(answer, all)
		if err != nil {
			t.Fatalf("%q: %v", answer, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%q gave %v, want %v", answer, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%q gave %v, want %v", answer, got, want)
			}
		}
	}

	for _, bad := range []string{"", "0", "9", "pdf", "2,pdf", "-1"} {
		if _, err := resolveFormatAnswer(bad, all); err == nil {
			t.Fatalf("%q should be refused", bad)
		}
	}
}

// TestVerifySaysWhatItCouldNotCheck covers two things a check reports beyond
// pass or fail: a piece in a text form carrying no checksum, as one typed in by
// hand may be, which says a mistyped character would surface only as a failed
// open; and a set sealed to a recipient key, which verifies as far as the
// pieces agreeing when the key is not given.
func TestVerifySaysWhatItCouldNotCheck(t *testing.T) {
	dir := t.TempDir()
	pieces := makePieces(t, core.SplitOptions{N: 2, K: 2, Keyless: true}, []byte("unchecked"))
	var paths []string
	for i, p := range pieces {
		path := filepath.Join(dir, fmt.Sprintf("plain.%d.txt", i+1))
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(p)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	var err error
	out := captureStderr(t, func() { err = cmdVerify(verifyOpts(t, paths)) })
	if err != nil || !strings.Contains(out, "no checksum in this format") {
		t.Fatalf("%v:\n%s", err, out)
	}

	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	paths = writeSet(t, t.TempDir(), core.SplitOptions{N: 2, K: 2, Info: core.InfoPublic,
		Layers: []core.LayerSpec{{Kind: core.RecipientLayer, Recipient: priv.Public()}}}, []byte("sealed"), pieceio.Binary)
	out = captureStderr(t, func() { err = cmdVerify(verifyOpts(t, paths)) })
	if err != nil || !strings.Contains(out, "rebuilding needs a recipient private key") {
		t.Fatalf("%v:\n%s", err, out)
	}
}
