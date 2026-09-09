// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// transportFormats are the export formats the binary offers.
var transportFormats = []string{"binary", "base64", "base32", "qr", "sheet"}

// pieceFiles is the file each format produces for piece n of a three-piece set.
func pieceFile(dir, base, formatName string, n int) string {
	switch formatName {
	case "base64":
		return filepath.Join(dir, base+"."+strconv.Itoa(n)+".txt")
	case "base32":
		return filepath.Join(dir, base+"."+strconv.Itoa(n)+".b32.txt")
	case "qr":
		return filepath.Join(dir, base+"."+strconv.Itoa(n)+".png")
	case "sheet":
		return filepath.Join(dir, base+"."+strconv.Itoa(n)+".html")
	default:
		return filepath.Join(dir, base+"."+strconv.Itoa(n))
	}
}

// TestEveryTransportRoundTripsThroughTheBinary is the guarantee for each stored
// form: written by the tool, read back by the tool, byte for byte.
func TestEveryTransportRoundTripsThroughTheBinary(t *testing.T) {
	data := make([]byte, 300)
	rand.Read(data)

	for _, f := range transportFormats {
		t.Run(f, func(t *testing.T) {
			dir := t.TempDir()
			in := writeFile(t, dir, "s.bin", data)
			out := filepath.Join(dir, "o")

			if o, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
				"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1",
				"--format", f, "--out", out, "-y"); err != nil {
				t.Fatalf("split: %v\n%s", err, o)
			}

			p1 := pieceFile(out, "s.bin", f, 1)
			p3 := pieceFile(out, "s.bin", f, 3)
			for _, p := range []string{p1, p3} {
				if _, err := os.Stat(p); err != nil {
					t.Fatalf("expected %s: %v", p, err)
				}
			}

			got, _, err := rivenRaw(t, env1, "combine", p1, p3,
				"--password-env", flagPw1, "-y")
			if err != nil {
				t.Fatalf("combine: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("%s: content changed", f)
			}
		})
	}
}

// TestMixedTransportsInOneCommand checks the formats are detected from content,
// so a set can be reassembled from whatever survived.
func TestMixedTransportsInOneCommand(t *testing.T) {
	dir := t.TempDir()
	data := []byte("one piece from each form")
	in := writeFile(t, dir, "m.bin", data)
	out := filepath.Join(dir, "o")

	if o, err := riven(t, env1, "split", in, "-n", "5", "-k", "5",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1",
		"--format", "all", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}

	// One piece from each of the five forms, all of the same set.
	args := []string{"combine"}
	for i, f := range transportFormats {
		args = append(args, pieceFile(out, "m.bin", f, i+1))
	}
	args = append(args, "--password-env", flagPw1, "-y")

	got, _, err := rivenRaw(t, env1, args...)
	if err != nil {
		t.Fatalf("mixed combine: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content changed")
	}
}

// TestBase32TypedByHand checks the shape a person produces when copying: lower
// case, hyphens between groups, and everything on one line.
func TestBase32TypedByHand(t *testing.T) {
	dir := t.TempDir()
	data := []byte("copied by hand")
	in := writeFile(t, dir, "h.bin", data)
	out := filepath.Join(dir, "o")

	if o, err := riven(t, env1, "split", in, "-n", "2", "-k", "2",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1",
		"--format", "base32", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}

	var retyped []string
	for i := 1; i <= 2; i++ {
		src := pieceFile(out, "h.bin", "base32", i)
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(string(body)), " ", "-"))
		text = strings.ReplaceAll(text, "\n", "-")
		p := filepath.Join(dir, "typed"+strconv.Itoa(i)+".txt")
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		retyped = append(retyped, p)
	}

	got, _, err := rivenRaw(t, env1, "combine", retyped[0], retyped[1],
		"--password-env", flagPw1, "-y")
	if err != nil {
		t.Fatalf("combine of retyped text: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content changed")
	}
}

// TestTypoInTextIsReported checks the checksum earns its four bytes: a single
// wrong character produces a message about the text, not about the password.
func TestTypoInTextIsReported(t *testing.T) {
	for _, f := range []string{"base64", "base32"} {
		t.Run(f, func(t *testing.T) {
			dir := t.TempDir()
			in := writeFile(t, dir, "t.bin", []byte("typo detection"))
			out := filepath.Join(dir, "o")
			if o, err := riven(t, env1, "split", in, "-n", "2", "-k", "2",
				"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1",
				"--format", f, "--out", out, "-y"); err != nil {
				t.Fatalf("split: %v\n%s", err, o)
			}

			path := pieceFile(out, "t.bin", f, 1)
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for i, c := range body {
				if c == 'A' {
					body[i] = 'B'
					break
				} else if c == 'B' {
					body[i] = 'A'
					break
				}
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}

			o, err := riven(t, env1, "combine", path, pieceFile(out, "t.bin", f, 2),
				"--password-env", flagPw1, "--out", filepath.Join(dir, "no"), "-y")
			if err == nil {
				t.Fatal("a damaged piece must not reconstruct")
			}
			if !strings.Contains(strings.ToLower(o), "checksum") {
				t.Fatalf("the failure should name the checksum:\n%s", o)
			}
		})
	}
}

// TestRecoverySheetIsPrintableAndReadable checks the sheet explains itself and
// still works as an input file.
func TestRecoverySheetIsPrintableAndReadable(t *testing.T) {
	dir := t.TempDir()
	data := []byte("printed on paper")
	in := writeFile(t, dir, "p.bin", data)
	out := filepath.Join(dir, "o")

	if o, err := riven(t, env1, "split", in, "-n", "4", "-k", "2",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1",
		"--format", "sheet", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}

	page, err := os.ReadFile(pieceFile(out, "p.bin", "sheet", 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Recovery piece 1 of 4", "Any 2 of the 4", "riven combine", "p.bin",
	} {
		if !strings.Contains(string(page), want) {
			t.Fatalf("the sheet is missing %q", want)
		}
	}

	got, _, err := rivenRaw(t, env1, "combine",
		pieceFile(out, "p.bin", "sheet", 1), pieceFile(out, "p.bin", "sheet", 3),
		"--password-env", flagPw1, "-y")
	if err != nil {
		t.Fatalf("combine from sheets: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content changed")
	}
}

// TestVerifyCommand covers what the command is for: a complete set passes, a
// short set says how many are missing, and a damaged piece is named.
func TestVerifyCommand(t *testing.T) {
	dir := t.TempDir()
	data := []byte("verify from the command line")
	in := writeFile(t, dir, "v.bin", data)
	out := filepath.Join(dir, "o")
	if o, err := riven(t, env1, "split", in, "-n", "4", "-k", "3",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}
	p := func(n int) string { return pieceFile(out, "v.bin", "binary", n) }

	o, err := riven(t, env1, "verify", p(1), p(2), p(3), "--password-env", flagPw1, "-y")
	if err != nil {
		t.Fatalf("a complete set should verify: %v\n%s", err, o)
	}
	if !strings.Contains(o, "OK:") || !strings.Contains(o, "rebuild") {
		t.Fatalf("the report should confirm the rebuild:\n%s", o)
	}

	o, err = riven(t, env1, "verify", p(1), p(2), "--password-env", flagPw1, "-y")
	if err == nil {
		t.Fatal("two pieces of a 3-of-4 set must not verify")
	}
	if !strings.Contains(o, "NOT ENOUGH") || !strings.Contains(o, "1 more piece") {
		t.Fatalf("the report should say how many more are needed:\n%s", o)
	}

	// Verify must not write anything.
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("verify changed the directory: %d entries", len(entries))
	}

	body, err := os.ReadFile(p(1))
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0xFF
	if err := os.WriteFile(p(1), body, 0o600); err != nil {
		t.Fatal(err)
	}
	o, err = riven(t, env1, "verify", p(1), p(2), p(3), "--password-env", flagPw1, "-y")
	if err == nil {
		t.Fatal("a damaged piece must fail verification")
	}
	if !strings.Contains(o, "FAILED") {
		t.Fatalf("the damaged piece should be named:\n%s", o)
	}
}
