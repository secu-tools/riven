// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/format"
)

// TestSafeNameRejectsAnythingButAName is the security test for the field: the
// name comes out of a piece, so it is attacker-controlled, and it is turned into
// a path.
func TestSafeNameRejectsAnythingButAName(t *testing.T) {
	keep := map[string]string{
		"secret.pdf":          "secret.pdf",
		"a b c.tar.gz":        "a b c.tar.gz",
		".bashrc":             ".bashrc",
		"UPPER.TXT":           "UPPER.TXT",
		"wallet-2026.kdbx":    "wallet-2026.kdbx",
		"/etc/passwd":         "passwd",
		`C:\Windows\me.txt`:   "me.txt",
		"../../../etc/shadow": "shadow",
		`..\..\evil.exe`:      "evil.exe",
		"c:relative.txt":      "relative.txt",
		// Windows drops trailing dots and spaces when it creates a file, so they
		// are dropped here instead, and the name means the same everywhere.
		"trailing.  ": "trailing",
	}
	for in, want := range keep {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}

	refuse := []string{
		"", ".", "..", "...", "/", `\`, "/////", "..//..//",
		"con", "CON", "nul.txt", "com1", "LPT9.log", "aux",
		"bad\x00name", "bell\x07", "line\nbreak", "tab\there",
		`quote"name`, "pipe|name", "star*", "question?", "less<", "greater>",
		"   ", "...   ",
		strings.Repeat("a", format.MaxNameLen+1),
	}
	for _, in := range refuse {
		if got := SafeName(in); got != "" {
			t.Errorf("SafeName(%q) = %q, want it refused", in, got)
		}
	}
}

// TestNameSurvivesASplit checks the name reaches the far side, and only through
// the encrypted manifest.
func TestNameSurvivesASplit(t *testing.T) {
	input := []byte("named content")
	opts := SplitOptions{N: 3, K: 2, Params: testParams, RecordAlgo: true, RecordKDF: true,
		Name:   "quarterly.pdf",
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("name test")}}}
	pieces := mustSplit(t, input, opts)

	open := OpenOptions{Passwords: [][]byte{[]byte("name test")}}
	got, name, err := CombineFile(pieces[:2], open)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("recovered %q", got)
	}
	if name != "quarterly.pdf" {
		t.Fatalf("name came back as %q", name)
	}

	info, err := Info(pieces[0], open)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "quarterly.pdf" {
		t.Fatalf("info reports %q", info.Name)
	}

	// The name must not be readable without opening the piece.
	for i, p := range pieces {
		if bytes.Contains(p, []byte("quarterly")) {
			t.Fatalf("piece %d carries the name in the clear", i+1)
		}
	}
}

// TestNoNameRecorded checks the field is genuinely optional, and that a split
// without it still opens.
func TestNoNameRecorded(t *testing.T) {
	opts := SplitOptions{N: 2, K: 2, Params: testParams, RecordAlgo: true, RecordKDF: true,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("no name")}}}
	pieces := mustSplit(t, []byte("anonymous"), opts)
	_, name, err := CombineFile(pieces, OpenOptions{Passwords: [][]byte{[]byte("no name")}})
	if err != nil {
		t.Fatal(err)
	}
	if name != "" {
		t.Fatalf("no name was recorded, but got %q", name)
	}
}

// TestRecordedNameIsSanitisedOnTheWayOut checks a piece written with a hostile
// name cannot steer where the recovered file lands. Encoding is deliberately
// permissive; the reader is where it is made safe.
func TestRecordedNameIsSanitisedOnTheWayOut(t *testing.T) {
	opts := SplitOptions{N: 2, K: 2, Params: testParams, RecordAlgo: true, RecordKDF: true,
		Name:   "../../../etc/cron.d/payload",
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("hostile")}}}
	pieces := mustSplit(t, []byte("x"), opts)

	_, name, err := CombineFile(pieces, OpenOptions{Passwords: [][]byte{[]byte("hostile")}})
	if err != nil {
		t.Fatal(err)
	}
	if name != "payload" {
		t.Fatalf("the path was not reduced to a name: %q", name)
	}
}

// TestNameDoesNotChangeTheSetSize checks every piece is still one size, which is
// what padding depends on.
func TestNameDoesNotChangeTheSetSize(t *testing.T) {
	for _, name := range []string{"", "a", strings.Repeat("n", 200)} {
		opts := SplitOptions{N: 4, K: 2, Params: testParams, RecordAlgo: true, RecordKDF: true,
			Name:   name,
			Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("sizes")}}}
		pieces := mustSplit(t, []byte("same size please"), opts)
		for i, p := range pieces {
			if len(p) != len(pieces[0]) {
				t.Fatalf("name %q: piece %d is %d bytes, piece 1 is %d",
					name, i+1, len(p), len(pieces[0]))
			}
		}
	}
}

// TestNameTooLongIsRefused checks the cap is enforced where it is written rather
// than silently truncated.
func TestNameTooLongIsRefused(t *testing.T) {
	opts := SplitOptions{N: 2, K: 2, Params: testParams, RecordAlgo: true, RecordKDF: true,
		Name:   strings.Repeat("x", format.MaxNameLen+1),
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("long")}}}
	if _, err := Split([]byte("x"), opts); err == nil {
		t.Fatal("a name past the limit must be refused")
	}
}
