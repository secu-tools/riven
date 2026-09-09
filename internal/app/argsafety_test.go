// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"os"
	"path/filepath"
	"testing"
)

// A shell glob expands to file names, so "riven combine *" in a directory that
// holds a file called "--out" would hand riven a flag the user never typed: the
// recovered data would be written wherever the next word pointed, destroying
// that file, while the pipeline got nothing. The word means two things, so
// neither is assumed.
func TestFlagShadowedByFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	for _, name := range []string{"--out", "-o", "--password-env", "--identity", "-y"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := parseArgs([]string{"combine", "piece.1", name, "value"}); err == nil {
			t.Fatalf("a file named %q was accepted as a flag", name)
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// The same word must still work as a flag when no such file exists, or the
// check would have broken every ordinary invocation.
func TestFlagStillWorksWithoutAShadowingFile(t *testing.T) {
	t.Chdir(t.TempDir())

	o, err := parseArgs([]string{"combine", "piece.1", "--out", "recovered.bin", "-y"})
	if err != nil {
		t.Fatalf("ordinary flags rejected: %v", err)
	}
	if o.outDir != "recovered.bin" {
		t.Fatalf("--out = %q, want %q", o.outDir, "recovered.bin")
	}
	if !o.yes {
		t.Fatal("-y was not set")
	}
	if len(o.files) != 1 || o.files[0] != "piece.1" {
		t.Fatalf("files = %v, want [piece.1]", o.files)
	}
}

// "--" is the escape hatch: everything after it is a file, so a piece really
// named like a flag can still be given.
func TestEndOfFlagsSentinel(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "--out"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	o, err := parseArgs([]string{"combine", "-y", "--", "--out", "piece.2"})
	if err != nil {
		t.Fatalf("-- was not accepted: %v", err)
	}
	if !o.yes {
		t.Fatal("-y before -- should still be a flag")
	}
	want := []string{"--out", "piece.2"}
	if len(o.files) != len(want) {
		t.Fatalf("files = %v, want %v", o.files, want)
	}
	for i := range want {
		if o.files[i] != want[i] {
			t.Fatalf("files = %v, want %v", o.files, want)
		}
	}
	if o.outDir != "" {
		t.Fatalf("--out after -- was still read as a flag: %q", o.outDir)
	}
}

// A lone dash means standard input and must stay an operand.
func TestLoneDashIsAnOperand(t *testing.T) {
	t.Chdir(t.TempDir())

	o, err := parseArgs([]string{"split", "-", "-y"})
	if err != nil {
		t.Fatalf("lone dash rejected: %v", err)
	}
	if len(o.files) != 1 || o.files[0] != "-" {
		t.Fatalf("files = %v, want [-]", o.files)
	}
}
