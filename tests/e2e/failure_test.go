// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestFailedCombineLeavesNoTrace checks a reconstruction that fails produces
// nothing: no bytes on standard output for a pipeline to take as the data, no new
// file, and no change to a file already at the destination. Losing that file to a
// run that recovered nothing would be data loss of its own.
func TestFailedCombineLeavesNoTrace(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "s.bin", []byte("the real content"))
	cheap := []string{"--kdf", cheapKDF, "-y"}

	split := func(out string, extra ...string) {
		t.Helper()
		args := append([]string{"split", in, "--out", out}, extra...)
		if o, err := riven(t, env1, append(args, cheap...)...); err != nil {
			t.Fatalf("split: %v\n%s", err, o)
		}
	}
	a, b, r := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "r")
	split(a, "-n", "4", "-k", "3", "--password-env", flagPw1)
	split(b, "-n", "4", "-k", "3", "--password-env", flagPw1)
	pub, priv := filepath.Join(dir, "k.pub"), filepath.Join(dir, "k.key")
	if o, err := riven(t, nil, "keygen", "x25519", "--pub", pub, "--priv", priv, "-y"); err != nil {
		t.Fatalf("keygen: %v\n%s", err, o)
	}
	split(r, "-n", "2", "-k", "2", "--recipient", pub, "--identity", priv)

	piece := func(set string, n int) string { return filepath.Join(set, fmt.Sprintf("s.bin.%d", n)) }
	damaged, err := os.ReadFile(piece(a, 2))
	if err != nil {
		t.Fatal(err)
	}
	damaged[len(damaged)/2] ^= 0xFF
	damagedPath := writeFile(t, dir, "damaged", damaged)

	withPw := []string{"--password-env", flagPw1}
	cases := []struct {
		name string
		env  []string
		args []string
	}{
		{"below the threshold", env1, append([]string{piece(a, 1), piece(a, 2)}, withPw...)},
		{"wrong password", []string{"RIVEN_TEST_BAD=not-the-password"},
			[]string{piece(a, 1), piece(a, 2), piece(a, 3), "--password-env", "RIVEN_TEST_BAD"}},
		{"damaged piece", env1, append([]string{piece(a, 1), damagedPath, piece(a, 3)}, withPw...)},
		{"pieces of two sets", env1, append([]string{piece(a, 1), piece(a, 2), piece(b, 3)}, withPw...)},
		{"no private key", nil, []string{piece(r, 1), piece(r, 2)}},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			combine := func(extra ...string) error {
				args := append(append([]string{"combine"}, c.args...), extra...)
				stdout, _, err := rivenRaw(t, c.env, append(args, "-y")...)
				if len(stdout) != 0 {
					t.Fatalf("a failed combine wrote %d bytes to standard output", len(stdout))
				}
				return err
			}
			if combine() == nil {
				t.Fatal("the combine should have failed")
			}

			fresh := filepath.Join(dir, fmt.Sprintf("fresh-%d", i))
			if combine("--out", fresh) == nil {
				t.Fatal("the combine should have failed")
			}
			if _, err := os.Stat(fresh); err == nil {
				t.Fatal("a failed combine created its output file")
			}

			kept := writeFile(t, dir, fmt.Sprintf("kept-%d", i), []byte("an unrelated file"))
			if combine("--out", kept) == nil {
				t.Fatal("the combine should have failed")
			}
			if got, _ := os.ReadFile(kept); string(got) != "an unrelated file" {
				t.Fatalf("a failed combine changed the file at its destination to %q", got)
			}
		})
	}
}

// TestSecretsNeverReachTheOutput checks that what the binary prints never holds a
// password or the content, on any command and any failure, except for the content
// on standard output when that is where it was asked to go. SECURITY.md counts a
// secret reaching a log as in scope, and terminal output is where logs come from.
func TestSecretsNeverReachTheOutput(t *testing.T) {
	const password = "pw-marker-7f3a9c"
	content := []byte("content-marker-41b2e8, the body of the file")
	env := []string{"RIVEN_TEST_SECRET_PW=" + password, "RIVEN_TEST_BAD=wrong", "RIVEN_TEST_TEXT=" + string(content)}

	dir := t.TempDir()
	in := writeFile(t, dir, "s.bin", content)
	out := filepath.Join(dir, "o")
	pw := []string{"--password-env", "RIVEN_TEST_SECRET_PW"}
	p1, p2 := filepath.Join(out, "s.bin.1"), filepath.Join(out, "s.bin.2")

	// Runs marked to succeed must, so that none of them passes by failing early.
	runs := []struct {
		succeeds bool
		args     []string
	}{
		{true, append([]string{"split", in, "-n", "3", "-k", "2", "-f", "binary,base64", "--kdf", cheapKDF,
			"--out", out, "-y"}, pw...)},
		{true, append([]string{"split", "--text-env", "RIVEN_TEST_TEXT", "-n", "2", "-k", "2", "--kdf", cheapKDF,
			"--out", filepath.Join(dir, "t"), "-y"}, pw...)},
		{true, append([]string{"info", p1, "-y"}, pw...)},
		{true, append([]string{"verify", out, "-y"}, pw...)},
		{true, append([]string{"combine", p1, p2, "--out", filepath.Join(dir, "rec"), "-y"}, pw...)},
		{false, append([]string{"verify", p1, "-y"}, pw...)},
		{false, append([]string{"combine", p1, "-y"}, pw...)},
		{false, []string{"combine", p1, p2, "--password-env", "RIVEN_TEST_BAD", "-y"}},
		{false, []string{"info", p1, "--password-env", "RIVEN_TEST_BAD", "-y"}},
	}
	for _, run := range runs {
		stdout, stderr, err := rivenRaw(t, env, run.args...)
		printed := append(stdout, stderr...)
		if run.succeeds && err != nil {
			t.Fatalf("%v failed: %v\n%s", run.args, err, printed)
		}
		if bytes.Contains(printed, []byte(password)) {
			t.Fatalf("%v printed the password:\n%s", run.args, printed)
		}
		if bytes.Contains(printed, content[:20]) {
			t.Fatalf("%v printed the content:\n%s", run.args, printed)
		}
	}

	// The one place the content belongs: standard output, when asked for.
	stdout, stderr, err := rivenRaw(t, env, append([]string{"combine", p1, p2, "-y"}, pw...)...)
	if err != nil || !bytes.Equal(stdout, content) {
		t.Fatalf("the content did not come back on standard output: %v", err)
	}
	if bytes.Contains(stderr, content[:20]) || bytes.Contains(stderr, []byte(password)) {
		t.Fatalf("standard error carried a secret:\n%s", stderr)
	}
}
