// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file is the recovery guarantee at the level a user experiences it: the
// compiled binary, real files, every way a set can be protected. Losing data is
// the one failure that cannot be walked back, so each combination is split and
// then reconstructed and compared byte for byte.

// algorithms are the AEADs the binary advertises. Taking them from the help text
// rather than a hard-coded list means a newly registered algorithm is covered
// here without editing this file.
func algorithms(t *testing.T) []string {
	t.Helper()
	out, err := riven(t, nil, "help")
	if err != nil {
		t.Fatalf("help: %v\n%s", err, out)
	}
	_, rest, ok := strings.Cut(out, "ALGORITHMS\n")
	if !ok {
		t.Fatal("help has no ALGORITHMS section")
	}
	line, _, _ := strings.Cut(rest, "\n")
	var names []string
	for _, n := range strings.Split(line, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	if len(names) < 2 {
		t.Fatalf("expected several algorithms, got %q", names)
	}
	return names
}

// fastCost keeps Argon2 cheap so a large matrix stays quick. The pipeline being
// exercised is the same whatever the cost.
var fastCost = []string{"--kdf", "m=8,t=1,p=1"}

// roundTrip splits input with the given flags, reconstructs from two pieces and
// checks the result. It returns the split output so a caller can assert on the
// summary.
func roundTrip(t *testing.T, env []string, name string, input []byte, splitFlags, openFlags []string) string {
	t.Helper()
	dir := t.TempDir()
	in := writeFile(t, dir, name, input)
	out := filepath.Join(dir, "o")

	args := append([]string{"split", in, "-n", "3", "-k", "2", "--out", out, "-y"}, splitFlags...)
	o, err := riven(t, env, args...)
	if err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}
	if !strings.Contains(o, "Verification: PASSED") && !strings.Contains(o, "Verification: pieces open") {
		t.Fatalf("split did not verify:\n%s", o)
	}

	// Any two of the three pieces must rebuild it, so the pair is not the one
	// that happens to work.
	pieces := []string{
		filepath.Join(out, name+".1"),
		filepath.Join(out, name+".2"),
		filepath.Join(out, name+".3"),
	}
	for i := 0; i < len(pieces); i++ {
		for j := i + 1; j < len(pieces); j++ {
			args := append([]string{"combine", pieces[i], pieces[j], "-y"}, openFlags...)
			got, _, err := rivenRaw(t, env, args...)
			if err != nil {
				t.Fatalf("combine %d,%d: %v", i+1, j+1, err)
			}
			if !bytes.Equal(got, input) {
				t.Fatalf("combine %d,%d: content changed", i+1, j+1)
			}
		}
	}
	return o
}

// TestMatrixEveryAlgorithm runs one password layer per registered algorithm.
func TestMatrixEveryAlgorithm(t *testing.T) {
	input := []byte("every algorithm must return the file unchanged")
	for _, algo := range algorithms(t) {
		t.Run(algo, func(t *testing.T) {
			o := roundTrip(t, env1, "a.bin", input,
				append([]string{"--password-env", flagPw1, "--algo", algo}, fastCost...),
				[]string{"--password-env", flagPw1})
			if !strings.Contains(o, algo) {
				t.Fatalf("the summary should name %s:\n%s", algo, o)
			}
		})
	}
}

// TestMatrixEveryAlgorithmPair stacks two layers, covering every ordered pair of
// different algorithms. This is where a cascade bug would show up: the layers
// are peeled in the reverse of the order they were applied.
func TestMatrixEveryAlgorithmPair(t *testing.T) {
	input := []byte("two layers, applied outermost first")
	algos := algorithms(t)
	for _, outer := range algos {
		for _, inner := range algos {
			if outer == inner {
				continue // adjacent layers must differ, which is checked elsewhere
			}
			t.Run(outer+"+"+inner, func(t *testing.T) {
				roundTrip(t, env2, "p.bin", input,
					append([]string{
						"--password-env", flagPw1, "--password-env", flagPw2,
						"--algo", outer + "," + inner,
					}, fastCost...),
					[]string{"--password-env", flagPw1, "--password-env", flagPw2})
			})
		}
	}
}

// TestMatrixEveryKeyTypeWithAndWithoutPassword covers each recipient key type on
// its own and combined with a password layer, which are the two shapes a
// recipient set comes in.
func TestMatrixEveryKeyTypeWithAndWithoutPassword(t *testing.T) {
	input := []byte("recipient sets must reconstruct too")
	for _, kind := range keyTypes {
		dir := t.TempDir()
		pub := filepath.Join(dir, "r.pub")
		priv := filepath.Join(dir, "r.key")
		if o, err := riven(t, nil, "keygen", kind, "--pub", pub, "--priv", priv, "-y"); err != nil {
			t.Fatalf("keygen %s: %v\n%s", kind, err, o)
		}

		t.Run(kind+"/key only", func(t *testing.T) {
			roundTrip(t, nil, "k.bin", input,
				[]string{"--recipient", pub, "--identity", priv},
				[]string{"--identity", priv})
		})
		t.Run(kind+"/key and password", func(t *testing.T) {
			roundTrip(t, env1, "k.bin", input,
				append([]string{"--password-env", flagPw1, "--recipient", pub, "--identity", priv}, fastCost...),
				[]string{"--password-env", flagPw1, "--identity", priv})
		})
	}
}

// TestMatrixTwoRecipientsMustBothTakePart checks a set addressed to two keys
// needs both, in either order, and cannot be opened by one alone.
func TestMatrixTwoRecipientsMustBothTakePart(t *testing.T) {
	dir := t.TempDir()
	input := []byte("two people have to agree")
	in := writeFile(t, dir, "board.bin", input)
	out := filepath.Join(dir, "o")

	var pubs, privs []string
	for i, kind := range []string{"x25519", "ml-kem-768"} {
		pub := filepath.Join(dir, fmt.Sprintf("k%d.pub", i))
		priv := filepath.Join(dir, fmt.Sprintf("k%d.key", i))
		if o, err := riven(t, nil, "keygen", kind, "--pub", pub, "--priv", priv, "-y"); err != nil {
			t.Fatalf("keygen: %v\n%s", err, o)
		}
		pubs = append(pubs, pub)
		privs = append(privs, priv)
	}

	if o, err := riven(t, nil, "split", in, "-n", "3", "-k", "2",
		"--recipient", pubs[0], "--recipient", pubs[1],
		"--identity", privs[0], "--identity", privs[1],
		"--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}

	p1 := filepath.Join(out, "board.bin.1")
	p2 := filepath.Join(out, "board.bin.2")

	// Both keys, in either order.
	for _, order := range [][]string{{privs[0], privs[1]}, {privs[1], privs[0]}} {
		got, _, err := rivenRaw(t, nil, "combine", p1, p2,
			"--identity", order[0], "--identity", order[1], "-y")
		if err != nil {
			t.Fatalf("combine with both keys: %v", err)
		}
		if !bytes.Equal(got, input) {
			t.Fatal("content changed")
		}
	}

	// Either key alone must fail.
	for i, priv := range privs {
		if _, err := riven(t, nil, "combine", p1, p2, "--identity", priv,
			"--out", filepath.Join(dir, "no"), "-y"); err == nil {
			t.Fatalf("key %d alone must not open the set", i+1)
		}
	}
}

// TestMatrixModesAndRecording covers the protection modes against the recording
// choices, since a set that records nothing needs both the algorithms and the
// cost supplied to open.
func TestMatrixModesAndRecording(t *testing.T) {
	input := []byte("recording combinations must all reconstruct")
	algos := algorithms(t)
	pair := algos[0] + "," + algos[1]

	cases := []struct {
		name  string
		split []string
		open  []string
	}{
		{"records everything",
			[]string{"--password-env", flagPw1},
			[]string{"--password-env", flagPw1}},
		{"no algorithms",
			[]string{"--password-env", flagPw1, "--password-env", flagPw2, "--algo", pair, "--record-algo", "false"},
			[]string{"--password-env", flagPw1, "--password-env", flagPw2, "--algo", pair}},
		{"no cost",
			[]string{"--password-env", flagPw1, "--record-kdf", "false"},
			[]string{"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1"}},
		{"neither",
			[]string{"--password-env", flagPw1, "--password-env", flagPw2, "--algo", pair,
				"--record-algo", "false", "--record-kdf", "false"},
			[]string{"--password-env", flagPw1, "--password-env", flagPw2, "--algo", pair,
				"--kdf", "m=8,t=1,p=1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			roundTrip(t, env2, "r.bin", input, append(c.split, fastCost...), c.open)
		})
	}
}

// TestMatrixContentShapes runs the shapes that break byte pipelines through the
// binary, including the sizes either side of the internal chunk boundary, which
// is where a large split changes shape.
func TestMatrixContentShapes(t *testing.T) {
	const chunk = 512 << 10
	cases := map[string][]byte{
		"empty":            {},
		"one byte":         {0x00},
		"one set bit":      {0x01},
		"all byte values":  allBytes(),
		"text":             []byte("line one\nline two\r\nno trailing newline"),
		"nul bytes":        []byte("before\x00after\x00\x00end"),
		"just under chunk": randomBytes(chunk - 1),
		"exactly chunk":    randomBytes(chunk),
		"just over chunk":  randomBytes(chunk + 1),
		"several chunks":   randomBytes(2*chunk + 1234),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			roundTrip(t, env1, "c.bin", input,
				append([]string{"--password-env", flagPw1}, fastCost...),
				[]string{"--password-env", flagPw1})
		})
	}
}

// TestMatrixThresholds covers the threshold shapes that matter: one piece that
// is sufficient on its own, an all-of-N set, and the 8-of-10 case a small secret
// is likely to use.
func TestMatrixThresholds(t *testing.T) {
	input := []byte("threshold shapes")
	for _, c := range []struct{ n, k int }{{1, 1}, {2, 2}, {5, 3}, {10, 8}} {
		t.Run(fmt.Sprintf("%dof%d", c.k, c.n), func(t *testing.T) {
			dir := t.TempDir()
			in := writeFile(t, dir, "t.bin", input)
			out := filepath.Join(dir, "o")
			args := []string{"split", in, "-n", fmt.Sprint(c.n), "-k", fmt.Sprint(c.k),
				"--password-env", flagPw1, "--out", out, "-y"}
			if o, err := riven(t, env1, append(args, fastCost...)...); err != nil {
				t.Fatalf("split: %v\n%s", err, o)
			}

			entries, err := os.ReadDir(out)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != c.n {
				t.Fatalf("wrote %d pieces, want %d", len(entries), c.n)
			}

			var use []string
			for i := 0; i < c.k; i++ {
				use = append(use, filepath.Join(out, entries[i].Name()))
			}
			got, _, err := rivenRaw(t, env1, append(append([]string{"combine"}, use...),
				"--password-env", flagPw1, "-y")...)
			if err != nil {
				t.Fatalf("combine: %v", err)
			}
			if !bytes.Equal(got, input) {
				t.Fatal("content changed")
			}

			// One short of the threshold must fail.
			if c.k > 1 {
				short := use[:c.k-1]
				if _, err := riven(t, env1, append(append([]string{"combine"}, short...),
					"--password-env", flagPw1, "--out", filepath.Join(dir, "no"), "-y")...); err == nil {
					t.Fatalf("%d pieces must not rebuild a %d-of-%d set", c.k-1, c.k, c.n)
				}
			}
		})
	}
}

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
