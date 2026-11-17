// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSetsPastAByteOfPieces splits a short secret into more pieces than an 8-bit
// field allows, through the binary and with its default full check, for both
// methods, and rebuilds from pieces whose serials need the second byte. Each
// piece is a few hundred bytes, so the files are small.
func TestSetsPastAByteOfPieces(t *testing.T) {
	secret := []byte("a key split three hundred ways")
	for _, method := range []string{"full", "compact"} {
		t.Run(method, func(t *testing.T) {
			dir := t.TempDir()
			in := writeFile(t, dir, "key.txt", secret)
			out := filepath.Join(dir, "o")
			if o, err := riven(t, nil, "split", in, "-n", "300", "-k", "2", "--keyless",
				"--method", method, "--out", out, "-y"); err != nil {
				t.Fatalf("split: %v\n%s", err, o)
			}
			entries, err := os.ReadDir(out)
			if err != nil || len(entries) != 300 {
				t.Fatalf("%d files written, want 300: %v", len(entries), err)
			}
			last := filepath.Join(out, "key.txt.300")
			stdout, _, err := rivenRaw(t, nil, "combine", filepath.Join(out, "key.txt.256"), last, "-y")
			if err != nil || !bytes.Equal(stdout, secret) {
				t.Fatalf("pieces 256 and 300 did not rebuild: %v", err)
			}
			o, err := riven(t, nil, "info", last)
			if err != nil || !strings.Contains(o, "300 of 300") {
				t.Fatalf("info on the last piece: %v\n%s", err, o)
			}
		})
	}

	in := writeFile(t, t.TempDir(), "key.txt", secret)
	if o, err := riven(t, nil, "split", in, "-n", "65536", "-k", "2", "--keyless", "-y"); err == nil {
		t.Fatalf("a split into 65536 pieces was accepted\n%s", o)
	}
}
