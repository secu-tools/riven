// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// This file drives --method and --info through the binary: every combination
// round-trips, info shows what each mode promises and no more, and the compact
// method makes pieces small enough for formats the full method cannot reach.

// infoModes are the values --info takes.
var infoModes = []string{"protected", "strict", "public", "none"}

// TestMethodAndInfoThroughTheCLI splits with every method and info mode, reads a
// piece with info, and rebuilds from two of three pieces.
func TestMethodAndInfoThroughTheCLI(t *testing.T) {
	input := randomBytes(20000)
	for _, method := range []string{"full", "compact"} {
		for _, info := range infoModes {
			t.Run(method+"/"+info, func(t *testing.T) {
				dir := t.TempDir()
				in := writeFile(t, dir, "data.bin", input)
				out := filepath.Join(dir, "o")
				o, err := riven(t, env1, "split", in, "-n", "3", "-k", "2", "--password-env", flagPw1,
					"--kdf", cheapKDF, "--method", method, "--info", info, "--out", out, "-y")
				if err != nil {
					t.Fatalf("split: %v\n%s", err, o)
				}
				if !strings.Contains(o, "method    "+method) {
					t.Fatalf("the summary does not name the method:\n%s", o)
				}

				piece := pieceFile(out, "data.bin", "binary", 1)
				infoArgs := []string{"info", piece, "-y"}
				if info == "protected" || info == "strict" {
					infoArgs = append(infoArgs, "--password-env", flagPw1)
				}
				o, err = riven(t, env1, infoArgs...)
				if err != nil {
					t.Fatalf("info: %v\n%s", err, o)
				}
				switch info {
				case "none":
					if !strings.Contains(o, "details    : hidden") || strings.Contains(o, "data.bin\n") ||
						strings.Contains(o, "piece      :") {
						t.Fatalf("info shows details of a hidden set:\n%s", o)
					}
				default:
					if !strings.Contains(o, "piece      : 1 of 3") || !strings.Contains(o, "method     : "+method) {
						t.Fatalf("info lacks the details:\n%s", o)
					}
				}

				got, _, err := rivenRaw(t, env1, "combine", pieceFile(out, "data.bin", "binary", 3),
					pieceFile(out, "data.bin", "binary", 2), "--password-env", flagPw1, "-y")
				if err != nil {
					t.Fatalf("combine: %v", err)
				}
				if !bytes.Equal(got, input) {
					t.Fatal("rebuilt different content")
				}
			})
		}
	}
}

// TestDetailsWithoutThePassword checks a public piece answers info with no
// password at all, and a protected piece does not.
func TestDetailsWithoutThePassword(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "d.bin", []byte("details"))
	for _, info := range []string{"public", "protected"} {
		out := filepath.Join(dir, info)
		if o, err := riven(t, env1, "split", in, "-n", "2", "-k", "2", "--password-env", flagPw1,
			"--kdf", cheapKDF, "--info", info, "--out", out, "-y"); err != nil {
			t.Fatalf("%s split: %v\n%s", info, err, o)
		}
		o, err := riven(t, nil, "info", pieceFile(out, "d.bin", "binary", 1), "-y")
		if info == "public" && (err != nil || !strings.Contains(o, "password   : 1 needed to combine")) {
			t.Fatalf("public info without a password: %v\n%s", err, o)
		}
		if info == "protected" && err == nil {
			t.Fatalf("protected details were read without the password:\n%s", o)
		}
	}
}

// TestHiddenSetWithoutAPassword checks a scripted combine of a hidden password
// set, given no password, says how many it needs rather than failing vaguely.
func TestHiddenSetWithoutAPassword(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "h.bin", []byte("hidden"))
	out := filepath.Join(dir, "o")
	if o, err := riven(t, env2, "split", in, "-n", "2", "-k", "2", "--password-env", flagPw1,
		"--password-env", flagPw2, "--kdf", cheapKDF, "--info", "none", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}
	o, err := riven(t, nil, "combine", pieceFile(out, "h.bin", "binary", 1), pieceFile(out, "h.bin", "binary", 2), "-y")
	if err == nil || !strings.Contains(o, "needs 2 password(s)") {
		t.Fatalf("no password: %v\n%s", err, o)
	}
}

// TestCompactReachesQR checks the practical gain: content too large for a QR code
// as full pieces fits as compact ones, the refusal says so, and the codes read
// back.
func TestCompactReachesQR(t *testing.T) {
	dir := t.TempDir()
	input := randomBytes(5000)
	in := writeFile(t, dir, "q.bin", input)

	o, err := riven(t, env1, "split", in, "-n", "5", "-k", "3", "--password-env", flagPw1,
		"--kdf", cheapKDF, "--format", "qr", "--out", filepath.Join(dir, "full"), "-y")
	if err == nil || !strings.Contains(o, "--method compact") {
		t.Fatalf("full pieces of 5000 bytes should not fit QR, and the error should name compact: %v\n%s", err, o)
	}

	out := filepath.Join(dir, "small")
	if o, err := riven(t, env1, "split", in, "-n", "5", "-k", "3", "--password-env", flagPw1,
		"--kdf", cheapKDF, "--format", "qr", "--method", "compact", "--out", out, "-y"); err != nil {
		t.Fatalf("compact QR split: %v\n%s", err, o)
	}
	var args []string
	for _, s := range []int{5, 1, 3} {
		args = append(args, pieceFile(out, "q.bin", "qr", s))
	}
	got, _, err := rivenRaw(t, env1, append(append([]string{"combine"}, args...), "--password-env", flagPw1, "-y")...)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("combine from compact QR codes: %v", err)
	}
}

// TestHelpExplainsMethodAndInfo keeps the help in step with the flags.
func TestHelpExplainsMethodAndInfo(t *testing.T) {
	o, err := riven(t, nil, "help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--method full|compact", "--info protected|strict|public|none", "test guesses of that password"} {
		if !strings.Contains(o, want) {
			t.Fatalf("help lacks %q", want)
		}
	}
}
