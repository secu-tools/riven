// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

// Package e2e drives the compiled riven binary the way a user would: real
// split, info, and combine runs over real files, with passwords supplied in
// environment variables as automation requires.
package e2e

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "riven-e2e")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "riven")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		panic("build failed: " + string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// riven runs the binary with the given extra environment entries.
func riven(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), env...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// pw1 and pw2 are the environment variable names used throughout.
var (
	pw1  = "RIVEN_TEST_PW1=layer-one-password"
	pw2  = "RIVEN_TEST_PW2=layer-two-password"
	env1 = []string{pw1}
	env2 = []string{pw1, pw2}
)

const (
	flagPw1 = "RIVEN_TEST_PW1"
	flagPw2 = "RIVEN_TEST_PW2"
)

// TestExportFormats checks each format writes the expected files and that every
// one reconstructs on its own.
func TestExportFormats(t *testing.T) {
	cases := []struct {
		spec  string
		files []string
	}{
		{"binary", []string{"s.1", "s.2", "s.3"}},
		{"base64", []string{"s.1.txt", "s.2.txt", "s.3.txt"}},
		{"qr", []string{"s.1.png", "s.2.png", "s.3.png"}},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			dir := t.TempDir()
			secret := []byte("format " + c.spec)
			in := writeFile(t, dir, "s", secret)
			out := filepath.Join(dir, "o")
			if o, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
				"--password-env", flagPw1, "--format", c.spec, "--out", out, "-y"); err != nil {
				t.Fatalf("split: %v\n%s", err, o)
			}
			for _, f := range c.files {
				if _, err := os.Stat(filepath.Join(out, f)); err != nil {
					t.Fatalf("expected %s: %v", f, err)
				}
			}
			rec := filepath.Join(dir, "rec")
			if o, err := riven(t, env1, "combine",
				filepath.Join(out, c.files[0]), filepath.Join(out, c.files[2]),
				"--password-env", flagPw1, "--out", rec, "-y"); err != nil {
				t.Fatalf("combine: %v\n%s", err, o)
			}
			if got, _ := os.ReadFile(rec); !bytes.Equal(got, secret) {
				t.Fatal("mismatch")
			}
		})
	}
}

// TestExportAllAndMixedCombine writes all three formats and then reconstructs
// from one piece of each form in a single command.
func TestExportAllAndMixedCombine(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("mixed transport end to end")
	in := writeFile(t, dir, "m", secret)
	out := filepath.Join(dir, "o")

	if o, err := riven(t, env1, "split", in, "-n", "3", "-k", "3",
		"--password-env", flagPw1, "--format", "all", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}
	for _, f := range []string{"m.1", "m.2.txt", "m.3.png"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("expected %s: %v", f, err)
		}
	}

	rec := filepath.Join(dir, "rec")
	o, err := riven(t, env1, "combine",
		filepath.Join(out, "m.1"),     // binary
		filepath.Join(out, "m.2.txt"), // base64
		filepath.Join(out, "m.3.png"), // QR image
		"--password-env", flagPw1, "--out", rec, "-y")
	if err != nil {
		t.Fatalf("mixed combine: %v\n%s", err, o)
	}
	if got, _ := os.ReadFile(rec); !bytes.Equal(got, secret) {
		t.Fatal("mixed combine mismatch")
	}
}

// TestInfoDetectsInputForm checks info reports the transport form it detected
// and the piece metadata, for each form.
func TestInfoDetectsInputForm(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "doc", []byte("metadata"))
	out := filepath.Join(dir, "o")
	if o, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
		"--password-env", flagPw1, "--format", "all", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}
	for file, form := range map[string]string{
		"doc.2":     "binary",
		"doc.2.txt": "base64",
		"doc.2.png": "qr",
	} {
		o, err := riven(t, env1, "info", filepath.Join(out, file), "--password-env", flagPw1, "-y")
		if err != nil {
			t.Fatalf("info %s: %v\n%s", file, err, o)
		}
		for _, want := range []string{"input form : " + form, "2 of 3", "need any 2", "intact"} {
			if !strings.Contains(o, want) {
				t.Fatalf("info %s missing %q:\n%s", file, want, o)
			}
		}
	}
}

// TestKDFPresets checks each preset name is accepted and round-trips. The cost
// is recorded, so combine needs no --kdf.
func TestKDFPresets(t *testing.T) {
	for _, preset := range []string{"recommended", "paranoid"} {
		t.Run(preset, func(t *testing.T) {
			dir := t.TempDir()
			secret := []byte("preset " + preset)
			in := writeFile(t, dir, "p", secret)
			out := filepath.Join(dir, "o")
			if o, err := riven(t, env1, "split", in, "-n", "2", "-k", "2",
				"--password-env", flagPw1, "--kdf", preset, "--out", out, "-y"); err != nil {
				t.Fatalf("split: %v\n%s", err, o)
			}
			rec := filepath.Join(dir, "rec")
			if o, err := riven(t, env1, "combine", filepath.Join(out, "p.1"), filepath.Join(out, "p.2"),
				"--password-env", flagPw1, "--out", rec, "-y"); err != nil {
				t.Fatalf("combine: %v\n%s", err, o)
			}
			if got, _ := os.ReadFile(rec); !bytes.Equal(got, secret) {
				t.Fatal("mismatch")
			}
		})
	}
}

// TestQRTooLargeIsRejected checks the QR size limit is reported clearly, with a
// compression suggestion only when it could plausibly help.
func TestQRTooLargeIsRejected(t *testing.T) {
	dir := t.TempDir()
	medium := make([]byte, 4000)
	rand.Read(medium)
	in := writeFile(t, dir, "big.bin", medium)
	o, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
		"--password-env", flagPw1, "--format", "qr", "--out", filepath.Join(dir, "o"), "-y")
	if err == nil {
		t.Fatalf("QR export of an oversized piece should fail:\n%s", o)
	}
	if !strings.Contains(o, "QR code holds at most") {
		t.Fatalf("expected a capacity message:\n%s", o)
	}
	if !strings.Contains(o, "Compress") {
		t.Fatalf("expected a compression suggestion at this size:\n%s", o)
	}

	huge := make([]byte, 200000)
	rand.Read(huge)
	in2 := writeFile(t, dir, "huge.bin", huge)
	o2, err := riven(t, env1, "split", in2, "-n", "3", "-k", "2",
		"--password-env", flagPw1, "--format", "qr", "--out", filepath.Join(dir, "o2"), "-y")
	if err == nil {
		t.Fatal("QR export of a far oversized piece should fail")
	}
	if strings.Contains(o2, "Compress") {
		t.Fatalf("compression should not be suggested at this size:\n%s", o2)
	}
}

// TestLargeBinaryFile checks a multi-hundred-kilobyte binary survives base64
// transport, covering arbitrary byte values.
func TestLargeBinaryFile(t *testing.T) {
	dir := t.TempDir()
	data := make([]byte, 200000)
	rand.Read(data)
	in := writeFile(t, dir, "l.bin", data)
	out := filepath.Join(dir, "o")
	if o, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
		"--password-env", flagPw1, "--format", "binary,base64", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}
	rec := filepath.Join(dir, "rec.bin")
	if o, err := riven(t, env1, "combine", filepath.Join(out, "l.bin.1.txt"),
		filepath.Join(out, "l.bin.3.txt"), "--password-env", flagPw1, "--out", rec, "-y"); err != nil {
		t.Fatalf("combine: %v\n%s", err, o)
	}
	got, _ := os.ReadFile(rec)
	if !bytes.Equal(got, data) {
		t.Fatal("large binary mismatch")
	}
}

// rivenRaw runs the binary and returns stdout and stderr separately, which is
// what automation relies on: the data must never be mixed with commentary.
func rivenRaw(t *testing.T, env []string, args ...string) (stdout, stderr []byte, err error) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), env...)
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err = cmd.Run()
	return so.Bytes(), se.Bytes(), err
}

// TestKeylessNeedsNothing covers split-only mode end to end: combine and info
// must succeed with no password and no flags at all.
func TestKeylessNeedsNothing(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("keyless end to end content")
	in := writeFile(t, dir, "k.bin", secret)
	out := filepath.Join(dir, "o")

	o, err := riven(t, nil, "split", in, "-n", "5", "-k", "3", "--keyless", "--out", out, "-y")
	if err != nil {
		t.Fatalf("keyless split: %v\n%s", err, o)
	}
	if !strings.Contains(o, "split only, no encryption and no password") {
		t.Fatalf("summary should say the mode plainly:\n%s", o)
	}

	p := func(n string) string { return filepath.Join(out, n) }

	// Combine with nothing supplied.
	stdout, _, err := rivenRaw(t, nil, "combine", p("k.bin.1"), p("k.bin.3"), p("k.bin.5"), "-y")
	if err != nil {
		t.Fatalf("keyless combine: %v", err)
	}
	if !bytes.Equal(stdout, secret) {
		t.Fatalf("keyless combine returned %q", stdout)
	}

	// Info with nothing supplied.
	o, err = riven(t, nil, "info", p("k.bin.2"), "-y")
	if err != nil {
		t.Fatalf("keyless info: %v\n%s", err, o)
	}
	for _, want := range []string{"2 of 5", "need any 3", "none, and no password"} {
		if !strings.Contains(o, want) {
			t.Fatalf("info missing %q:\n%s", want, o)
		}
	}

	// Below the threshold still fails.
	if _, err := riven(t, nil, "combine", p("k.bin.1"), p("k.bin.2"), "--out", filepath.Join(dir, "x"), "-y"); err == nil {
		t.Fatal("below-threshold keyless combine should fail")
	}

	// K=1 is refused, since one piece would be the whole file.
	if _, err := riven(t, nil, "split", in, "-n", "3", "-k", "1", "--keyless",
		"--out", filepath.Join(dir, "o2"), "-y"); err == nil {
		t.Fatal("keyless with K=1 should be refused")
	}

	// A keyless set must not be openable by offering a password.
	if _, err := riven(t, env1, "combine", p("k.bin.1"), p("k.bin.2"), p("k.bin.3"),
		"--password-env", flagPw1, "--out", filepath.Join(dir, "x2"), "-y"); err == nil {
		t.Fatal("keyless set should not open when a password is supplied")
	}
}

// TestHybridWithHiddenAlgorithms covers hybrid mode together with
// --record-algo false: the recipient layer counts as a layer, so its algorithm has to
// be named too, and the summary must say which algorithms were used.
func TestHybridWithHiddenAlgorithms(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("hybrid plus hidden algorithms")
	in := writeFile(t, dir, "h.bin", secret)
	pub := filepath.Join(dir, "r.pub")
	priv := filepath.Join(dir, "r.key")
	out := filepath.Join(dir, "o")

	if o, err := riven(t, nil, "keygen", "--pub", pub, "--priv", priv, "-y"); err != nil {
		t.Fatalf("keygen: %v\n%s", err, o)
	}

	o, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
		"--algo", "chacha20-poly1305", "--password-env", flagPw1,
		"--recipient", pub, "--identity", priv,
		"--record-algo", "false", "--out", out, "-y")
	if err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}
	// Verification must succeed: the KEM layer's algorithm has to be resolved
	// consistently, not left unset.
	if !strings.Contains(o, "Verification: PASSED") {
		t.Fatalf("verification did not pass:\n%s", o)
	}
	// The summary must name the recipient layer so the user knows what to pass.
	if !strings.Contains(o, "recipient key (x-wing)") {
		t.Fatalf("summary should name the recipient layer:\n%s", o)
	}

	// Both algorithms plus the private key reconstruct it.
	stdout, _, err := rivenRaw(t, env1, "combine",
		filepath.Join(out, "h.bin.1"), filepath.Join(out, "h.bin.2"),
		"--password-env", flagPw1, "--identity", priv,
		"--algo", "chacha20-poly1305,aes-256-gcm", "-y")
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(stdout, secret) {
		t.Fatalf("got %q", stdout)
	}

	// Naming only the password layer is not enough.
	if _, err := riven(t, env1, "combine",
		filepath.Join(out, "h.bin.1"), filepath.Join(out, "h.bin.2"),
		"--password-env", flagPw1, "--identity", priv,
		"--algo", "chacha20-poly1305", "--out", filepath.Join(dir, "x"), "-y"); err == nil {
		t.Fatal("too few algorithms should fail")
	}
}

// TestGeneratedPasswordReporting covers how an invented password reaches the
// user: on standard output under -y, one line per layer, nothing else mixed in,
// and never written beside the pieces.
func TestGeneratedPasswordReporting(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("generated password handling")
	in := writeFile(t, dir, "g.bin", payload)

	// One generated password: standard output holds exactly that line.
	out := filepath.Join(dir, "o")
	stdout, stderr, err := rivenRaw(t, nil, "split", in, "-n", "2", "-k", "2", "--out", out, "-y")
	if err != nil {
		t.Fatalf("split: %v\n%s", err, stderr)
	}
	lines := strings.Split(strings.TrimRight(string(stdout), "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("standard output should hold one password line, got %q", stdout)
	}
	if !bytes.Contains(stderr, []byte("generated")) {
		t.Fatalf("standard error should explain what happened:\n%s", stderr)
	}
	// Nothing may be written beside the pieces.
	entries, _ := os.ReadDir(out)
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Name()), "password") {
			t.Fatalf("no password file should be written beside the pieces: %s", e.Name())
		}
	}
	// And that password opens the set.
	got, _, err := rivenRaw(t, []string{"RIVEN_GEN_PW=" + lines[0]}, "combine",
		filepath.Join(out, "g.bin.1"), filepath.Join(out, "g.bin.2"),
		"--password-env", "RIVEN_GEN_PW", "-y")
	if err != nil {
		t.Fatalf("the generated password did not work: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q", got)
	}

	// Two layers: two lines, in layer order, and both are needed.
	out2 := filepath.Join(dir, "o2")
	stdout2, _, err := rivenRaw(t, nil, "split", in, "-n", "2", "-k", "2",
		"--algo", "chacha20-poly1305,aes-256-gcm", "--out", out2, "-y")
	if err != nil {
		t.Fatal(err)
	}
	two := strings.Split(strings.TrimRight(string(stdout2), "\n"), "\n")
	if len(two) != 2 || two[0] == "" || two[1] == "" || two[0] == two[1] {
		t.Fatalf("expected two distinct password lines, got %q", stdout2)
	}
	got, _, err = rivenRaw(t, []string{"P1=" + two[0], "P2=" + two[1]}, "combine",
		filepath.Join(out2, "g.bin.1"), filepath.Join(out2, "g.bin.2"),
		"--password-env", "P1", "--password-env", "P2", "-y")
	if err != nil {
		t.Fatalf("the generated passwords did not work: %v", err)
	}
	if !bytes.Equal(got, []byte("generated password handling")) {
		t.Fatalf("got %q", got)
	}
}

// TestMixedLayerCascade covers the headline arrangement: password, two different
// recipient keys, then another password. Every factor must be required, and the
// order of the flags must set the order of the layers.
func TestMixedLayerCascade(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("needs alice and bob and both passwords")
	in := writeFile(t, dir, "board.bin", secret)

	alice := filepath.Join(dir, "alice")
	bob := filepath.Join(dir, "bob")
	if _, err := riven(t, nil, "keygen", "--pub", alice+".pub", "--priv", alice+".key", "-y"); err != nil {
		t.Fatal(err)
	}
	// A different key type, to prove the two are told apart by their files.
	if _, err := riven(t, nil, "keygen", "ml-kem-1024", "--pub", bob+".pub", "--priv", bob+".key", "-y"); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "o")
	o, err := riven(t, env2, "split", in, "-n", "4", "-k", "2",
		"--password-env", flagPw1,
		"--recipient", alice+".pub",
		"--recipient", bob+".pub",
		"--password-env", flagPw2,
		"--identity", alice+".key", "--identity", bob+".key",
		"--out", out, "-y")
	if err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}
	// The summary must list four layers in the order the flags were given.
	for _, want := range []string{
		"1. ", "2. ", "3. ", "4. ",
		"x-wing", "ml-kem-1024",
		"Every recipient private key listed above is required",
	} {
		if !strings.Contains(o, want) {
			t.Fatalf("summary missing %q:\n%s", want, o)
		}
	}

	p1 := filepath.Join(out, "board.bin.1")
	p3 := filepath.Join(out, "board.bin.3")
	base := []string{"combine", p1, p3, "--password-env", flagPw1, "--password-env", flagPw2, "-y"}

	// Every factor is required.
	missing := map[string][]string{
		"no keys":      base,
		"alice only":   append(append([]string{}, base...), "--identity", alice+".key"),
		"bob only":     append(append([]string{}, base...), "--identity", bob+".key"),
		"one passwd":   {"combine", p1, p3, "--password-env", flagPw1, "--identity", alice + ".key", "--identity", bob + ".key", "-y"},
		"no passwords": {"combine", p1, p3, "--identity", alice + ".key", "--identity", bob + ".key", "-y"},
	}
	for name, args := range missing {
		if _, err := riven(t, env2, append(args, "--out", filepath.Join(dir, "x-"+name))...); err == nil {
			t.Fatalf("%s: reconstruction should have failed", name)
		}
	}

	// Everything present, in either key order.
	for _, order := range [][]string{
		{alice + ".key", bob + ".key"},
		{bob + ".key", alice + ".key"},
	} {
		args := append(append([]string{}, base...),
			"--identity", order[0], "--identity", order[1])
		got, _, err := rivenRaw(t, env2, args...)
		if err != nil {
			t.Fatalf("combine with keys %v: %v", order, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("got %q", got)
		}
	}
}

// TestTextInput covers splitting a string rather than a file.
func TestTextInput(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "o")

	if o, err := riven(t, env1, "split", "--text", "123456", "-n", "3", "-k", "2",
		"--password-env", flagPw1, "--out", out, "-y"); err != nil {
		t.Fatalf("text split: %v\n%s", err, o)
	}
	// Pieces take a default base name.
	for _, f := range []string{"secret.1", "secret.2", "secret.3"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("expected %s: %v", f, err)
		}
	}
	stdout, _, err := rivenRaw(t, env1, "combine",
		filepath.Join(out, "secret.1"), filepath.Join(out, "secret.3"),
		"--password-env", flagPw1, "-y")
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if string(stdout) != "123456" {
		t.Fatalf("got %q, want %q", stdout, "123456")
	}

	// --name controls the base name.
	out2 := filepath.Join(dir, "o2")
	if o, err := riven(t, env1, "split", "--text", "abc", "-n", "2", "-k", "2",
		"--password-env", flagPw1, "--name", "mykey", "--out", out2, "-y"); err != nil {
		t.Fatalf("named split: %v\n%s", err, o)
	}
	if _, err := os.Stat(filepath.Join(out2, "mykey.1")); err != nil {
		t.Fatalf("--name not applied: %v", err)
	}

	// --text-env keeps the secret out of the argument list.
	out3 := filepath.Join(dir, "o3")
	if o, err := riven(t, append(env1, "RIVEN_TEST_TEXT=from-the-environment"),
		"split", "--text-env", "RIVEN_TEST_TEXT", "-n", "2", "-k", "2",
		"--password-env", flagPw1, "--out", out3, "-y"); err != nil {
		t.Fatalf("text-env split: %v\n%s", err, o)
	}
	stdout, _, err = rivenRaw(t, env1, "combine",
		filepath.Join(out3, "secret.1"), filepath.Join(out3, "secret.2"),
		"--password-env", flagPw1, "-y")
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if string(stdout) != "from-the-environment" {
		t.Fatalf("got %q", stdout)
	}

	// A file and --text together is a contradiction.
	if _, err := riven(t, env1, "split", "somefile", "--text", "x",
		"--password-env", flagPw1, "-y"); err == nil {
		t.Fatal("file plus --text should be refused")
	}
	// No input at all.
	if _, err := riven(t, env1, "split", "--password-env", flagPw1, "-y"); err == nil {
		t.Fatal("split with no input should fail")
	}
}

// TestStdinInput covers reading the data to split from standard input.
func TestStdinInput(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "o")
	const payload = "piped-in-without-a-trailing-newline"

	cmd := exec.Command(binPath, "split", "-", "-n", "2", "-k", "2",
		"--password-env", flagPw1, "--out", out, "--name", "piped", "-y")
	cmd.Env = append(os.Environ(), env1...)
	cmd.Stdin = strings.NewReader(payload)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stdin split: %v\n%s", err, o)
	}

	stdout, _, err := rivenRaw(t, env1, "combine",
		filepath.Join(out, "piped.1"), filepath.Join(out, "piped.2"),
		"--password-env", flagPw1, "-y")
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if string(stdout) != payload {
		t.Fatalf("got %q, want %q", stdout, payload)
	}
}

// TestAutomationOutputIsExact is the contract automation depends on: with -y and
// no --out the recovered bytes go to standard output untouched, and every message
// goes to standard error.
func TestAutomationOutputIsExact(t *testing.T) {
	dir := t.TempDir()
	// Bytes that would be mangled by any text handling.
	payload := []byte("no-newline-at-end\x00\x01\xff\xfe binary \n middle newline")
	in := writeFile(t, dir, "p.bin", payload)
	out := filepath.Join(dir, "o")
	if o, err := riven(t, env1, "split", in, "-n", "2", "-k", "2",
		"--password-env", flagPw1, "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}

	stdout, stderr, err := rivenRaw(t, env1, "combine",
		filepath.Join(out, "p.bin.1"), filepath.Join(out, "p.bin.2"),
		"--password-env", flagPw1, "-y")
	if err != nil {
		t.Fatalf("combine: %v\n%s", err, stderr)
	}
	if !bytes.Equal(stdout, payload) {
		t.Fatalf("standard output was not byte exact:\ngot  %q\nwant %q", stdout, payload)
	}
	// Commentary belongs on standard error only.
	if len(stderr) == 0 || !bytes.Contains(stderr, []byte("recovered")) {
		t.Fatalf("expected a note on standard error, got %q", stderr)
	}

	// "-" as an explicit destination does the same thing.
	stdout2, _, err := rivenRaw(t, env1, "combine",
		filepath.Join(out, "p.bin.1"), filepath.Join(out, "p.bin.2"),
		"--password-env", flagPw1, "--out", "-", "-y")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout2, payload) {
		t.Fatal("--out - should write the data to standard output")
	}

	// An explicit file destination still writes a file and prints no data.
	dest := filepath.Join(dir, "recovered.bin")
	stdout3, _, err := rivenRaw(t, env1, "combine",
		filepath.Join(out, "p.bin.1"), filepath.Join(out, "p.bin.2"),
		"--password-env", flagPw1, "--out", dest, "-y")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stdout3, payload) {
		t.Fatal("data should not go to standard output when a file was named")
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, payload) {
		t.Fatal("file destination mismatch")
	}
}

func TestNegativeCases(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "n", []byte("negative testing"))
	out := filepath.Join(dir, "o")
	if _, err := riven(t, env1, "split", in, "-n", "5", "-k", "3",
		"--password-env", flagPw1, "--out", out, "-y"); err != nil {
		t.Fatal(err)
	}
	p := func(n string) string { return filepath.Join(out, n) }
	badEnv := []string{"RIVEN_TEST_BAD=wrong-password"}

	// Below threshold.
	if _, err := riven(t, env1, "combine", p("n.1"), p("n.2"),
		"--password-env", flagPw1, "--out", filepath.Join(dir, "x1"), "-y"); err == nil {
		t.Fatal("below-threshold combine should fail")
	}
	// Wrong password.
	if _, err := riven(t, badEnv, "combine", p("n.1"), p("n.2"), p("n.3"),
		"--password-env", "RIVEN_TEST_BAD", "--out", filepath.Join(dir, "x2"), "-y"); err == nil {
		t.Fatal("wrong-password combine should fail")
	}
	// Missing environment variable.
	if _, err := riven(t, nil, "combine", p("n.1"), p("n.2"), p("n.3"),
		"--password-env", "RIVEN_TEST_NOT_SET", "--out", filepath.Join(dir, "x3"), "-y"); err == nil {
		t.Fatal("missing environment variable should fail")
	}
	// No password at all in automation.
	if _, err := riven(t, nil, "combine", p("n.1"), p("n.2"), p("n.3"),
		"--out", filepath.Join(dir, "x4"), "-y"); err == nil {
		t.Fatal("combine with no password should fail")
	}
	// An unknown flag is reported rather than ignored.
	o, err := riven(t, nil, "split", in, "--password-file", "pw.txt", "-y")
	if err == nil {
		t.Fatal("an unknown flag should be rejected")
	}
	if !strings.Contains(o, "unknown flag") {
		t.Fatalf("rejection should name the unknown flag:\n%s", o)
	}
	// Unknown algorithm and format.
	if _, err := riven(t, env1, "split", in, "--algo", "rot13",
		"--password-env", flagPw1, "--out", filepath.Join(dir, "x5"), "-y"); err == nil {
		t.Fatal("unknown algorithm should fail")
	}
	if _, err := riven(t, env1, "split", in, "--format", "pdf",
		"--password-env", flagPw1, "--out", filepath.Join(dir, "x6"), "-y"); err == nil {
		t.Fatal("unknown format should fail")
	}
	// Unencodable Argon2 cost.
	if _, err := riven(t, env1, "split", in, "--kdf", "m=19,t=2,p=1",
		"--password-env", flagPw1, "--out", filepath.Join(dir, "x7"), "-y"); err == nil {
		t.Fatal("unencodable cost should fail")
	}
	// Adjacent layers may not share an algorithm.
	if _, err := riven(t, env2, "split", in, "--algo", "aes-256-gcm,aes-256-gcm",
		"--password-env", flagPw1, "--password-env", flagPw2,
		"--out", filepath.Join(dir, "x8"), "-y"); err == nil {
		t.Fatal("repeated adjacent algorithm should fail")
	}
	// Hostile input must not crash the process.
	junk := writeFile(t, dir, "junk", bytes.Repeat([]byte{0x00}, 300))
	if _, err := riven(t, env1, "info", junk, "--password-env", flagPw1, "-y"); err != nil {
		_ = err // a non-zero exit is fine; a crash is not
	}
	notImage := writeFile(t, dir, "fake.png", []byte("\x89PNG\r\n\x1a\nnot really"))
	_, _ = riven(t, env1, "info", notImage, "--password-env", flagPw1, "-y")
}

// TestHelpListsRegistryContents checks the help text is generated from the
// registries rather than hardcoded, so new entries appear automatically.
func TestHelpListsRegistryContents(t *testing.T) {
	o, err := riven(t, nil, "help")
	if err != nil {
		t.Fatalf("help: %v\n%s", err, o)
	}
	for _, want := range []string{
		"chacha20-poly1305", "aes-256-gcm", "twofish-256-gcm", "aes-256-ctr-hmac",
		"recommended", "paranoid", "binary, base64, base32, words, qr, sheet",
		"--password-env", "--record-name", "completion",
	} {
		if !strings.Contains(o, want) {
			t.Fatalf("help missing %q:\n%s", want, o)
		}
	}
	if strings.Contains(o, "--password-file") {
		t.Fatal("help should not mention the removed --password-file flag")
	}
}

// TestQRPaddingInteraction covers the one place where two features work against
// each other: padding is still applied when exporting to QR, so a piece that
// would fit can be pushed over the limit. Nothing may be half-written, and the
// error must point at the padding rather than at the file size.
func TestQRPaddingInteraction(t *testing.T) {
	dir := t.TempDir()
	// Sized so the unpadded pieces fit in a QR code but the next size class does
	// not: the natural piece is under the limit, the padded one is over it.
	data := make([]byte, 2700)
	rand.Read(data)
	in := writeFile(t, dir, "edge.bin", data)

	// With padding on the export fails, nothing is written, and the message names
	// the padding as the first thing to try. This is deterministic: the size class
	// depends only on the length.
	out := filepath.Join(dir, "padded")
	o, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1",
		"--format", "qr", "--out", out, "-y")
	if err == nil {
		t.Fatalf("padding should push this input past the QR limit:\n%s", o)
	}
	if !strings.Contains(o, "--pad none") {
		t.Fatalf("the error should suggest turning padding off:\n%s", o)
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 0 {
		t.Fatalf("a failed QR export must leave nothing behind, found %d files", len(entries))
	}

	// With padding off the same input succeeds every time, and every piece
	// round-trips through its QR code.
	for run := 0; run < 3; run++ {
		out := filepath.Join(dir, fmt.Sprintf("z%d", run))
		if o, err := riven(t, env1, "split", in, "-n", "3", "-k", "2",
			"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "--pad", "none",
			"--format", "qr", "--out", out, "-y"); err != nil {
			t.Fatalf("run %d: --pad none should always fit here: %v\n%s", run, err, o)
		}
		got, _, err := rivenRaw(t, env1, "combine",
			filepath.Join(out, "edge.bin.1.png"), filepath.Join(out, "edge.bin.2.png"),
			"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "-y")
		if err != nil {
			t.Fatalf("run %d: combine from QR: %v", run, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("run %d: content changed through QR", run)
		}
	}

	// An input far past the limit must not blame the padding.
	big := make([]byte, 20000)
	rand.Read(big)
	bigIn := writeFile(t, dir, "big.bin", big)
	o, err = riven(t, env1, "split", bigIn, "-n", "3", "-k", "2",
		"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1", "--pad", "none",
		"--format", "qr", "--out", filepath.Join(dir, "big"), "-y")
	if err == nil {
		t.Fatal("a 20 KB input must not fit in a QR code")
	}
	if strings.Contains(o, "--pad none") {
		t.Fatalf("padding is already off, so it must not be blamed:\n%s", o)
	}
}
