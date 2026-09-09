// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -o was accepted and ignored, so a private key landed in the working directory
// instead of where it was asked for. Every other keygen test names both files
// with --pub/--priv, which is the path that always worked.
func TestKeygenWritesUnderOut(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if err := cmdKeygen(&cliOptions{command: "keygen", outDir: "keys", yes: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"keys/riven-key.pub", "keys/riven-key.key"} {
		if _, err := os.Stat(filepath.FromSlash(want)); err != nil {
			t.Errorf("%s was not written: %v", want, err)
		}
	}
	if _, err := os.Stat("riven-key.key"); err == nil {
		t.Error("the private key was also written to the working directory")
	}
}

// --pub and --priv name exact paths, so -o places only what riven names itself.
func TestKeygenOutPlacesOnlyTheUnnamedFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	opts := &cliOptions{command: "keygen", pubOut: "mine.pub", outDir: "elsewhere", yes: true}
	if err := cmdKeygen(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("mine.pub"); err != nil {
		t.Errorf("--pub path was not honoured: %v", err)
	}
	if _, err := os.Stat(filepath.Join("elsewhere", "riven-key.key")); err != nil {
		t.Errorf("the private key did not go under -o: %v", err)
	}
}

// A directory named in --pub/--priv is created too, so the two ways of naming a
// path behave the same.
func TestKeygenCreatesDirectoriesForNamedPaths(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	opts := &cliOptions{
		command: "keygen",
		pubOut:  filepath.Join("deep", "nested", "a.pub"),
		privOut: filepath.Join("deep", "nested", "a.key"),
		yes:     true,
	}
	if err := cmdKeygen(opts); err != nil {
		t.Fatalf("naming a path under a missing directory failed: %v", err)
	}
	if _, err := os.Stat(opts.privOut); err != nil {
		t.Errorf("private key not written: %v", err)
	}
}

// Overwriting a private key loses everything sealed to it, and the default base
// name means a second keygen aims straight at the first one's files. Under -y
// there is nobody to ask, and -y is documented as failing rather than assuming.
func TestKeygenRefusesToOverwriteAnExistingKey(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	opts := &cliOptions{command: "keygen", yes: true}
	if err := cmdKeygen(opts); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile("riven-key.key")
	if err != nil {
		t.Fatal(err)
	}

	err = cmdKeygen(opts)
	if err == nil {
		t.Fatal("a second keygen replaced the key pair without asking")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error does not explain the refusal: %v", err)
	}

	after, err := os.ReadFile("riven-key.key")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the private key was changed despite the refusal")
	}
}

// keygen accepted every split-only flag and silently dropped it.
func TestKeygenRejectsFlagsThatDoNothing(t *testing.T) {
	cases := []struct {
		name string
		opts cliOptions
	}{
		{"-n", cliOptions{n: 5, nSet: true}},
		{"-k", cliOptions{k: 3, kSet: true}},
		{"--keyless", cliOptions{keyless: true}},
		{"--algo", cliOptions{algo: "aes-256-gcm", algoSet: true}},
		{"--format", cliOptions{format: "qr"}},
		{"--pad", cliOptions{pad: "10", padSet: true}},
		{"--kdf", cliOptions{kdfSpec: "paranoid"}},
		{"--generate", cliOptions{generate: true}},
		{"--name", cliOptions{name: "foo"}},
		{"--qr-scale", cliOptions{qrScale: 4}},
		{"--record-algo", cliOptions{recordAlgoSet: true}},
		{"--verify", cliOptions{verifySet: true}},
		{"--identity", cliOptions{identities: []string{"k.key"}}},
		{"--text", cliOptions{text: "x", textSet: true}},
		{"stray operand", cliOptions{files: []string{"extra"}}},
		{"--out with both named", cliOptions{outDir: "d", pubOut: "a.pub", privOut: "b.key"}},
	}
	for _, c := range cases {
		o := c.opts
		o.command = "keygen"
		o.yes = true
		if err := validateKeygenOptions(&o); err == nil {
			t.Errorf("%s was accepted by keygen and would have been ignored", c.name)
		}
	}
}

// The type argument and the two path flags must still be accepted.
func TestKeygenAcceptsItsOwnFlags(t *testing.T) {
	for _, o := range []cliOptions{
		{command: "keygen", yes: true},
		{command: "keygen", keyType: "x25519", yes: true},
		{command: "keygen", outDir: "keys", yes: true},
		{command: "keygen", pubOut: "a.pub", privOut: "b.key", yes: true},
		{command: "keygen", pubOut: "a.pub", outDir: "keys", yes: true},
	} {
		if err := validateKeygenOptions(&o); err != nil {
			t.Errorf("a valid keygen invocation was rejected: %v", err)
		}
	}
}
