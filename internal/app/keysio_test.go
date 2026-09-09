// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/kem"
)

// TestKeyFileRoundTrip covers every key type through the files a user actually
// handles: written, read back, and still able to encapsulate and decapsulate.
func TestKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for _, s := range kem.All() {
		t.Run(s.Name(), func(t *testing.T) {
			priv, err := kem.Generate(s)
			if err != nil {
				t.Fatal(err)
			}
			pubPath := filepath.Join(dir, s.Name()+".pub")
			privPath := filepath.Join(dir, s.Name()+".key")
			if err := writePublicKey(pubPath, priv.Public()); err != nil {
				t.Fatal(err)
			}
			if err := writePrivateKey(privPath, priv); err != nil {
				t.Fatal(err)
			}

			gotPub, err := readPublicKey(pubPath)
			if err != nil {
				t.Fatal(err)
			}
			gotPriv, err := readPrivateKey(privPath)
			if err != nil {
				t.Fatal(err)
			}
			if gotPub.Scheme() != s || gotPriv.Scheme() != s {
				t.Fatalf("scheme lost: pub=%s priv=%s", gotPub.Scheme(), gotPriv.Scheme())
			}
			secret, ct, err := gotPub.Encapsulate()
			if err != nil {
				t.Fatal(err)
			}
			back, err := gotPriv.Decapsulate(ct)
			if err != nil {
				t.Fatal(err)
			}
			if string(secret) != string(back) {
				t.Fatal("keys from disk do not agree")
			}
		})
	}
}

// TestPrivateKeyFilePermissions checks a private key is not written
// world-readable. Windows uses ACLs rather than mode bits, so the check only
// applies elsewhere.
func TestPrivateKeyFilePermissions(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("mode bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "k.key")
	if err := writePrivateKey(path, priv); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("private key is %v, which is readable by others", mode)
	}
}

// TestKeyFileLabels checks the labels are distinct per type and per role, which
// is what stops a public key being used where a private one is meant.
func TestKeyFileLabels(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range kem.All() {
		for _, label := range []string{pubKeyLabel(s), privKeyLabel(s)} {
			if seen[label] {
				t.Fatalf("label %q is used twice", label)
			}
			seen[label] = true
			if !strings.HasPrefix(label, "riven-") || !strings.Contains(label, s.Name()) {
				t.Fatalf("label %q does not name riven and the key type", label)
			}
		}
	}
	if kindPublic.describe() == kindPrivate.describe() {
		t.Fatal("the two roles describe themselves identically")
	}
	if kindPublic.label(kem.Default()) == kindPrivate.label(kem.Default()) {
		t.Fatal("the two roles share a label")
	}
}

// TestKeyFileRejectsBadInput covers the ways a key file can be wrong: swapped
// roles, an unknown type, a mislabelled body, damaged base64, no label at all,
// and an empty file.
func TestKeyFileRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "good.pub")
	privPath := filepath.Join(dir, "good.key")
	if err := writePublicKey(pubPath, priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateKey(privPath, priv); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := map[string]struct {
		path   string
		read   func(string) error
		hasErr string
	}{
		"private read as public": {privPath, func(p string) error { _, e := readPublicKey(p); return e }, "public key"},
		"public read as private": {pubPath, func(p string) error { _, e := readPrivateKey(p); return e }, "private key"},
		"unknown label": {write("unknown.pub", "riven-rsa-4096-public\nAAAA\n"),
			func(p string) error { _, e := readPublicKey(p); return e }, "public key"},
		"no label": {write("nolabel.pub", "AAAA\n"),
			func(p string) error { _, e := readPublicKey(p); return e }, "label"},
		"bad base64": {write("bad64.pub", "riven-x25519-public\nnot base64!!!\n"),
			func(p string) error { _, e := readPublicKey(p); return e }, "base64"},
		"empty": {write("empty.pub", ""),
			func(p string) error { _, e := readPublicKey(p); return e }, "no key data"},
		"missing file": {filepath.Join(dir, "absent.pub"),
			func(p string) error { _, e := readPublicKey(p); return e }, ""},
		"mislabelled body": {write("wrongtype.pub",
			"riven-p256-public\n"+strings.SplitN(string(good), "\n", 2)[1]),
			func(p string) error { _, e := readPublicKey(p); return e }, "p256"},
	}
	for name, c := range cases {
		err := c.read(c.path)
		if err == nil {
			t.Fatalf("%s should be refused", name)
		}
		if c.hasErr != "" && !strings.Contains(err.Error(), c.hasErr) {
			t.Fatalf("%s: message %q should mention %q", name, err, c.hasErr)
		}
	}
}

// TestKeyFileIgnoresCommentsAndBlanks checks the file stays readable after a
// user adds a note to it, which is the likely thing to happen to a key file.
func TestKeyFileIgnoresCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	priv, err := kem.Generate(kem.Default())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "k.pub")
	if err := writePublicKey(path, priv.Public()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	annotated := "# alice, generated 2026\n\n" + string(body) + "\n# end\n"
	annotatedPath := filepath.Join(dir, "annotated.pub")
	if err := os.WriteFile(annotatedPath, []byte(annotated), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPublicKey(annotatedPath)
	if err != nil {
		t.Fatalf("comments and blank lines should be ignored: %v", err)
	}
	if got.Scheme() != priv.Scheme() {
		t.Fatal("wrong scheme after annotation")
	}
}
