// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keyTypes are the recipient key types the binary offers, in the order the help
// text lists them.
var keyTypes = []string{"x-wing", "ml-kem-768", "ml-kem-1024", "x25519", "p256", "p384"}

// TestRecipientKeyTypes covers every recipient key type through the binary: the
// key type is the argument after the command, both key files label their type,
// the split summary names it, and the round trip works.
func TestRecipientKeyTypes(t *testing.T) {
	for _, kind := range keyTypes {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			secret := []byte(kind + " payload")
			in := writeFile(t, dir, "m.bin", secret)
			pub := filepath.Join(dir, "r.pub")
			priv := filepath.Join(dir, "r.key")
			out := filepath.Join(dir, "o")

			o, err := riven(t, nil, "keygen", kind, "--pub", pub, "--priv", priv, "-y")
			if err != nil {
				t.Fatalf("keygen: %v\n%s", err, o)
			}
			if !strings.Contains(o, kind) {
				t.Fatalf("keygen should name the key type:\n%s", o)
			}

			// Both files carry the type, which is what tells two key files apart.
			for _, f := range []struct{ path, label string }{
				{pub, "riven-" + kind + "-public"},
				{priv, "riven-" + kind + "-private"},
			} {
				body, err := os.ReadFile(f.path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(body, []byte(f.label)) {
					t.Fatalf("%s is missing the label %q:\n%s", f.path, f.label, body)
				}
			}

			o, err = riven(t, env1, "split", in, "-n", "3", "-k", "2",
				"--password-env", flagPw1, "--recipient", pub, "--identity", priv,
				"--out", out, "-y")
			if err != nil {
				t.Fatalf("split: %v\n%s", err, o)
			}
			if !strings.Contains(o, kind) {
				t.Fatalf("summary should name the key type:\n%s", o)
			}

			got, _, err := rivenRaw(t, env1, "combine",
				filepath.Join(out, "m.bin.1"), filepath.Join(out, "m.bin.2"),
				"--password-env", flagPw1, "--identity", priv, "-y")
			if err != nil {
				t.Fatalf("combine: %v", err)
			}
			if !bytes.Equal(got, secret) {
				t.Fatalf("got %q", got)
			}
		})
	}
}

// TestRecipientKeyCost checks the trade-off the key type exists for: the
// encapsulated key rides in every piece, so a classical key gives far smaller
// pieces than a post-quantum one. That is what decides whether a recipient set
// can be exported as QR at all.
func TestRecipientKeyCost(t *testing.T) {
	dir := t.TempDir()
	data := make([]byte, 200)
	rand.Read(data)
	in := writeFile(t, dir, "c.bin", data)

	sizeFor := func(kind string) int64 {
		pub := filepath.Join(dir, kind+".pub")
		priv := filepath.Join(dir, kind+".key")
		if o, err := riven(t, nil, "keygen", kind, "--pub", pub, "--priv", priv, "-y"); err != nil {
			t.Fatalf("keygen %s: %v\n%s", kind, err, o)
		}
		out := filepath.Join(dir, "o-"+kind)
		if o, err := riven(t, nil, "split", in, "-n", "2", "-k", "2",
			"--recipient", pub, "--identity", priv, "--out", out, "-y"); err != nil {
			t.Fatalf("split %s: %v\n%s", kind, err, o)
		}
		fi, err := os.Stat(filepath.Join(out, "c.bin.1"))
		if err != nil {
			t.Fatal(err)
		}
		return fi.Size()
	}

	small := sizeFor("x25519")
	hybrid := sizeFor("x-wing")
	big := sizeFor("ml-kem-1024")
	if small >= hybrid || hybrid >= big {
		t.Fatalf("piece sizes should grow x25519 < x-wing < ml-kem-1024, got %d, %d, %d",
			small, hybrid, big)
	}

	// The classical piece fits a QR code at the strongest error correction level
	// (1272 bytes); the largest post-quantum one cannot fit there at all.
	const strongestQR = 1272
	if small > strongestQR {
		t.Fatalf("an x25519 piece of %d bytes should fit a QR code at level H", small)
	}
	if big <= strongestQR {
		t.Fatalf("an ml-kem-1024 piece of %d bytes was expected to exceed level H", big)
	}
}

// TestWrongRecipientKeyRejected checks that a key of another type fails with a
// message naming the mismatch rather than silently producing garbage.
func TestWrongRecipientKeyRejected(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("the key type must match")
	in := writeFile(t, dir, "m.bin", secret)

	pubA, privA := filepath.Join(dir, "a.pub"), filepath.Join(dir, "a.key")
	privB := filepath.Join(dir, "b.key")
	if _, err := riven(t, nil, "keygen", "ml-kem-1024", "--pub", pubA, "--priv", privA, "-y"); err != nil {
		t.Fatal(err)
	}
	if _, err := riven(t, nil, "keygen", "ml-kem-768",
		"--pub", filepath.Join(dir, "b.pub"), "--priv", privB, "-y"); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "o")
	if _, err := riven(t, nil, "split", in, "-n", "2", "-k", "2",
		"--recipient", pubA, "--identity", privA, "--out", out, "-y"); err != nil {
		t.Fatal(err)
	}

	o, err := riven(t, nil, "combine", filepath.Join(out, "m.bin.1"), filepath.Join(out, "m.bin.2"),
		"--identity", privB, "--out", filepath.Join(dir, "x"), "-y")
	if err == nil {
		t.Fatal("an ml-kem-768 key should not open an ml-kem-1024 set")
	}
	if !strings.Contains(o, "1568") || !strings.Contains(o, "1088") {
		t.Fatalf("the error should name both encapsulated key sizes:\n%s", o)
	}
}

// TestUnknownKeyTypeRejected checks an unsupported key type is refused before
// anything is written, and that the message lists what is supported.
func TestUnknownKeyTypeRejected(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"rsa", "ed25519", "pgp", "ml-kem-512"} {
		o, err := riven(t, nil, "keygen", bad,
			"--pub", filepath.Join(dir, "x.pub"), "--priv", filepath.Join(dir, "x.key"), "-y")
		if err == nil {
			t.Fatalf("keygen %s should be refused", bad)
		}
		if !strings.Contains(o, "x25519") {
			t.Fatalf("the message should list the supported types:\n%s", o)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "x.pub")); err == nil {
		t.Fatal("a refused keygen must not write a key file")
	}
}

// TestKeyFileLabelMismatch checks a key file whose label does not match its
// contents is refused, since that is what the label is for.
func TestKeyFileLabelMismatch(t *testing.T) {
	dir := t.TempDir()
	pub := filepath.Join(dir, "r.pub")
	priv := filepath.Join(dir, "r.key")
	if _, err := riven(t, nil, "keygen", "x25519", "--pub", pub, "--priv", priv, "-y"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	swapped := bytes.Replace(body, []byte("riven-x25519-public"), []byte("riven-p256-public"), 1)
	bad := filepath.Join(dir, "bad.pub")
	if err := os.WriteFile(bad, swapped, 0o600); err != nil {
		t.Fatal(err)
	}

	in := writeFile(t, dir, "m.bin", []byte("label must match"))
	o, err := riven(t, nil, "split", in, "-n", "2", "-k", "2",
		"--recipient", bad, "--out", filepath.Join(dir, "o"), "-y")
	if err == nil {
		t.Fatalf("a mislabelled key file should be refused:\n%s", o)
	}
	if !strings.Contains(o, "p256") || !strings.Contains(o, "x25519") {
		t.Fatalf("the message should name the label and the real type:\n%s", o)
	}
}
