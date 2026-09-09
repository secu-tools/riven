// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/memory"
)

// Key files name their scheme in the first line. Key lengths happen to be
// distinct per scheme, but the label is what decides, so a mismatch is reported
// rather than guessed at.
func pubKeyLabel(s kem.Scheme) string  { return "riven-" + s.Name() + "-public" }
func privKeyLabel(s kem.Scheme) string { return "riven-" + s.Name() + "-private" }

// writePublicKey writes a shareable recipient public key file.
func writePublicKey(path string, pub *kem.PublicKey) error {
	body := pubKeyLabel(pub.Scheme()) + "\n" +
		base64.StdEncoding.EncodeToString(pub.Bytes()) + "\n"
	return os.WriteFile(path, []byte(body), 0o644)
}

// writePrivateKey writes a secret recipient private key file with restrictive
// permissions.
func writePrivateKey(path string, priv *kem.PrivateKey) error {
	raw, err := priv.Bytes()
	if err != nil {
		return err
	}
	body := privKeyLabel(priv.Scheme()) + "\n" +
		base64.StdEncoding.EncodeToString(raw) + "\n" +
		"# keep this file secret; anyone with it can decrypt pieces sent to you\n"
	memory.Zero(raw)
	return writeSecret(path, []byte(body))
}

// writeSecret writes a file that must not be readable by other users.
//
// os.WriteFile applies its mode only when it creates the file, so writing over
// an existing world-readable file would silently keep that mode. The mode is set
// explicitly instead. Windows has no POSIX modes and governs access by inherited
// ACLs, so the Chmod is best effort there.
func writeSecret(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_ = f.Chmod(0o600)
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// keyKind distinguishes the two file roles.
type keyKind int

const (
	kindPublic keyKind = iota
	kindPrivate
)

func (k keyKind) label(s kem.Scheme) string {
	if k == kindPrivate {
		return privKeyLabel(s)
	}
	return pubKeyLabel(s)
}

func (k keyKind) describe() string {
	if k == kindPrivate {
		return "private key"
	}
	return "public key"
}

// decodeKeyBody reads a key file, returning its bytes and the scheme named by
// its label.
func decodeKeyBody(path string, kind keyKind) ([]byte, kem.Scheme, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	scheme := kem.Default()
	haveScheme := false
	var b64 string

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "riven-") {
			matched := false
			for _, s := range kem.All() {
				if line == kind.label(s) {
					scheme, haveScheme, matched = s, true, true
					break
				}
			}
			if matched {
				continue
			}
			// A label of the other role, or an unknown scheme.
			return nil, 0, fmt.Errorf("%q is not a riven recipient %s file", path, kind.describe())
		}
		b64 = line
		break
	}

	if b64 == "" {
		return nil, 0, fmt.Errorf("no key data found in %q", path)
	}
	body, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, 0, fmt.Errorf("%q is not valid base64: %w", path, err)
	}
	if !haveScheme {
		return nil, 0, fmt.Errorf("%q has no riven key label, so its key type is unknown", path)
	}
	return body, scheme, nil
}

// readPublicKey loads a recipient public key.
func readPublicKey(path string) (*kem.PublicKey, error) {
	b, scheme, err := decodeKeyBody(path, kindPublic)
	if err != nil {
		return nil, err
	}
	pub, err := kem.PublicFromBytes(b, scheme)
	if err != nil {
		// A length matching a different scheme means the label is wrong, which is
		// worth saying plainly.
		if other := kem.SchemeForPublicKeySize(len(b)); len(other) == 1 && other[0] != scheme {
			return nil, fmt.Errorf("%q is labelled %s but holds a %s key", path, scheme.Name(), other[0].Name())
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pub, nil
}

// readPrivateKey loads a recipient private key.
func readPrivateKey(path string) (*kem.PrivateKey, error) {
	b, scheme, err := decodeKeyBody(path, kindPrivate)
	if err != nil {
		return nil, err
	}
	priv, err := kem.PrivateFromBytes(b, scheme)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return priv, nil
}

// Key file extensions. inputs.go steps over both when scanning a directory for
// pieces, so the two places agree by construction.
const (
	extPubKey  = ".pub"
	extPrivKey = ".key"
)

// keyPaths resolves where a generated key pair is written. pub and priv come
// from --pub and --priv: they name exact paths and are used as given. Whichever
// is empty is built from base inside dir, which is empty for the current
// directory.
func keyPaths(dir, base, pub, priv string) (pubPath, privPath string) {
	if pub == "" {
		pub = filepath.Join(dir, base+extPubKey)
	}
	if priv == "" {
		priv = filepath.Join(dir, base+extPrivKey)
	}
	return pub, priv
}
