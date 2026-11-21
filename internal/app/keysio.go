// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/pieceio"
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
	return pieceio.Write(path, []byte(body))
}

// writeKeyPair writes a new key pair to pubPath and privPath, refusing to
// replace a key file that is already at either: see refuseKeyOverwrite.
func writeKeyPair(opts *cliOptions, priv *kem.PrivateKey, pubPath, privPath string) error {
	for _, p := range []string{pubPath, privPath} {
		if err := refuseKeyOverwrite(opts, p); err != nil {
			return err
		}
	}
	if err := writePublicKey(pubPath, priv.Public()); err != nil {
		return err
	}
	return writePrivateKey(privPath, priv)
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
// its label. A private key file holds the key itself, in base64, so the file
// is read as bytes and never copied into a string, and is wiped once decoded;
// the caller wipes what is returned.
func decodeKeyBody(path string, kind keyKind) ([]byte, kem.Scheme, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	defer memory.Zero(raw)

	var scheme kem.Scheme
	haveScheme := false
	var b64 []byte

	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if bytes.HasPrefix(line, []byte("riven-")) {
			all := kem.All()
			i := slices.IndexFunc(all, func(s kem.Scheme) bool { return string(line) == kind.label(s) })
			if i < 0 {
				// A label of the other role, or an unknown scheme.
				return nil, 0, fmt.Errorf("%q is not a riven recipient %s file", path, kind.describe())
			}
			scheme, haveScheme = all[i], true
			continue
		}
		b64 = line
		break
	}

	if len(b64) == 0 {
		return nil, 0, fmt.Errorf("no key data found in %q", path)
	}
	body := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(body, b64)
	if err != nil {
		memory.Zero(body)
		return nil, 0, fmt.Errorf("%q is not valid base64: %w", path, err)
	}
	body = body[:n]
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
	// The key keeps its own copy, so the decoded bytes are wiped too.
	defer memory.Zero(b)
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
