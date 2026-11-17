// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package cascade

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/kem"
)

// twoLayerPayload is a short payload under a password layer and a recipient
// layer, with what opens it.
func twoLayerPayload(t *testing.T) (payload []byte, pws [][]byte, decaps []Decapsulator) {
	t.Helper()
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	ss, ct, err := priv.Public().Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	payload, err = encrypt([]byte("short"), []Layer{
		{Kind: Password, SchemeID: 1, Password: []byte("pw")},
		{Kind: KEM, SchemeID: 2, KEMSecret: ss, KEMCiphertext: ct},
	}, fastProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	return payload, [][]byte{[]byte("pw")}, []Decapsulator{func(c []byte) ([]byte, error) { return priv.Decapsulate(c) }}
}

// TestEveryTruncationIsRefused cuts a payload at every length short of whole.
// Each must be refused, as a header that ends early or a layer that does not
// open, and none may be read past its end.
func TestEveryTruncationIsRefused(t *testing.T) {
	payload, pws, decaps := twoLayerPayload(t)
	if _, err := decrypt(payload, pws, decaps, fastProfile, nil); err != nil {
		t.Fatal(err)
	}
	for n := range len(payload) {
		if _, err := decrypt(payload[:n], pws, decaps, fastProfile, nil); err == nil {
			t.Fatalf("a payload cut to %d of %d bytes opened", n, len(payload))
		}
	}
}

// TestAMalformedHeaderIsRefused covers a header naming what this build cannot
// use: another version, an algorithm it does not have, and a kind of layer it
// does not know. Each is named, rather than reported as a wrong password.
func TestAMalformedHeaderIsRefused(t *testing.T) {
	payload, pws, decaps := twoLayerPayload(t)
	// The header is the version, the layer count, then each layer's kind and
	// algorithm id.
	for name, c := range map[string]struct {
		at   int
		to   byte
		pws  [][]byte
		want string
	}{
		"version":   {0, 9, pws, "unsupported header version"},
		"algorithm": {4, 250, pws, "unknown scheme id 250"},
		// No longer a password layer, so it takes no password.
		"kind": {3, 9, nil, "unknown layer kind 9"},
	} {
		bad := bytes.Clone(payload)
		bad[c.at] = c.to
		_, err := decrypt(bad, c.pws, decaps, fastProfile, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error saying %q", name, err, c.want)
		}
	}
}

// TestThePasswordCountMustMatch checks a payload is not tried with fewer or
// more passwords than it has password layers: that is a mistake to name, not a
// wrong password.
func TestThePasswordCountMustMatch(t *testing.T) {
	payload, _, decaps := twoLayerPayload(t)
	for _, pws := range [][][]byte{nil, {[]byte("pw"), []byte("extra")}} {
		_, err := decrypt(payload, pws, decaps, fastProfile, nil)
		if err == nil || !strings.Contains(err.Error(), "need 1 passwords") {
			t.Errorf("%d passwords: %v", len(pws), err)
		}
	}
}

// TestTooManyLayersAreRefused checks the layer count is bounded by what the
// header's one byte can count.
func TestTooManyLayersAreRefused(t *testing.T) {
	layers := make([]Layer, maxLayers+1)
	for i := range layers {
		layers[i] = Layer{Kind: Password, SchemeID: 1, Password: []byte("pw")}
	}
	if _, err := Len(10, layers); err == nil || !strings.Contains(err.Error(), "too many layers") {
		t.Fatalf("%d layers: %v", len(layers), err)
	}
}

// TestAKeyThatCannotDecapsulateIsNamed checks a recipient layer that no key
// opens reports why the last key failed, which is usually that it is of
// another type, and that a key giving no secret at all is refused rather than
// used to derive one.
func TestAKeyThatCannotDecapsulateIsNamed(t *testing.T) {
	payload, pws, _ := twoLayerPayload(t)
	failing := []Decapsulator{func([]byte) ([]byte, error) { return nil, errors.New("a p256 key cannot read this") }}
	_, err := decrypt(payload, pws, failing, fastProfile, nil)
	if !errors.Is(err, ErrKeyRequired) || !strings.Contains(err.Error(), "a p256 key cannot read this") {
		t.Fatalf("got %v", err)
	}
	empty := []Decapsulator{func([]byte) ([]byte, error) { return []byte{}, nil }}
	if _, err := decrypt(payload, pws, empty, fastProfile, nil); err == nil || !strings.Contains(err.Error(), "empty KEM shared secret") {
		t.Fatalf("an empty shared secret: %v", err)
	}
}
