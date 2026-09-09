// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package format

import (
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/kdf"
)

// The creator fields are printed by `riven info`, and a keyless piece can be
// written by anyone, since its envelope key is a public function of the salt.
// Raw bytes would therefore let a crafted file drive the reader's terminal with
// escape sequences, directly above a line reporting the piece as intact.
func TestCreatorFieldsAreNotPassedThroughToTheTerminal(t *testing.T) {
	evil := "\x1b]0;PWNED\x07\x1b[31mriven 9.9 - VERIFIED\x1b[0m"
	piece, err := Encode(EncodeInput{
		SetID:          make([]byte, SetIDLen),
		K:              2,
		N:              3,
		Serial:         1,
		Keyless:        true,
		PayloadLen:     10,
		PayloadHash:    make([]byte, hashLen),
		Share:          []byte("xxxxxxxxxx"),
		CreatorVersion: evil,
		CreatorCommit:  "\x1b[32mdeadbeef",
		Params:         kdf.Default(),
	})
	if err != nil {
		t.Fatal(err)
	}

	m, _, err := Decode(piece, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range []string{m.CreatorVersion, m.CreatorCommit} {
		if strings.ContainsRune(got, 0x1b) {
			t.Errorf("an escape character survived into %q", got)
		}
		for _, r := range got {
			if r < 0x20 || r > 0x7e {
				t.Errorf("%q holds a non-printable rune %U", got, r)
			}
		}
	}
	if len(m.CreatorVersion) != len(evil) {
		t.Errorf("sanitising changed the length: %d, want %d", len(m.CreatorVersion), len(evil))
	}
}

// An ordinary version and commit must come back untouched.
func TestOrdinaryCreatorFieldsRoundTrip(t *testing.T) {
	piece, err := Encode(EncodeInput{
		SetID:          make([]byte, SetIDLen),
		K:              2,
		N:              3,
		Serial:         1,
		Keyless:        true,
		PayloadLen:     10,
		PayloadHash:    make([]byte, hashLen),
		Share:          []byte("xxxxxxxxxx"),
		CreatorVersion: "v1.2.3.9",
		CreatorCommit:  "cea8ee0c0cad+dirty",
		Params:         kdf.Default(),
	})
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := Decode(piece, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.CreatorVersion != "v1.2.3.9" || m.CreatorCommit != "cea8ee0c0cad+dirty" {
		t.Fatalf("round trip changed the fields: %q / %q", m.CreatorVersion, m.CreatorCommit)
	}
}
