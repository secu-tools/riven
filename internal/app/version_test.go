// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/format"
)

// A pseudo-version ends with the commit that is recorded separately, and both
// strings sit in every piece, where their length comes off the QR budget. A real
// tag is short and says something the commit does not, so it is kept.
func TestPseudoVersion(t *testing.T) {
	pseudo := []string{
		"v0.0.0-20260901064216-cea8ee0c0cad",
		"v0.0.0-20260901064216-cea8ee0c0cad+dirty",
		"v1.2.4-0.20260901064216-abcdef123456",
	}
	for _, v := range pseudo {
		if !pseudoVersion(v) {
			t.Errorf("pseudoVersion(%q) = false, want true", v)
		}
	}

	real := []string{
		"v1.2.3", "v1.2.3+dirty", "v0.1.0-beta.1", "1.0.0", "dev", "",
		"v1.2.3-20260901064216-tooshort",     // commit prefix not 12 chars
		"v1.2.3-2026090106421-cea8ee0c0cad",  // timestamp not 14 digits
		"v1.2.3-2026090x064216-cea8ee0c0cad", // timestamp not all digits
	}
	for _, v := range real {
		if pseudoVersion(v) {
			t.Errorf("pseudoVersion(%q) = true, want false", v)
		}
	}
}

// Every piece carries these strings, and format.Encode rejects one over the
// limit, so a long module version must not be able to fail a split.
func TestCreatorFieldsFitTheFormat(t *testing.T) {
	if got := clampCreator(strings.Repeat("x", format.MaxCreatorLen+50)); len(got) > format.MaxCreatorLen {
		t.Fatalf("clampCreator returned %d bytes, over the %d limit", len(got), format.MaxCreatorLen)
	}
	if got := clampCreator("v1.2.3.9"); got != "v1.2.3.9" {
		t.Fatalf("clampCreator changed a short value: %q", got)
	}
	if len(creatorVersion()) > format.MaxCreatorLen {
		t.Fatalf("creatorVersion() is %d bytes, over the limit", len(creatorVersion()))
	}
	if len(creatorCommit()) > format.MaxCreatorLen {
		t.Fatalf("creatorCommit() is %d bytes, over the limit", len(creatorCommit()))
	}
}
