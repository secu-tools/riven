// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"strconv"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
)

// The wizard prints a numbered list and takes either the number or the name.
// These resolvers are pure, but nothing reached them: only the interactive
// prompt calls them, and that needs a terminal.
func TestSchemeAnswerAcceptsANumberOrAName(t *testing.T) {
	all := ciphers.All()

	for i, want := range all {
		answer := strings.TrimSpace(strconv.Itoa(i + 1))
		got, err := resolveSchemeAnswer(answer, all)
		if err != nil {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if got != want.ID {
			t.Errorf("answer %q gave id %d, want %d (%s)", answer, got, want.ID, want.Name)
		}

		got, err = resolveSchemeAnswer(want.Name, all)
		if err != nil {
			t.Fatalf("answer %q: %v", want.Name, err)
		}
		if got != want.ID {
			t.Errorf("answer %q gave id %d, want %d", want.Name, got, want.ID)
		}
	}

	// Surrounding space is what a typed answer usually carries.
	if _, err := resolveSchemeAnswer("  1  ", all); err != nil {
		t.Errorf("a padded answer was rejected: %v", err)
	}
}

// A number outside the list, or anything that is not an algorithm, has to say
// so rather than resolve to something the user did not choose.
func TestSchemeAnswerRejectsWhatIsNotOnTheList(t *testing.T) {
	all := ciphers.All()
	for _, answer := range []string{"0", "-1", "99", "", "aes", "rot13", "aes-256-gcm,chacha20-poly1305"} {
		if got, err := resolveSchemeAnswer(answer, all); err == nil {
			t.Errorf("answer %q was accepted as id %d", answer, got)
		}
	}
}

// A comma or space separated list is how the advanced path names one algorithm
// per layer, mixing numbers and names.
func TestSchemeListResolvesEveryEntry(t *testing.T) {
	all := ciphers.All()
	if len(all) < 2 {
		t.Skip("needs at least two registered algorithms")
	}

	spec := all[0].Name + "," + strconv.Itoa(2)
	ids, err := resolveSchemeList(spec, all)
	if err != nil {
		t.Fatalf("%q: %v", spec, err)
	}
	if len(ids) != 2 || ids[0] != all[0].ID || ids[1] != all[1].ID {
		t.Fatalf("%q gave %v, want [%d %d]", spec, ids, all[0].ID, all[1].ID)
	}

	if _, err := resolveSchemeList("", all); err == nil {
		t.Error("an empty list was accepted")
	}
	if _, err := resolveSchemeList("aes-256-gcm, nonsense", all); err == nil {
		t.Error("a list holding an unknown name was accepted")
	}
}

// schemeByName must name exactly one algorithm: ParseList would happily take a
// comma separated spec, which is not an answer to "which one".
func TestSchemeByNameTakesExactlyOne(t *testing.T) {
	for _, s := range ciphers.All() {
		got, err := schemeByName(s.Name)
		if err != nil {
			t.Errorf("%s: %v", s.Name, err)
			continue
		}
		if got.ID != s.ID {
			t.Errorf("%s resolved to id %d", s.Name, got.ID)
		}
	}
	for _, bad := range []string{"", "nope", "aes-256-gcm,chacha20-poly1305"} {
		if _, err := schemeByName(bad); err == nil {
			t.Errorf("%q was accepted as a single algorithm", bad)
		}
	}
}
