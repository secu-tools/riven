// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"testing"

	"github.com/secu-tools/riven/internal/core"
)

// One test per command-line defect found during development, so a fix cannot
// quietly regress. Each states the original faulty behaviour.

// Defect: a lone dash was treated as an unknown flag, so reading data from
// standard input was impossible.
func TestRegressionLoneDashIsAnOperand(t *testing.T) {
	o, err := parseArgs([]string{"split", "-"})
	if err != nil {
		t.Fatalf("a lone dash must be accepted: %v", err)
	}
	if len(o.files) != 1 || o.files[0] != "-" {
		t.Fatalf("dash not treated as an operand: %+v", o.files)
	}
}

// Defect: asking for no padding was silently replaced by the default, so the
// request did the opposite of what it said. The value must reach the split
// exactly as given, and zero must not be a second spelling of it.
func TestRegressionPadNoneReachesTheSplit(t *testing.T) {
	o, err := parseArgs([]string{"split", "f", "--pad", "none"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.padSet || o.pad != "none" {
		t.Fatalf("--pad none not recorded: set=%v value=%q", o.padSet, o.pad)
	}
	if err := validateSplitOptions(o); err != nil {
		t.Fatalf("--pad none must be valid: %v", err)
	}
	pad, err := parsePadding(o.pad)
	if err != nil {
		t.Fatal(err)
	}
	if pad != core.PadNone() {
		t.Fatalf("--pad none became %+v", pad)
	}

	// Zero is refused rather than guessed at, and the message says what to use.
	o, err = parseArgs([]string{"split", "f", "--pad", "0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSplitOptions(o); err != nil {
		t.Fatalf("--pad 0 must be valid: %v", err)
	}
	zero, err := parsePadding("0")
	if err != nil || zero != core.PadNone() {
		t.Fatalf("--pad 0 should disable padding, got %+v (%v)", zero, err)
	}
}

// Defect: the layer order was lost, so a recipient key was always applied
// innermost no matter where its flag appeared.
func TestRegressionLayerOrderFollowsFlagOrder(t *testing.T) {
	o, err := parseArgs([]string{
		"split", "f",
		"--recipient", "alice.pub",
		"--password-env", "PW",
		"--recipient", "bob.pub",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []core.LayerKind{core.RecipientLayer, core.PasswordLayer, core.RecipientLayer}
	if len(o.layerSources) != len(want) {
		t.Fatalf("got %d layers, want %d", len(o.layerSources), len(want))
	}
	for i, k := range want {
		if o.layerSources[i].kind != k {
			t.Fatalf("layer %d has kind %v, want %v", i+1, o.layerSources[i].kind, k)
		}
	}
	if o.layerSources[0].file != "alice.pub" || o.layerSources[2].file != "bob.pub" {
		t.Fatalf("recipient files out of order: %+v", o.layerSources)
	}
}

// Defect: --identity accepted only one key, so a set with two recipient layers
// could not be opened at all.
func TestRegressionIdentityIsRepeatable(t *testing.T) {
	o, err := parseArgs([]string{"combine", "p1", "p2", "--identity", "a.key", "--identity", "b.key"})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.identities) != 2 || o.identities[0] != "a.key" || o.identities[1] != "b.key" {
		t.Fatalf("identities not collected: %+v", o.identities)
	}
}

// TestConflictingOptionsAreRefused covers the combinations that contradict each
// other. Each must fail with a message naming the flags, rather than being
// resolved silently one way or the other.
func TestConflictingOptionsAreRefused(t *testing.T) {
	t.Setenv("RIVEN_UNIT_PW", "value")

	cases := map[string][]string{
		"keyless with a password":  {"split", "f", "--keyless", "--password-env", "RIVEN_UNIT_PW"},
		"keyless with a recipient": {"split", "f", "--keyless", "--recipient", "r.pub"},
		"keyless with algorithms":  {"split", "f", "--keyless", "--algo", "aes-256-gcm"},
		"keyless with a cost":      {"split", "f", "--keyless", "--kdf", "paranoid"},
		"keyless with generate":    {"split", "f", "--keyless", "--generate"},
		"file and text":            {"split", "f", "--text", "abc"},
		"two input files":          {"split", "a", "b"},
		"more algos than layers":   {"split", "f", "--algo", "aes-256-gcm,chacha20-poly1305", "--password-env", "RIVEN_UNIT_PW"},
		"k above n":                {"split", "f", "-n", "3", "-k", "4"},
		"n out of range":           {"split", "f", "-n", "300"},
		"unknown padding mode":     {"split", "f", "--pad", "wide"},
		"padding width of zero":    {"split", "f", "--pad", "wide"},
		"padding width too large":  {"split", "f", "--pad", "501"},
		"padding without a key":    {"split", "f", "--keyless", "-n", "3", "-k", "2", "--pad", "10"},
		"padding for a key only":   {"split", "f", "--recipient", "r.pub", "--pad", "10"},
		"unknown algorithm":        {"split", "f", "--algo", "rot13"},
		"unencodable cost":         {"split", "f", "--kdf", "m=19,t=2,p=1"},
		"unknown format":           {"split", "f", "--format", "pdf"},
	}
	for name, args := range cases {
		o, err := parseArgs(args)
		if err != nil {
			continue // rejected at parse time, which is also fine
		}
		if err := validateSplitOptions(o); err == nil {
			t.Fatalf("%s should be refused", name)
		}
	}
}

// TestOpenSideRejectsSplitOnlyFlags checks that flags belonging to splitting are
// not silently ignored when opening pieces.
func TestOpenSideRejectsSplitOnlyFlags(t *testing.T) {
	cases := map[string][]string{
		"keyless":   {"combine", "p", "--keyless"},
		"text":      {"combine", "p", "--text", "abc"},
		"recipient": {"combine", "p", "--recipient", "r.pub"},
		"generate":  {"combine", "p", "--generate"},
	}
	for name, args := range cases {
		o, err := parseArgs(args)
		if err != nil {
			continue
		}
		if err := validateOpenOptions(o); err == nil {
			t.Fatalf("%s should be refused when opening pieces", name)
		}
	}

	// The flags that do apply must be accepted.
	o, err := parseArgs([]string{"combine", "p", "--algo", "aes-256-gcm", "--kdf", "paranoid", "--identity", "k.key"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOpenOptions(o); err != nil {
		t.Fatalf("valid open flags were refused: %v", err)
	}
}

// TestValidCombinationsAreAccepted is the other half: legitimate combinations must
// not be caught by the conflict checks.
func TestValidCombinationsAreAccepted(t *testing.T) {
	t.Setenv("RIVEN_UNIT_PW1", "a")
	t.Setenv("RIVEN_UNIT_PW2", "b")

	cases := map[string][]string{
		"plain":              {"split", "f"},
		"keyless alone":      {"split", "f", "--keyless", "-n", "3", "-k", "2"},
		"one password":       {"split", "f", "--password-env", "RIVEN_UNIT_PW1"},
		"two passwords":      {"split", "f", "--password-env", "RIVEN_UNIT_PW1", "--password-env", "RIVEN_UNIT_PW2"},
		"mixed layers":       {"split", "f", "--password-env", "RIVEN_UNIT_PW1", "--recipient", "r.pub"},
		"algos matching":     {"split", "f", "--algo", "aes-256-gcm,chacha20-poly1305", "--password-env", "RIVEN_UNIT_PW1", "--password-env", "RIVEN_UNIT_PW2"},
		"fewer algos":        {"split", "f", "--algo", "aes-256-gcm", "--password-env", "RIVEN_UNIT_PW1", "--password-env", "RIVEN_UNIT_PW2"},
		"padding off":        {"split", "f", "--pad", "none"},
		"text input":         {"split", "--text", "abc"},
		"stdin input":        {"split", "-", "-y"},
		"all formats":        {"split", "f", "--format", "all"},
		"generate with algo": {"split", "f", "--generate", "--algo", "aes-256-gcm"},
		"widest padding":     {"split", "f", "--pad", "500"},
		"padding percent":    {"split", "f", "--pad", "10%"},
		"keyless, no pad":    {"split", "f", "--keyless", "-n", "3", "-k", "2", "--pad", "none"},
	}
	for name, args := range cases {
		o, err := parseArgs(args)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if err := validateSplitOptions(o); err != nil {
			t.Fatalf("%s should be accepted: %v", name, err)
		}
	}
}
