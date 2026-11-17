// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// TestUsageListsEveryChoice checks the help text is generated from the same
// registries the code uses, so a newly registered algorithm, key type, preset or
// export format cannot be left undocumented.
func TestUsageListsEveryChoice(t *testing.T) {
	out := capture(t, printUsage)

	for _, name := range ciphers.Names() {
		if !strings.Contains(out, name) {
			t.Fatalf("help does not list the algorithm %q", name)
		}
	}
	for _, s := range kem.All() {
		if !strings.Contains(out, s.Name()) {
			t.Fatalf("help does not list the key type %q", s.Name())
		}
	}
	for _, p := range kdf.PresetNames() {
		if !strings.Contains(out, p) {
			t.Fatalf("help does not list the Argon2 preset %q", p)
		}
	}
	for _, f := range pieceio.All() {
		if !strings.Contains(out, f.String()) {
			t.Fatalf("help does not list the export format %q", f)
		}
	}
	if !strings.Contains(out, strconv.Itoa(pieceio.QRMaxBytes)) {
		t.Fatal("help does not state the QR capacity")
	}
}

// TestUsageCoversEveryFlag checks each flag the parser accepts is documented,
// because an undocumented flag is one nobody can use.
func TestUsageCoversEveryFlag(t *testing.T) {
	out := capture(t, printUsage)
	flags := []string{
		"-n", "-k", "--algo", "--keyless", "--text", "--text-env", "--name",
		"--password-env", "--generate", "--recipient", "--identity",
		"--out", "--format", "--qr-scale", "--kdf",
		"--record-algo", "--record-kdf",
		"--pad", "--pub", "--priv", "-y", "--no-color",
	}
	for _, f := range flags {
		if !strings.Contains(out, f) {
			t.Fatalf("help does not document %q", f)
		}
	}
	for _, cmd := range []string{"split", "combine", "info", "keygen"} {
		if !strings.Contains(out, "riven "+cmd) {
			t.Fatalf("help does not show the %q command", cmd)
		}
	}
	// version and help share one synopsis line.
	if !strings.Contains(out, "riven version | help") {
		t.Fatal("help does not show the version and help commands")
	}
}

// TestUsageDoesNotAdvertiseWhatWasRemoved guards against the help text drifting
// back to options the parser no longer accepts.
func TestUsageDoesNotAdvertiseWhatWasRemoved(t *testing.T) {
	out := capture(t, printUsage)
	for _, gone := range []string{"--jitter", "--password-file", "--kem ", "--pure",
		"--no-record-algo", "--no-record-kdf"} {
		if strings.Contains(out, gone) {
			t.Fatalf("help still mentions the removed %q", gone)
		}
	}
}

func TestKeygenTypeListStatesTheCost(t *testing.T) {
	list := keygenTypeList()
	for _, s := range kem.All() {
		if !strings.Contains(list, s.Name()) {
			t.Fatalf("key type %q is missing", s.Name())
		}
		if !strings.Contains(list, strconv.Itoa(s.CiphertextSize())) {
			t.Fatalf("key type %q does not state its per-piece cost", s.Name())
		}
	}
}

// TestUsageListsEveryFormat checks the help names every export format, in one
// list under its heading.
func TestUsageListsEveryFormat(t *testing.T) {
	usage := capture(t, printUsage)
	_, list, found := strings.Cut(usage, "EXPORT FORMATS\n")
	if !found {
		t.Fatalf("the help has no export formats section:\n%s", usage)
	}
	list, _, _ = strings.Cut(list, "\n")
	for _, f := range pieceio.All() {
		if !slices.Contains(strings.Split(strings.TrimSpace(list), ", "), f.String()) {
			t.Fatalf("the help's format list %q is missing %q", list, f)
		}
	}
}

func TestJoinHelpers(t *testing.T) {
	if got := joinChoices([]uint32{1, 16, 1024}); got != "1/16/1024" {
		t.Fatalf("joinChoices gave %q", got)
	}
	if got := joinChoices([]uint8{1, 2, 4}); got != "1/2/4" {
		t.Fatalf("joinChoices gave %q", got)
	}
	if got := joinChoices[uint32](nil); got != "" {
		t.Fatalf("joinChoices(nil) gave %q", got)
	}
}

func TestVersionIsReported(t *testing.T) {
	if Version() == "" {
		t.Fatal("version must not be empty")
	}
	out := capture(t, func() {
		if err := run([]string{"version"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, Version()) {
		t.Fatalf("version output %q does not carry %q", out, Version())
	}
}

// TestRunDispatch checks the top-level command routing, including the unknown
// command message and the help flags.
func TestRunDispatch(t *testing.T) {
	out := capture(t, func() {
		if err := run([]string{"help"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "USAGE") {
		t.Fatal("help should print the usage text")
	}

	out = capture(t, func() {
		if err := run([]string{"--help"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "USAGE") {
		t.Fatal("--help should print the usage text")
	}

	if err := run([]string{"frobnicate"}); err == nil {
		t.Fatal("an unknown command must fail")
	} else if !strings.Contains(err.Error(), "frobnicate") {
		t.Fatalf("the error should name the command: %v", err)
	}
}
