// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// capture returns whatever fn prints to standard output.
func capture(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	// Drain while fn runs: the usage text is larger than a pipe buffer, so
	// reading afterwards would deadlock.
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	os.Stdout = old
	out := <-done
	r.Close()
	return out
}

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
		"--pad", "--pub", "--priv", "-y",
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

func TestFormatNames(t *testing.T) {
	got := formatNames()
	for _, f := range pieceio.All() {
		if !strings.Contains(got, f.String()) {
			t.Fatalf("formatNames is missing %q", f)
		}
	}
}

func TestJoinHelpers(t *testing.T) {
	if got := joinUint32([]uint32{1, 16, 1024}); got != "1/16/1024" {
		t.Fatalf("joinUint32 gave %q", got)
	}
	if got := joinUint8([]uint8{1, 2, 4}); got != "1/2/4" {
		t.Fatalf("joinUint8 gave %q", got)
	}
	if got := joinUint32(nil); got != "" {
		t.Fatalf("joinUint32(nil) gave %q", got)
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
