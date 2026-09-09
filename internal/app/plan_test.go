// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// planFor resolves a command line into a split plan the way a non-interactive
// run does, which is the path every scripted use takes.
func planFor(t *testing.T, args ...string) *splitPlan {
	t.Helper()
	opts, err := parseArgs(append([]string{"split", "f"}, args...))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	opts.yes = true
	if err := validateSplitOptions(opts); err != nil {
		t.Fatalf("validate: %v", err)
	}
	plan, err := planSplit(opts, t.TempDir())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func TestPlanDefaults(t *testing.T) {
	plan := planFor(t)
	if plan.opts.N != 5 || plan.opts.K != 3 {
		t.Fatalf("defaults are %d of %d, want 3 of 5", plan.opts.K, plan.opts.N)
	}
	if len(plan.opts.Layers) != 1 || plan.opts.Layers[0].Kind != core.PasswordLayer {
		t.Fatalf("default should be one password layer, got %+v", plan.opts.Layers)
	}
	if len(plan.generated) != 1 {
		t.Fatalf("a password should have been generated, got %d", len(plan.generated))
	}
	if !plan.opts.RecordAlgo || !plan.opts.RecordKDF {
		t.Fatal("recording should be on by default")
	}
	if plan.opts.Params != kdf.Default() {
		t.Fatalf("cost is %+v, want the default", plan.opts.Params)
	}
	if plan.opts.Padding.Off || plan.opts.Padding.Width() != core.DefaultPadPercent {
		t.Fatalf("padding is %+v, want the default width", plan.opts.Padding)
	}
	if plan.qrScale != defaultQRScale {
		t.Fatalf("qr scale is %d, want %d", plan.qrScale, defaultQRScale)
	}
}

// TestPlanFlagsAreHonoured checks each flag reaches the split options, which is
// the parity the wizard and the command line have to keep.
func TestPlanFlagsAreHonoured(t *testing.T) {
	t.Setenv("RIVEN_UNIT_PW1", "one")
	t.Setenv("RIVEN_UNIT_PW2", "two")

	plan := planFor(t,
		"-n", "7", "-k", "4",
		"--password-env", "RIVEN_UNIT_PW1", "--password-env", "RIVEN_UNIT_PW2",
		"--algo", "aes-256-gcm,chacha20-poly1305",
		"--kdf", "m=8,t=1,p=1",
		"--record-algo", "false", "--record-kdf", "false",
		"--pad", "100",
	)
	if plan.opts.N != 7 || plan.opts.K != 4 {
		t.Fatalf("got %d of %d", plan.opts.K, plan.opts.N)
	}
	if len(plan.opts.Layers) != 2 {
		t.Fatalf("got %d layers, want 2", len(plan.opts.Layers))
	}
	if string(plan.opts.Layers[0].Password) != "one" || string(plan.opts.Layers[1].Password) != "two" {
		t.Fatal("passwords are not in flag order")
	}
	wantFirst, _ := ciphers.ParseList("aes-256-gcm")
	if plan.opts.Layers[0].SchemeID != wantFirst[0] {
		t.Fatal("the first algorithm was not applied to the first layer")
	}
	if plan.opts.RecordAlgo || plan.opts.RecordKDF {
		t.Fatal("recording should be off")
	}
	if plan.opts.Params.Memory != 8*1024 {
		t.Fatalf("cost is %+v, want the given one", plan.opts.Params)
	}
	if plan.opts.Padding.Width() != 100 {
		t.Fatalf("padding width is %d, want 100", plan.opts.Padding.Width())
	}
	if len(plan.generated) != 0 {
		t.Fatal("nothing should be generated when passwords are supplied")
	}
}

// TestPlanLayerOrderMixesKinds checks the order of --password-env and
// --recipient decides the cascade order, and that a recipient layer needs no
// password.
func TestPlanLayerOrderMixesKinds(t *testing.T) {
	t.Setenv("RIVEN_UNIT_PW1", "one")
	dir := t.TempDir()
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(dir, "r.pub")
	if err := writePublicKey(pub, priv.Public()); err != nil {
		t.Fatal(err)
	}

	plan := planFor(t, "--recipient", pub, "--password-env", "RIVEN_UNIT_PW1", "--kdf", "m=8,t=1,p=1")
	if len(plan.opts.Layers) != 2 {
		t.Fatalf("got %d layers", len(plan.opts.Layers))
	}
	if plan.opts.Layers[0].Kind != core.RecipientLayer || plan.opts.Layers[1].Kind != core.PasswordLayer {
		t.Fatal("layer order does not follow the flags")
	}
	if !plan.hasRecipient() {
		t.Fatal("hasRecipient should report the recipient layer")
	}
	if len(plan.verifyPasswords) != 1 {
		t.Fatalf("got %d verify passwords, want 1", len(plan.verifyPasswords))
	}
}

// TestPlanKeylessTakesNoPassword checks the split-only mode plans no layers and
// generates nothing.
func TestPlanKeylessTakesNoPassword(t *testing.T) {
	plan := planFor(t, "--keyless", "-n", "3", "-k", "2")
	if !plan.opts.Keyless || len(plan.opts.Layers) != 0 {
		t.Fatalf("keyless plan has %d layers", len(plan.opts.Layers))
	}
	if len(plan.generated) != 0 || len(plan.verifyPasswords) != 0 {
		t.Fatal("keyless mode must not invent a password")
	}
}

// TestPlanGeneratesOnePasswordPerLayer checks --generate covers every layer, so
// a cascade is not left with one password reused.
func TestPlanGeneratesOnePasswordPerLayer(t *testing.T) {
	plan := planFor(t, "--generate", "--algo", "aes-256-gcm,chacha20-poly1305", "--kdf", "m=8,t=1,p=1")
	if len(plan.generated) != 2 {
		t.Fatalf("generated %d passwords for 2 layers", len(plan.generated))
	}
	if bytes.Equal(plan.generated[0], plan.generated[1]) {
		t.Fatal("generated passwords repeat across layers")
	}
	for _, pw := range plan.generated {
		if len(pw) < 20 {
			t.Fatalf("generated password is only %d bytes", len(pw))
		}
	}
}

// TestPlanRejectsRepeatedPasswords covers the rule that each layer must have its
// own secret: reusing one would make the second layer free to anyone who broke
// the first.
func TestPlanRejectsRepeatedPasswords(t *testing.T) {
	t.Setenv("RIVEN_UNIT_SAME", "same-password")
	opts, err := parseArgs([]string{"split", "f",
		"--password-env", "RIVEN_UNIT_SAME", "--password-env", "RIVEN_UNIT_SAME",
		"--kdf", "m=8,t=1,p=1"})
	if err != nil {
		t.Fatal(err)
	}
	opts.yes = true
	if _, err := planSplit(opts, t.TempDir()); err == nil {
		t.Fatal("the same password on two layers must be refused")
	}
}

// TestPlanKeyTypeSelection checks the recipient key type asked for is the one
// generated, and that the default applies when none is named.
func TestPlanKeyTypeSelection(t *testing.T) {
	for _, name := range []string{"", "x25519", "ml-kem-768", "p384"} {
		opts := &cliOptions{keyType: name, yes: true}
		got, err := resolveKeyScheme(opts)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		want := kem.Default()
		if name != "" {
			want, _ = kem.Parse(name)
		}
		if got != want {
			t.Fatalf("%q resolved to %s, want %s", name, got, want)
		}
		// Not interactive, so the chooser must fall back to the same answer.
		chosen, err := chooseKeyScheme(opts)
		if err != nil || chosen != want {
			t.Fatalf("%q: chooser gave %s (%v)", name, chosen, err)
		}
	}
	if _, err := resolveKeyScheme(&cliOptions{keyType: "rsa"}); err == nil {
		t.Fatal("an unknown key type must be refused")
	}
}

// TestSplitSummaryDescribesTheSet checks the summary states what a user needs to
// recover the data: the layers in order, what keys them, and what was withheld.
func TestSplitSummaryDescribesTheSet(t *testing.T) {
	t.Setenv("RIVEN_UNIT_PW1", "one")
	dir := t.TempDir()
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(dir, "r.pub")
	if err := writePublicKey(pub, priv.Public()); err != nil {
		t.Fatal(err)
	}
	plan := planFor(t, "--password-env", "RIVEN_UNIT_PW1", "--recipient", pub,
		"--kdf", "m=8,t=1,p=1", "--record-algo", "false", "--record-kdf", "false")

	var buf bytes.Buffer
	printSplitSummary(&buf, plan, []pieceio.Format{pieceio.Binary},
		map[pieceio.Format][]string{pieceio.Binary: {"a.1", "a.2"}}, true)
	out := buf.String()
	for _, want := range []string{
		"1. ", "2. ", "password", "recipient key (x25519)",
		"Every recipient private key listed above is required",
		"Algorithms are NOT recorded", "Argon2 cost is NOT recorded",
		"a.1", "a.2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary is missing %q:\n%s", want, out)
		}
	}
}

func TestSplitSummaryForKeylessSets(t *testing.T) {
	plan := planFor(t, "--keyless", "-n", "3", "-k", "2")
	var buf bytes.Buffer
	printSplitSummary(&buf, plan, []pieceio.Format{pieceio.Binary},
		map[pieceio.Format][]string{pieceio.Binary: {"a.1"}}, true)
	out := buf.String()
	if !strings.Contains(out, "no encryption and no password") {
		t.Fatalf("keyless summary should say so:\n%s", out)
	}
	if strings.Contains(out, "Key derivation") {
		t.Fatalf("keyless summary should not mention key derivation:\n%s", out)
	}
}

// TestPaddingLineStatesWhatTheSizeReveals covers all three cases, since this is
// the line that tells a user whether the piece size is covered.
func TestPaddingLineStatesWhatTheSizeReveals(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"padded", []string{"--pad", "10"}, "padded to a 10 percent size class"},
		{"off", []string{"--pad", "none"}, "not padded, so it reveals"},
		{"no password", []string{"--keyless", "-n", "3", "-k", "2"}, "Without a password"},
	}
	for _, c := range cases {
		args := c.args
		if c.name != "no password" {
			args = append(args, "--kdf", "m=8,t=1,p=1")
		}
		plan := planFor(t, args...)
		var buf bytes.Buffer
		printPaddingLine(&buf, plan)
		if !strings.Contains(buf.String(), c.want) {
			t.Fatalf("%s: got %q, want it to mention %q", c.name, buf.String(), c.want)
		}
	}
}

// TestExportAndVerify drives the write path end to end inside the package: every
// format is written, the files exist, and the verification step re-reads them.
func TestExportAndVerify(t *testing.T) {
	t.Setenv("RIVEN_UNIT_PW1", "one")
	plan := planFor(t, "--password-env", "RIVEN_UNIT_PW1", "-n", "3", "-k", "2", "--kdf", "m=8,t=1,p=1")
	plan.outDir = t.TempDir()

	input := []byte("export and verify")

	var buf bytes.Buffer
	written, formats, err := exportSplit(&buf, plan, &cliOptions{yes: true, format: "all"}, input, "doc")
	if err != nil {
		t.Fatal(err)
	}
	if len(formats) != len(pieceio.All()) {
		t.Fatalf("chose %d formats, want all of them", len(formats))
	}
	for _, f := range pieceio.All() {
		if len(written[f]) != 3 {
			t.Fatalf("%s: wrote %d files, want 3", f, len(written[f]))
		}
		for _, p := range written[f] {
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	}
	if !strings.Contains(buf.String(), "error correction") {
		t.Fatalf("the QR export should report its level:\n%s", buf.String())
	}

	if err := verifySplit(&buf, input, written[pieceio.Binary], plan); err != nil {
		t.Fatalf("verification should pass: %v", err)
	}

	// Verification must fail loudly if a piece is not what it claims to be.
	damaged := written[pieceio.Binary][0]
	body, err := os.ReadFile(damaged)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0xFF
	if err := os.WriteFile(damaged, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySplit(&buf, input, written[pieceio.Binary], plan); err == nil {
		t.Fatal("a damaged piece must fail verification")
	}
}

// TestReportQRSizesCountsEveryPiece checks the report is derived per piece
// rather than assumed from one of them.
func TestReportQRSizesCountsEveryPiece(t *testing.T) {
	var buf bytes.Buffer
	reportQRSizes(&buf, []int{100, 100, 2900})
	out := buf.String()
	if !strings.Contains(out, "2 piece(s)") || !strings.Contains(out, "1 piece(s)") {
		t.Fatalf("mixed levels should be reported per piece:\n%s", out)
	}
	if !strings.Contains(out, "weakest correction") {
		t.Fatalf("a piece near capacity should be flagged:\n%s", out)
	}

	buf.Reset()
	reportQRSizes(&buf, []int{100, 100})
	if strings.Contains(buf.String(), "weakest correction") {
		t.Fatalf("small pieces should not be flagged:\n%s", buf.String())
	}
}

// TestGeneratedPasswordsReachTheUser checks the one output that cannot be
// recreated: under -y the passwords go to standard output, one per line, and
// nothing else goes with them.
func TestGeneratedPasswordsReachTheUser(t *testing.T) {
	plan := planFor(t, "--generate", "--algo", "aes-256-gcm,chacha20-poly1305", "--kdf", "m=8,t=1,p=1")

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	err = reportGeneratedPasswords(&cliOptions{yes: true}, plan)
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout carried %d lines, want one per generated password:\n%q", len(lines), buf.String())
	}
	for i, l := range lines {
		if l != string(plan.generated[i]) {
			t.Fatalf("line %d is %q, want the generated password", i+1, l)
		}
	}
}

func TestWipeAllClearsEveryBuffer(t *testing.T) {
	bufs := [][]byte{[]byte("secret one"), []byte("secret two"), nil}
	wipeAll(bufs)
	for i, b := range bufs {
		for _, c := range b {
			if c != 0 {
				t.Fatalf("buffer %d still holds data: %q", i, b)
			}
		}
	}
}

func TestMsgWriterKeepsStdoutClean(t *testing.T) {
	if msgWriter(&cliOptions{yes: true}) != os.Stderr {
		t.Fatal("under -y messages must go to standard error")
	}
	if msgWriter(&cliOptions{}) != os.Stdout {
		t.Fatal("interactively messages go to standard output")
	}
}

func TestEnsureDir(t *testing.T) {
	base := t.TempDir()
	nested := filepath.Join(base, "a", "b")
	if err := ensureDir(nested); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(nested); err != nil || !fi.IsDir() {
		t.Fatalf("directory not created: %v", err)
	}
	// The current directory needs no work and must not error.
	if err := ensureDir("."); err != nil {
		t.Fatal(err)
	}
	if err := ensureDir(""); err != nil {
		t.Fatal(err)
	}
}
