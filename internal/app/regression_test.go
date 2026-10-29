// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
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

// Defect: a recipient key with no password caused a password to be generated
// behind the user's back, which is not what public-key delivery means. The set
// must be keyed by the recipient key alone.
func TestRegressionRecipientOnlyGeneratesNoPassword(t *testing.T) {
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(t.TempDir(), "r.pub")
	if err := writePublicKey(pub, priv.Public()); err != nil {
		t.Fatal(err)
	}
	plan := planFor(t, "--recipient", pub)
	if len(plan.opts.Layers) != 1 || plan.opts.Layers[0].Kind != core.RecipientLayer {
		t.Fatalf("a recipient-only split planned %+v", plan.opts.Layers)
	}
	if len(plan.generated) != 0 || len(plan.verifyPasswords) != 0 {
		t.Fatalf("a recipient-only split invented %d password(s)", len(plan.generated))
	}
}

// Defect: the recovered data was written with os.WriteFile, which applies its
// mode only when it creates the file. Recovering over an existing world-readable
// file therefore left the secret readable by every user, although a new file was
// created private.
func TestRegressionRecoveredFileIsPrivateOverAnExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows does not implement POSIX mode bits; access is governed by
		// inherited ACLs, so the reported permissions are not meaningful.
		t.Skip("mode bits are not enforced on windows")
	}
	path := filepath.Join(t.TempDir(), "recovered.bin")
	if err := os.WriteFile(path, []byte("an older file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // past any umask
		t.Fatal(err)
	}

	if err := writeRecovered(&cliOptions{outDir: path, yes: true}, []byte("the secret"), ""); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Fatalf("the recovered file has mode %o, want 600", mode)
	}
	if got, _ := os.ReadFile(path); string(got) != "the secret" {
		t.Fatalf("the recovered file holds %q", got)
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

// Defect: a split addressed only to a recipient key, run without --identity as
// the usage guide shows, warned that the pieces could not be verified and exited
// with an error. The missing key was reported as a plain error, so the check that
// verifies as far as it can without the key never ran.
func TestRegressionRecipientOnlySplitVerifiesWithoutTheKey(t *testing.T) {
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pub := filepath.Join(dir, "r.pub")
	if err := writePublicKey(pub, priv.Public()); err != nil {
		t.Fatal(err)
	}
	opts, err := parseArgs([]string{"split", "--text", "for the key holder", "-n", "3", "-k", "2",
		"--recipient", pub, "-o", filepath.Join(dir, "o"), "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := captureOutput(t, func() error { return cmdSplit(opts) }); err != nil {
		t.Fatalf("a sound split failed its own check: %v\n%s", err, out)
	}
}

// Defect: the wizard's "generate a new key pair" wrote riven-key.pub and
// riven-key.key without the check keygen makes, so a second run replaced the
// first private key and everything sealed to it became unrecoverable.
func TestRegressionWizardKeyPairDoesNotReplaceAKey(t *testing.T) {
	t.Chdir(t.TempDir())
	old := []byte("an earlier private key")
	if err := os.WriteFile("riven-key.key", old, 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	// Enter generates a pair, then the default type, the default base name, and
	// the default answer to the replace question, which is no.
	withTerminal(t, "\n\n\n\n", func() {
		_, err = recipientForLayer(&splitPlan{}, &cliOptions{})
	})
	if err == nil {
		t.Fatal("an existing private key was replaced without being asked")
	}
	if got, _ := os.ReadFile("riven-key.key"); !bytes.Equal(got, old) {
		t.Fatal("the earlier private key was overwritten")
	}
}

// Defect: a set that recorded neither its cost nor its algorithms could not be
// combined through the prompts. Once the cost was entered the retry stopped for
// the algorithms, and that answer was dropped in favour of the first "wrong
// password" error, so the algorithm question was never asked.
func TestRegressionCombineAsksForAlgorithmsAfterTheCost(t *testing.T) {
	pw := []byte("cost and algorithms both withheld")
	input := []byte("rebuilt through two questions")
	pieces, err := core.Split(input, core.SplitOptions{N: 2, K: 2, Params: fastKDF,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, SchemeID: 2, Password: pw}}})
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	withTerminal(t, "m=8,t=1,p=1\nchacha20-poly1305\n", func() {
		got, _, err = combineWithRecovery(&cliOptions{}, pieces, core.OpenOptions{Passwords: [][]byte{pw}})
	})
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("the set did not rebuild through the prompts: %q, %v", got, err)
	}
}

// Defect: a split wrote over files with the names its pieces take, so splitting
// a file again into the same directory destroyed the earlier set without a word.
// Combine asks before replacing a file; split did not.
func TestRegressionSplitAsksBeforeReplacingPieces(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "secret.1")
	earlier := []byte("a piece of an earlier set")
	if err := os.WriteFile(old, earlier, 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := parseArgs([]string{"split", "--text", "a new secret", "-n", "2", "-k", "2",
		"--keyless", "-o", dir, "-f", "binary"})
	if err != nil {
		t.Fatal(err)
	}
	withTerminal(t, "n\n", func() { err = cmdSplit(opts) })
	if err == nil {
		t.Fatal("the split replaced existing pieces although the answer was no")
	}
	if got, _ := os.ReadFile(old); !bytes.Equal(got, earlier) {
		t.Fatal("a piece of the earlier set was overwritten")
	}
}

// Defect: a recovery sheet printed the input's file name as "Original file" even
// under --record-name false, on the one format meant to be printed and left where
// others can read it.
func TestRegressionSheetLeavesOutAnUnrecordedName(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "merger-plan.txt")
	if err := os.WriteFile(in, []byte("the terms"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "o")
	opts, err := parseArgs([]string{"split", in, "-n", "2", "-k", "2", "--keyless",
		"--record-name", "false", "-f", "sheet", "-o", out, "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if log, err := captureOutput(t, func() error { return cmdSplit(opts) }); err != nil {
		t.Fatalf("split: %v\n%s", err, log)
	}
	page, err := os.ReadFile(pieceio.Path(out, "merger-plan.txt.1", pieceio.Sheet))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(page, []byte("merger-plan")) {
		t.Fatal("the sheet prints a file name the split was told not to record")
	}
}

// Defect: info printed each piece's path as it was, so a piece named with a
// terminal escape, as a file from an unpacked archive can be, drove the terminal.
// Every other line that shows a path quotes it.
func TestRegressionPiecePathsAreQuotedInOutput(t *testing.T) {
	path := "piece\x1b[31m.1"
	info := &core.PieceInfo{SetID: strings.Repeat("a", 32), PayloadHashHex: strings.Repeat("b", 64),
		Serial: 1, K: 2, N: 3}
	out := capture(t, func() { printPieceInfo(path, pieceio.Detected{Format: pieceio.Binary}, info) })
	var warning bytes.Buffer
	warnUnverified(&warning, pieceio.Detected{Path: path})
	if strings.ContainsRune(out+warning.String(), 0x1b) {
		t.Fatalf("a raw escape reached the terminal: %q", out+warning.String())
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
