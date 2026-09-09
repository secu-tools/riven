// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/pieceio"
)

func TestParseArgsCommands(t *testing.T) {
	cases := map[string]string{
		"split":   "split",
		"info":    "info",
		"combine": "combine",
		"keygen":  "keygen",
		"version": "version",
		"help":    "help",
	}
	for arg, want := range cases {
		o, err := parseArgs([]string{arg})
		if err != nil {
			t.Fatalf("%s: %v", arg, err)
		}
		if o.command != want {
			t.Fatalf("%s: got command %q", arg, o.command)
		}
	}

	// A bare file argument means split, resolved by run.
	o, err := parseArgs([]string{"myfile.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if o.command != "" || len(o.files) != 1 || o.files[0] != "myfile.bin" {
		t.Fatalf("bare file not treated as an operand: %+v", o)
	}

	// Help and version shorthands.
	for _, f := range []string{"-h", "--help"} {
		if o, err := parseArgs([]string{f}); err != nil || o.command != "help" {
			t.Fatalf("%s should select help", f)
		}
	}
	for _, f := range []string{"-V", "--version"} {
		if o, err := parseArgs([]string{f}); err != nil || o.command != "version" {
			t.Fatalf("%s should select version", f)
		}
	}
}

func TestParseArgsAllFlags(t *testing.T) {
	o, err := parseArgs([]string{
		"split", "in.bin",
		"-n", "7", "-k", "4",
		"--algo", "aes-256-gcm,chacha20-poly1305",
		"--format", "all",
		"--qr-scale", "6",
		"--kdf", "paranoid",
		"--record-algo", "false", "--record-kdf", "false",
		"--pad", "none",
		"--password-env", "A", "--password-env", "B",
		"--recipient", "r.pub", "--identity", "r.key",
		"--generate",
		"--out", "outdir",
		"-y",
	})
	if err != nil {
		t.Fatal(err)
	}
	if o.n != 7 || !o.nSet || o.k != 4 || !o.kSet {
		t.Fatalf("n/k not parsed: %+v", o)
	}
	if o.algo != "aes-256-gcm,chacha20-poly1305" || !o.algoSet {
		t.Fatalf("algo not parsed: %+v", o)
	}
	if o.format != "all" || o.qrScale != 6 {
		t.Fatalf("format flags not parsed: %+v", o)
	}
	if o.kdfSpec != "paranoid" {
		t.Fatalf("kdf not parsed: %+v", o)
	}
	if !o.recordAlgoSet || o.recordAlgo || !o.recordKDFSet || o.recordKDF {
		t.Fatalf("recording flags not parsed: %+v", o)
	}
	if o.pad != "none" || !o.padSet {
		t.Fatalf("pad not parsed: %+v", o)
	}
	if len(o.passwordEnvs()) != 2 || o.passwordEnvs()[0] != "A" || o.passwordEnvs()[1] != "B" {
		t.Fatalf("password envs not parsed in order: %+v", o.passwordEnvs())
	}
	if len(o.identities) != 1 || o.identities[0] != "r.key" {
		t.Fatalf("identities not parsed: %+v", o.identities)
	}
	// The layer order follows the flag order: two passwords then the recipient.
	if len(o.layerSources) != 3 ||
		o.layerSources[0].kind != core.PasswordLayer ||
		o.layerSources[1].kind != core.PasswordLayer ||
		o.layerSources[2].kind != core.RecipientLayer ||
		o.layerSources[2].file != "r.pub" {
		t.Fatalf("layer sources not recorded in order: %+v", o.layerSources)
	}
	if !o.generate || o.outDir != "outdir" || !o.yes {
		t.Fatalf("remaining flags not parsed: %+v", o)
	}
	if len(o.files) != 1 || o.files[0] != "in.bin" {
		t.Fatalf("operand lost: %+v", o.files)
	}
}

// TestParseArgsRecordFlags covers the true/false forms and the spellings a user
// is likely to type, since the recording choice decides whether a set can be
// opened with the password alone.
func TestParseArgsRecordFlags(t *testing.T) {
	cases := map[string]bool{
		"true": true, "yes": true, "y": true, "on": true, "1": true,
		"false": false, "no": false, "n": false, "off": false, "0": false,
		"TRUE": true, " False ": false,
	}
	for v, want := range cases {
		o, err := parseArgs([]string{"split", "f", "--record-algo", v, "--record-kdf", v})
		if err != nil {
			t.Fatalf("--record-algo %q: %v", v, err)
		}
		if !o.recordAlgoSet || o.recordAlgo != want || !o.recordKDFSet || o.recordKDF != want {
			t.Fatalf("--record-algo %q gave %v, want %v", v, o.recordAlgo, want)
		}
	}

	for _, bad := range []string{"maybe", "", "2"} {
		if _, err := parseArgs([]string{"split", "f", "--record-algo", bad}); err == nil {
			t.Fatalf("--record-algo %q should be refused", bad)
		}
	}
	// The flag needs a value now, so a bare flag must not silently mean true.
	if _, err := parseArgs([]string{"split", "f", "--record-algo"}); err == nil {
		t.Fatal("--record-algo with no value should fail")
	}

	// Unset means the default applies, which is recording.
	o, err := parseArgs([]string{"split", "f"})
	if err != nil {
		t.Fatal(err)
	}
	if o.recordAlgoSet || o.recordKDFSet {
		t.Fatal("nothing should be marked set when the flags are absent")
	}
}

func TestParseArgsNewInputModes(t *testing.T) {
	o, err := parseArgs([]string{"split", "--text", "123456", "--name", "mykey", "--keyless"})
	if err != nil {
		t.Fatal(err)
	}
	if o.text != "123456" || !o.textSet {
		t.Fatalf("text not parsed: %+v", o)
	}
	if o.name != "mykey" || !o.keyless {
		t.Fatalf("name or keyless not parsed: %+v", o)
	}

	// A lone dash is an operand meaning standard input, not a flag.
	o, err = parseArgs([]string{"split", "-"})
	if err != nil {
		t.Fatalf("a lone dash should be accepted: %v", err)
	}
	if len(o.files) != 1 || o.files[0] != "-" {
		t.Fatalf("dash not treated as an operand: %+v", o.files)
	}

	// --no-encryption is an alias for --keyless.
	if o, err := parseArgs([]string{"split", "f", "--no-encryption"}); err != nil || !o.keyless {
		t.Fatalf("--no-encryption should set keyless: %v", err)
	}

	// --text-env reads the value from the environment.
	t.Setenv("RIVEN_UNIT_TEXT", "secret-from-env")
	o, err = parseArgs([]string{"split", "--text-env", "RIVEN_UNIT_TEXT"})
	if err != nil {
		t.Fatal(err)
	}
	if o.text != "secret-from-env" || !o.textSet {
		t.Fatalf("--text-env not resolved: %+v", o)
	}
	if _, err := parseArgs([]string{"split", "--text-env", "RIVEN_UNIT_NOT_SET"}); err == nil {
		t.Fatal("--text-env with an unset variable should fail")
	}
}

func TestReadSplitInput(t *testing.T) {
	// A string input gets the default base name, the current directory, and no
	// recorded name: "secret" is this tool's invention, not the content's name.
	in, err := readSplitInput(&cliOptions{text: "abc", textSet: true, yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(in.data) != "abc" || in.baseName != "secret" || in.dir != "." || in.origName != "" {
		t.Fatalf("text input: %+v", in)
	}

	// --name overrides the base name but is not the content's name either.
	in, err = readSplitInput(&cliOptions{text: "abc", textSet: true, name: "kn", yes: true})
	if err != nil || in.baseName != "kn" || in.origName != "" {
		t.Fatalf("name override: %+v %v", in, err)
	}

	// A file input takes its own name and directory, and records that name.
	dirPath := t.TempDir()
	path := filepath.Join(dirPath, "thing.bin")
	if err := os.WriteFile(path, []byte("filedata"), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err = readSplitInput(&cliOptions{files: []string{path}, yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(in.data) != "filedata" || in.baseName != "thing.bin" || in.dir != dirPath ||
		in.origName != "thing.bin" {
		t.Fatalf("file input: %+v", in)
	}

	// --name changes the piece names without changing what is recorded.
	in, err = readSplitInput(&cliOptions{files: []string{path}, name: "other", yes: true})
	if err != nil || in.baseName != "other" || in.origName != "thing.bin" {
		t.Fatalf("name override on a file: %+v %v", in, err)
	}

	// Contradictions, missing input and a directory are refused.
	if _, err := readSplitInput(&cliOptions{text: "a", textSet: true, files: []string{"f"}, yes: true}); err == nil {
		t.Fatal("file plus text should fail")
	}
	if _, err := readSplitInput(&cliOptions{yes: true}); err == nil {
		t.Fatal("no input should fail")
	}
	if _, err := readSplitInput(&cliOptions{files: []string{filepath.Join(dirPath, "missing")}, yes: true}); err == nil {
		t.Fatal("a missing file should fail")
	}
	if _, err := readSplitInput(&cliOptions{files: []string{dirPath}, yes: true}); err == nil {
		t.Fatal("a directory should fail, with advice to pack it first")
	}
}

func TestParseArgsErrors(t *testing.T) {
	cases := map[string][]string{
		"unknown flag":       {"split", "--nope"},
		"missing value":      {"split", "f", "-n"},
		"non-numeric parts":  {"split", "f", "-n", "many"},
		"missing algo value": {"split", "f", "--algo"},
		"missing out value":  {"split", "f", "--out"},
	}
	for name, args := range cases {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("%s should fail", name)
		}
	}
}

// TestFlagValuesAreAccepted checks the values the help text advertises actually
// parse, so help and behaviour cannot drift apart.
func TestFlagValuesAreAccepted(t *testing.T) {
	for _, name := range ciphers.Names() {
		if _, err := ciphers.ParseList(name); err != nil {
			t.Fatalf("advertised algorithm %q rejected: %v", name, err)
		}
	}
	for _, name := range kdf.PresetNames() {
		if _, err := kdf.Parse(name); err != nil {
			t.Fatalf("advertised preset %q rejected: %v", name, err)
		}
	}
	for _, f := range pieceio.All() {
		if _, err := pieceio.ParseFormats(f.String()); err != nil {
			t.Fatalf("advertised format %q rejected: %v", f, err)
		}
	}
	if _, err := pieceio.ParseFormats("all"); err != nil {
		t.Fatalf("advertised format \"all\" rejected: %v", err)
	}
}

func TestPasswordFromEnv(t *testing.T) {
	const name = "RIVEN_UNIT_TEST_PW"
	t.Setenv(name, "secret-value")
	got, err := passwordFromEnv(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret-value" {
		t.Fatalf("got %q", got)
	}

	t.Setenv(name, "")
	if _, err := passwordFromEnv(name); err == nil {
		t.Fatal("empty variable should fail")
	}
	os.Unsetenv(name)
	if _, err := passwordFromEnv(name); err == nil {
		t.Fatal("unset variable should fail")
	}
}

// TestPasswordEnvsPreservesOrder checks the password variables come back in the
// order the flags were given, which is the order of the layers.
func TestPasswordEnvsPreservesOrder(t *testing.T) {
	o, err := parseArgs([]string{
		"split", "f",
		"--password-env", "A", "--recipient", "r.pub", "--password-env", "B",
	})
	if err != nil {
		t.Fatal(err)
	}
	envs := o.passwordEnvs()
	if len(envs) != 2 || envs[0] != "A" || envs[1] != "B" {
		t.Fatalf("order not preserved: %v", envs)
	}
	// The recipient sits between them in the layer list.
	if len(o.layerSources) != 3 || o.layerSources[1].kind != core.RecipientLayer {
		t.Fatalf("layer order lost: %+v", o.layerSources)
	}
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		pw, err := generatePassword(defaultGenLen)
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != defaultGenLen {
			t.Fatalf("length %d", len(pw))
		}
		for _, c := range pw {
			if !strings.ContainsRune(pwCharset, rune(c)) {
				t.Fatalf("character %q outside the charset", c)
			}
		}
		if seen[string(pw)] {
			t.Fatal("generated the same password twice")
		}
		seen[string(pw)] = true
	}
	// A non-positive length falls back to the default.
	pw, err := generatePassword(0)
	if err != nil || len(pw) != defaultGenLen {
		t.Fatalf("zero length should use the default: %d %v", len(pw), err)
	}
}

func TestPasswordCharsetHasNoAmbiguousCharacters(t *testing.T) {
	for _, c := range "0O1lI" {
		if strings.ContainsRune(pwCharset, c) {
			t.Fatalf("charset contains the ambiguous character %q", c)
		}
	}
}

func TestIsDistinct(t *testing.T) {
	prior := [][]byte{[]byte("a"), []byte("b")}
	if !isDistinct([]byte("c"), prior) {
		t.Fatal("new password should be distinct")
	}
	if isDistinct([]byte("a"), prior) {
		t.Fatal("reused password should not be distinct")
	}
	if !isDistinct([]byte("a"), nil) {
		t.Fatal("anything is distinct against no prior passwords")
	}
}

func TestResolveOpenParams(t *testing.T) {
	o := &cliOptions{}
	params, schemes, err := resolveOpenParams(o)
	if err != nil || params != nil || schemes != nil {
		t.Fatalf("no flags should yield no overrides: %v %v %v", params, schemes, err)
	}

	o = &cliOptions{kdfSpec: "m=32,t=2,p=2", algo: "aes-256-gcm", algoSet: true}
	params, schemes, err = resolveOpenParams(o)
	if err != nil {
		t.Fatal(err)
	}
	if params == nil || params.Memory != 32*1024 || params.Time != 2 || params.Par != 2 {
		t.Fatalf("cost override not resolved: %+v", params)
	}
	if len(schemes) != 1 {
		t.Fatalf("algorithms not resolved: %v", schemes)
	}

	if _, _, err := resolveOpenParams(&cliOptions{kdfSpec: "bogus"}); err == nil {
		t.Fatal("bad cost spec should fail")
	}
	if _, _, err := resolveOpenParams(&cliOptions{algo: "bogus", algoSet: true}); err == nil {
		t.Fatal("bad algorithm should fail")
	}
}

func TestSplitFields(t *testing.T) {
	got := splitFields("  a.1   b.2\tc.3 ")
	want := []string{"a.1", "b.2", "c.3"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if len(splitFields("   ")) != 0 {
		t.Fatal("blank input should yield no fields")
	}
}
