// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// The paths below run only when a terminal is attached, which no test has, so
// nothing had reached them: the menu, the overwrite questions, the password
// loop, and the prompts for what a set did not record. withTerminal stands in
// a terminal and scripts the answers; the prompts read from the shared reader
// either way, so the answers reach them unchanged.

// withTerminal runs fn as though stdin were a terminal, feeding answers to the
// prompts, and returns what was printed to standard output.
func withTerminal(t *testing.T, answers string, fn func()) string {
	t.Helper()
	old := isInteractive
	isInteractive = func() bool { return true }
	defer func() { isInteractive = old }()
	return withInput(t, answers, fn)
}

// writePieces stores a set as binary files in dir and returns their paths.
func writePieces(t *testing.T, dir string, pieces [][]byte) []string {
	t.Helper()
	paths := make([]string, len(pieces))
	for i, p := range pieces {
		paths[i] = filepath.Join(dir, fmt.Sprintf("piece.%d", i+1))
		if err := pieceio.Write(paths[i], p); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

// generatedPassword finds the password the wizard invented in what it printed.
func generatedPassword(t *testing.T, stderr string) []byte {
	t.Helper()
	const mark = "generated password for auto: "
	i := strings.Index(stderr, mark)
	if i < 0 {
		t.Fatalf("no generated password was shown:\n%s", stderr)
	}
	line := stderr[i+len(mark):]
	if j := strings.IndexAny(line, "\r\n"); j >= 0 {
		line = line[:j]
	}
	return []byte(line)
}

// The menu's first entry is the recommended path end to end: one password,
// generated on an empty answer, default algorithm and cost, pieces beside the
// input, binary export, and the self-check. The generated password is the only
// way back in, so the test opens the pieces with it.
func TestMenuSplitsAFileThroughTheRecommendedPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	input := []byte("the recommended path, from the menu")
	if err := os.WriteFile("input.bin", input, 0o600); err != nil {
		t.Fatal(err)
	}

	// choice, file, N, K, security mode, password (Enter generates), output
	// directory, export format.
	answers := "1\ninput.bin\n3\n2\n1\n\n\n\n"
	var out string
	var err error
	errOut := captureStderr(t, func() {
		out = withTerminal(t, answers, func() {
			err = cmdMenu(&cliOptions{})
		})
	})
	if err != nil {
		t.Fatalf("menu split: %v\n%s\n%s", err, out, errOut)
	}
	for _, want := range []string{"Done. 3 pieces written", "Verification: PASSED", "one password layer"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errOut, "GENERATED PASSWORD") {
		t.Errorf("the generated password block was not shown:\n%s", errOut)
	}

	pw := generatedPassword(t, errOut)
	var pieces [][]byte
	for _, name := range []string{"input.bin.1", "input.bin.3"} {
		p, _, err := pieceio.Load(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pieces = append(pieces, p)
	}
	got, name, err := core.CombineFile(pieces, core.OpenOptions{Passwords: [][]byte{pw}})
	if err != nil {
		t.Fatalf("the pieces do not open with the generated password: %v", err)
	}
	if !bytes.Equal(got, input) || name != "input.bin" {
		t.Fatalf("rebuilt %q as %q", got, name)
	}
}

// The advanced path asks about every layer and every recording choice. Two
// layers are built here, a password and a recipient key generated on the spot,
// and the pieces are opened with both to prove the answers took effect.
func TestSplitAsksTheAdvancedQuestions(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	input := []byte("two layers, chosen at the prompts")
	if err := os.WriteFile("input.bin", input, 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := parseArgs([]string{"input.bin", "--kdf", "m=8,t=1,p=1"})
	if err != nil {
		t.Fatal(err)
	}

	answers := strings.Join([]string{
		"2", "2", // N, K
		"1", "", "pw-one", "pw-one", "y", // layer 1: password, default algorithm, typed twice, add another
		"2", "", "", "4", "layerkey", "n", // layer 2: recipient, default algorithm, generate a key, x25519, base name, no more
		"y", "n", // record the algorithms, not the name
		"y",  // record the cost (the cost itself came from --kdf)
		"10", // padding percent
		"",   // output directory
		"base64",
	}, "\n") + "\n"
	var out string
	errOut := captureStderr(t, func() {
		out = withTerminal(t, answers, func() {
			err = cmdSplit(opts)
		})
	})
	if err != nil {
		t.Fatalf("advanced split: %v\n%s\n%s", err, out, errOut)
	}
	for _, want := range []string{
		"Layers (outer to inner)", "password", "recipient key (x25519)",
		"Every recipient private key listed above is required",
		"Piece size: padded to a 10 percent size class",
		"Verification: PASSED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "File name:") {
		t.Error("the name was recorded although the answer was no")
	}

	priv, err := readPrivateKey("layerkey.key")
	if err != nil {
		t.Fatalf("the generated key pair was not written: %v", err)
	}
	var pieces [][]byte
	for _, name := range []string{"input.bin.1.txt", "input.bin.2.txt"} {
		p, det, err := pieceio.Load(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if det.Format != pieceio.Base64 {
			t.Errorf("%s was written as %s, want base64", name, det.Format)
		}
		pieces = append(pieces, p)
	}
	got, name, err := core.CombineFile(pieces, core.OpenOptions{
		Passwords:   [][]byte{[]byte("pw-one")},
		PrivateKeys: []*kem.PrivateKey{priv},
	})
	if err != nil {
		t.Fatalf("the pieces do not open with the password and the key: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("rebuilt %q", got)
	}
	if name != "" {
		t.Errorf("a name %q came out of pieces written with --record-name no", name)
	}
}

// An empty answer to the menu's file or text question is a refusal, not a
// split of nothing.
func TestMenuRefusesAnEmptyInput(t *testing.T) {
	for _, c := range []struct{ answers, want string }{
		{"1\n\n", "no file given"},
		{"2\n\n", "no text given"},
	} {
		var err error
		withTerminal(t, c.answers, func() { err = cmdMenu(&cliOptions{}) })
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("answers %q: got %v, want %q", c.answers, err, c.want)
		}
	}
}

// Inspecting and rebuilding from the menu run the open-side commands with a
// keyless set, which asks for no password, so the only prompts are the paths.
func TestMenuInspectsAndRebuildsASet(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	input := []byte("rebuilt from the menu")
	paths := writePieces(t, dir, makePieces(t, core.SplitOptions{N: 3, K: 2, Keyless: true}, input))

	var err error
	out := withTerminal(t, "3\n"+paths[0]+"\n", func() { err = cmdMenu(&cliOptions{}) })
	if err != nil {
		t.Fatalf("inspect: %v\n%s", err, out)
	}
	for _, want := range []string{"set id", "piece      : 1 of 3", "encryption : none"} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect output lacks %q:\n%s", want, out)
		}
	}

	// The set recorded no name, so the default file name is offered.
	out = withTerminal(t, "4\n"+paths[1]+" "+paths[2]+"\nrebuilt.bin\n", func() {
		err = cmdMenu(&cliOptions{})
	})
	if err != nil {
		t.Fatalf("rebuild: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[default: riven-recovered.out]") {
		t.Errorf("the default output name was not offered:\n%s", out)
	}
	got, err := os.ReadFile("rebuilt.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("rebuilt %q", got)
	}
}

func TestMenuGeneratesAKeyPair(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var err error
	out := withTerminal(t, "5\nmenukey\n", func() { err = cmdMenu(&cliOptions{}) })
	if err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	if _, err := readPublicKey("menukey.pub"); err != nil {
		t.Error(err)
	}
	if _, err := readPrivateKey("menukey.key"); err != nil {
		t.Error(err)
	}
}

// The overwrite question is asked only where it applies: a file that exists,
// with a terminal to answer on. The answer decides.
func TestConfirmOverwriteAsksOnlyForAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "taken")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error

	withTerminal(t, "", func() { err = confirmOverwrite(&cliOptions{}, filepath.Join(dir, "free")) })
	if err != nil {
		t.Errorf("a missing file was asked about: %v", err)
	}
	withTerminal(t, "", func() { err = confirmOverwrite(&cliOptions{yes: true}, existing) })
	if err != nil {
		t.Errorf("-y must not ask: %v", err)
	}
	out := withTerminal(t, "n\n", func() { err = confirmOverwrite(&cliOptions{}, existing) })
	if err == nil || !strings.Contains(err.Error(), "not overwriting") {
		t.Errorf("a no was not honoured: %v", err)
	}
	if !strings.Contains(out, "already exists") {
		t.Errorf("the question does not say the file exists:\n%s", out)
	}
	withTerminal(t, "y\n", func() { err = confirmOverwrite(&cliOptions{}, existing) })
	if err != nil {
		t.Errorf("a yes was not honoured: %v", err)
	}
}

// A key file is the one thing that is never replaced without a clear answer:
// no by default, an error without a terminal, and a warning in the question.
func TestRefuseKeyOverwriteAsksWhenItCan(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "k.key")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error

	withTerminal(t, "", func() { err = refuseKeyOverwrite(&cliOptions{}, filepath.Join(dir, "new.key")) })
	if err != nil {
		t.Errorf("a missing file was refused: %v", err)
	}
	withTerminal(t, "", func() { err = refuseKeyOverwrite(&cliOptions{yes: true}, existing) })
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("-y must fail rather than ask: %v", err)
	}
	out := withTerminal(t, "\n", func() { err = refuseKeyOverwrite(&cliOptions{}, existing) })
	if err == nil || !strings.Contains(err.Error(), "not overwriting the key file") {
		t.Errorf("Enter must mean no: %v", err)
	}
	if !strings.Contains(out, "unrecoverable") {
		t.Errorf("the question does not warn about the consequence:\n%s", out)
	}
	withTerminal(t, "y\n", func() { err = refuseKeyOverwrite(&cliOptions{}, existing) })
	if err != nil {
		t.Errorf("a yes was not honoured: %v", err)
	}
}

// At a terminal the passwords are asked for one layer at a time until an empty
// line, and at least one is required.
func TestGatherOpenPasswordsPromptsUntilAnEmptyLine(t *testing.T) {
	sealed := makePieces(t, core.SplitOptions{N: 2, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("one")}}}, []byte("open"))

	var pws [][]byte
	var err error
	out := withTerminal(t, "one\ntwo\n\n", func() { pws, err = gatherOpenPasswords(&cliOptions{}, sealed) })
	if err != nil {
		t.Fatal(err)
	}
	if len(pws) != 2 || string(pws[0]) != "one" || string(pws[1]) != "two" {
		t.Fatalf("passwords are %q, want the two typed in order", pws)
	}
	if !strings.Contains(out, "Layer 1 password") || !strings.Contains(out, "no more layers") {
		t.Errorf("the prompts do not explain the loop:\n%s", out)
	}

	withTerminal(t, "\n", func() { _, err = gatherOpenPasswords(&cliOptions{}, sealed) })
	if err == nil || !strings.Contains(err.Error(), "no password entered") {
		t.Errorf("an immediate empty line must fail: %v", err)
	}

	// Without a terminal there is nobody to ask.
	if _, err := gatherOpenPasswords(&cliOptions{}, sealed); err == nil ||
		!strings.Contains(err.Error(), "--password-env") {
		t.Errorf("a run with no terminal must name the flag: %v", err)
	}
}

// A set that did not record its algorithms needs exactly one per layer, given
// as the numbers shown or the names, and the count is checked before use.
func TestAskMissingAlgosAcceptsNumbersAndNames(t *testing.T) {
	var ids []uint8
	var err error
	out := withTerminal(t, "1\n2,aes-256-gcm\n", func() { ids, err = askMissingAlgos(&cliOptions{}, 2) })
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != 2 || ids[1] != 1 {
		t.Fatalf("ids are %v, want [2 1]", ids)
	}
	if !strings.Contains(out, "expected 2 algorithms, got 1") {
		t.Errorf("a short answer was not refused:\n%s", out)
	}

	if _, err := askMissingAlgos(&cliOptions{}, 2); err == nil || !strings.Contains(err.Error(), "--algo") {
		t.Errorf("a run with no terminal must name the flag: %v", err)
	}
	withTerminal(t, "", func() { _, err = askMissingAlgos(&cliOptions{yes: true}, 2) })
	if err == nil {
		t.Error("-y must fail rather than ask")
	}
}

// The cost question after a failed open is optional: Enter gives up, a spec is
// parsed, and nothing is asked without a terminal.
func TestAskMissingKDFParsesTheAnswerOrGivesUp(t *testing.T) {
	var p *kdf.Params
	var err error
	withTerminal(t, "\n", func() { p, err = askMissingKDF(&cliOptions{}) })
	if err != nil || p != nil {
		t.Errorf("Enter should give up quietly: %v %v", p, err)
	}
	withTerminal(t, "m=8,t=1,p=1\n", func() { p, err = askMissingKDF(&cliOptions{}) })
	if err != nil || p == nil || p.Memory != 8*1024 || p.Time != 1 || p.Par != 1 {
		t.Errorf("a spec was not parsed: %v %v", p, err)
	}
	withTerminal(t, "bogus\n", func() { p, err = askMissingKDF(&cliOptions{}) })
	if err == nil {
		t.Error("a bad spec was accepted")
	}
	if p, err := askMissingKDF(&cliOptions{}); err != nil || p != nil {
		t.Errorf("no terminal, nothing to ask: %v %v", p, err)
	}
}

// The key type menu is skipped whenever the answer is already known.
func TestChooseKeySchemeListsTheTypes(t *testing.T) {
	var s kem.Scheme
	var err error
	out := withTerminal(t, "2\n", func() { s, err = chooseKeyScheme(&cliOptions{}) })
	if err != nil || s != kem.MLKEM768 {
		t.Errorf("choice 2 gave %v %v", s, err)
	}
	for _, sch := range kem.All() {
		if !strings.Contains(out, sch.Name()) {
			t.Errorf("the list does not offer %s:\n%s", sch.Name(), out)
		}
	}
	withTerminal(t, "", func() { s, err = chooseKeyScheme(&cliOptions{keyType: "x25519"}) })
	if err != nil || s != kem.X25519 {
		t.Errorf("a named type was not used: %v %v", s, err)
	}
	withTerminal(t, "", func() { s, err = chooseKeyScheme(&cliOptions{yes: true}) })
	if err != nil || s != kem.Default() {
		t.Errorf("-y should take the default: %v %v", s, err)
	}
	if s, err := chooseKeyScheme(&cliOptions{}); err != nil || s != kem.Default() {
		t.Errorf("no terminal should take the default: %v %v", s, err)
	}
}

func TestResolveModeReadsTheChoice(t *testing.T) {
	for _, c := range []struct {
		answer string
		want   securityMode
	}{
		{"1\n", modeRecommended}, {"2\n", modeAdvanced}, {"3\n", modeKeyless}, {"\n", modeRecommended},
	} {
		var got securityMode
		var err error
		out := withInput(t, c.answer, func() { got, err = resolveMode(&cliOptions{}, true) })
		if err != nil || got != c.want {
			t.Errorf("answer %q: got %v %v, want %v", c.answer, got, err, c.want)
		}
		if c.want == modeKeyless && !strings.Contains(out, "warning") {
			t.Errorf("choosing no encryption must warn:\n%s", out)
		}
	}
	// Flags that only make sense in the advanced path select it without asking.
	if got, err := resolveMode(&cliOptions{padSet: true}, true); err != nil || got != modeAdvanced {
		t.Errorf("--pad should select the advanced path: %v %v", got, err)
	}
	if got, err := resolveMode(&cliOptions{keyless: true}, true); err != nil || got != modeKeyless {
		t.Errorf("--keyless should select keyless: %v %v", got, err)
	}
}

// The export answer is re-asked until it names formats the pieces fit, mixing
// the numbers shown with the names.
func TestResolveFormatsRetriesABadAnswer(t *testing.T) {
	plan := &splitPlan{}
	plan.opts.N = 2
	var formats []pieceio.Format
	var err error
	out := withTerminal(t, "nonsense\n2,qr\n", func() { formats, err = resolveFormats(&cliOptions{}, plan, 200) })
	if err != nil {
		t.Fatal(err)
	}
	if len(formats) != 2 || formats[0] != pieceio.Base64 || formats[1] != pieceio.QR {
		t.Fatalf("formats are %v, want [base64 qr]", formats)
	}
	if !strings.Contains(out, "nonsense") {
		t.Errorf("the bad answer was not explained:\n%s", out)
	}

	// A piece too large for a code is offered again, since the choice would fail.
	out = withTerminal(t, "qr\nbinary\n", func() {
		formats, err = resolveFormats(&cliOptions{}, plan, pieceio.QRMaxBytes+1)
	})
	if err != nil || len(formats) != 1 || formats[0] != pieceio.Binary {
		t.Errorf("got %v %v after refusing qr", formats, err)
	}
	if !strings.Contains(out, "NOT AVAILABLE") || !strings.Contains(out, "cannot export as QR") {
		t.Errorf("the size problem was not stated:\n%s", out)
	}
}

// The name a set recorded is offered, never used unasked; Enter takes it.
func TestWriteRecoveredOffersTheRecordedName(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	data := []byte("recovered at a terminal")
	var err error

	out := withTerminal(t, "\n", func() { err = writeRecovered(&cliOptions{}, data, "photo.jpg") })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "[default: photo.jpg]") {
		t.Errorf("the recorded name was not offered:\n%s", out)
	}
	if got, err := os.ReadFile("photo.jpg"); err != nil || !bytes.Equal(got, data) {
		t.Errorf("photo.jpg holds %q, %v", got, err)
	}

	withTerminal(t, "elsewhere.bin\n", func() { err = writeRecovered(&cliOptions{}, data, "photo.jpg") })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("elsewhere.bin"); err != nil {
		t.Errorf("the typed name was not used: %v", err)
	}

	// The offered file now exists, so taking it again is an overwrite question.
	withTerminal(t, "\nn\n", func() { err = writeRecovered(&cliOptions{}, data, "photo.jpg") })
	if err == nil || !strings.Contains(err.Error(), "not overwriting") {
		t.Errorf("declining the overwrite did not stop the write: %v", err)
	}
}

// The cost warning names a slow open before it starts, and only for one.
func TestNoteExpensiveOpenWarnsAboutACostlySet(t *testing.T) {
	pieces := makePieces(t, core.SplitOptions{N: 2, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("pw")}}}, []byte("x"))

	out := withTerminal(t, "", func() { noteExpensiveOpen(pieces, nil) })
	if out != "" {
		t.Errorf("a cheap set was warned about:\n%s", out)
	}
	costly := kdf.Paranoid
	out = withTerminal(t, "", func() { noteExpensiveOpen(pieces, &costly) })
	if !strings.Contains(out, "takes a moment") || !strings.Contains(out, costly.Describe()) {
		t.Errorf("a costly override was not announced:\n%s", out)
	}
	if out := withInput(t, "", func() { noteExpensiveOpen(pieces, &costly) }); out != "" {
		t.Errorf("without a terminal there is nobody to warn:\n%s", out)
	}
}
