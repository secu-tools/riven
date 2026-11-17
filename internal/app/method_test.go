// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// This file covers --method and --info on the command line: parsing, what the
// plan and the summary make of them, what info prints for each mode, and how
// combine and verify handle sets whose pieces show nothing.

func TestParseMethodAndInfo(t *testing.T) {
	methods := map[string]core.Method{"full": core.MethodFull, "1": core.MethodFull,
		"Compact": core.MethodCompact, " 2 ": core.MethodCompact}
	for in, want := range methods {
		if got, err := parseMethod(in); err != nil || got != want {
			t.Fatalf("--method %q gave %v, %v", in, got, err)
		}
	}
	infos := map[string]core.InfoMode{"protected": core.InfoProtected, "Strict": core.InfoStrict, "PUBLIC": core.InfoPublic,
		"none": core.InfoHidden, "hidden": core.InfoHidden}
	for in, want := range infos {
		if got, err := parseInfo(in); err != nil || got != want {
			t.Fatalf("--info %q gave %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "3", "small", "password"} {
		if _, err := parseMethod(bad); err == nil {
			t.Fatalf("--method %q was accepted", bad)
		}
		if _, err := parseInfo(bad); err == nil {
			t.Fatalf("--info %q was accepted", bad)
		}
	}
}

// TestDefaultsKeepTheFormatAsItWas checks a plain split asks for nothing new: the
// full method, with the details protected.
func TestDefaultsKeepTheFormatAsItWas(t *testing.T) {
	plan := planFor(t)
	info, err := core.EffectiveInfo(plan.opts)
	if plan.opts.Method != core.MethodFull || err != nil || info != core.InfoProtected {
		t.Fatalf("defaults are %v and %v (%v)", plan.opts.Method, info, err)
	}
}

func TestMethodAndInfoFlagsReachThePlan(t *testing.T) {
	plan := planFor(t, "--method", "compact", "--info", "none")
	if plan.opts.Method != core.MethodCompact || plan.opts.Info != core.InfoHidden {
		t.Fatalf("plan has %v and %v", plan.opts.Method, plan.opts.Info)
	}
	plan = planFor(t, "--keyless", "-n", "3", "-k", "2", "--info", "none", "--method", "2")
	if plan.opts.Method != core.MethodCompact || plan.opts.Info != core.InfoHidden || !plan.opts.Keyless {
		t.Fatalf("keyless plan has %v and %v", plan.opts.Method, plan.opts.Info)
	}
}

// TestMethodAndInfoMistakesAreRefused checks each wrong use names the problem.
func TestMethodAndInfoMistakesAreRefused(t *testing.T) {
	split := map[string][]string{
		"keyless with protected details": {"split", "f", "--keyless", "--info", "protected"},
		"keyless with strict details":    {"split", "f", "--keyless", "--info", "strict"},
		"unknown method":                 {"split", "f", "--method", "tiny"},
		"unknown info mode":              {"split", "f", "--info", "secret"},
	}
	for name, args := range split {
		o, err := parseArgs(args)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if err := validateSplitOptions(o); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	for _, args := range [][]string{{"combine", "p", "--method", "full"}, {"info", "p", "--info", "none"}} {
		o, _ := parseArgs(args)
		if err := validateOpenOptions(o); err == nil || !strings.Contains(err.Error(), "apply to splitting") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	o, _ := parseArgs([]string{"keygen", "--method", "compact"})
	if err := validateKeygenOptions(o); err == nil {
		t.Fatal("keygen accepted --method")
	}

	// A recipient-only split protects its details with the private key, and has
	// no password for one piece to test guesses against.
	dir := t.TempDir()
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(dir, "r.pub")
	if err := writePublicKey(pub, priv.Public()); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"split", "f", "--recipient", pub, "-y"},
		{"split", "f", "--recipient", pub, "--info", "protected", "-y"}} {
		o, _ = parseArgs(args)
		plan, err := planSplit(o, dir)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if s := infoSummary(plan); s != "readable with the private key" {
			t.Fatalf("%v: summary says %q", args, s)
		}
	}
}

// TestSummaryNamesMethodAndInfo checks the summary says how the content was
// spread and what one piece gives away, warning about guessing only where it
// applies.
func TestSummaryNamesMethodAndInfo(t *testing.T) {
	t.Setenv("RIVEN_UNIT_MI", "method info")
	t.Setenv("RIVEN_UNIT_MI2", "second layer")
	cases := []struct {
		args []string
		want []string
		not  string
	}{
		{nil, []string{"full: fewer than 3 pieces reveal nothing, proven", "readable with the password",
			"one piece can test guesses"}, ""},
		{[]string{"--method", "compact", "-k", "2"}, []string{"compact: pieces 1/2 of the file",
			"safe while AES-256 and ChaCha20 hold"}, ""},
		{[]string{"--info", "public"}, []string{"readable by anyone", "trying passwords needs 3 pieces"}, "can test guesses"},
		{[]string{"--info", "none"}, []string{"hidden: one piece shows nothing", "needs 3 pieces"}, "can test guesses"},
		// Protected keeps the details behind the first layer alone; strict behind
		// every password, which one piece can only test together.
		{[]string{"--password-env", "RIVEN_UNIT_MI2"}, []string{"readable with the layer 1 password; one piece can test guesses"}, ""},
		{[]string{"--password-env", "RIVEN_UNIT_MI2", "--info", "strict"},
			[]string{"readable with every password; one piece tests them only together"}, "can test guesses"},
	}
	for _, c := range cases {
		plan := planFor(t, append([]string{"--password-env", "RIVEN_UNIT_MI"}, c.args...)...)
		text := methodSummary(plan) + " " + infoSummary(plan)
		for _, w := range c.want {
			if !strings.Contains(text, w) {
				t.Fatalf("%v: summary lacks %q:\n%s", c.args, w, text)
			}
		}
		if c.not != "" && strings.Contains(text, c.not) {
			t.Fatalf("%v: summary says %q:\n%s", c.args, c.not, text)
		}
	}
	// A set with no password has nothing to guess, so the line says nothing of it.
	plan := planFor(t, "--keyless", "-n", "3", "-k", "2", "--info", "none")
	if s := infoSummary(plan); strings.Contains(s, "password") {
		t.Fatalf("a keyless summary talks about passwords: %s", s)
	}
}

// TestInfoPrintsEachMode runs the info command over a piece of each mode.
func TestInfoPrintsEachMode(t *testing.T) {
	t.Setenv("RIVEN_UNIT_INFO", "info password")
	pw := []byte("info password")
	layers := []core.LayerSpec{{Kind: core.PasswordLayer, Password: pw}}
	cases := []struct {
		name string
		opts core.SplitOptions
		args []string
		want []string
		not  []string
	}{
		{"password", core.SplitOptions{N: 3, K: 2, Layers: layers, Name: "a.txt"},
			[]string{"--password-env", "RIVEN_UNIT_INFO"},
			[]string{"piece      : 1 of 3", "method     : full", "file name  : a.txt", "kdf        :"}, nil},
		{"public compact", core.SplitOptions{N: 3, K: 2, Layers: layers, Name: "a.txt",
			Info: core.InfoPublic, Method: core.MethodCompact}, nil,
			[]string{"piece      : 1 of 3", "method     : compact (this piece holds 1/2", "password   : 1 needed to combine",
				"file name  : a.txt"}, nil},
		{"hidden", core.SplitOptions{N: 3, K: 2, Layers: layers, Name: "a.txt", Info: core.InfoHidden}, nil,
			[]string{"details    : hidden until the set is combined"}, []string{"a.txt", "piece      :", "layers"}},
	}
	for _, c := range cases {
		dir := t.TempDir()
		paths := writePieces(t, dir, makePieces(t, c.opts, []byte("content")))
		opts, err := parseArgs(append(append([]string{"info"}, paths[0]), c.args...))
		if err != nil {
			t.Fatal(err)
		}
		opts.yes = true
		out := capture(t, func() { err = cmdInfo(opts) })
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Fatalf("%s: info lacks %q:\n%s", c.name, w, out)
			}
		}
		for _, w := range c.not {
			if strings.Contains(out, w) {
				t.Fatalf("%s: info shows %q:\n%s", c.name, w, out)
			}
		}
	}
}

// TestCombineAsksForWhatAHiddenSetWithheld covers a set that hides its details
// and records neither its algorithms nor its cost: the two flags are named in
// turn, and once both are given the set rebuilds.
func TestCombineAsksForWhatAHiddenSetWithheld(t *testing.T) {
	t.Setenv("RIVEN_UNIT_HW", "withheld")
	input := []byte("withheld everything")
	pieces, err := core.Split(input, core.SplitOptions{N: 3, K: 2, Info: core.InfoHidden, Params: fastKDF,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("withheld"), SchemeID: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	run := func(extra ...string) ([]byte, error) {
		opts, err := parseArgs(append([]string{"combine", "p", "--password-env", "RIVEN_UNIT_HW"}, extra...))
		if err != nil {
			t.Fatal(err)
		}
		opts.yes = true
		got, _, err := combinePieces(opts, copied(pieces[:2]), nil)
		return got, err
	}
	if _, err := run(); err == nil || !strings.Contains(err.Error(), "--algo") {
		t.Fatalf("no algorithms: %v", err)
	}
	if _, err := run("--algo", "aes-256-gcm"); err == nil || !strings.Contains(err.Error(), "--kdf") {
		t.Fatalf("no cost: %v", err)
	}
	got, err := run("--algo", "aes-256-gcm", "--kdf", "m=8,t=1,p=1")
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("with both: %q, %v", got, err)
	}
}

// TestCombineAsksAPublicSetForItsPasswords checks a set whose envelopes take no
// password is opened without asking first, and asked for exactly the passwords
// it turns out to need.
func TestCombineAsksAPublicSetForItsPasswords(t *testing.T) {
	input := []byte("two layers, asked late")
	pieces := makePieces(t, core.SplitOptions{N: 3, K: 2, Info: core.InfoPublic, Layers: []core.LayerSpec{
		{Kind: core.PasswordLayer, Password: []byte("first")},
		{Kind: core.PasswordLayer, Password: []byte("second"), SchemeID: 3},
	}}, input)
	opts := &cliOptions{command: "combine"}
	var got []byte
	var err error
	out := withTerminal(t, "first\nsecond\n", func() { got, _, err = combinePieces(opts, copied(pieces[:2]), nil) })
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("rebuilt %q, %v\n%s", got, err, out)
	}
	if !strings.Contains(out, "needs 2 password(s)") {
		t.Fatalf("the prompt did not say how many:\n%s", out)
	}

	if _, err := askSetPasswords(&cliOptions{yes: true}, 2, nil); err == nil || !strings.Contains(err.Error(), "--password-env") {
		t.Fatalf("without a terminal: %v", err)
	}
}

// TestCombineKeepsThePasswordThatOpenedThePieces checks a protected set opened
// with the first layer's password alone asks for the second only, rather than
// for both again.
func TestCombineKeepsThePasswordThatOpenedThePieces(t *testing.T) {
	input := []byte("two layers, the first typed once")
	pieces := makePieces(t, core.SplitOptions{N: 3, K: 2, Layers: []core.LayerSpec{
		{Kind: core.PasswordLayer, Password: []byte("first")},
		{Kind: core.PasswordLayer, Password: []byte("second"), SchemeID: 3},
	}}, input)
	opts := &cliOptions{command: "combine"}
	var got []byte
	var err error
	out := withTerminal(t, "first\n\nsecond\n", func() { got, _, err = combinePieces(opts, copied(pieces[:2]), nil) })
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("rebuilt %q, %v\n%s", got, err, out)
	}
	if strings.Count(out, "Layer 1 password") != 1 || !strings.Contains(out, "Layer 1 is the one entered above") {
		t.Fatalf("layer 1 was asked for again:\n%s", out)
	}
}

// TestQRAdviceSuggestsCompact checks a set too large for QR is pointed at the
// compact method, which divides the piece size by K, and only where it would.
func TestQRAdviceSuggestsCompact(t *testing.T) {
	t.Setenv("RIVEN_UNIT_QRC", "qr")
	full := planFor(t, "--password-env", "RIVEN_UNIT_QRC", "-k", "3")
	err := checkQRFeasible(full, []pieceio.Format{pieceio.QR}, 99999, 5)
	if err == nil || !strings.Contains(err.Error(), "--method compact") || !strings.Contains(err.Error(), "1/3") {
		t.Fatalf("a full set: %v", err)
	}
	small := planFor(t, "--password-env", "RIVEN_UNIT_QRC", "-k", "3", "--method", "compact")
	if err := checkQRFeasible(small, []pieceio.Format{pieceio.QR}, 99999, 5); err == nil || strings.Contains(err.Error(), "--method compact") {
		t.Fatalf("a compact set: %v", err)
	}
}

// TestVerifyHiddenSet checks verify rebuilds a set that hides its details, and
// reports a shortfall without a count, which it cannot know.
func TestVerifyHiddenSet(t *testing.T) {
	dir := t.TempDir()
	paths := writeSet(t, dir, core.SplitOptions{N: 4, K: 3, Keyless: true, Info: core.InfoHidden,
		Method: core.MethodCompact}, []byte("hidden verify"), pieceio.Binary)

	var err error
	out := captureStderr(t, func() { err = cmdVerify(verifyOpts(t, paths[:3])) })
	if err != nil || !strings.Contains(out, "OK: these pieces rebuild") || !strings.Contains(out, "hides how many") {
		t.Fatalf("three of a 3-of-4 set: %v\n%s", err, out)
	}
	out = captureStderr(t, func() { err = cmdVerify(verifyOpts(t, paths[:2])) })
	if err == nil || !strings.Contains(out, "NOT ENOUGH") {
		t.Fatalf("two of a 3-of-4 set: %v\n%s", err, out)
	}
}

// TestCostNoticeIgnoresNoise checks the slow-open notice does not quote a cost a
// keyless piece never recorded: its cost byte is random, and nothing derives.
func TestCostNoticeIgnoresNoise(t *testing.T) {
	for i := 0; i < 8; i++ {
		pieces := makePieces(t, core.SplitOptions{N: 2, K: 2, Keyless: true}, []byte("noise"))
		out := withTerminal(t, "", func() {
			if _, _, err := combinePieces(&cliOptions{command: "combine"}, copied(pieces), nil); err != nil {
				t.Error(err)
			}
		})
		if strings.Contains(out, "takes a moment") {
			t.Fatalf("a keyless set produced a cost notice: %q", out)
		}
	}
}

// TestSheetKeepsHiddenDetailsHidden runs a sheet export of a set split with
// --info none: the printed page must not give away what the pieces hide.
func TestSheetKeepsHiddenDetailsHidden(t *testing.T) {
	t.Setenv("RIVEN_UNIT_SH", "sheet")
	plan := planFor(t, "--password-env", "RIVEN_UNIT_SH", "-n", "5", "-k", "3", "--info", "none")
	plan.opts.Name = "wallet.kdbx"
	pieces := makePieces(t, plan.opts, []byte("printed"))
	page, err := encodeOne(pieces[1], pieceio.Sheet, plan, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"wallet.kdbx", "2 of 5", "Any 3"} {
		if strings.Contains(string(page), bad) {
			t.Fatalf("the sheet of a hidden set shows %q", bad)
		}
	}
	// A set that shows its details still prints them.
	plan = planFor(t, "--password-env", "RIVEN_UNIT_SH", "-n", "5", "-k", "3")
	plan.opts.Name = "wallet.kdbx"
	page, err = encodeOne(makePieces(t, plan.opts, []byte("printed"))[1], pieceio.Sheet, plan, 2)
	if err != nil || !strings.Contains(string(page), "2 of 5") || !strings.Contains(string(page), "wallet.kdbx") {
		t.Fatalf("the sheet of a visible set lost its details: %v", err)
	}
}

// TestVerifyNamesTheMissingFlag checks verify, which does not ask, says which
// flag a set that withheld its cost or algorithms needs.
func TestVerifyNamesTheMissingFlag(t *testing.T) {
	t.Setenv("RIVEN_UNIT_VF", "verify flag")
	dir := t.TempDir()
	pieces, err := core.Split([]byte("withheld"), core.SplitOptions{N: 2, K: 2, Info: core.InfoPublic, Params: fastKDF,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("verify flag"), SchemeID: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	paths := writePieces(t, dir, pieces)
	out := captureStderr(t, func() { err = cmdVerify(verifyOpts(t, paths, "--password-env", "RIVEN_UNIT_VF")) })
	if err == nil || !strings.Contains(out, "--algo") {
		t.Fatalf("unrecorded algorithms: %v\n%s", err, out)
	}
	out = captureStderr(t, func() {
		err = cmdVerify(verifyOpts(t, paths, "--password-env", "RIVEN_UNIT_VF", "--algo", "aes-256-gcm"))
	})
	if err == nil || !strings.Contains(out, "--kdf") {
		t.Fatalf("unrecorded cost: %v\n%s", err, out)
	}
	out = captureStderr(t, func() {
		err = cmdVerify(verifyOpts(t, paths, "--password-env", "RIVEN_UNIT_VF", "--algo", "aes-256-gcm", "--kdf", "m=8,t=1,p=1"))
	})
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("with both flags: %v\n%s", err, out)
	}
}

// TestCombineAsksForTheCostBeforeThePasswords drives an interactive combine of a
// public set that withheld its cost: the cost is asked for first and each
// password once, rather than every password, then the cost, then every password
// again.
func TestCombineAsksForTheCostBeforeThePasswords(t *testing.T) {
	input := []byte("cost, then the password")
	pieces, err := core.Split(input, core.SplitOptions{N: 2, K: 2, Info: core.InfoPublic, Params: fastKDF, RecordAlgo: true,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("only once")}}})
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	out := withTerminal(t, "m=8,t=1,p=1\nonly once\n", func() {
		got, _, err = combinePieces(&cliOptions{command: "combine"}, copied(pieces), nil)
	})
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("rebuilt %q, %v\n%s", got, err, out)
	}
	if n := strings.Count(out, "Layer 1 password"); n != 1 {
		t.Fatalf("the password was asked for %d times:\n%s", n, out)
	}
}

// TestCraftedKeylessPieceStillAsksForThePassword puts a crafted keyless piece in
// front of a password set. The open must still ask for the password, since some
// pieces did not open without one, and with it the crafted content never wins.
func TestCraftedKeylessPieceStillAsksForThePassword(t *testing.T) {
	genuine := makePieces(t, core.SplitOptions{N: 3, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("pw")}}}, []byte("real"))
	crafted := makePieces(t, core.SplitOptions{N: 2, K: 2, Keyless: true}, []byte("crafted"))
	var got []byte
	var err error
	out := withTerminal(t, "pw\n\n", func() {
		got, _, err = combinePieces(&cliOptions{command: "combine"}, copied([][]byte{crafted[0], genuine[0], genuine[1]}), nil)
	})
	if !strings.Contains(out, "Some pieces opened without a password") {
		t.Fatalf("the password was not asked for:\n%s", out)
	}
	if err == nil && string(got) != "real" {
		t.Fatalf("the crafted content came back: %q", got)
	}
	// Under -y it refuses rather than guessing.
	if _, _, err := combinePieces(&cliOptions{yes: true}, copied([][]byte{crafted[0], genuine[0], genuine[1]}), nil); err == nil {
		t.Fatal("automation combined a mixed set without a password")
	}
}

// TestInfoNoneNeedsAThresholdAboveOne refuses -k 1 with --info none at planning,
// with a message that says why.
func TestInfoNoneNeedsAThresholdAboveOne(t *testing.T) {
	t.Setenv("RIVEN_UNIT_K1", "k1")
	o, _ := parseArgs([]string{"split", "f", "--password-env", "RIVEN_UNIT_K1", "-n", "3", "-k", "1", "--info", "none", "-y"})
	if _, err := planSplit(o, t.TempDir()); err == nil || !strings.Contains(err.Error(), "-k 1") {
		t.Fatalf("-k 1 with --info none: %v", err)
	}
}

// TestInfoRefusalsAreWordedForTheCommandLine checks each mode core refuses comes
// back naming the flags to change, and that a mode it accepts passes. The
// planner once took any refusal for a missing password, whatever core's reason.
func TestInfoRefusalsAreWordedForTheCommandLine(t *testing.T) {
	password := []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("pw")}}
	for _, c := range []struct {
		opts core.SplitOptions
		want string
	}{
		{core.SplitOptions{N: 3, K: 2, Keyless: true, Info: core.InfoProtected}, "--info protected needs a password or a recipient key"},
		{core.SplitOptions{N: 3, K: 2, Keyless: true, Info: core.InfoStrict}, "--info strict needs a password or a recipient key"},
		{core.SplitOptions{N: 3, K: 1, Layers: password, Info: core.InfoHidden}, "--info none needs -k 2 or more"},
		{core.SplitOptions{N: 3, K: 2, Info: core.InfoMode(99)}, "unknown info mode"},
		{core.SplitOptions{N: 3, K: 2, Layers: password, Info: core.InfoStrict}, ""},
		{core.SplitOptions{N: 3, K: 2, Keyless: true, Info: core.InfoHidden}, ""},
		{core.SplitOptions{N: 3, K: 1, Keyless: true}, ""},
	} {
		err := checkInfo(&splitPlan{opts: c.opts})
		switch {
		case c.want == "" && err != nil:
			t.Errorf("--info %s at K %d was refused: %v", c.opts.Info, c.opts.K, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("--info %s at K %d: got %v, want %q", c.opts.Info, c.opts.K, err, c.want)
		}
	}
}

// TestInfoAsksOnceForSeveralPieces runs info over every piece of a password set
// with no --password-env: the password is asked for once, not once per piece.
func TestInfoAsksOnceForSeveralPieces(t *testing.T) {
	dir := t.TempDir()
	paths := writePieces(t, dir, makePieces(t, core.SplitOptions{N: 3, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("pw")}}}, []byte("info")))
	opts, err := parseArgs(append([]string{"info"}, paths...))
	if err != nil {
		t.Fatal(err)
	}
	out := withTerminal(t, "pw\n\n", func() { err = cmdInfo(opts) })
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "Layer 1 password"); n != 1 {
		t.Fatalf("the password was asked for %d times:\n%s", n, out)
	}
	if n := strings.Count(out, "piece      :"); n != 3 {
		t.Fatalf("info described %d of 3 pieces:\n%s", n, out)
	}
}

// copied gives combinePieces a copy of pieces of its own. It takes over what it
// is given and wipes it, so a test that hands it the same pieces twice would
// otherwise hand it wiped ones the second time.
func copied(pieces [][]byte) [][]byte {
	out := make([][]byte, len(pieces))
	for i, p := range pieces {
		out[i] = bytes.Clone(p)
	}
	return out
}

// TestInfoDescribesWhatASetNeeds covers the info lines about what a set needs
// besides its pieces: a recipient key and no password, and a cost it did not
// record; the grouping of pieces whose details are hidden; and the failure when
// no piece can be read at all, which a script has to be able to see.
func TestInfoDescribesWhatASetNeeds(t *testing.T) {
	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	recipient := makePieces(t, core.SplitOptions{N: 2, K: 2, Info: core.InfoPublic,
		Layers: []core.LayerSpec{{Kind: core.RecipientLayer, Recipient: priv.Public()}}}, []byte("x"))
	noCost, err := core.Split([]byte("x"), core.SplitOptions{N: 2, K: 2, Info: core.InfoPublic, Params: fastKDF,
		RecordAlgo: true, Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("pw")}}})
	if err != nil {
		t.Fatal(err)
	}
	hidden := makePieces(t, core.SplitOptions{N: 3, K: 2, Keyless: true, Info: core.InfoHidden}, []byte("x"))
	locked := makePieces(t, core.SplitOptions{N: 2, K: 2,
		Layers: []core.LayerSpec{{Kind: core.PasswordLayer, Password: []byte("pw")}}}, []byte("x"))

	run := func(paths ...string) (string, error) {
		opts, err := parseArgs(append([]string{"info"}, paths...))
		if err != nil {
			t.Fatal(err)
		}
		opts.yes = true
		var runErr error
		out := capture(t, func() { runErr = cmdInfo(opts) })
		return out, runErr
	}
	for name, c := range map[string]struct {
		paths []string
		want  []string
	}{
		"recipient only": {writePieces(t, t.TempDir(), recipient)[:1],
			[]string{"password   : none; a recipient private key is required", "recipients : 1 layer(s) need a private key"}},
		"cost not recorded": {writePieces(t, t.TempDir(), noCost)[:1],
			[]string{"kdf        : not recorded; give it with --kdf to combine"}},
		"hidden grouped": {writePieces(t, t.TempDir(), hidden)[:2],
			[]string{"2 piece(s), details hidden"}},
	} {
		out, err := run(c.paths...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: info lacks %q:\n%s", name, w, out)
			}
		}
	}
	if _, err := run(writePieces(t, t.TempDir(), locked)[:1]...); err == nil ||
		!strings.Contains(err.Error(), "no piece could be opened") {
		t.Fatalf("a piece nothing opens: %v", err)
	}
}

// TestSummaryCoversEveryThresholdAndSecret covers the summary lines the other
// cases do not reach: at a threshold of one there is no promise about fewer
// pieces to make, and a strict set says what reads it, with the guessing it
// allows only when a password alone does.
func TestSummaryCoversEveryThresholdAndSecret(t *testing.T) {
	t.Setenv("RIVEN_UNIT_SK", "one")
	for method, want := range map[string]string{
		"full": "full; any one piece rebuilds it", "compact": "compact; any one piece rebuilds it",
	} {
		plan := planFor(t, "--password-env", "RIVEN_UNIT_SK", "-n", "2", "-k", "1", "--method", method)
		if got := methodSummary(plan); got != want {
			t.Errorf("%s at k=1: %q, want %q", method, got, want)
		}
	}
	plan := planFor(t, "--password-env", "RIVEN_UNIT_SK", "--info", "strict")
	if got, want := infoSummary(plan), "readable with the password; one piece can test guesses"; got != want {
		t.Errorf("strict, one password: %q, want %q", got, want)
	}

	dir := t.TempDir()
	var args []string
	for _, name := range []string{"a.pub", "b.pub"} {
		priv, err := kem.Generate(kem.X25519)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := writePublicKey(path, priv.Public()); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--recipient", path)
	}
	plan = planFor(t, append(args, "--info", "strict")...)
	if got, want := infoSummary(plan), "readable with every private key"; got != want {
		t.Errorf("strict, two keys: %q, want %q", got, want)
	}
}
