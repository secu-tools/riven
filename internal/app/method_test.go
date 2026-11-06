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
		got, _, err := combinePieces(opts, pieces[:2], nil)
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
	out := withTerminal(t, "first\nsecond\n", func() { got, _, err = combinePieces(opts, pieces[:2], nil) })
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
	out := withTerminal(t, "first\n\nsecond\n", func() { got, _, err = combinePieces(opts, pieces[:2], nil) })
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
			if _, _, err := combinePieces(&cliOptions{command: "combine"}, pieces, nil); err != nil {
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
	page, _, err := encodeOne(pieces[1], pieceio.Sheet, plan, 2)
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
	page, _, err = encodeOne(makePieces(t, plan.opts, []byte("printed"))[1], pieceio.Sheet, plan, 2)
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
		got, _, err = combinePieces(&cliOptions{command: "combine"}, pieces, nil)
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
		got, _, err = combinePieces(&cliOptions{command: "combine"}, [][]byte{crafted[0], genuine[0], genuine[1]}, nil)
	})
	if !strings.Contains(out, "Some pieces opened without a password") {
		t.Fatalf("the password was not asked for:\n%s", out)
	}
	if err == nil && string(got) != "real" {
		t.Fatalf("the crafted content came back: %q", got)
	}
	// Under -y it refuses rather than guessing.
	if _, _, err := combinePieces(&cliOptions{yes: true}, [][]byte{crafted[0], genuine[0], genuine[1]}, nil); err == nil {
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
