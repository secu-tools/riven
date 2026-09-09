// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
)

// The advanced wizard steps only run when a terminal is attached, so nothing
// reached them: the answers they turn into a plan were never checked. The
// prompts read from the same reader whether or not a terminal is present, so
// feeding answers drives them directly.

// A "no" to either recording question has to reach the plan, because it decides
// whether the piece can be opened without --algo, and whether combine can
// restore the original name.
func TestPlanRecordingCarriesBothAnswers(t *testing.T) {
	for _, c := range []struct {
		answers    string
		algo, name bool
	}{
		{"y\ny\n", true, true},
		{"n\ny\n", false, true},
		{"y\nn\n", true, false},
		{"n\nn\n", false, false},
	} {
		plan := &splitPlan{}
		opts := &cliOptions{}
		withInput(t, c.answers, func() {
			if err := planRecording(plan, opts); err != nil {
				t.Fatalf("answers %q: %v", c.answers, err)
			}
		})
		if plan.opts.RecordAlgo != c.algo {
			t.Errorf("answers %q: RecordAlgo = %v, want %v", c.answers, plan.opts.RecordAlgo, c.algo)
		}
		if !opts.recordNameSet || opts.recordName != c.name {
			t.Errorf("answers %q: recordName = %v (set %v), want %v",
				c.answers, opts.recordName, opts.recordNameSet, c.name)
		}
	}
}

// A flag already given must not be asked about again, or the wizard would
// override what the user put on the command line.
func TestPlanRecordingSkipsWhatTheFlagsAnswered(t *testing.T) {
	plan := &splitPlan{}
	opts := &cliOptions{recordAlgoSet: true, recordNameSet: true, recordName: false}
	plan.opts.RecordAlgo = true

	withInput(t, "", func() { // no answers available: nothing may be asked
		if err := planRecording(plan, opts); err != nil {
			t.Fatalf("a fully flagged run still prompted: %v", err)
		}
	})
	if !plan.opts.RecordAlgo || opts.recordName {
		t.Fatal("the wizard overrode a flag")
	}
}

// The cost chosen at the prompt is what every piece is sealed with, and the
// answer to recording it decides whether --kdf is needed to open them.
func TestPlanCostTakesThePresetAndTheRecordingAnswer(t *testing.T) {
	plan := &splitPlan{}
	plan.opts.Params = kdf.Default()
	opts := &cliOptions{}

	// First answer picks a preset from the list, second declines recording.
	withInput(t, "1\nn\n", func() {
		if err := planCost(plan, opts); err != nil {
			t.Fatalf("planCost: %v", err)
		}
	})
	if err := plan.opts.Params.Validate(); err != nil {
		t.Fatalf("the chosen cost is not usable: %v", err)
	}
	if plan.opts.RecordKDF {
		t.Error("declining to record the cost was not carried into the plan")
	}
}

// --kdf on the command line settles the cost, so only the recording question
// remains.
func TestPlanCostHonoursTheKDFFlag(t *testing.T) {
	plan := &splitPlan{}
	want := kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}
	plan.opts.Params = want
	opts := &cliOptions{kdfSpec: "m=8,t=1,p=1"}

	withInput(t, "y\n", func() {
		if err := planCost(plan, opts); err != nil {
			t.Fatalf("planCost: %v", err)
		}
	})
	if plan.opts.Params != want {
		t.Fatalf("the flagged cost was replaced: %v", plan.opts.Params)
	}
	if !plan.opts.RecordKDF {
		t.Error("the recording answer was not carried")
	}
}

// Padding is the one wizard answer that changes what a piece's size reveals, so
// both the ordinary width and the disabling answer have to land.
func TestPlanPaddingTurnsTheAnswerIntoAMode(t *testing.T) {
	plan := &splitPlan{}
	withInput(t, "0\n", func() {
		if err := planPadding(plan, &cliOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	if !plan.opts.Padding.Off {
		t.Error("0 percent should disable padding")
	}

	plan = &splitPlan{}
	withInput(t, "40\n", func() {
		if err := planPadding(plan, &cliOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	if plan.opts.Padding.Off || plan.opts.Padding.Width() != 40 {
		t.Errorf("Padding = %+v, want a 40 percent class", plan.opts.Padding)
	}

	// --pad already answered it.
	plan = &splitPlan{}
	withInput(t, "", func() {
		if err := planPadding(plan, &cliOptions{padSet: true}); err != nil {
			t.Fatal(err)
		}
	})
}

// The algorithm menu must never offer the layer above's algorithm as the
// default, because two adjacent layers sharing one is refused later: the wizard
// would be walking the user into an error.
func TestChooseSchemeNeverDefaultsToTheForbiddenOne(t *testing.T) {
	all := ciphers.All()
	if len(all) < 2 {
		t.Skip("needs at least two algorithms")
	}
	forbid := all[0].ID

	var got uint8
	out := withInput(t, "\n", func() { // Enter takes the default
		id, err := chooseScheme(forbid, forbid)
		if err != nil {
			t.Fatal(err)
		}
		got = id
	})
	if got == forbid {
		t.Fatalf("the default was the forbidden algorithm %d", forbid)
	}
	if !strings.Contains(out, all[0].Name) {
		t.Errorf("the menu did not list the algorithms:\n%s", out)
	}

	// A typed name is taken as given.
	withInput(t, all[1].Name+"\n", func() {
		id, err := chooseScheme(all[0].ID, 0)
		if err != nil {
			t.Fatal(err)
		}
		if id != all[1].ID {
			t.Errorf("typed %q, got id %d", all[1].Name, id)
		}
	})
}

// A generated password has to reach the plan so it can be shown afterwards:
// it is the only copy, and losing it loses the data.
func TestChoosePasswordGeneratesOnAnEmptyAnswer(t *testing.T) {
	plan := &splitPlan{}
	var pw []byte
	withInput(t, "\n", func() { // Enter asks for a generated one
		got, err := choosePassword("Password", nil, plan)
		if err != nil {
			t.Fatal(err)
		}
		pw = got
	})
	if len(pw) == 0 {
		t.Fatal("no password was produced")
	}
	if len(plan.generated) != 1 || string(plan.generated[0]) != string(pw) {
		t.Fatal("the generated password was not recorded for reporting")
	}
}

// layersInteractive is the advanced path's main loop: it decides how many layers
// there are, what keys each one, and which algorithm it uses. Nothing reached
// it, so the order those answers are applied in was never checked.
func TestLayersInteractiveBuildsOnePasswordLayer(t *testing.T) {
	plan := &splitPlan{}
	// keyed by password, default algorithm, generated password, no more layers.
	withInput(t, "1\n\n\nn\n", func() {
		if err := layersInteractive(plan, &cliOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	if len(plan.opts.Layers) != 1 {
		t.Fatalf("built %d layers, want 1", len(plan.opts.Layers))
	}
	if plan.opts.Layers[0].Kind != core.PasswordLayer {
		t.Error("the layer is not keyed by a password")
	}
	if len(plan.verifyPasswords) != 1 {
		t.Error("the password was not kept for the post-split verification")
	}
}

// Two layers must not share an algorithm: adjacent duplicates are refused later,
// so the wizard has to hand back a set that will actually split.
func TestLayersInteractiveKeepsAdjacentAlgorithmsDistinct(t *testing.T) {
	plan := &splitPlan{}
	withInput(t, "1\n\n\ny\n1\n\n\nn\n", func() {
		if err := layersInteractive(plan, &cliOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	if len(plan.opts.Layers) != 2 {
		t.Fatalf("built %d layers, want 2", len(plan.opts.Layers))
	}
	if _, err := core.AssignSchemes(plan.opts.Layers); err != nil {
		t.Fatalf("the wizard produced layers the split refuses: %v", err)
	}
	if len(plan.verifyPasswords) != 2 {
		t.Errorf("kept %d passwords for two layers", len(plan.verifyPasswords))
	}
}

// Offered a recipient layer with no key to hand, the wizard generates a pair and
// writes both files, because the private one is the only way back.
func TestRecipientForLayerGeneratesAndWritesAPair(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	plan := &splitPlan{}
	opts := &cliOptions{keyType: "x25519"} // fastest type; the choice is tested elsewhere

	var pub *kem.PublicKey
	withInput(t, "\nmine\n", func() { // Enter: generate; base name "mine"
		got, err := recipientForLayer(plan, opts)
		if err != nil {
			t.Fatal(err)
		}
		pub = got
	})
	if pub == nil {
		t.Fatal("no public key came back")
	}
	for _, want := range []string{"mine.pub", "mine.key"} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("%s was not written: %v", want, err)
		}
	}
	if len(plan.privateKeys) != 1 {
		t.Error("the new private key was not kept, so the split cannot verify itself")
	}
}

// Naming an existing key file uses it rather than generating another.
func TestRecipientForLayerReadsANamedKey(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	priv, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "alice.pub")
	if err := writePublicKey(path, priv.Public()); err != nil {
		t.Fatal(err)
	}

	plan := &splitPlan{}
	withInput(t, path+"\n", func() {
		got, err := recipientForLayer(plan, &cliOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Scheme() != kem.X25519 {
			t.Errorf("read a %s key, want x25519", got.Scheme().Name())
		}
	})
	if len(plan.privateKeys) != 0 {
		t.Error("naming a public key should not add a private one")
	}
}

// The cost retry only applies where it can help: a piece that failed for any
// other reason, or a run that already named a cost, must not be asked again.
func TestRetryWithKDFOnlyOffersItselfWhenItCouldWork(t *testing.T) {
	params := kdf.Default()

	// An explicit cost was already supplied: nothing to retry with.
	got, err := retryWithKDF(&cliOptions{}, nil, core.OpenOptions{Params: &params}, format.ErrWrongPassword)
	if got != nil || err != nil {
		t.Errorf("retried despite an explicit cost: %v %v", got, err)
	}

	// The failure was not a wrong-password/parameters one.
	got, err = retryWithKDF(&cliOptions{}, nil, core.OpenOptions{}, errors.New("some other failure"))
	if got != nil || err != nil {
		t.Errorf("retried on an unrelated failure: %v %v", got, err)
	}

	// Automation cannot be asked, so it declines rather than prompting.
	got, err = retryWithKDF(&cliOptions{yes: true}, nil, core.OpenOptions{}, format.ErrWrongPassword)
	if got != nil || err != nil {
		t.Errorf("prompted under -y: %v %v", got, err)
	}
}
