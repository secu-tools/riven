// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/kem"
)

// TestEveryFlagSpellingIsAccepted checks the long and short spellings the help
// text gives for the same flag all reach the same option.
func TestEveryFlagSpellingIsAccepted(t *testing.T) {
	o, err := parseArgs([]string{"split", "f", "--parts", "6", "--threshold", "4",
		"--algos", "aes-256-gcm", "-t", "text", "-v", "--yes"})
	if err != nil {
		t.Fatal(err)
	}
	if o.n != 6 || !o.nSet || o.k != 4 || !o.kSet || o.algo != "aes-256-gcm" || !o.algoSet ||
		o.text != "text" || !o.textSet || o.verify != verifyFull || !o.verifySet || !o.yes {
		t.Fatalf("an alias did not reach its option: %+v", o)
	}
}

// TestKeylessRefusesACostFlag checks --record-kdf is refused beside --keyless,
// which derives no key and so has no cost to record or leave out.
func TestKeylessRefusesACostFlag(t *testing.T) {
	o, err := parseArgs([]string{"split", "f", "--keyless", "--record-kdf", "false", "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSplitOptions(o); err == nil || !strings.Contains(err.Error(), "--record-kdf") {
		t.Fatalf("got %v", err)
	}
}

// TestErrorsReadAsTheUserNeedsThem checks a cancelled question ends with a word
// rather than an error, and a failure core did not tie to a piece is still
// printed beside the file it came from, without the package name.
func TestErrorsReadAsTheUserNeedsThem(t *testing.T) {
	var out strings.Builder
	printError(&out, errAborted)
	if got := out.String(); got != "\nriven: aborted\n" {
		t.Fatalf("a cancel printed %q", got)
	}
	if got, want := pieceFailure("a.1", errors.New("format: not a piece")), `"a.1": not a piece`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestAConsoleThatRefusesColourStaysPlain checks a terminal that will not take
// colour is left plain, and nothing is set to restore for it.
func TestAConsoleThatRefusesColourStaysPlain(t *testing.T) {
	t.Setenv("TERM", "xterm")
	t.Setenv("NO_COLOR", "")
	oldTerminal, oldEnable := streamIsTerminal, enableStream
	t.Cleanup(func() { streamIsTerminal, enableStream = oldTerminal, oldEnable })
	streamIsTerminal = func(*os.File) bool { return true }
	enableStream = func(*os.File) (bool, func()) { return false, nil }
	restore := setupColor(false)
	defer restore()
	if len(colorOn) != 0 {
		t.Fatalf("colour was turned on for %d streams that refused it", len(colorOn))
	}
}

// TestAKeyFileOfTheRightLengthCanStillBeWrong checks a key file whose label and
// length are right but whose bytes are not a key is refused, naming the file.
func TestAKeyFileOfTheRightLengthCanStillBeWrong(t *testing.T) {
	dir := t.TempDir()
	write := func(name, label string, body []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(label+"\n"+base64.StdEncoding.EncodeToString(body)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pub := make([]byte, kem.P256.PublicKeySize())
	pub[0] = 4 // an uncompressed point, but not one on the curve
	for i := 1; i < len(pub); i++ {
		pub[i] = 0xff
	}
	p := write("bad.pub", pubKeyLabel(kem.P256), pub)
	if _, err := readPublicKey(p); err == nil || !strings.Contains(err.Error(), p) {
		t.Fatalf("a point off the curve: %v", err)
	}
	priv := make([]byte, kem.P256.PrivateKeySize())
	for i := range priv {
		priv[i] = 0xff // past the group order
	}
	p = write("bad.key", privKeyLabel(kem.P256), priv)
	if _, err := readPrivateKey(p); err == nil || !strings.Contains(err.Error(), p) {
		t.Fatalf("a scalar past the order: %v", err)
	}
}
