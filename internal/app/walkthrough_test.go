// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The interactive half of docs/WALKTHROUGH.txt. docs/walkthrough.sh runs
//
//	go test ./internal/app -run TestWalkthrough -walkthrough DIR
//
// which drives the menu, the wizard and every prompt through the same code the
// binary runs, with the answers below typed in, and writes the transcript to
// DIR/interactive.txt. Only the terminal is stood in for: a piped answer goes
// through the reader the prompts use, and is echoed after its prompt the way a
// terminal shows typing, a password as one star per character. Without the flag
// the test is skipped.

var walkthroughDir = flag.String("walkthrough", "", "write the interactive walkthrough transcript into this directory")

// answer is one line typed at a prompt.
type answer struct {
	text   string
	secret bool
}

func typed(s string) answer  { return answer{text: s} }
func hidden(s string) answer { return answer{text: s, secret: true} }

// enter is the Enter key alone, which takes a prompt's default.
var enter = typed("")

// echoReader hands the program one answer per read and writes it to the
// transcript as it goes, so each answer appears right after the prompt that read
// it.
type echoReader struct {
	answers []answer
	out     io.Writer
}

func (r *echoReader) Read(p []byte) (int, error) {
	if len(r.answers) == 0 {
		return 0, io.EOF
	}
	a := r.answers[0]
	r.answers = r.answers[1:]
	shown := a.text
	if a.secret {
		shown = strings.Repeat("*", len(a.text))
	}
	fmt.Fprintln(r.out, shown)
	return copy(p, a.text+"\n"), nil
}

// transcript collects what the sessions print.
type transcript struct {
	t   *testing.T
	out *os.File
}

// section starts a part of the transcript.
func (tr *transcript) section(title, intro string) {
	fmt.Fprintf(tr.out, "\n%s\n%s\n%s\n\n", strings.Repeat("=", 79), title, strings.Repeat("=", 79))
	if intro != "" {
		fmt.Fprintf(tr.out, "%s\n\n", intro)
	}
}

// session runs one command line as the binary would with a terminal attached,
// answering its prompts in order, and records everything it prints. Every answer
// must be asked for, and the session must not run out of them.
func (tr *transcript) session(args []string, answers ...answer) {
	tr.t.Helper()
	fmt.Fprintf(tr.out, "$ %s\n", strings.TrimSpace("riven "+strings.Join(args, " ")))

	oldIn, oldOut, oldErr, oldInteractive := stdin, os.Stdout, os.Stderr, isInteractive
	r, w, err := os.Pipe()
	if err != nil {
		tr.t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	isInteractive = func() bool { return true }
	reader := &echoReader{answers: answers, out: w}
	stdin = bufio.NewReaderSize(reader, 4096)
	done := make(chan struct{})
	go func() {
		io.Copy(tr.out, r)
		close(done)
	}()

	runErr := run(args)
	if runErr != nil {
		printError(w, runErr)
	}

	w.Close()
	<-done
	stdin, os.Stdout, os.Stderr, isInteractive = oldIn, oldOut, oldErr, oldInteractive
	fmt.Fprintln(tr.out)
	if len(reader.answers) > 0 {
		tr.t.Errorf("riven %v: %d answer(s) were never asked for", args, len(reader.answers))
	}
	if errors.Is(runErr, errAborted) {
		tr.t.Errorf("riven %v ran out of answers", args)
	}
}

func TestWalkthrough(t *testing.T) {
	if *walkthroughDir == "" {
		t.Skip("run by docs/walkthrough.sh with -walkthrough DIR")
	}
	t.Chdir(*walkthroughDir)
	old := lineWidth
	lineWidth = func() int { return clampWidth(fallbackLineWidth) }
	defer func() { lineWidth = old }()

	f, err := os.Create(filepath.Join(*walkthroughDir, "interactive.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := &transcript{t: t, out: f}
	if err := os.WriteFile("seed.txt", []byte("twelve word seed goes here, and this is the thing worth protecting\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	const pw = "correct horse battery"
	t.Setenv("RIVEN_PW", pw)

	tr.section("W1. The menu, then the recommended split",
		"Running riven with no arguments opens the menu. The recommended path asks\n"+
			"how many pieces, how many to rebuild, one password, and where to write.")
	tr.session(nil, typed("1"), typed("seed.txt"), enter, enter, enter,
		hidden(pw), hidden(pw), typed("wizard"), enter)

	tr.section("W2. A generated password",
		"Naming the file skips the menu. Enter at the password prompt generates one;\n"+
			"it is shown once and stored nowhere.")
	tr.session([]string{"seed.txt"}, typed("3"), typed("2"), enter, enter, typed("generated"), enter)

	tr.section("W3. The advanced path: two layers, compact, nothing shown on a piece",
		"A password layer and a recipient key layer, with a new key pair made on the\n"+
			"way, then the method, what one piece shows, recording, cost and padding.")
	tr.session([]string{"split", "seed.txt"}, typed("4"), typed("2"), typed("2"),
		typed("1"), enter, hidden(pw), hidden(pw), typed("y"),
		typed("2"), enter, enter, enter, typed("alice"), typed("n"),
		typed("2"), typed("4"), enter, enter, enter, enter, enter,
		typed("advanced"), typed("binary,qr"))

	tr.section("W4. No encryption at all",
		"The third answer splits without a password. The threshold is the only lock,\n"+
			"and the wizard says so.")
	tr.session([]string{"split", "seed.txt"}, typed("3"), typed("2"), typed("3"), typed("keyless"), enter)

	tr.section("W5. Splitting a piece of text",
		"The second menu entry reads the secret without echoing it, like a password.")
	tr.session(nil, typed("2"), hidden("my recovery code 4417-0921"), typed("3"), typed("2"), enter,
		hidden(pw), hidden(pw), typed("text"), enter)

	tr.section("W6. Inspecting a piece",
		"The details are protected by the password, so it is asked for.")
	tr.session(nil, typed("3"), typed("wizard/seed.txt.1"), hidden(pw), enter)

	tr.section("W7. Inspecting a whole folder asks once",
		"One answer opens every piece.")
	tr.session([]string{"info", "wizard"}, hidden(pw), enter)

	tr.section("W8. Rebuilding from the menu",
		"The recorded file name is offered as the default, never used unasked.")
	tr.session(nil, typed("4"),
		typed("wizard/seed.txt.2 wizard/seed.txt.4 wizard/seed.txt.5"),
		hidden(pw), enter, typed("recovered.txt"))

	tr.section("W9. Checking a set before you need it",
		"verify rebuilds in memory and writes nothing. The password is asked once.")
	tr.session([]string{"verify", "wizard"}, hidden(pw), enter)

	tr.section("W10. A wrong password",
		"A piece that does not open could also be one whose cost was not recorded, so\n"+
			"the cost is offered once; Enter gives up.")
	tr.session([]string{"combine", "wizard/seed.txt.1", "wizard/seed.txt.2",
		"wizard/seed.txt.3"}, hidden("not the password"), enter, enter)

	tr.section("W11. Rebuilding the compact set from W3",
		"Its pieces show nothing, so nothing is asked until the set is rebuilt: then\n"+
			"it says how many passwords it needs. The private key comes from a flag.")
	tr.session([]string{"combine", "advanced/seed.txt.1", "advanced/seed.txt.3",
		"--identity", "alice.key"}, hidden(pw), typed("from-advanced.txt"))

	tr.section("W12. A keyless set with one damaged piece",
		"Piece 2 of the W4 set has had a byte changed. Some pieces open without a\n"+
			"password and one does not, which is also how a crafted piece slipped into a\n"+
			"password set would look, so the user is asked; Enter means no password.")
	damage(t, "keyless/seed.txt.2")
	tr.session([]string{"combine", "keyless/seed.txt.1", "keyless/seed.txt.2",
		"keyless/seed.txt.3"}, enter, typed("from-keyless.txt"))

	tr.section("W13. A set that did not record its algorithms or cost",
		"Split with flags first. Combining then asks for what the pieces left out,\n"+
			"each once, before the password.")
	tr.session([]string{"split", "seed.txt", "-n", "2", "-k", "2", "--password-env", "RIVEN_PW",
		"--record-algo", "false", "--record-kdf", "false", "--info", "public", "--out", "withheld", "-y"})
	tr.session([]string{"combine", "withheld/seed.txt.1", "withheld/seed.txt.2"},
		typed("aes-256-gcm"), typed("recommended"), hidden(pw), typed("from-withheld.txt"))

	tr.section("W14. Splitting again into the same folder",
		"Existing pieces are not replaced without asking.")
	tr.session([]string{"split", "seed.txt", "-n", "5", "-k", "3", "--password-env", "RIVEN_PW", "--out", "wizard"},
		enter, enter, typed("n"))

	tr.section("W15. A key pair from the menu", "")
	tr.session(nil, typed("5"), typed("bob"))

	tr.section("W16. A set protected by a private key alone",
		"Its pieces open only with the key, so without --identity the password prompt\n"+
			"has nothing to take, and an empty answer says what is missing.")
	tr.session([]string{"split", "seed.txt", "-n", "2", "-k", "2", "--recipient", "alice.pub",
		"--out", "sealed", "-y"})
	tr.session([]string{"info", "sealed/seed.txt.1"}, enter)
	tr.session([]string{"info", "sealed/seed.txt.1", "--identity", "alice.key"})

	const pw2 = "second layer phrase"
	t.Setenv("RIVEN_PW2", pw2)
	tr.section("W17. Two passwords, and only the first typed",
		"The first layer's password is enough to open the pieces, so the second is\n"+
			"asked for once the set says it needs two.")
	tr.session([]string{"split", "seed.txt", "-n", "3", "-k", "2", "--password-env", "RIVEN_PW",
		"--password-env", "RIVEN_PW2", "--out", "two", "-y"})
	tr.session([]string{"combine", "two/seed.txt.1", "two/seed.txt.3"},
		hidden(pw), enter, hidden(pw2), typed("from-two.txt"))
}

// damage flips one byte in the middle of a file.
func damage(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x01
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
