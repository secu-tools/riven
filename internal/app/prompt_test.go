// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// withInput points the prompt reader at a script of answers and captures what
// was printed, so the question-and-answer behaviour can be checked without a
// terminal.
func withInput(t *testing.T, answers string, fn func()) string {
	t.Helper()
	oldStdin, oldStdout := stdin, os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	stdin = bufio.NewReader(strings.NewReader(answers))
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	defer func() {
		stdin, os.Stdout = oldStdin, oldStdout
	}()
	fn()
	w.Close()
	out := <-done
	r.Close()
	return out
}

// TestReadLineTakesTheDefaultOnEnter is the wizard's central promise: pressing
// Enter accepts what is shown in brackets.
func TestReadLineTakesTheDefaultOnEnter(t *testing.T) {
	var got string
	out := withInput(t, "\n", func() {
		v, err := readLine("Output directory", "pieces")
		if err != nil {
			t.Fatal(err)
		}
		got = v
	})
	if got != "pieces" {
		t.Fatalf("Enter gave %q, want the default", got)
	}
	if !strings.Contains(out, "[default: pieces]") {
		t.Fatalf("the prompt should show the default: %q", out)
	}
}

func TestReadLineTakesTypedInput(t *testing.T) {
	var got string
	withInput(t, "  somewhere else  \n", func() {
		v, err := readLine("Output directory", "pieces")
		if err != nil {
			t.Fatal(err)
		}
		got = v
	})
	if got != "  somewhere else  " {
		t.Fatalf("got %q, want the line as typed apart from the newline", got)
	}
}

// TestReadLineWithoutDefault checks a prompt with no default does not print
// empty brackets.
func TestReadLineWithoutDefault(t *testing.T) {
	out := withInput(t, "value\n", func() {
		if _, err := readLine("Name", ""); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "[]") {
		t.Fatalf("no default should mean no brackets: %q", out)
	}
}

// TestReadIntRetriesUntilValid checks an out-of-range or non-numeric answer is
// re-asked rather than accepted or fatal, which is what makes the wizard usable.
func TestReadIntRetriesUntilValid(t *testing.T) {
	var got int
	out := withInput(t, "abc\n99\n0\n4\n", func() {
		v, err := readInt("Total pieces", 5, 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		got = v
	})
	if got != 4 {
		t.Fatalf("got %d, want the first valid answer", got)
	}
	if n := strings.Count(out, "please enter a number between 1 and 10"); n != 3 {
		t.Fatalf("expected three retries, saw %d in %q", n, out)
	}
}

func TestReadIntTakesTheDefault(t *testing.T) {
	var got int
	withInput(t, "\n", func() {
		v, err := readInt("Threshold", 3, 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		got = v
	})
	if got != 3 {
		t.Fatalf("got %d, want the default 3", got)
	}
}

// TestConfirmAnswers checks every spelling the wizard accepts, and that anything
// else is re-asked instead of being taken as a no.
func TestConfirmAnswers(t *testing.T) {
	cases := map[string]bool{
		"y\n": true, "Y\n": true, "yes\n": true, "YES\n": true,
		"n\n": false, "no\n": false, " N \n": false,
	}
	for answer, want := range cases {
		var got bool
		withInput(t, answer, func() {
			v, err := confirm("Record the algorithms", true)
			if err != nil {
				t.Fatal(err)
			}
			got = v
		})
		if got != want {
			t.Fatalf("answer %q gave %v, want %v", answer, got, want)
		}
	}

	for _, def := range []bool{true, false} {
		var got bool
		withInput(t, "\n", func() {
			v, err := confirm("Question", def)
			if err != nil {
				t.Fatal(err)
			}
			got = v
		})
		if got != def {
			t.Fatalf("Enter gave %v, want the default %v", got, def)
		}
	}

	var got bool
	out := withInput(t, "maybe\nq\ny\n", func() {
		v, err := confirm("Question", false)
		if err != nil {
			t.Fatal(err)
		}
		got = v
	})
	if !got {
		t.Fatal("the valid answer after two invalid ones was not used")
	}
	if n := strings.Count(out, "please answer y or n"); n != 2 {
		t.Fatalf("expected two retries, saw %d in %q", n, out)
	}
}

// TestPromptsAbortWhenInputEnds covers Ctrl-C and a closed pipe: both end the
// input, and both must read as an abort rather than an unexplained EOF.
func TestPromptsAbortWhenInputEnds(t *testing.T) {
	checks := map[string]func() error{
		"readLine": func() error { _, err := readLine("Name", ""); return err },
		"readInt":  func() error { _, err := readInt("Count", 1, 1, 5); return err },
		"confirm":  func() error { _, err := confirm("Sure", true); return err },
		"password": func() error { _, err := readPasswordMasked("Password: "); return err },
	}
	for name, fn := range checks {
		var err error
		withInput(t, "", func() { err = fn() })
		if !errors.Is(err, errAborted) {
			t.Fatalf("%s: got %v, want an abort", name, err)
		}
	}
}

func TestPromptErr(t *testing.T) {
	if !errors.Is(promptErr(nil), errAborted) {
		t.Fatal("no error at the end of input is still an abort")
	}
	if !errors.Is(promptErr(io.EOF), errAborted) {
		t.Fatal("EOF should read as an abort")
	}
	real := errors.New("disk on fire")
	if got := promptErr(real); !errors.Is(got, real) {
		t.Fatalf("a real failure should pass through, got %v", got)
	}
}

// TestReadPasswordFromNonTerminal checks the password path used when input is
// piped: the line is taken as the password, with no echo of its own.
func TestReadPasswordFromNonTerminal(t *testing.T) {
	var got []byte
	out := withInput(t, "hunter2\n", func() {
		v, err := readPasswordMasked("Password: ")
		if err != nil {
			t.Fatal(err)
		}
		got = v
	})
	if string(got) != "hunter2" {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("the password must not be echoed: %q", out)
	}
}

// TestReadPasswordConfirmedRequiresAMatch checks a mistyped confirmation is
// re-asked rather than accepted.
func TestReadPasswordConfirmedRequiresAMatch(t *testing.T) {
	var got []byte
	out := withInput(t, "first\nsecond\nagain\nagain\n", func() {
		v, err := readPasswordConfirmed("Password")
		if err != nil {
			t.Fatal(err)
		}
		got = v
	})
	if string(got) != "again" {
		t.Fatalf("got %q, want the confirmed password", got)
	}
	if !strings.Contains(strings.ToLower(out), "match") {
		t.Fatalf("the mismatch should be reported: %q", out)
	}
}
