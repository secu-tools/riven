// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/secu-tools/riven/internal/memory"
)

// errAborted is returned when the user cancels a prompt with Ctrl-C, or when
// input ends before a prompt was answered.
var errAborted = errors.New("aborted")

var stdin = bufio.NewReader(os.Stdin)

// promptErr maps a read failure to something meaningful. Input running out is an
// abort, not a condition worth reporting as "EOF".
func promptErr(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return errAborted
	}
	return err
}

// secretOut is where a secret meant for the reader's eyes is written.
//
// isInteractive asks about standard input, which is a different question:
// stdin can be a terminal while stdout is redirected into a file or a pipe. A
// generated password is the only copy that will ever exist, so it goes to the
// terminal rather than into whatever standard output happens to be.
func secretOut() io.Writer {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		return os.Stdout
	}
	return os.Stderr
}

// isInteractive reports whether stdin is a terminal we can prompt on.
//
// It is a variable so the tests can stand in a terminal and drive the paths that
// only run with one attached: the menu, the overwrite questions, and the prompts
// for what a set did not record. The prompts themselves read from the shared
// reader either way, so scripted answers reach them unchanged.
var isInteractive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// readLine prints prompt (with an optional default) and returns the entered
// line, or def if the user just presses Enter.
func readLine(prompt, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [default: %s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", promptErr(err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return def, nil
	}
	return line, nil
}

// readInt prompts for an integer with a default and inclusive bounds.
func readInt(prompt string, def, min, max int) (int, error) {
	for {
		s, err := readLine(prompt, strconv.Itoa(def))
		if err != nil {
			return 0, err
		}
		v, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || v < min || v > max {
			fmt.Printf("  please enter a number between %d and %d\n", min, max)
			continue
		}
		return v, nil
	}
}

// confirm asks a yes/no question with a default.
func confirm(prompt string, def bool) (bool, error) {
	d := "no"
	if def {
		d = "yes"
	}
	for {
		fmt.Printf("%s (y/n) [default: %s]: ", prompt, d)
		line, err := stdin.ReadString('\n')
		if err != nil && line == "" {
			return false, promptErr(err)
		}
		line = strings.ToLower(strings.TrimSpace(line))
		switch line {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Println("  please answer y or n")
	}
}

// readPasswordMasked reads a password, echoing '*' per byte when stdin is a
// terminal. Non-terminal input is read as a plain line. The caller owns the
// returned bytes and should wipe them.
func readPasswordMasked(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := stdin.ReadString('\n')
		if err != nil && line == "" {
			return nil, promptErr(err)
		}
		// A piped password also sits in the immutable string above and in the
		// buffered reader, neither of which can be wiped. Piping one in is the
		// weaker way to supply it; --password-env avoids both copies.
		return memory.Copy([]byte(strings.TrimRight(line, "\r\n"))), nil
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer term.Restore(fd, oldState)

	pw := newPasswordBuf()
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			fmt.Print("\r\n")
			pw.free()
			return nil, promptErr(err)
		}
		c := buf[0]
		switch c {
		case '\r', '\n':
			fmt.Print("\r\n")
			return pw.take(), nil
		case 3, 4: // Ctrl-C, Ctrl-D
			fmt.Print("\r\n")
			pw.free()
			return nil, errAborted
		case 27: // Escape also cancels
			fmt.Print("\r\n")
			pw.free()
			return nil, errAborted
		case 127, 8: // Backspace / Delete
			if pw.backspace() {
				fmt.Print("\b \b")
			}
		default:
			if c >= 32 {
				pw.add(c)
				fmt.Print("*")
			}
		}
	}
}

// passwordBufMin is the starting capacity, chosen so an ordinary password never
// causes a growth.
const passwordBufMin = 256

// passwordBuf accumulates a typed password in locked memory.
//
// append would abandon the old array at every growth, each holding a prefix of
// the password, unwiped and on the heap. Growth here is explicit and wipes what
// it replaces.
type passwordBuf struct {
	b []byte
	n int
}

func newPasswordBuf() *passwordBuf {
	return &passwordBuf{b: memory.Bytes(passwordBufMin)}
}

func (p *passwordBuf) add(c byte) {
	if p.n == len(p.b) {
		bigger := memory.Bytes(len(p.b) * 2)
		copy(bigger, p.b)
		memory.Free(p.b)
		p.b = bigger
	}
	p.b[p.n] = c
	p.n++
}

// backspace drops the last byte and reports whether there was one.
func (p *passwordBuf) backspace() bool {
	if p.n == 0 {
		return false
	}
	p.n--
	p.b[p.n] = 0
	return true
}

// take hands the password to the caller, who frees it with memory.Free. The
// capacity is clipped so a later append cannot write into the locked tail.
func (p *passwordBuf) take() []byte {
	if p.n == 0 {
		p.free()
		return []byte{}
	}
	out := p.b[:p.n:p.n]
	p.b, p.n = nil, 0
	return out
}

func (p *passwordBuf) free() {
	memory.Free(p.b)
	p.b, p.n = nil, 0
}

// readPasswordConfirmed prompts twice and requires a match.
func readPasswordConfirmed(prompt string) ([]byte, error) {
	for {
		p1, err := readPasswordMasked(prompt + ": ")
		if err != nil {
			return nil, err
		}
		p2, err := readPasswordMasked("confirm password: ")
		if err != nil {
			for i := range p1 {
				p1[i] = 0
			}
			return nil, err
		}
		if string(p1) == string(p2) {
			for i := range p2 {
				p2[i] = 0
			}
			return p1, nil
		}
		for i := range p1 {
			p1[i] = 0
		}
		for i := range p2 {
			p2[i] = 0
		}
		fmt.Println("  passwords did not match, try again")
	}
}
