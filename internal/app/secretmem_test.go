// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"testing"

	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/password"
)

// reachedByWipeAll reports whether b is registered locked memory, by checking
// that the signal handler's wipe clears it. Only memory.Bytes registers, so this
// distinguishes a locked buffer from an ordinary allocation.
func reachedByWipeAll(t *testing.T, b []byte) bool {
	t.Helper()
	if len(b) == 0 {
		t.Fatal("nothing to check")
	}
	saved := append([]byte(nil), b...)
	memory.WipeAll()
	cleared := bytes.Equal(b, make([]byte, len(b)))
	copy(b, saved) // put it back so the caller can carry on
	return cleared
}

// The README says passwords are held in locked memory and wiped on Ctrl-C. That
// is only true while these entry points keep allocating from memory.Bytes, and
// nothing else in the program would notice if one of them stopped.
func TestPasswordsAreHeldInLockedMemory(t *testing.T) {
	t.Setenv("RIVEN_TEST_PW", "correct-horse-battery-staple")

	fromEnv, err := passwordFromEnv("RIVEN_TEST_PW")
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Free(fromEnv)
	if !reachedByWipeAll(t, fromEnv) {
		t.Error("a password from --password-env is not in locked memory")
	}

	generated, err := generatePassword(defaultGenLen)
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Free(generated)
	if !reachedByWipeAll(t, generated) {
		t.Error("a generated password is not in locked memory")
	}

	// The canonical form is what the key is actually derived from.
	canon := password.Canonical(fromEnv)
	defer memory.Free(canon)
	if !reachedByWipeAll(t, canon) {
		t.Error("the canonical password form is not in locked memory")
	}
}

// An interrupt runs WipeAll and then os.Exit, which skips deferred functions, so
// the registry is the only thing that clears a password on Ctrl-C.
func TestInterruptClearsAPassword(t *testing.T) {
	t.Setenv("RIVEN_TEST_PW", "a-password-worth-losing")
	pw, err := passwordFromEnv("RIVEN_TEST_PW")
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Free(pw)

	memory.WipeAll() // what the signal handler runs
	if !bytes.Equal(pw, make([]byte, len(pw))) {
		t.Fatalf("the password survived an interrupt: %q", pw)
	}
}

// append would abandon the old array at every growth, each holding a prefix of
// the password, unwiped on the heap. Growth here hands the old buffer to
// memory.Free, which zeroes it and then releases it, so it cannot be read back
// to assert on -- releasing is the stronger guarantee. What is checkable is that
// growth happens and carries the password across intact.
func TestPasswordBufGrowsWithoutLosingThePassword(t *testing.T) {
	p := newPasswordBuf()
	var want []byte
	for i := 0; i < passwordBufMin+16; i++ {
		c := byte('a' + i%26)
		p.add(c)
		want = append(want, c)
	}
	if len(p.b) <= passwordBufMin {
		t.Fatal("the buffer never grew, so this test proves nothing")
	}

	got := p.take()
	defer memory.Free(got)
	if !bytes.Equal(got, want) {
		t.Fatal("growth lost or reordered the password")
	}
	if cap(got) != len(got) {
		t.Errorf("capacity %d is past the length, so an append would write into the locked tail", cap(got))
	}
}

// Backspace must clear the byte it drops, not just move the index.
func TestPasswordBufBackspaceClearsTheByte(t *testing.T) {
	p := newPasswordBuf()
	defer p.free()
	p.add('s')
	p.add('X')
	if !p.backspace() {
		t.Fatal("backspace reported nothing to remove")
	}
	if p.b[1] != 0 {
		t.Fatalf("the dropped byte is still readable: %q", p.b[1])
	}
	if p.backspace(); p.n != 0 {
		t.Fatal("backspace did not reach the first byte")
	}
	if p.backspace() {
		t.Fatal("backspace on an empty buffer reported a removal")
	}
}

// An empty password is a normal answer and must not leak the buffer.
func TestPasswordBufEmptyTake(t *testing.T) {
	p := newPasswordBuf()
	got := p.take()
	if len(got) != 0 {
		t.Fatalf("take on an empty buffer returned %d bytes", len(got))
	}
	if p.b != nil {
		t.Error("the buffer was not released")
	}
}

// The rejection bound is what keeps the generator unbiased: without it the
// first 256 mod len(pwCharset) characters would come up more often, and the
// existing tests only check that every character is in the charset. A bias is
// invisible until you count.
func TestGeneratedPasswordsAreUnbiased(t *testing.T) {
	const perChar = 1000
	total := len(pwCharset) * perChar

	counts := map[byte]int{}
	for got := 0; got < total; {
		pw, err := generatePassword(64)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range pw {
			counts[c]++
			got++
		}
		memory.Free(pw)
	}

	// Chi-square over the charset. 69 degrees of freedom: the 0.001 critical
	// value is about 119, so 150 leaves room for an unlucky run while a real
	// bias lands in the thousands.
	expected := float64(total) / float64(len(pwCharset))
	chi := 0.0
	for i := 0; i < len(pwCharset); i++ {
		d := float64(counts[pwCharset[i]]) - expected
		chi += d * d / expected
	}
	if chi > 150 {
		t.Fatalf("character distribution is skewed: chi-square %.1f over %d samples", chi, total)
	}

	// Every character must actually be reachable.
	for i := 0; i < len(pwCharset); i++ {
		if counts[pwCharset[i]] == 0 {
			t.Errorf("character %q never appeared", pwCharset[i])
		}
	}
}
