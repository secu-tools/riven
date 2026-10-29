// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package pieceio

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// One test per defect found during development, so a fix cannot quietly
// regress. Each states the original faulty behaviour.

// Defect: pieces were written with os.WriteFile, which applies its mode only when
// it creates a file, so a split over existing readable files left the new pieces
// readable by every user although a new piece was created private. Write also
// stores private keys and recovered files, which need the same.
func TestRegressionWriteIsPrivateOverAnExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are not enforced on Windows; access follows inherited ACLs")
	}
	path := filepath.Join(t.TempDir(), "s.1")
	if err := os.WriteFile(path, []byte("an older file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // past any umask
		t.Fatal(err)
	}
	if err := Write(path, []byte("a new piece")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode is %04o, want 0600: the file stayed readable by others", perm)
	}
	if got, _ := os.ReadFile(path); string(got) != "a new piece" {
		t.Fatalf("the file holds %q", got)
	}
}
