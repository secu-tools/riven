// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build smoke

// Package smoke does a minimal build-and-run check of the compiled binary.
package smoke

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var binPath string

// workDir is where the binary runs. Every invocation gets it as its working
// directory, so a command that writes files -- "keygen -y" writes a key pair
// into the current directory -- lands there and not in the source tree.
var workDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "riven-smoke")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "riven")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		panic("build failed: " + string(out))
	}
	workDir = filepath.Join(dir, "work")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func run(args ...string) (string, error) {
	cmd := exec.Command(binPath, args...)
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestVersion(t *testing.T) {
	out, err := run("version")
	if err != nil {
		t.Fatalf("version: %v\n%s", err, out)
	}
	if !bytes.Contains([]byte(out), []byte("riven")) {
		t.Fatalf("version output unexpected: %s", out)
	}
}

func TestHelp(t *testing.T) {
	out, err := run("help")
	if err != nil {
		t.Fatalf("help: %v\n%s", err, out)
	}
	for _, want := range []string{"USAGE", "split", "combine", "info", "keygen"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Fatalf("help missing %q", want)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	if _, err := run("frobnicate"); err == nil {
		t.Fatal("unknown command should exit non-zero")
	}
}

// runBounded runs the binary with stdin closed and a deadline, so a launch that
// blocks waiting for input fails as a hang rather than stalling the suite.
func runBounded(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = workDir
	cmd.Stdin = nil // not a terminal, and never becomes one
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("riven %v did not return within the deadline; output so far:\n%s", args, out)
	}
	return string(out), err
}

// The bare invocation is the one a user types first and the one nothing else
// covers: with no arguments and no terminal there is nobody to prompt, so it has
// to print usage and exit rather than block on a read that is never answered.
func TestBareInvocationReturns(t *testing.T) {
	out, err := runBounded(t)
	if err != nil {
		t.Fatalf("a bare invocation failed: %v\n%s", err, out)
	}
	for _, want := range []string{"USAGE", "split", "combine"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output is missing %q:\n%s", want, out)
		}
	}
}

// Whatever a command is given, the answer is an error message, never a stack
// trace: a panic reaching the user is a bug in every case.
func TestNoInvocationPanics(t *testing.T) {
	invocations := [][]string{
		{},
		{"version"},
		{"help"},
		{"split"},
		{"combine"},
		{"verify"},
		{"info"},
		{"keygen", "-y"},
		{"completion"},
		{"completion", "nonsense"},
		{"frobnicate"},
		{"--not-a-flag"},
		{"split", "--parts", "not-a-number"},
		{"combine", "/nonexistent/path"},
	}
	for _, args := range invocations {
		t.Run(strings.Join(append([]string{"riven"}, args...), " "), func(t *testing.T) {
			out, _ := runBounded(t, args...)
			for _, bad := range []string{"panic:", "goroutine ", "runtime error:", "fatal error:"} {
				if strings.Contains(out, bad) {
					t.Fatalf("output contains %q:\n%s", bad, out)
				}
			}
		})
	}
}

// Every invocation used to run in the package directory, so "keygen -y" wrote
// a private key into the source tree, where it sat unnoticed beside the tests.
// The binary now runs in its own working directory, and the key lands there.
func TestCommandsDoNotWriteIntoTheSourceTree(t *testing.T) {
	src, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	out, err := runBounded(t, "keygen", "-y", "--pub", "smoke.pub", "--priv", "smoke.key")
	if err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	for _, name := range []string{"smoke.pub", "smoke.key"} {
		if _, err := os.Stat(filepath.Join(src, name)); err == nil {
			t.Errorf("%s was written into the source tree", name)
		}
		if _, err := os.Stat(filepath.Join(workDir, name)); err != nil {
			t.Errorf("%s was not written into the working directory: %v", name, err)
		}
	}
}
