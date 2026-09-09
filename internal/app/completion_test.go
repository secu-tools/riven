// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// scriptFor renders the completion script for one shell.
func scriptFor(t *testing.T, shell string) string {
	t.Helper()
	var b strings.Builder
	if err := writeCompletion(&b, shell); err != nil {
		t.Fatalf("%s: %v", shell, err)
	}
	if b.Len() == 0 {
		t.Fatalf("%s: empty script", shell)
	}
	return b.String()
}

// mentions reports whether a script offers a flag. fish spells one as "-l name"
// or "-s c" rather than writing it out, so the name is translated first.
func mentions(shell, script, flag string) bool {
	if shell != shellFish {
		return strings.Contains(script, flag)
	}
	if long := strings.TrimPrefix(flag, "--"); long != flag {
		return strings.Contains(script, " -l "+long+" ")
	}
	return strings.Contains(script, " -s "+strings.TrimPrefix(flag, "-")+" ")
}

// TestCompletionKnowsEveryFlag is the check that matters over time: a flag added
// to the parser and forgotten in the scripts is invisible until someone tries to
// complete it.
func TestCompletionKnowsEveryFlag(t *testing.T) {
	for _, shell := range completionShells() {
		script := scriptFor(t, shell)
		for _, flag := range allFlags() {
			if !mentions(shell, script, flag) {
				t.Errorf("%s completion does not mention %s", shell, flag)
			}
		}
	}
}

// TestCompletionKnowsEveryCommand checks the same for the command list, and that
// every command has a description for the shells that show one.
func TestCompletionKnowsEveryCommand(t *testing.T) {
	for _, cmd := range sortedCommands() {
		if commandHelp[cmd] == "" {
			t.Errorf("command %q has no description", cmd)
		}
		for _, shell := range completionShells() {
			if !strings.Contains(scriptFor(t, shell), cmd) {
				t.Errorf("%s completion does not mention the %s command", shell, cmd)
			}
		}
	}
}

// TestCompletionOffersEveryChoice covers the enumerated values, so a new format,
// algorithm, cost preset or key type reaches the shell as well as the help text.
func TestCompletionOffersEveryChoice(t *testing.T) {
	var want []string
	for _, f := range pieceio.All() {
		want = append(want, f.String())
	}
	want = append(want, "all")
	want = append(want, ciphers.Names()...)
	want = append(want, kdf.PresetNames()...)
	for _, s := range kem.All() {
		want = append(want, s.Name())
	}
	want = append(want, completionShells()...)

	for _, shell := range completionShells() {
		script := scriptFor(t, shell)
		for _, v := range want {
			if !strings.Contains(script, v) {
				t.Errorf("%s completion does not offer %q", shell, v)
			}
		}
	}
}

// TestCompletionCompletesFilePaths is the point of the feature for anyone naming
// a piece: every shell must still complete an ordinary path such as
// /root/piece1.data. Each does it differently, so each is checked for the
// mechanism it uses.
func TestCompletionCompletesFilePaths(t *testing.T) {
	bash := scriptFor(t, shellBash)
	// Leaving COMPREPLY empty only completes files if the compspec says so.
	if !strings.Contains(bash, "complete -o default -F _riven riven") {
		t.Error("the bash compspec must fall back to filenames")
	}

	zsh := scriptFor(t, shellZsh)
	if !strings.Contains(zsh, "'*: :->rest'") || !strings.Contains(zsh, "_files") {
		t.Error("zsh must complete operands with _files")
	}

	fish := scriptFor(t, shellFish)
	// fish completes files unless told not to, so the command must never be
	// marked -f, and the path flags must force files back on.
	for _, line := range strings.Split(fish, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 3 && fields[0] == "complete" && fields[3] == "-f" {
			t.Errorf("fish line disables file completion: %s", line)
		}
	}
	for _, flag := range []string{"identity", "recipient", "pub", "priv", "out"} {
		if !strings.Contains(fish, "-l "+flag+" -r -F") {
			t.Errorf("fish --%s must complete files", flag)
		}
	}

	ps := scriptFor(t, shellPowerShell)
	// A native completer replaces PowerShell's own file completion rather than
	// adding to it, so paths have to be produced here.
	if !strings.Contains(ps, "Get-ChildItem -LiteralPath $parent") {
		t.Error("the PowerShell completer must produce paths itself")
	}
}

// TestCompletionFlagKindsMatchTheParser checks the table that decides what a
// flag's value completes to names only flags that exist.
func TestCompletionFlagKindsMatchTheParser(t *testing.T) {
	for flag := range flagArgKinds {
		if _, ok := valueFlags[flag]; !ok {
			t.Errorf("flagArgKinds names %q, which is not a value flag", flag)
		}
	}
	// Every flag not in the table completes as a path. That is only correct for
	// flags that take one, so check the ones that do not are all listed.
	for _, flag := range []string{"-n", "-k", "--qr-scale", "--kdf", "--pad", "-f",
		"--algo", "--record-algo", "--record-kdf", "--record-name",
		"--password-env", "--text-env", "--name"} {
		if _, ok := flagArgKinds[flag]; !ok {
			t.Errorf("%s does not take a path, so it needs an entry in flagArgKinds", flag)
		}
	}
	// argFile is what a flag gets by not being in the table, so the flags that
	// land there are exactly the ones whose value is a path.
	want := map[string]bool{"-o": true, "--out": true, "--identity": true,
		"--recipient": true, "--pub": true, "--priv": true}
	got := flagsOfKind(argFile)
	if len(got) != len(want) {
		t.Fatalf("flags completing as a path are %v, want %v", got, want)
	}
	for _, flag := range got {
		if !want[flag] {
			t.Errorf("%s completes as a path, but its value is not one", flag)
		}
	}
}

// TestCompletionScriptsAreAscii keeps the scripts inside the character set the
// rest of the project uses; a stray byte in a sourced file is hard to find.
func TestCompletionScriptsAreAscii(t *testing.T) {
	for _, shell := range completionShells() {
		for i, r := range scriptFor(t, shell) {
			if r > 0x7E || (r < 0x20 && r != '\n' && r != '\t') {
				t.Fatalf("%s completion has a non-ascii byte at %d: %q", shell, i, r)
			}
		}
	}
}

// TestCompletionRejectsAnUnknownShell checks the error names the shells that do
// work, since a wrong guess is the likely mistake.
func TestCompletionRejectsAnUnknownShell(t *testing.T) {
	var b strings.Builder
	err := writeCompletion(&b, "csh")
	if err == nil {
		t.Fatal("an unsupported shell must be refused")
	}
	for _, shell := range completionShells() {
		if !strings.Contains(err.Error(), shell) {
			t.Errorf("the error should name %s: %v", shell, err)
		}
	}
	if b.Len() != 0 {
		t.Error("nothing should be written for an unsupported shell")
	}
}

// TestCmdCompletionArguments covers the command itself: one shell name, the
// aliases PowerShell is known by, and the error when there is nothing to go on.
func TestCmdCompletionArguments(t *testing.T) {
	t.Setenv("SHELL", "")
	t.Setenv("PSModulePath", "")
	if err := cmdCompletion(&cliOptions{files: []string{"bash", "zsh"}}); err == nil {
		t.Fatal("two shells must be refused")
	}
	if err := cmdCompletion(&cliOptions{}); err == nil {
		t.Fatal("with no shell and no environment there is nothing to print")
	}
	for _, alias := range []string{"pwsh", "powershell.exe", "POWERSHELL"} {
		var b strings.Builder
		if err := writeCompletion(&b, strings.ToLower(alias)); err != nil {
			t.Errorf("%s should be understood: %v", alias, err)
		}
	}
}

// TestDetectShellReadsTheEnvironment checks the guess made when no shell is
// named, including that an unknown one is not guessed at.
func TestDetectShellReadsTheEnvironment(t *testing.T) {
	cases := []struct{ shellVar, psVar, want string }{
		{"/bin/bash", "", shellBash},
		{"/usr/local/bin/fish", "", shellFish},
		{"/bin/zsh", "", shellZsh},
		{"C:\\Program Files\\Git\\bin\\bash.exe", "", shellBash},
		{"/bin/dash", "", ""},
		{"", "C:\\Modules", shellPowerShell},
		{"", "", ""},
	}
	for _, c := range cases {
		t.Setenv("SHELL", c.shellVar)
		t.Setenv("PSModulePath", c.psVar)
		if got := detectShell(); got != c.want {
			t.Errorf("SHELL=%q PSModulePath=%q gave %q, want %q", c.shellVar, c.psVar, got, c.want)
		}
	}
}

// TestBashCompletionRuns is the only end-to-end check available in a Go test:
// the script is sourced by a real bash, then the function is called with the
// words a user would have typed. It is skipped where bash is not installed.
func TestBashCompletionRuns(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "riven.bash")
	if err := os.WriteFile(script, []byte(scriptFor(t, shellBash)), 0o600); err != nil {
		t.Fatal(err)
	}

	// The harness prints what the shell would have offered, one case per line.
	harness := filepath.Join(dir, "try.bash")
	body := `source "$1"
try() {
    COMP_WORDS=( "$@" )
    COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
    COMPREPLY=()
    _riven
    echo "|${COMPREPLY[*]}"
}
`
	cases := []struct {
		words []string
		want  string // a substring the answer must contain, or "" for no answer
	}{
		{[]string{"riven", ""}, "split"},
		{[]string{"riven", "comb"}, "combine"},
		{[]string{"riven", "split", "-f", ""}, "words"},
		{[]string{"riven", "split", "--kdf", ""}, kdf.PresetNames()[0]},
		{[]string{"riven", "keygen", ""}, kem.Default().Name()},
		{[]string{"riven", "completion", ""}, shellPowerShell},
		{[]string{"riven", "split", "--pad", ""}, "none"},
		{[]string{"riven", "--rec"}, "--record-algo"},
		// A path must produce nothing, so that "complete -o default" takes over.
		{[]string{"riven", "combine", "/root/piece1.data"}, ""},
		{[]string{"riven", "split", "-n", "3"}, ""},
	}
	for _, c := range cases {
		body += "try " + strings.Join(quoteAll(c.words), " ") + "\n"
	}
	if err := os.WriteFile(harness, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(bash, harness, script).CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != len(cases) {
		t.Fatalf("expected %d answers, got %d:\n%s", len(cases), len(lines), out)
	}
	for i, c := range cases {
		got := strings.TrimSpace(strings.TrimPrefix(lines[i], "|"))
		switch {
		case c.want == "" && got != "":
			t.Errorf("%v should complete as a path, but offered %q", c.words, got)
		case c.want != "" && !strings.Contains(got, c.want):
			t.Errorf("%v offered %q, which does not include %q", c.words, got, c.want)
		}
	}
}

func quoteAll(words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = "'" + w + "'"
	}
	return out
}
