// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// Shells that can be completed for.
const (
	shellBash       = "bash"
	shellZsh        = "zsh"
	shellFish       = "fish"
	shellPowerShell = "powershell"
)

func completionShells() []string {
	return []string{shellBash, shellZsh, shellFish, shellPowerShell}
}

// argKind is what completes after a flag that takes a value. Everything not
// named in flagArgKinds is a path, which is right for every file flag and is the
// only sensible guess for a flag added later.
type argKind int

const (
	argFile argKind = iota
	argFree         // free text: a name, a number, a secret. Nothing to suggest.
	argFormat
	argAlgo
	argKDF
	argPad
	argBool
	argEnv
)

// flagArgKinds records the flags whose value is not a path. Completing a value
// the program will reject is worse than completing nothing, so a flag whose
// values cannot be enumerated is argFree.
var flagArgKinds = map[string]argKind{
	"-f": argFormat, "--format": argFormat,
	"--algo": argAlgo, "--algos": argAlgo,
	"--kdf":         argKDF,
	"--pad":         argPad,
	"--record-algo": argBool, "--record-kdf": argBool, "--record-name": argBool,
	"--verify":       argBool,
	"--password-env": argEnv, "--text-env": argEnv,
	"-n": argFree, "--parts": argFree,
	"-k": argFree, "--threshold": argFree,
	"--qr-scale": argFree,
	"-t":         argFree, "--text": argFree,
	"--name": argFree,
}

// flagsOfKind lists the flags that complete a given way, sorted. Reading them
// back out of the parser's own tables is what keeps the completion scripts and
// the accepted flags from drifting apart.
func flagsOfKind(want argKind) []string {
	var out []string
	for name := range valueFlags {
		if flagArgKinds[name] == want {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// allFlags lists every flag the parser accepts, sorted.
func allFlags() []string {
	out := make([]string, 0, len(valueFlags)+len(switchFlags))
	for name := range valueFlags {
		out = append(out, name)
	}
	for name := range switchFlags {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// sortedCommands lists the commands, sorted, so the script is the same on every
// run and a diff of two versions shows only real changes.
func sortedCommands() []string {
	out := make([]string, 0, len(knownCommands))
	for name := range knownCommands {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// commandHelp is the one-line description shown beside a command by the shells
// that display one.
var commandHelp = map[string]string{
	"split":      "split a file or directory into pieces",
	"info":       "show what a piece is",
	"combine":    "reconstruct the original from pieces",
	"verify":     "check that pieces rebuild the file",
	"keygen":     "generate a recipient key pair",
	"completion": "print a shell completion script",
	"version":    "print the version",
	"help":       "print usage",
}

// completionFormats are the export format names plus "all", which -f accepts.
func completionFormats() []string {
	out := make([]string, 0, len(pieceio.All())+1)
	for _, f := range pieceio.All() {
		out = append(out, f.String())
	}
	return append(out, "all")
}

func completionKeyTypes() []string {
	out := make([]string, 0, len(kem.All()))
	for _, s := range kem.All() {
		out = append(out, s.Name())
	}
	return out
}

// completionPads are the padding answers worth suggesting. Any percent is legal,
// so this is a starting point rather than the set of valid values.
func completionPads() []string { return []string{"none", "0", "5", "10", "25", "50"} }

// cmdCompletion prints a completion script for one shell.
func cmdCompletion(opts *cliOptions) error {
	shell := ""
	if len(opts.files) > 0 {
		shell = strings.ToLower(opts.files[0])
	}
	if len(opts.files) > 1 {
		return fmt.Errorf("completion takes one shell name, but %d were given", len(opts.files))
	}
	if shell == "" {
		shell = detectShell()
	}
	if shell == "" {
		return fmt.Errorf("name the shell: riven completion %s", strings.Join(completionShells(), "|"))
	}
	return writeCompletion(os.Stdout, shell)
}

// detectShell guesses from the environment, so "riven completion" alone works in
// the common case. It guesses only when it is sure.
func detectShell() string {
	if sh := os.Getenv("SHELL"); sh != "" {
		// Both separators: on Windows $SHELL is often a Git Bash path, and
		// filepath.Base only knows the separator of the host it is running on.
		if i := strings.LastIndexAny(sh, `/\`); i >= 0 {
			sh = sh[i+1:]
		}
		switch base := strings.TrimSuffix(sh, ".exe"); base {
		case shellBash, shellZsh, shellFish:
			return base
		}
	}
	// PowerShell sets this for its own child processes, and nothing else does.
	if os.Getenv("PSModulePath") != "" {
		return shellPowerShell
	}
	return ""
}

func writeCompletion(w io.Writer, shell string) error {
	switch shell {
	case shellBash:
		return writeBashCompletion(w)
	case shellZsh:
		return writeZshCompletion(w)
	case shellFish:
		return writeFishCompletion(w)
	case shellPowerShell, "pwsh", "powershell.exe":
		return writePowerShellCompletion(w)
	}
	return fmt.Errorf("unknown shell %q (use %s)", shell, strings.Join(completionShells(), ", "))
}

// words joins a list for a shell script, where every value is a bare word.
func words(v []string) string { return strings.Join(v, " ") }

// alternatives joins flag names for a bash case pattern.
func alternatives(v []string) string { return strings.Join(v, "|") }

func writeBashCompletion(w io.Writer) error {
	_, err := fmt.Fprintf(w, `# riven completion for bash.
#
# Load it for this session with
#   source <(riven completion bash)
# or install it with
#   riven completion bash > ~/.local/share/bash-completion/completions/riven

_riven() {
    local cur prev commands
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="%s"

    # A flag's value depends only on the flag, so it is settled first.
    case "$prev" in
        %s)
            COMPREPLY=( $(compgen -W "%s" -- "$cur") ); return 0 ;;
        %s)
            COMPREPLY=( $(compgen -W "%s" -- "$cur") ); return 0 ;;
        %s)
            COMPREPLY=( $(compgen -W "%s" -- "$cur") ); return 0 ;;
        %s)
            COMPREPLY=( $(compgen -W "%s" -- "$cur") ); return 0 ;;
        %s)
            COMPREPLY=( $(compgen -W "true false" -- "$cur") ); return 0 ;;
        %s)
            COMPREPLY=( $(compgen -v -- "$cur") ); return 0 ;;
        %s)
            return 0 ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "%s" -- "$cur") ); return 0
    fi

    # The command, when there is one, is the first argument.
    local cmd=""
    if (( COMP_CWORD > 1 )); then
        case " $commands " in
            *" ${COMP_WORDS[1]} "*) cmd="${COMP_WORDS[1]}" ;;
        esac
    fi

    case "$cmd" in
        keygen)     COMPREPLY=( $(compgen -W "%s" -- "$cur") ); return 0 ;;
        completion) COMPREPLY=( $(compgen -W "%s" -- "$cur") ); return 0 ;;
    esac

    if (( COMP_CWORD == 1 )); then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
    fi

    # Everything left is a path: the file or directory to split, or the pieces to
    # read. Leaving COMPREPLY empty hands the word to "complete -o default", so
    # absolute paths, directories and quoting behave as they do everywhere else.
    return 0
}

complete -o default -F _riven riven
`,
		words(sortedCommands()),
		alternatives(flagsOfKind(argFormat)), words(completionFormats()),
		alternatives(flagsOfKind(argAlgo)), words(ciphers.Names()),
		alternatives(flagsOfKind(argKDF)), words(kdf.PresetNames()),
		alternatives(flagsOfKind(argPad)), words(completionPads()),
		alternatives(flagsOfKind(argBool)),
		alternatives(flagsOfKind(argEnv)),
		alternatives(flagsOfKind(argFree)),
		words(allFlags()),
		words(completionKeyTypes()),
		words(completionShells()),
	)
	return err
}

// zshCommandList renders the commands as zsh "name:description" pairs.
func zshCommandList() string {
	var b strings.Builder
	for _, c := range sortedCommands() {
		fmt.Fprintf(&b, "    '%s:%s'\n", c, commandHelp[c])
	}
	return strings.TrimRight(b.String(), "\n")
}

func writeZshCompletion(w io.Writer) error {
	_, err := fmt.Fprintf(w, `#compdef riven
# riven completion for zsh.
#
# Load it for this session with
#   source <(riven completion zsh)
# or install it with
#   riven completion zsh > "${fpath[1]}/_riven"

_riven() {
  local -a commands formats algos kdfs pads keytypes shells
  commands=(
%s
  )
  formats=(%s)
  algos=(%s)
  kdfs=(%s)
  pads=(%s)
  keytypes=(%s)
  shells=(%s)

  local context state line
  typeset -A opt_args

  _arguments -s -C \
    '(-h --help)'{-h,--help}'[print usage]' \
    '(-V --version)'{-V,--version}'[print the version]' \
    '(-y --yes)'{-y,--yes}'[never prompt; use defaults]' \
    '--keyless[no encryption and no password]' \
    '--no-encryption[no encryption and no password]' \
    '--generate[generate the password(s)]' \
    '(-n --parts)'{-n,--parts}'[total pieces to produce]:count:' \
    '(-k --threshold)'{-k,--threshold}'[pieces required to reconstruct]:count:' \
    '--qr-scale[QR module size in pixels]:pixels:' \
    '(-f --format)'{-f,--format}'[export formats]:format:_values -s , format $formats' \
    '(--algo --algos)'{--algo,--algos}'[algorithm per layer]:algorithm:_values -s , algorithm $algos' \
    '--kdf[Argon2id cost]:cost:($kdfs)' \
    '--pad[size-class width in percent]:percent:($pads)' \
    '--record-algo[write the algorithms into each piece]:choice:(true false)' \
    '--record-kdf[write the Argon2id cost into each piece]:choice:(true false)' \
    '--record-name[write the input file name into each piece]:choice:(true false)' \
    '--verify[re-read and rebuild the pieces after writing]:choice:(true false)' \
    '-v[re-read and rebuild the pieces after writing]' \
    '--no-verify[skip the post-split self-check]' \
    '--password-env[environment variable holding a password]:variable:_parameters' \
    '--text-env[environment variable holding the data]:variable:_parameters' \
    '(-t --text)'{-t,--text}'[split this string]:text:' \
    '--name[base name for the pieces]:name:' \
    '(-o --out)'{-o,--out}'[output directory or file]:path:_files' \
    '--identity[your recipient private key]:key file:_files' \
    '--recipient[recipient public key]:key file:_files' \
    '--pub[public key output path]:path:_files' \
    '--priv[private key output path]:path:_files' \
    '1: :->first' \
    '*: :->rest'

  case $state in
    first)
      # A bare "riven FILE" splits that file, so paths are offered alongside the
      # commands rather than instead of them.
      _describe -t commands 'command' commands
      _files
      ;;
    rest)
      case ${words[2]} in
        keygen)     _values 'key type' $keytypes ;;
        completion) _values 'shell' $shells ;;
        *)          _files ;;
      esac
      ;;
  esac
}

if [ "$funcstack[1]" = "_riven" ]; then
  _riven
else
  compdef _riven riven
fi
`,
		zshCommandList(),
		words(completionFormats()),
		words(ciphers.Names()),
		words(kdf.PresetNames()),
		words(completionPads()),
		words(completionKeyTypes()),
		words(completionShells()),
	)
	return err
}

func writeFishCompletion(w io.Writer) error {
	var b strings.Builder
	b.WriteString(`# riven completion for fish.
#
# Load it for this session with
#   riven completion fish | source
# or install it with
#   riven completion fish > ~/.config/fish/completions/riven.fish
#
# File completion is left on, so a piece can be named by any path.

`)
	for _, c := range sortedCommands() {
		fmt.Fprintf(&b, "complete -c riven -n __fish_use_subcommand -a %s -d '%s'\n", c, commandHelp[c])
	}
	fmt.Fprintf(&b, "\ncomplete -c riven -n '__fish_seen_subcommand_from keygen' -x -a '%s'\n",
		words(completionKeyTypes()))
	fmt.Fprintf(&b, "complete -c riven -n '__fish_seen_subcommand_from completion' -x -a '%s'\n\n",
		words(completionShells()))

	// Switches, then value flags, each with what its value may be.
	fish := []struct{ flag, spec, help string }{
		{"-h/--help", "", "print usage"},
		{"-V/--version", "", "print the version"},
		{"-y/--yes", "", "never prompt; use defaults"},
		{"--keyless", "", "no encryption and no password"},
		{"--no-encryption", "", "no encryption and no password"},
		{"--generate", "", "generate the password(s)"},
		{"-n/--parts", "-x", "total pieces to produce"},
		{"-k/--threshold", "-x", "pieces required to reconstruct"},
		{"--qr-scale", "-x", "QR module size in pixels"},
		{"-t/--text", "-x", "split this string"},
		{"--name", "-x", "base name for the pieces"},
		{"-f/--format", "-x -a '" + words(completionFormats()) + "'", "export formats"},
		{"--algo", "-x -a '" + words(ciphers.Names()) + "'", "algorithm per layer"},
		{"--algos", "-x -a '" + words(ciphers.Names()) + "'", "algorithm per layer"},
		{"--kdf", "-x -a '" + words(kdf.PresetNames()) + "'", "Argon2id cost"},
		{"--pad", "-x -a '" + words(completionPads()) + "'", "size-class width in percent"},
		{"--record-algo", "-x -a 'true false'", "write the algorithms into each piece"},
		{"--record-kdf", "-x -a 'true false'", "write the Argon2id cost into each piece"},
		{"--record-name", "-x -a 'true false'", "write the input file name into each piece"},
		{"--verify", "-x -a 'true false'", "re-read and rebuild the pieces after writing"},
		{"-v", "", "re-read and rebuild the pieces after writing"},
		{"--no-verify", "", "skip the post-split self-check"},
		{"--password-env", "-x -a '(set --names --export)'", "environment variable holding a password"},
		{"--text-env", "-x -a '(set --names --export)'", "environment variable holding the data"},
		{"-o/--out", "-r -F", "output directory or file"},
		{"--identity", "-r -F", "your recipient private key"},
		{"--recipient", "-r -F", "recipient public key"},
		{"--pub", "-r -F", "public key output path"},
		{"--priv", "-r -F", "private key output path"},
	}
	for _, f := range fish {
		line := "complete -c riven"
		for _, name := range strings.Split(f.flag, "/") {
			if strings.HasPrefix(name, "--") {
				line += " -l " + strings.TrimPrefix(name, "--")
			} else {
				line += " -s " + strings.TrimPrefix(name, "-")
			}
		}
		if f.spec != "" {
			line += " " + f.spec
		}
		fmt.Fprintf(&b, "%s -d '%s'\n", line, f.help)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// psList renders a Go list as a PowerShell single-quoted array literal.
func psList(v []string) string {
	quoted := make([]string, len(v))
	for i, s := range v {
		quoted[i] = "'" + s + "'"
	}
	return strings.Join(quoted, ", ")
}

func writePowerShellCompletion(w io.Writer) error {
	_, err := fmt.Fprintf(w, `# riven completion for PowerShell.
#
# Load it for this session with
#   riven completion powershell | Out-String | Invoke-Expression
# or add that line to $PROFILE to keep it.

Register-ArgumentCompleter -Native -CommandName riven -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commands = @(%s)
    $words    = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })
    $previous = ''
    if ($words.Count -ge 2) { $previous = $words[$words.Count - 2] }
    if ($wordToComplete -eq '') { $previous = $words[$words.Count - 1] }

    $values = switch -Exact ($previous) {
        { $_ -in @(%s) } { @(%s); break }
        { $_ -in @(%s) } { @(%s); break }
        { $_ -in @(%s) } { @(%s); break }
        { $_ -in @(%s) } { @(%s); break }
        { $_ -in @(%s) } { @('true', 'false'); break }
        { $_ -in @(%s) } { Get-ChildItem env: | ForEach-Object { $_.Name }; break }
        default { $null }
    }
    if ($null -ne $values) {
        return $values | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [System.Management.Automation.CompletionResult]::new(
                $_, $_, 'ParameterValue', $_) }
    }

    if ($wordToComplete.StartsWith('-')) {
        return @(%s) | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [System.Management.Automation.CompletionResult]::new(
                $_, $_, 'ParameterName', $_) }
    }

    $command = ''
    if ($words.Count -ge 2 -and $commands -contains $words[1]) { $command = $words[1] }
    $sub = switch -Exact ($command) {
        'keygen'     { @(%s) }
        'completion' { @(%s) }
        default      { $null }
    }
    if ($null -ne $sub) {
        return $sub | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [System.Management.Automation.CompletionResult]::new(
                $_, $_, 'ParameterValue', $_) }
    }

    $results = @()
    if ($words.Count -le 1 -or ($words.Count -eq 2 -and $wordToComplete -ne '')) {
        $results += $commands | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [System.Management.Automation.CompletionResult]::new(
                $_, $_, 'ParameterValue', $_) }
    }

    # Anything else is a path: the file or directory to split, or the pieces to
    # read. These are completed here rather than left to the shell, because a
    # native command with a registered completer gets no fallback.
    $leaf   = ''
    $parent = '.'
    if ($wordToComplete.EndsWith('\') -or $wordToComplete.EndsWith('/')) {
        $parent = $wordToComplete
    } elseif (-not [string]::IsNullOrEmpty($wordToComplete)) {
        $leaf   = Split-Path -Leaf $wordToComplete
        $parent = Split-Path -Parent $wordToComplete
        if ([string]::IsNullOrEmpty($parent)) { $parent = '.' }
    }
    $results += Get-ChildItem -LiteralPath $parent -Filter "$leaf*" -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            $path = Join-Path $parent $_.Name
            if ($parent -eq '.') { $path = $_.Name }
            if ($path -match '\s') { $path = "'$path'" }
            [System.Management.Automation.CompletionResult]::new(
                $path, $_.Name, 'ProviderItem', $_.FullName)
        }
    return $results
}
`,
		psList(sortedCommands()),
		psList(flagsOfKind(argFormat)), psList(completionFormats()),
		psList(flagsOfKind(argAlgo)), psList(ciphers.Names()),
		psList(flagsOfKind(argKDF)), psList(kdf.PresetNames()),
		psList(flagsOfKind(argPad)), psList(completionPads()),
		psList(flagsOfKind(argBool)),
		psList(flagsOfKind(argEnv)),
		psList(allFlags()),
		psList(completionKeyTypes()),
		psList(completionShells()),
	)
	return err
}
