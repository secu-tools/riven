// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

// layerSource is one cascade layer as named on the command line. The kind decides
// which of the two fields is meaningful.
type layerSource struct {
	kind core.LayerKind
	env  string // environment variable holding the password
	file string // recipient public key file
}

// passwordEnvs returns the password variables in order, which is what the open
// side needs: one password per password layer, outermost first.
func (o *cliOptions) passwordEnvs() []string {
	var out []string
	for _, s := range o.layerSources {
		if s.kind == core.PasswordLayer {
			out = append(out, s.env)
		}
	}
	return out
}

// cliOptions holds every command-line answer. A zero value means "not given",
// so the wizard knows what still needs asking.
type cliOptions struct {
	command string
	files   []string

	n, k       int
	nSet, kSet bool

	algo    string
	algoSet bool
	keyless bool

	text    string
	textSet bool
	name    string

	// layerSources records --password-env and --recipient in the order they were
	// given, which is the order of the cascade layers, outermost first.
	layerSources []layerSource

	generate bool

	identities []string
	keyType    string // recipient key type for keygen

	outDir  string
	format  string
	qrScale int

	kdfSpec string

	recordAlgo, recordKDF       bool
	recordAlgoSet, recordKDFSet bool

	recordName    bool
	recordNameSet bool

	pad    string
	padSet bool

	// verify controls the post-split self-check that re-reads the pieces and
	// rebuilds the original. Default on; verifySet records an explicit choice.
	verify    bool
	verifySet bool

	yes bool

	pubOut, privOut string
}

var knownCommands = map[string]bool{
	"split": true, "info": true, "combine": true, "verify": true,
	"keygen": true, "completion": true, "version": true, "help": true,
}

func run(args []string) error {
	opts, err := parseArgs(args)
	if err != nil {
		return err
	}

	switch opts.command {
	case "version":
		fmt.Println("riven", Version())
		return nil
	case "help":
		printUsage()
		return nil
	case "keygen":
		return cmdKeygen(opts)
	case "completion":
		return cmdCompletion(opts)
	case "info":
		return cmdInfo(opts)
	case "combine":
		return cmdCombine(opts)
	case "verify":
		return cmdVerify(opts)
	case "split":
		return cmdSplit(opts)
	case "":
		// No explicit command: a file argument means split, otherwise a menu.
		if len(opts.files) > 0 {
			opts.command = "split"
			return cmdSplit(opts)
		}
		return cmdMenu(opts)
	default:
		return fmt.Errorf("unknown command %q (try 'riven help')", opts.command)
	}
}

// flagValue handles a flag that consumes the next argument.
type flagValue func(o *cliOptions, v string) error

// flagSwitch handles a flag that stands alone.
type flagSwitch func(o *cliOptions)

// boolFlag adapts a value handler that wants true or false.
func boolFlag(name string, set func(o *cliOptions, b bool)) flagValue {
	return func(o *cliOptions, v string) error {
		b, err := parseBool(v)
		if err != nil {
			return fmt.Errorf("invalid %s: %q is not true or false", name, v)
		}
		set(o, b)
		return nil
	}
}

// parseBool accepts the spellings a user is likely to type.
func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "y", "on", "1":
		return true, nil
	case "false", "no", "n", "off", "0":
		return false, nil
	}
	return false, fmt.Errorf("not a true or false value")
}

// intFlag adapts a value handler that wants a number, naming the flag in the
// error so a typo is easy to place.
func intFlag(name string, set func(o *cliOptions, n int)) flagValue {
	return func(o *cliOptions, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid %s: %q is not a number", name, v)
		}
		set(o, n)
		return nil
	}
}

// valueFlags and switchFlags are the whole command-line surface. Keeping them as
// tables means the parser stays a loop rather than a long chain of cases, and
// the help text can be checked against them.
var valueFlags = map[string]flagValue{
	"-n":          intFlag("-n", func(o *cliOptions, n int) { o.n, o.nSet = n, true }),
	"--parts":     intFlag("-n", func(o *cliOptions, n int) { o.n, o.nSet = n, true }),
	"-k":          intFlag("-k", func(o *cliOptions, n int) { o.k, o.kSet = n, true }),
	"--threshold": intFlag("-k", func(o *cliOptions, n int) { o.k, o.kSet = n, true }),
	"--qr-scale":  intFlag("--qr-scale", func(o *cliOptions, n int) { o.qrScale = n }),
	"--algo":      func(o *cliOptions, v string) error { o.algo, o.algoSet = v, true; return nil },
	"--algos":     func(o *cliOptions, v string) error { o.algo, o.algoSet = v, true; return nil },
	"-t":          func(o *cliOptions, v string) error { o.text, o.textSet = v, true; return nil },
	"--text":      func(o *cliOptions, v string) error { o.text, o.textSet = v, true; return nil },
	"--name":      func(o *cliOptions, v string) error { o.name = v; return nil },
	"-o":          func(o *cliOptions, v string) error { o.outDir = v; return nil },
	"--out":       func(o *cliOptions, v string) error { o.outDir = v; return nil },
	"-f":          func(o *cliOptions, v string) error { o.format = v; return nil },
	"--format":    func(o *cliOptions, v string) error { o.format = v; return nil },
	"--kdf":       func(o *cliOptions, v string) error { o.kdfSpec = v; return nil },
	"--pub":       func(o *cliOptions, v string) error { o.pubOut = v; return nil },
	"--priv":      func(o *cliOptions, v string) error { o.privOut = v; return nil },
	"--identity":  func(o *cliOptions, v string) error { o.identities = append(o.identities, v); return nil },
	"--pad":       func(o *cliOptions, v string) error { o.pad, o.padSet = v, true; return nil },
	"--record-algo": boolFlag("--record-algo", func(o *cliOptions, b bool) {
		o.recordAlgo, o.recordAlgoSet = b, true
	}),
	"--record-kdf": boolFlag("--record-kdf", func(o *cliOptions, b bool) {
		o.recordKDF, o.recordKDFSet = b, true
	}),
	"--record-name": boolFlag("--record-name", func(o *cliOptions, b bool) {
		o.recordName, o.recordNameSet = b, true
	}),
	"--verify":       boolFlag("--verify", setVerify),
	"--password-env": func(o *cliOptions, v string) error { return addLayerSource(o, core.PasswordLayer, v) },
	"--recipient":    func(o *cliOptions, v string) error { return addLayerSource(o, core.RecipientLayer, v) },
	"--text-env": func(o *cliOptions, v string) error {
		secret, err := passwordFromEnv(v)
		if err != nil {
			return err
		}
		o.text, o.textSet = string(secret), true
		return nil
	},
}

var switchFlags = map[string]flagSwitch{
	"-h":              func(o *cliOptions) { o.command = "help" },
	"--help":          func(o *cliOptions) { o.command = "help" },
	"-V":              func(o *cliOptions) { o.command = "version" },
	"--version":       func(o *cliOptions) { o.command = "version" },
	"--keyless":       func(o *cliOptions) { o.keyless = true },
	"--no-encryption": func(o *cliOptions) { o.keyless = true },
	"--generate":      func(o *cliOptions) { o.generate = true },
	"-v":              func(o *cliOptions) { setVerify(o, true) },
	"--no-verify":     func(o *cliOptions) { setVerify(o, false) },
	"-y":              func(o *cliOptions) { o.yes = true },
	"--yes":           func(o *cliOptions) { o.yes = true },
}

// setVerify records the post-split self-check preference, marking it explicitly
// set so verifyEnabled honours it over the default. It backs --verify, -v and
// --no-verify so they cannot drift apart.
func setVerify(o *cliOptions, b bool) {
	o.verify, o.verifySet = b, true
}

// addLayerSource records a cascade layer in the order its flag appeared, which
// is the order the layers are applied.
func addLayerSource(o *cliOptions, kind core.LayerKind, v string) error {
	src := layerSource{kind: kind}
	if kind == core.RecipientLayer {
		src.file = v
	} else {
		src.env = v
	}
	o.layerSources = append(o.layerSources, src)
	return nil
}

func parseArgs(args []string) (*cliOptions, error) {
	o := &cliOptions{}
	i := 0

	if len(args) > 0 && !strings.HasPrefix(args[0], "-") && knownCommands[args[0]] {
		o.command = args[0]
		i = 1
	}

	// keygen takes the key type as its next argument, so the common case is one
	// word rather than a flag: riven keygen x25519.
	if o.command == "keygen" && i < len(args) && !strings.HasPrefix(args[i], "-") {
		if _, err := kem.Parse(args[i]); err != nil {
			return nil, err
		}
		o.keyType = args[i]
		i++
	}

	endOfFlags := false
	for ; i < len(args); i++ {
		a := args[i]
		// Everything after "--" is a file, however it is spelled.
		if !endOfFlags && a == "--" {
			endOfFlags = true
			continue
		}
		if endOfFlags {
			o.files = append(o.files, a)
			continue
		}
		extra, err := applyFlag(o, a, args, i)
		if err != nil {
			return nil, err
		}
		if extra == notAFlag {
			o.files = append(o.files, a)
			continue
		}
		i += extra
	}
	return o, nil
}

// notAFlag is what applyFlag returns for an argument that names no flag, and so
// is an operand.
const notAFlag = -1

// applyFlag applies args[i] if it names a flag, and reports how many further
// arguments it consumed.
func applyFlag(o *cliOptions, a string, args []string, i int) (int, error) {
	if fn, ok := switchFlags[a]; ok {
		if err := rejectShadowedFlag(a); err != nil {
			return 0, err
		}
		fn(o)
		return 0, nil
	}
	if fn, ok := valueFlags[a]; ok {
		if err := rejectShadowedFlag(a); err != nil {
			return 0, err
		}
		if i+1 >= len(args) {
			return 0, fmt.Errorf("flag %q requires a value", a)
		}
		return 1, fn(o, args[i+1])
	}
	// A lone dash is an operand meaning standard input, not a flag.
	if strings.HasPrefix(a, "-") && a != "-" {
		return 0, fmt.Errorf("unknown flag %q (try 'riven help')", a)
	}
	return notAFlag, nil
}

// rejectShadowedFlag refuses a flag that is also the name of a file here.
//
// A glob expands to file names, so `riven combine *` in a directory holding a
// file called "--out" hands riven a flag the user never typed: the recovered
// data would be written to whatever name followed. The word means two things,
// so neither is assumed.
func rejectShadowedFlag(name string) error {
	if _, err := os.Lstat(name); err != nil {
		return nil
	}
	return fmt.Errorf("%q is both a flag and a file in this directory, so it is ambiguous: "+
		"write %q to mean the file, or put -- before the file list", name, "./"+name)
}

func printUsage() {
	fmt.Print(`riven ` + Version() + `

Split a file into stealth, post-quantum-hardened pieces using cascade
encryption and Shamir secret sharing. Any K of N pieces plus the correct
password(s) reconstruct the original; fewer reveal nothing.

USAGE
  riven [FILE]                 wizard: split FILE (or show the menu with no FILE)
  riven split  FILE            split a file into pieces
  riven split  -               split data read from standard input
  riven split  --text STRING   split a string instead of a file
  riven info   PIECE...        show what a piece is (needs the password)
  riven verify PIECE...        check the pieces rebuild the file, writing nothing
  riven combine PIECE...       reconstruct the original from pieces
  riven keygen [TYPE]          generate a recipient key pair (default ` + kem.Default().Name() + `)
  riven completion [SHELL]     print a completion script (` + strings.Join(completionShells(), ", ") + `)
  riven version | help

INPUT
  FILE                         path to the file to split. To split a directory,
                               pack it into an archive first (tar, zip, 7z).
                               Compress it too if you can: every piece is a full
                               copy of the input, so a smaller archive means N
                               smaller pieces
  -                            read the data from standard input
  -t, --text STRING            split this string (visible in the process list)
  --text-env NAME              split the contents of environment variable NAME
  --name BASE                  base name for the piece files (default: the input
                               file name, or "secret" for text and standard
                               input). This names the pieces, not the content

LAYERS
  A split can be protected by several layers, applied outermost first. Each layer
  is keyed either by a password or by a recipient public key, and every one of them
  is needed to decrypt. The order of the --password-env and --recipient flags is
  the order of the layers:

    riven split f --password-env PW1 --recipient alice.pub \
                  --recipient bob.pub --password-env PW2

  gives four layers: password, alice's key, bob's key, password. Alice and Bob must
  both take part, and both passwords are needed as well.

  --password-env NAME          add a password layer, read from environment NAME
  --recipient FILE             add a recipient layer, using that public key
  --algo a,b,c                 algorithm per layer, in the same order. Layers left
                               unnamed get one automatically

SPLIT OPTIONS
  -n, --parts N                total pieces to produce
  -k, --threshold K            pieces required to reconstruct (1..N)
  --keyless                    no encryption and no password: any K pieces rebuild
                               the file on their own (needs K of 2 or more)
  -f, --format LIST            export formats: ` + formatNames() + `, or all
                               (comma-separated; default binary)
  --qr-scale N                 QR module size in pixels (default ` + strconv.Itoa(defaultQRScale) + `)
  --kdf SPEC                   Argon2id cost: a preset or m=<MiB>,t=<passes>,p=<lanes>
  --record-algo true|false     write the algorithms into each piece (default
                               true; false means --algo is needed to decrypt)
  --record-kdf true|false      write the Argon2id cost into each piece (default
                               true; false means --kdf is needed to decrypt)
  --record-name true|false     write the input file's name into each piece, so
                               combine restores it (default true). Only the name
                               is kept, never the path or any other attribute, and
                               it sits inside the encrypted metadata
  --pad PCT                    size-class width in percent (default 5, maximum
                               500). Every piece is rounded up to the next class,
                               so its size gives only a range. 0 or "none" leaves
                               the natural size, which reveals the content length.
                               A split with no password cannot hide its length, so
                               padding is skipped there
  -v, --verify true|false      after writing, re-read the pieces and rebuild the
                               original to confirm they work (default true).
                               --no-verify skips it
  --generate                   generate strong password(s) instead of prompting
  -o, --out DIR                output directory for pieces

COMBINE AND INFO OPTIONS
  --algo a,b,c                 algorithms, for sets that did not record them
  --kdf SPEC                   Argon2id cost, for sets that did not record it
  --identity FILE              your recipient private key; repeat once per
                               recipient layer, in any order
  -o, --out FILE               where to write recovered data ("-" means standard
                               output); combine only. Without it, combine asks
                               where to write, offering the name recorded in the
                               pieces as the default -- that name was chosen by
                               whoever wrote them, so it is confirmed rather than
                               used unasked. Under -y the data goes to standard
                               output instead

  Input format is detected from the content, so binary pieces, base64 text, and
  QR images can be mixed freely in one command. Keyless sets need no password and
  are opened without asking for one.

  A directory may be given instead of a piece: the files directly inside it are
  read, anything that is not a piece is ignored, and one piece exported in
  several formats is only counted once.

  With -y and no --out, the recovered bytes go to standard output exactly as they
  were, and nothing else is printed there, so the result can be piped straight
  into another program.

KEYGEN
  riven keygen [TYPE]          generate a recipient key pair of that type
                               (default ` + kem.Default().Name() + `). The type decides how many bytes
                               every piece carries, which matters most for QR:

` + keygenTypeList() + `
  --pub FILE                   public key output path
  --priv FILE                  private key output path
  -o, --out DIR                directory for the files riven names itself. Not
                               needed once --pub and --priv name both, and
                               refused there. Any directory in a path is created

COMPLETION
  riven completion [SHELL]     print the script for ` + strings.Join(completionShells(), ", ") + `.
                               With no SHELL it is taken from the environment

    bash        source <(riven completion bash)
    zsh         riven completion zsh > "${fpath[1]}/_riven"
    fish        riven completion fish > ~/.config/fish/completions/riven.fish
    powershell  riven completion powershell | Out-String | Invoke-Expression

COMMON OPTIONS
  -y, --yes                    non-interactive: use defaults, never prompt, and
                               fail instead of asking for missing values. Standard
                               output then carries only machine-readable results:
                               generated passwords when splitting, one per line, and
                               the recovered data when combining. Everything else
                               goes to standard error

ALGORITHMS
  ` + strings.Join(ciphers.Names(), ", ") + `

ARGON2 PRESETS
  ` + strings.Join(kdf.PresetNames(), ", ") + `
  custom: m=<MiB>,t=<passes>,p=<lanes>; memory is one of ` + joinUint32(kdf.MemoryChoices()) + ` MiB,
  passes 1-` + strconv.Itoa(kdf.MaxTime) + `, lanes one of ` + joinUint8(kdf.ParChoices()) + `

EXPORT FORMATS
  ` + formatNames() + `
  qr holds at most ` + strconv.Itoa(pieceio.QRMaxBytes) + ` bytes per piece, words at most ` +
		strconv.Itoa(pieceio.Bip39MaxPiece) + `.
  words is BIP-39 English text, about ` + strconv.FormatFloat(pieceio.Bip39Expansion, 'f', 1, 64) +
		` times the size of a binary piece: it is
  for a small secret written out by hand, not for a file.
`)
}

func formatNames() string {
	names := make([]string, 0, len(pieceio.All()))
	for _, f := range pieceio.All() {
		names = append(names, f.String())
	}
	return strings.Join(names, ", ")
}

func joinUint32(v []uint32) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.FormatUint(uint64(x), 10)
	}
	return strings.Join(parts, "/")
}

func joinUint8(v []uint8) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.FormatUint(uint64(x), 10)
	}
	return strings.Join(parts, "/")
}

// keygenTypeList renders the recipient key types for the help text, with the
// per-piece cost that decides between them.
func keygenTypeList() string {
	var b strings.Builder
	for _, s := range kem.All() {
		fmt.Fprintf(&b, "    %-12s %s\n", s.Name(), s.Summary())
		fmt.Fprintf(&b, "    %-12s adds %d bytes to every piece\n", "", s.CiphertextSize())
	}
	return strings.TrimRight(b.String(), "\n")
}
