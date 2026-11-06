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

	method    string
	methodSet bool
	info      string
	infoSet   bool

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
	"--method":    func(o *cliOptions, v string) error { o.method, o.methodSet = v, true; return nil },
	"--info":      func(o *cliOptions, v string) error { o.info, o.infoSet = v, true; return nil },
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
	// Colour is set up before parsing, from the raw arguments; the flag is only
	// accepted here.
	"--no-color": func(*cliOptions) {},
	"-y":         func(o *cliOptions) { o.yes = true },
	"--yes":      func(o *cliOptions) { o.yes = true },
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

Split a file into N pieces: any K of them, with the password, rebuild it, and
fewer than K reveal nothing. docs/usage.md explains every option in full.

USAGE
  riven [FILE]                wizard: split FILE, or a menu with no FILE
  riven split FILE | -        split a file, or standard input (needs -y)
  riven split --text STRING   split a string
  riven combine PIECE...      rebuild the original from K pieces
  riven verify PIECE...       check the pieces rebuild it, writing nothing
  riven info PIECE...         show what a piece is
  riven keygen [TYPE]         make a recipient key pair (default ` + kem.Default().Name() + `)
  riven completion [SHELL]    print a completion script for your shell
  riven version | help
  A folder can be given in place of its pieces.

EXAMPLES
  riven secret.pdf
  riven split secret.pdf -n 5 -k 3 --password-env PW -y
  riven combine secret.pdf.1 secret.pdf.3 secret.pdf.5 --password-env PW

SPLIT
  -n, --parts N               pieces to write (default 5)
  -k, --threshold K           pieces needed to rebuild (default 3)
  --password-env NAME         add a password layer, read from variable NAME
  --recipient FILE            add a layer for that recipient public key
  --algo a,b,c                algorithm per layer, outermost first
  --generate                  generate the password(s)
  --keyless                   no password: any K pieces rebuild it on their own
  --method full|compact       full (default): fewer than K pieces reveal
                              nothing, proven. compact: pieces 1/K the size,
                              safe while AES-256 and ChaCha20 hold
  --info protected|strict|public|none
                              who can read a piece's details. protected
                              (default): the layer 1 password or key; one
                              piece can then test guesses of that password.
                              strict: every password and key. public and
                              none: guessing needs K pieces
  -f, --format LIST           formats, comma-separated, or all (default binary)
  --kdf SPEC                  Argon2id cost: a preset or m=MiB,t=passes,p=lanes
  --pad PCT                   size class width in percent (default 1), or none
  --record-algo true|false    record the algorithms (default true)
  --record-kdf true|false     record the Argon2id cost (default true)
  --record-name true|false    record the file name (default true)
  --verify true|false         rebuild after writing, as a check (default true)
  --qr-scale N                QR module size in pixels (default ` + strconv.Itoa(defaultQRScale) + `)
  -t, --text STRING           split this string (seen in the process list)
  --text-env NAME             split the contents of variable NAME
  --name BASE                 base name for the piece files
  -o, --out DIR               where to write the pieces

COMBINE, VERIFY AND INFO
  --password-env NAME         a password; repeat once per layer, in order
  --identity FILE             your recipient private key; repeat as needed
  --algo a,b,c                algorithms, for a set that did not record them
  --kdf SPEC                  Argon2id cost, for a set that did not record it
  -o, --out FILE              combine: where to write it ("-" for standard out)

KEYGEN
  riven keygen [TYPE] [--pub FILE] [--priv FILE] [-o DIR]
  TYPE, with the bytes it adds to every piece:
` + keygenTypeList() + `

COMMON
  -y, --yes                   never prompt: use defaults, or fail and name the
                              flag. Standard output then carries only results
  --no-color                  plain output, without colour (as does NO_COLOR)
  -h, --help / -V, --version

ALGORITHMS
  ` + indentList(ciphers.Names()) + `

ARGON2 PRESETS
  ` + strings.Join(kdf.PresetNames(), ", ") + `
  custom: memory ` + joinUint32(kdf.MemoryChoices()) + ` MiB, passes 1-` +
		strconv.Itoa(kdf.MaxTime) + `, lanes ` + joinUint8(kdf.ParChoices()) + `

EXPORT FORMATS
  ` + formatNames() + `
  qr holds at most ` + strconv.Itoa(pieceio.QRMaxBytes) + ` bytes per piece, words at most ` +
		strconv.Itoa(pieceio.Bip39MaxPiece) + `.
`)
}

// indentList prints names comma-separated over as many indented lines as the
// help text's width needs.
func indentList(names []string) string {
	return strings.Join(wrapWords(strings.Join(names, ", "), helpWidth-2), "\n  ")
}

// helpWidth is the widest line of the help text: it is printed as it is, not
// folded to the terminal, so it is kept to what an 80-column window shows.
const helpWidth = 79

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
// bytes each adds to every piece, which is what decides between them.
func keygenTypeList() string {
	var b strings.Builder
	for _, s := range kem.All() {
		fmt.Fprintf(&b, "    %-12s %-7s  %s\n", s.Name(), fmt.Sprintf("+%d B", s.CiphertextSize()), s.Summary())
	}
	return strings.TrimRight(b.String(), "\n")
}
