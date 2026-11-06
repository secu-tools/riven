// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/pieceio"
)

const defaultQRScale = 8

// splitPlan is the fully resolved configuration for one split.
type splitPlan struct {
	opts            core.SplitOptions
	verifyPasswords [][]byte          // password-layer passwords, outer to inner
	privateKeys     []*kem.PrivateKey // keys on hand, used to verify the split
	schemeIDs       []uint8           // algorithm resolved per layer
	outDir          string
	generated       [][]byte
	qrScale         int
	pieceSizes      []int // each piece's length once written, for the summary's notes
}

// secrets names what reads a protected set's details: every password and every
// private key the set takes.
func (p *splitPlan) secrets() string {
	passwords, keys := p.layerCounts()
	var parts []string
	switch {
	case passwords == 1:
		parts = append(parts, "the password")
	case passwords > 1:
		parts = append(parts, "every password")
	}
	switch {
	case keys == 1:
		parts = append(parts, "the private key")
	case keys > 1:
		parts = append(parts, "every private key")
	}
	return strings.Join(parts, " and ")
}

// firstSecret names what reads a protected set's details, the first layer's
// password or private key, and reports whether it is a password.
func (p *splitPlan) firstSecret() (name string, isPassword bool) {
	if len(p.opts.Layers) == 0 {
		return "", false
	}
	isPassword = p.opts.Layers[0].Kind != core.RecipientLayer
	what := "private key"
	if isPassword {
		what = "password"
	}
	if len(p.opts.Layers) == 1 {
		return "the " + what, isPassword
	}
	return "the layer 1 " + what, isPassword
}

// layerCounts counts the password and recipient key layers.
func (p *splitPlan) layerCounts() (passwords, keys int) {
	for _, l := range p.opts.Layers {
		if l.Kind == core.RecipientLayer {
			keys++
		} else {
			passwords++
		}
	}
	return passwords, keys
}

// strictGuessing says what one strict piece offers someone guessing passwords:
// nothing when a key is needed too, or only every password at once.
func (p *splitPlan) strictGuessing() string {
	switch passwords, keys := p.layerCounts(); {
	case keys > 0 || passwords == 0:
		return ""
	case passwords == 1:
		return "one piece can test guesses"
	default:
		return "one piece tests them only together"
	}
}

// hasRecipient reports whether any layer is keyed to a recipient key.
func (p *splitPlan) hasRecipient() bool {
	for _, l := range p.opts.Layers {
		if l.Kind == core.RecipientLayer {
			return true
		}
	}
	return false
}

// planSplit resolves every decision for a split, consulting flags first, then
// prompting when interactive, then falling back to defaults. defaultDir is where
// pieces land unless the user says otherwise. Export format is resolved later,
// once the real piece sizes are known.
func planSplit(opts *cliOptions, defaultDir string) (*splitPlan, error) {
	interactive := isInteractive() && !opts.yes
	plan := &splitPlan{qrScale: opts.qrScale}
	if plan.qrScale < 1 {
		plan.qrScale = defaultQRScale
	}

	if err := planCounts(plan, opts, interactive); err != nil {
		return nil, err
	}
	if err := planDefaults(plan, opts); err != nil {
		return nil, err
	}

	if err := planIdentities(plan, opts); err != nil {
		return nil, err
	}
	if err := planProtection(plan, opts, interactive); err != nil {
		return nil, err
	}
	if plan.opts.Info == core.InfoHidden && plan.opts.K == 1 {
		return nil, errors.New("--info none needs -k 2 or more: with -k 1 every piece is the whole set, " +
			"so its details cannot be hidden from whoever holds one")
	}
	if _, err := core.EffectiveInfo(plan.opts); err != nil {
		return nil, fmt.Errorf("--info %s needs a password or a recipient key: add --password-env or "+
			"--recipient, or use --info public or --info none", plan.opts.Info)
	}

	// Resolve the algorithms once, so the summary and the verification step agree
	// with what was actually used.
	ids, err := core.AssignSchemes(plan.opts.Layers)
	if err != nil {
		return nil, err
	}
	plan.schemeIDs = ids

	outDir, err := planOutDir(opts, defaultDir, interactive)
	if err != nil {
		return nil, err
	}
	plan.outDir = outDir
	return plan, nil
}

// planCounts resolves how many pieces to write and how many are needed, asking
// when the run is interactive and nothing settled it.
func planCounts(plan *splitPlan, opts *cliOptions, interactive bool) error {
	n := 5
	if opts.nSet {
		n = opts.n
	} else if interactive {
		v, err := readInt("Total pieces to create (N)", n, 1, 255)
		if err != nil {
			return err
		}
		n = v
	}
	if n < 1 || n > 255 {
		return fmt.Errorf("total pieces N=%d must be between 1 and 255", n)
	}

	defK := 3
	if defK > n {
		defK = n
	}
	k := defK
	if opts.kSet {
		k = opts.k
	} else if interactive {
		v, err := readInt("Pieces required to reconstruct (K)", defK, 1, n)
		if err != nil {
			return err
		}
		k = v
	}
	if k < 1 || k > n {
		return fmt.Errorf("threshold K=%d must be between 1 and N=%d", k, n)
	}

	plan.opts.N, plan.opts.K = n, k
	return nil
}

// planDefaults fills in everything the recommended path does not ask about,
// letting a flag override each one.
func planDefaults(plan *splitPlan, opts *cliOptions) error {
	plan.opts.Params = kdf.Default()
	plan.opts.RecordAlgo = true
	plan.opts.RecordKDF = true

	if opts.padSet {
		mode, err := parsePadding(opts.pad)
		if err != nil {
			return err
		}
		plan.opts.Padding = mode
	}
	if opts.kdfSpec != "" {
		p, err := kdf.Parse(opts.kdfSpec)
		if err != nil {
			return err
		}
		plan.opts.Params = p
	}
	if opts.recordAlgoSet {
		plan.opts.RecordAlgo = opts.recordAlgo
	}
	if opts.recordKDFSet {
		plan.opts.RecordKDF = opts.recordKDF
	}
	if opts.methodSet {
		m, err := parseMethod(opts.method)
		if err != nil {
			return err
		}
		plan.opts.Method = m
	}
	if opts.infoSet {
		info, err := parseInfo(opts.info)
		if err != nil {
			return err
		}
		plan.opts.Info = info
	}
	return nil
}

// planIdentities loads the private keys given with --identity, so a split can be
// verified end to end rather than only as far as the pieces opening.
func planIdentities(plan *splitPlan, opts *cliOptions) error {
	for _, path := range opts.identities {
		key, err := readPrivateKey(path)
		if err != nil {
			return err
		}
		plan.privateKeys = append(plan.privateKeys, key)
	}
	return nil
}

// planProtection resolves the security mode and builds the layers for it.
func planProtection(plan *splitPlan, opts *cliOptions, interactive bool) error {
	mode, err := resolveMode(opts, interactive)
	if err != nil {
		return err
	}

	switch mode {
	case modeKeyless:
		plan.opts.Keyless = true
		if plan.opts.K < 2 {
			return errors.New("split-only mode needs a threshold (K) of at least 2, otherwise one piece is the whole file")
		}
		return nil

	case modeAdvanced:
		if err := planLayers(plan, opts, interactive, true); err != nil {
			return err
		}
		return planAdvancedTail(plan, opts, interactive)

	default:
		return planLayers(plan, opts, interactive, false)
	}
}

// planOutDir decides where the pieces go: the flag, then the prompt, then the
// directory the input came from.
func planOutDir(opts *cliOptions, defaultDir string, interactive bool) (string, error) {
	if opts.outDir != "" {
		return opts.outDir, nil
	}
	def := defaultDir
	if def == "" {
		def = "."
	}
	if !interactive {
		return def, nil
	}
	return readLine("Output directory", def)
}

// securityMode is how the wizard's one security question is answered.
type securityMode int

const (
	modeRecommended securityMode = iota
	modeAdvanced
	modeKeyless
)

// resolveMode decides which path to take. A flag that only makes sense in the
// advanced path selects it, so nothing is asked that was already answered.
func resolveMode(opts *cliOptions, interactive bool) (securityMode, error) {
	if opts.keyless {
		return modeKeyless, nil
	}
	advancedFromFlags := opts.algoSet || opts.kdfSpec != "" || opts.recordAlgoSet ||
		opts.recordKDFSet || opts.recordNameSet || opts.padSet || opts.methodSet || opts.infoSet ||
		len(opts.layerSources) > 1 || countRecipientSources(opts) > 0
	if advancedFromFlags {
		return modeAdvanced, nil
	}
	if !interactive {
		return modeRecommended, nil
	}

	heading(os.Stdout, "Security:")
	writeWrapped(os.Stdout, "  1) ", "recommended: encrypt with one password ("+ciphers.Default().Name+")")
	writeWrapped(os.Stdout, "  2) ", "advanced: several layers, each a password or a recipient key")
	// A password given as a flag has already settled that the split is
	// encrypted. Offering no encryption then would drop it without a word.
	choices := 2
	if len(opts.layerSources) == 0 {
		writeWrapped(os.Stdout, "  3) ", "no encryption: split only, no password, any K pieces rebuild the file")
		choices = 3
	}
	choice, err := readInt("Choose", 1, 1, choices)
	if err != nil {
		return modeRecommended, err
	}
	switch choice {
	case 2:
		return modeAdvanced, nil
	case 3:
		warn(os.Stdout, "anyone with K pieces can rebuild the file, and nothing proves a piece is genuine.")
		return modeKeyless, nil
	default:
		return modeRecommended, nil
	}
}

func countRecipientSources(opts *cliOptions) int {
	n := 0
	for _, s := range opts.layerSources {
		if s.kind == core.RecipientLayer {
			n++
		}
	}
	return n
}

// planLayers builds the cascade. Flags win when present; otherwise the wizard
// asks, and a non-interactive run falls back to a single password layer.
func planLayers(plan *splitPlan, opts *cliOptions, interactive, advanced bool) error {
	algos, err := requestedAlgos(opts)
	if err != nil {
		return err
	}

	switch {
	case len(opts.layerSources) > 0:
		if len(algos) > len(opts.layerSources) {
			return fmt.Errorf("--algo names %d algorithms but only %d layers were given; add more --password-env or --recipient flags",
				len(algos), len(opts.layerSources))
		}
		return layersFromSources(plan, opts, algos)

	case len(algos) > 0:
		// Algorithms alone imply that many password layers.
		for i, id := range algos {
			pw, err := passwordForLayer(plan, opts, interactive, i, plan.verifyPasswords)
			if err != nil {
				return err
			}
			plan.opts.Layers = append(plan.opts.Layers, core.LayerSpec{
				Kind: core.PasswordLayer, SchemeID: id, Password: pw,
			})
			plan.verifyPasswords = append(plan.verifyPasswords, pw)
		}
		return nil

	case advanced && interactive:
		return layersInteractive(plan, opts)

	default:
		// One password layer with the default algorithm.
		pw, err := passwordForLayer(plan, opts, interactive, 0, nil)
		if err != nil {
			return err
		}
		plan.opts.Layers = []core.LayerSpec{{
			Kind: core.PasswordLayer, SchemeID: ciphers.Default().ID, Password: pw,
		}}
		plan.verifyPasswords = [][]byte{pw}
		if interactive {
			writeWrapped(os.Stdout, "  ", fmt.Sprintf("one password layer: %s, %s",
				ciphers.Default().Name, plan.opts.Params.Describe()))
		}
		return nil
	}
}

// layersFromSources turns the ordered --password-env and --recipient flags into
// layers. Flag order is layer order, outermost first.
func layersFromSources(plan *splitPlan, opts *cliOptions, algos []uint8) error {
	for i, src := range opts.layerSources {
		var id uint8
		if i < len(algos) {
			id = algos[i]
		}
		switch src.kind {
		case core.RecipientLayer:
			pub, err := readPublicKey(src.file)
			if err != nil {
				return err
			}
			plan.opts.Layers = append(plan.opts.Layers, core.LayerSpec{
				Kind: core.RecipientLayer, SchemeID: id, Recipient: pub,
			})
		default:
			pw, err := passwordFromEnv(src.env)
			if err != nil {
				return err
			}
			if !isDistinct(pw, plan.verifyPasswords) {
				return fmt.Errorf("layer %d: %w", i+1, errPasswordReused)
			}
			plan.opts.Layers = append(plan.opts.Layers, core.LayerSpec{
				Kind: core.PasswordLayer, SchemeID: id, Password: pw,
			})
			plan.verifyPasswords = append(plan.verifyPasswords, pw)
		}
	}
	return nil
}

// layersInteractive asks for each layer in turn: what keys it, which algorithm,
// and where the key or password comes from.
func layersInteractive(plan *splitPlan, opts *cliOptions) error {
	var prev uint8
	for i := 0; ; i++ {
		fmt.Println()
		heading(os.Stdout, fmt.Sprintf("Layer %d:", i+1))
		writeWrapped(os.Stdout, "  1) ", "password")
		writeWrapped(os.Stdout, "  2) ", "recipient key (only the holder of the private key can peel it)")
		kind, err := readInt("Keyed by", 1, 1, 2)
		if err != nil {
			return err
		}

		sid, err := chooseScheme(i, prev)
		if err != nil {
			return err
		}
		prev = sid

		if kind == 2 {
			pub, err := recipientForLayer(plan, opts)
			if err != nil {
				return err
			}
			plan.opts.Layers = append(plan.opts.Layers, core.LayerSpec{
				Kind: core.RecipientLayer, SchemeID: sid, Recipient: pub,
			})
		} else {
			pw, err := choosePassword(i+1, plan.verifyPasswords, plan)
			if err != nil {
				return err
			}
			plan.opts.Layers = append(plan.opts.Layers, core.LayerSpec{
				Kind: core.PasswordLayer, SchemeID: sid, Password: pw,
			})
			plan.verifyPasswords = append(plan.verifyPasswords, pw)
		}

		more, err := confirm("Add another layer?", false)
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
}

// recipientForLayer obtains a public key for a recipient layer, generating a pair
// if the user has none yet.
func recipientForLayer(plan *splitPlan, opts *cliOptions) (*kem.PublicKey, error) {
	path, err := readLine("Recipient public key file (Enter to generate a new key pair)", "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) != "" {
		return readPublicKey(path)
	}

	scheme, err := chooseKeyScheme(opts)
	if err != nil {
		return nil, err
	}
	priv, err := kem.Generate(scheme)
	if err != nil {
		return nil, err
	}
	base, err := readLine("Save new key pair as (base name)", "riven-key")
	if err != nil {
		return nil, err
	}
	// dir is empty on purpose: --out is where the pieces go, and a private key
	// must not be written beside them. The prompt takes a path when the user
	// wants the pair somewhere else.
	pubPath, privPath := keyPaths("", base, "", "")
	// The default base name is keygen's too, so this aims at an existing pair as
	// readily as a second keygen does, and is refused the same way.
	for _, p := range []string{pubPath, privPath} {
		if err := refuseKeyOverwrite(opts, p); err != nil {
			return nil, err
		}
	}
	if err := writePublicKey(pubPath, priv.Public()); err != nil {
		return nil, err
	}
	if err := writePrivateKey(privPath, priv); err != nil {
		return nil, err
	}
	fmt.Printf("  wrote %s (share this) and %s (keep secret)\n", pubPath, privPath)
	plan.privateKeys = append(plan.privateKeys, priv)
	return priv.Public(), nil
}

// requestedAlgos resolves --algo into scheme ids.
func requestedAlgos(opts *cliOptions) ([]uint8, error) {
	if !opts.algoSet {
		return nil, nil
	}
	return ciphers.ParseList(opts.algo)
}

// planAdvancedTail asks the settings that apply whether or not there are password
// layers: what to record, the Argon2 cost, and the size padding. Each is skipped
// when a flag already answered it, or when it does not apply.
func planAdvancedTail(plan *splitPlan, opts *cliOptions, interactive bool) error {
	if !interactive {
		return nil
	}
	if err := planMethod(plan, opts); err != nil {
		return err
	}
	if err := planInfo(plan, opts); err != nil {
		return err
	}
	if err := planRecording(plan, opts); err != nil {
		return err
	}
	// The cost only matters when a password is stretched into a key.
	if len(plan.verifyPasswords) > 0 {
		if err := planCost(plan, opts); err != nil {
			return err
		}
	}
	return planPadding(plan, opts)
}

// planMethod asks how the content is spread over the pieces.
func planMethod(plan *splitPlan, opts *cliOptions) error {
	if opts.methodSet {
		return nil
	}
	fmt.Println()
	heading(os.Stdout, "Split method:")
	for i, m := range splitMethods {
		writeWrapped(os.Stdout, fmt.Sprintf("  %d) ", i+1), m.String()+": "+methodChoice(m))
	}
	choice, err := readInt("Choose", 1, 1, len(splitMethods))
	if err != nil {
		return err
	}
	plan.opts.Method = splitMethods[choice-1]
	return nil
}

// methodChoice describes one answer to the method question.
func methodChoice(m core.Method) string {
	if m == core.MethodCompact {
		return "pieces about 1/K of the file; fewer than K are safe while AES-256 and " +
			"ChaCha20 hold. For large files and QR codes."
	}
	return "pieces as large as the file; fewer than K reveal nothing, proven. The safer choice."
}

// planInfo asks what one piece shows. With a password or a key the default keeps
// the details behind the first layer's; strict, offered when there is more than
// one layer, keeps them behind every one. With a password, public and none
// trade that for not letting one piece be used to try passwords.
func planInfo(plan *splitPlan, opts *cliOptions) error {
	if opts.infoSet {
		return nil
	}
	fmt.Println()
	heading(os.Stdout, "What one piece shows (pieces needed, layers, file name):")
	var modes []core.InfoMode
	if len(plan.opts.Layers) > 0 {
		modes = append(modes, core.InfoProtected)
	}
	if len(plan.opts.Layers) > 1 {
		modes = append(modes, core.InfoStrict)
	}
	modes = append(modes, core.InfoPublic)
	// At K 1 every piece is the whole set, so nothing can be hidden from one.
	if plan.opts.K > 1 {
		modes = append(modes, core.InfoHidden)
	}
	for i, m := range modes {
		writeWrapped(os.Stdout, fmt.Sprintf("  %d) ", i+1), infoChoice(m, plan))
	}
	choice, err := readInt("Choose", 1, 1, len(modes))
	if err != nil {
		return err
	}
	plan.opts.Info = modes[choice-1]
	return nil
}

// infoChoice describes one answer to the info question. Guessing comes into it
// only when the set has a password to guess.
func infoChoice(m core.InfoMode, plan *splitPlan) string {
	hasPassword := len(plan.verifyPasswords) > 0
	guess := ""
	if hasPassword {
		guess = " Trying passwords needs K pieces."
	}
	switch m {
	case core.InfoProtected:
		first, isPassword := plan.firstSecret()
		if isPassword {
			return "with " + first + ". One piece is enough to try guesses of it."
		}
		return "with " + first + "."
	case core.InfoStrict:
		if g := plan.strictGuessing(); g != "" {
			return "with " + plan.secrets() + "; " + g + "."
		}
		return "with " + plan.secrets() + "."
	case core.InfoPublic:
		return "to anyone, nothing needed." + guess
	default:
		return "nothing." + guess
	}
}

// planRecording asks what each piece carries about how it was made.
func planRecording(plan *splitPlan, opts *cliOptions) error {
	if !opts.recordAlgoSet {
		yes, err := confirm("Record the algorithms? (else --algo is needed later)", true)
		if err != nil {
			return err
		}
		plan.opts.RecordAlgo = yes
	}
	// Whether there is a name to record depends on the input, which cmdSplit
	// resolves after planning, so the answer is kept rather than applied here.
	if !opts.recordNameSet {
		yes, err := confirm("Record the file name? (combine then restores it)", true)
		if err != nil {
			return err
		}
		opts.recordName, opts.recordNameSet = yes, true
	}
	return nil
}

// planCost asks for the Argon2 cost and whether to record it.
func planCost(plan *splitPlan, opts *cliOptions) error {
	if opts.kdfSpec == "" {
		p, err := chooseKDF(plan.opts.Params)
		if err != nil {
			return err
		}
		plan.opts.Params = p
	}
	if !opts.recordKDFSet {
		yes, err := confirm("Record the Argon2 cost? (else --kdf is needed later)", true)
		if err != nil {
			return err
		}
		plan.opts.RecordKDF = yes
	}
	return nil
}

// planPadding asks how coarse the size class should be.
func planPadding(plan *splitPlan, opts *cliOptions) error {
	if opts.padSet {
		return nil
	}
	fmt.Println()
	writeWrapped(os.Stdout, "", "Padding rounds each piece up to a size class, so its size gives only a range.")
	pct, err := readInt("Padding percent (0 for no size class)", core.DefaultPadPercent, 0, maxWizardPad)
	if err != nil {
		return err
	}
	if pct == 0 {
		plan.opts.Padding = core.PadNone()
	} else {
		plan.opts.Padding = core.PadPercent(pct)
	}
	return nil
}

// maxWizardPad is the widest class the wizard offers. The flag accepts more, but
// past this the storage cost outweighs the extra vagueness.
const maxWizardPad = 100

// parsePadding resolves the --pad value: a class width in percent, or "none".
func parsePadding(spec string) (core.Padding, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	switch s {
	case "":
		return core.Padding{}, nil
	case "none", "off", "no":
		return core.PadNone(), nil
	}
	s = strings.TrimSuffix(s, "%")
	pct, err := strconv.Atoi(s)
	if err != nil {
		return core.Padding{}, fmt.Errorf("invalid --pad %q: give a class width in percent (%d-%d) or none",
			spec, core.MinPadPercent, core.MaxPadPercent)
	}
	if pct == 0 {
		return core.PadNone(), nil
	}
	p := core.PadPercent(pct)
	if err := p.Validate(); err != nil {
		return core.Padding{}, fmt.Errorf("invalid --pad %q: the class width must be between %d and %d percent",
			spec, core.MinPadPercent, core.MaxPadPercent)
	}
	return p, nil
}

// splitMethods and infoModes are the values --method and --info take, in the
// order the wizard numbers them. Each is spelled as its String method says, so
// parsing, the wizard and shell completion all read from these.
var (
	splitMethods = []core.Method{core.MethodFull, core.MethodCompact}
	infoModes    = []core.InfoMode{core.InfoProtected, core.InfoStrict, core.InfoPublic, core.InfoHidden}
)

// names spells each value as the command line does.
func names[T fmt.Stringer](values []T) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = v.String()
	}
	return out
}

// oneOf lists names for an error message: "a, b or c".
func oneOf(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// parseMethod resolves the --method value. The numbers are the wizard's.
func parseMethod(spec string) (core.Method, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	for i, m := range splitMethods {
		if s == m.String() || s == strconv.Itoa(i+1) {
			return m, nil
		}
	}
	return 0, fmt.Errorf("invalid --method %q: use %s", spec, oneOf(names(splitMethods)))
}

// parseInfo resolves the --info value; "hidden" is taken for none.
func parseInfo(spec string) (core.InfoMode, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	if s == "hidden" {
		return core.InfoHidden, nil
	}
	for _, m := range infoModes {
		if s == m.String() {
			return m, nil
		}
	}
	return 0, fmt.Errorf("invalid --info %q: use %s", spec, oneOf(names(infoModes)))
}

// passwordForLayer resolves the password for a layer that has no explicit source.
func passwordForLayer(plan *splitPlan, opts *cliOptions, interactive bool, i int, prior [][]byte) ([]byte, error) {
	if opts.generate || !interactive {
		return generateAndRecord(plan, fmt.Sprintf("layer %d", i+1))
	}
	return choosePassword(i+1, prior, plan)
}

// choosePassword prompts for the password of a layer, counted from 1; empty
// input generates a strong one.
func choosePassword(layer int, prior [][]byte, plan *splitPlan) ([]byte, error) {
	for {
		pw, err := readPasswordMasked(fmt.Sprintf("Password for layer %d (press Enter to generate): ", layer))
		if err != nil {
			return nil, err
		}
		if len(pw) == 0 {
			return generateAndRecord(plan, fmt.Sprintf("layer %d", layer))
		}
		if !isDistinct(pw, prior) {
			fmt.Println("  that password was already used; choose a different one")
			continue
		}
		again, err := readPasswordMasked("confirm password: ")
		if err != nil {
			return nil, err
		}
		if string(pw) != string(again) {
			fmt.Println("  passwords did not match, try again")
			continue
		}
		return pw, nil
	}
}

func generateAndRecord(plan *splitPlan, label string) ([]byte, error) {
	pw, err := generatePassword(defaultGenLen)
	if err != nil {
		return nil, err
	}
	plan.generated = append(plan.generated, pw)
	if isInteractive() {
		fmt.Fprintf(secretOut(), "  generated password for %s: %s\n", label, string(pw))
	}
	return pw, nil
}

// chooseScheme lists the registered algorithms and returns the one chosen for
// layer i, counting from zero. forbid is the previous layer's algorithm, which
// may not be reused.
func chooseScheme(i int, forbid uint8) (uint8, error) {
	all := ciphers.All()
	def := ciphers.Suggested(i, forbid)
	for {
		heading(os.Stdout, "Encryption algorithm:")
		defIdx := 1
		for i, sc := range all {
			if sc.ID == def {
				defIdx = i + 1
			}
			line := fmt.Sprintf("  %d) %s", i+1, sc.Name)
			if sc.ID == forbid {
				line = fmt.Sprintf("  %d) %-20s  (used by the layer above)", i+1, sc.Name)
			}
			fmt.Println(line)
		}
		answer, err := readLine("Number or name", all[defIdx-1].Name)
		if err != nil {
			return 0, err
		}
		sid, err := resolveSchemeAnswer(answer, all)
		if err != nil {
			writeWrapped(os.Stdout, "  ", err.Error())
			continue
		}
		if sid == forbid {
			fmt.Println("  that algorithm was used by the layer above; pick another")
			continue
		}
		return sid, nil
	}
}

// resolveByNumberOrName resolves one token that is either the 1-based number
// shown in a list or an item's own name, looked up by byName. noun names what a
// name would be, for the out-of-range message.
func resolveByNumberOrName[T any](tok, noun string, all []T, byName func(string) (T, error)) (T, error) {
	tok = strings.TrimSpace(tok)
	if n, err := strconv.Atoi(tok); err == nil {
		if n < 1 || n > len(all) {
			var zero T
			return zero, fmt.Errorf("choose a number between 1 and %d, or %s", len(all), noun)
		}
		return all[n-1], nil
	}
	return byName(tok)
}

// resolveSchemeAnswer accepts either the number shown in the list or the
// algorithm name, so the list is a convenience rather than the only way in.
func resolveSchemeAnswer(answer string, all []ciphers.Scheme) (uint8, error) {
	sc, err := resolveByNumberOrName(answer, "an algorithm name", all, schemeByName)
	if err != nil {
		return 0, err
	}
	return sc.ID, nil
}

// schemeByName resolves a single algorithm name to its scheme, rejecting a spec
// that names anything other than exactly one known algorithm.
func schemeByName(name string) (ciphers.Scheme, error) {
	ids, err := ciphers.ParseList(name)
	if err != nil || len(ids) != 1 {
		return ciphers.Scheme{}, fmt.Errorf("%q is not one of the algorithms listed", name)
	}
	sc, _ := ciphers.ByID(ids[0])
	return sc, nil
}

// resolveKeyScheme returns the key type for a new key pair, from the argument
// when given and the default otherwise.
func resolveKeyScheme(opts *cliOptions) (kem.Scheme, error) {
	if opts.keyType == "" {
		return kem.Default(), nil
	}
	return kem.Parse(opts.keyType)
}

// chooseKeyScheme resolves the key type for a new key pair, asking when the run
// is interactive and nothing settled it. The listing states the per-piece cost,
// which is what the choice turns on.
func chooseKeyScheme(opts *cliOptions) (kem.Scheme, error) {
	if opts.keyType != "" || !isInteractive() || opts.yes {
		return resolveKeyScheme(opts)
	}
	all := kem.All()
	heading(os.Stdout, "Recipient key type, with the bytes it adds to every piece:")
	for i, s := range all {
		writeWrapped(os.Stdout, fmt.Sprintf("  %d) %-11s %-7s ", i+1, s.Name(),
			fmt.Sprintf("+%d B", s.CiphertextSize())), s.Summary())
	}
	choice, err := readInt("Choose", 1, 1, len(all))
	if err != nil {
		return kem.Default(), err
	}
	return all[choice-1], nil
}

// chooseKDF offers the cost presets plus a custom option.
func chooseKDF(def kdf.Params) (kdf.Params, error) {
	names := kdf.PresetNames()
	heading(os.Stdout, "Argon2id cost (higher is slower to attack, and slower per piece):")
	defIdx := 1
	for i, n := range names {
		p, _ := kdf.Parse(n)
		if p == def {
			defIdx = i + 1
		}
		fmt.Printf("  %d) %-12s %s\n", i+1, n, p.Describe())
	}
	custom := len(names) + 1
	fmt.Printf("  %d) custom\n", custom)

	choice, err := readInt("Cost", defIdx, 1, custom)
	if err != nil {
		return kdf.Params{}, err
	}
	if choice < custom {
		return kdf.Parse(names[choice-1])
	}
	for {
		spec, err := readLine("Enter m=<MiB>,t=<passes>,p=<lanes>", def.String())
		if err != nil {
			return kdf.Params{}, err
		}
		p, err := kdf.Parse(spec)
		if err != nil {
			writeWrapped(os.Stdout, "  ", err.Error())
			continue
		}
		return p, nil
	}
}

// resolveFormats decides the export formats. It runs after the split so the
// real piece sizes are known and QR feasibility can be reported exactly.
func resolveFormats(opts *cliOptions, plan *splitPlan, pieceSize int) ([]pieceio.Format, error) {
	interactive := isInteractive() && !opts.yes

	if opts.format != "" {
		formats, err := pieceio.ParseFormats(opts.format)
		if err != nil {
			return nil, err
		}
		return formats, checkFormatsFit(plan, formats, pieceSize, plan.opts.N)
	}
	if !interactive {
		return []pieceio.Format{pieceio.Binary}, nil
	}

	all := pieceio.All()

	fmt.Println()
	heading(os.Stdout, "Export format:")
	for i, f := range all {
		writeItem(os.Stdout, fmt.Sprintf("  %d) %-7s ", i+1, f), f.Describe(), formatNote(f, pieceSize))
	}

	for {
		answer, err := readLine("Numbers or names, comma-separated, or all", string(pieceio.Binary))
		if err != nil {
			return nil, err
		}
		formats, err := resolveFormatAnswer(answer, all)
		if err != nil {
			writeWrapped(os.Stdout, "  ", err.Error())
			continue
		}
		if err := checkFormatsFit(plan, formats, pieceSize, plan.opts.N); err != nil {
			writeWrapped(os.Stdout, "  ", err.Error())
			continue
		}
		return formats, nil
	}
}

// resolveFormatAnswer reads the export answer: "all", or a comma-separated list
// mixing the numbers shown and the format names, so "base64,3" is as valid as
// "2,3" or "base64,qr".
func resolveFormatAnswer(answer string, all []pieceio.Format) ([]pieceio.Format, error) {
	if strings.EqualFold(strings.TrimSpace(answer), "all") {
		return all, nil
	}
	parts := splitFields(answer)
	if len(parts) == 0 {
		return nil, fmt.Errorf("name at least one format, or all")
	}
	seen := map[pieceio.Format]bool{}
	var out []pieceio.Format
	for _, p := range parts {
		f, err := resolveByNumberOrName(p, "a format name", all, pieceio.ParseFormat)
		if err != nil {
			return nil, err
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out, nil
}

// checkFormatsFit refuses a choice the pieces are too large for, before any file
// is written. Failing halfway through an export would leave a set that is
// complete in one format and partial in another.
func checkFormatsFit(plan *splitPlan, formats []pieceio.Format, pieceSize, count int) error {
	if err := checkQRFeasible(plan, formats, pieceSize, count); err != nil {
		return err
	}
	if err := checkWordsFeasible(formats, pieceSize, count); err != nil {
		return err
	}
	return checkSheetFeasible(formats, pieceSize, count)
}

// checkSheetFeasible refuses a sheet export for pieces that would run to more
// pages than anyone would print and file.
func checkSheetFeasible(formats []pieceio.Format, pieceSize, count int) error {
	if !slices.Contains(formats, pieceio.Sheet) || pieceSize <= pieceio.SheetMaxPiece {
		return nil
	}
	return fmt.Errorf("cannot export as a sheet: each of the %d pieces is %d bytes, "+
		"about %d printed pages. The limit is %d pages; use base32 or binary",
		count, pieceSize, pieceio.SheetPages(pieceSize), pieceio.SheetMaxPages)
}

// checkWordsFeasible refuses a word export for pieces past the size a person
// could reasonably transcribe.
func checkWordsFeasible(formats []pieceio.Format, pieceSize, count int) error {
	if !slices.Contains(formats, pieceio.Words) || pieceSize <= pieceio.Bip39MaxPiece {
		return nil
	}
	return fmt.Errorf("cannot export as words: each of the %d pieces is %d bytes, which is %d words. "+
		"The limit is %d bytes; use base32, or split into more pieces",
		count, pieceSize, pieceio.Bip39Words(pieceSize), pieceio.Bip39MaxPiece)
}

// checkQRFeasible refuses a QR export when any piece is too large. It is all or
// nothing: a set where only some pieces have a code cannot be scanned back.
//
// Padding applies to QR too, so a piece can be over the limit by padding alone.
// The message says so when that is possible, since turning padding off is the
// fix and compressing the input is not.
func checkQRFeasible(plan *splitPlan, formats []pieceio.Format, pieceSize, count int) error {
	if !slices.Contains(formats, pieceio.QR) || pieceio.QRFits(pieceSize) {
		return nil
	}
	// Every piece of a set is the same size, so one is enough to decide.
	msg := fmt.Sprintf("cannot export as QR: none of the %d pieces fits. %s",
		count, pieceio.QRTooLargeMessage(pieceSize))
	if !plan.opts.Padding.Off {
		width := plan.opts.Padding.Width()
		msg += fmt.Sprintf(". Pieces are padded up to a %d percent size class, so try "+
			"--pad none, which drops the size class", width)
		if width > core.MinPadPercent {
			msg += ", or a narrower class"
		}
	}
	if plan.opts.Method == core.MethodFull && plan.opts.K > 1 {
		msg += fmt.Sprintf(". --method compact makes each piece about 1/%d of the file", plan.opts.K)
	}
	return errors.New(msg)
}

// resolveOpenParams gathers the algorithm and cost overrides needed to open
// pieces that did not record them.
func resolveOpenParams(opts *cliOptions) (*kdf.Params, []uint8, error) {
	var params *kdf.Params
	if opts.kdfSpec != "" {
		p, err := kdf.Parse(opts.kdfSpec)
		if err != nil {
			return nil, nil, err
		}
		params = &p
	}
	schemes, err := requestedAlgos(opts)
	if err != nil {
		return nil, nil, err
	}
	return params, schemes, nil
}

// askMissingKDF prompts for cost parameters after a failed open, or explains the
// flag to use when running non-interactively.
func askMissingKDF(opts *cliOptions) (*kdf.Params, error) {
	return askMissingKDFFor(opts, "The piece did not open. If its Argon2 cost was not recorded, enter it now.")
}

// askMissingKDFFor is askMissingKDF with the reason it is asking.
func askMissingKDFFor(opts *cliOptions, why string) (*kdf.Params, error) {
	if !isInteractive() || opts.yes {
		return nil, nil
	}
	fmt.Println("\n" + why)
	spec, err := readLine("Argon2 cost (Enter to give up)", "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	p, err := kdf.Parse(spec)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// askMissingAlgos prompts for the cascade algorithms of a set that omitted them.
func askMissingAlgos(opts *cliOptions, layers int) ([]uint8, error) {
	if !isInteractive() || opts.yes {
		return nil, fmt.Errorf("this set did not record its algorithms; supply them with --algo (%d needed, outer to inner; available: %s)",
			layers, strings.Join(ciphers.Names(), ", "))
	}
	all := ciphers.All()
	fmt.Println("\nThis set was written without recording its algorithms, so they have to be")
	fmt.Printf("supplied. It has %d layer(s): name one per layer, outermost first.\n", layers)
	for i, sc := range all {
		fmt.Printf("  %d) %s\n", i+1, sc.Name)
	}
	for {
		spec, err := readLine(fmt.Sprintf("%d algorithm(s), numbers or names, comma-separated", layers), "")
		if err != nil {
			return nil, err
		}
		ids, err := resolveSchemeList(spec, all)
		if err != nil {
			writeWrapped(os.Stdout, "  ", err.Error())
			continue
		}
		if len(ids) != layers {
			fmt.Printf("  expected %d algorithms, got %d\n", layers, len(ids))
			continue
		}
		return ids, nil
	}
}

// resolveSchemeList reads a comma-separated answer of numbers, names, or a mix.
func resolveSchemeList(spec string, all []ciphers.Scheme) ([]uint8, error) {
	parts := splitFields(spec)
	if len(parts) == 0 {
		return nil, fmt.Errorf("name at least one algorithm")
	}
	ids := make([]uint8, 0, len(parts))
	for _, p := range parts {
		id, err := resolveSchemeAnswer(p, all)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// formatNote states why a format is unavailable, or what it costs, so the choice
// is made with the consequence in view rather than after the fact. The note is
// returned bare: writeItem decides whether it sits beside the description or on
// a line of its own.
func formatNote(f pieceio.Format, pieceSize int) string {
	switch f {
	case pieceio.QR:
		if !pieceio.QRFits(pieceSize) {
			return fmt.Sprintf("NOT AVAILABLE: pieces are %d bytes, over the %d limit",
				pieceSize, pieceio.QRMaxBytes)
		}
	case pieceio.Sheet:
		switch {
		case pieceSize > pieceio.SheetMaxPiece:
			return fmt.Sprintf("NOT AVAILABLE: pieces are %d bytes, over %d printed pages",
				pieceSize, pieceio.SheetMaxPages)
		case !pieceio.QRFits(pieceSize):
			return fmt.Sprintf("(text only, about %d page(s): too large for a QR code)",
				pieceio.SheetPages(pieceSize))
		case pieceio.SheetPages(pieceSize) > 1:
			return fmt.Sprintf("(about %d printed pages per piece)", pieceio.SheetPages(pieceSize))
		}
	case pieceio.Words:
		if pieceSize > pieceio.Bip39MaxPiece {
			return fmt.Sprintf("NOT AVAILABLE: pieces are %d bytes, over the %d limit",
				pieceSize, pieceio.Bip39MaxPiece)
		}
		return fmt.Sprintf("(%d words per piece, about %.1f times the size)",
			pieceio.Bip39Words(pieceSize), pieceio.Bip39Expansion)
	}
	return ""
}
