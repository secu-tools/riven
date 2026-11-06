// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"errors"
	"fmt"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/memory"
)

// The open side asks for nothing up front beyond what the flags give. core opens
// each piece once and calls back for a password, a cost or the algorithms at the
// point a set turns out to need one, so a set is never opened again for an
// answer, and a keyless set is opened without a question.

// resolveOpenCredentials gathers everything an open needs from opts: the
// passwords from the environment, the KDF parameters and schemes, the recipient
// private keys, and the callbacks that ask for what a set turns out to need,
// assembled into a core.OpenOptions. The returned cleanup wipes every password
// it holds; the caller still owns the pieces.
func resolveOpenCredentials(opts *cliOptions, pieces [][]byte) (core.OpenOptions, func(), error) {
	pws, err := gatherOpenPasswords(opts)
	if err != nil {
		return core.OpenOptions{}, nil, err
	}
	params, schemes, err := resolveOpenParams(opts)
	if err != nil {
		memory.FreeAll(pws)
		return core.OpenOptions{}, nil, err
	}
	keys, err := resolveOpenKeys(opts)
	if err != nil {
		memory.FreeAll(pws)
		return core.OpenOptions{}, nil, err
	}
	p := &prompter{opts: opts}
	open := core.OpenOptions{
		Passwords: pws, PrivateKeys: keys, Params: params, Schemes: schemes,
		EnvelopePasswords: p.envelopePasswords,
		AskParams:         p.askParams,
		AskSchemes:        p.askSchemes,
		BeforeDerive:      noteCost,
	}
	if len(pws) == 0 {
		open.AskPasswords = p.layerPasswords
	}
	return open, func() { memory.FreeAll(pws); p.wipe() }, nil
}

// combinePieces rebuilds a set, asking for whatever it turns out to need, and
// returns the content and the file name the pieces recorded. damaged, when set,
// is told about each piece set aside as damaged.
func combinePieces(opts *cliOptions, pieces [][]byte, damaged func(int, error)) ([]byte, string, error) {
	open, wipe, err := resolveOpenCredentials(opts, pieces)
	if err != nil {
		return nil, "", err
	}
	defer wipe()
	open.Damaged = damaged
	return core.CombineFile(pieces, open)
}

// gatherOpenPasswords reads the passwords named with --password-env, in order.
// Without any it returns none: the pieces are opened first, and the prompter
// asks only if they turn out to need a password.
func gatherOpenPasswords(opts *cliOptions) ([][]byte, error) {
	var out [][]byte
	for _, name := range opts.passwordEnvs() {
		pw, err := passwordFromEnv(name)
		if err != nil {
			memory.FreeAll(out)
			return nil, err
		}
		out = append(out, pw)
	}
	return out, nil
}

// prompter answers what core asks for while a set is opened. Each answer is kept
// and given again, so a command that opens several pieces one at a time, as info
// and verify do, asks the user only once.
type prompter struct {
	opts     *cliOptions
	envelope [][]byte
	asked    bool // envelope was answered, possibly with no password
	layers   [][]byte
	params   *kdf.Params
	schemes  []uint8
}

// wipe clears every password the prompter holds.
func (p *prompter) wipe() {
	memory.FreeAll(p.envelope)
	memory.FreeAll(p.layers)
	p.envelope, p.layers = nil, nil
}

// copies returns fresh copies, since core wipes what it is handed.
func copies(pws [][]byte) [][]byte {
	out := make([][]byte, len(pws))
	for i, pw := range pws {
		out[i] = append([]byte(nil), pw...)
	}
	return out
}

// envelopePasswords asks for the passwords that seal the pieces, once some piece
// did not open without one.
//
// When others did open, the set may be keyless with a damaged piece, or a
// crafted keyless piece may sit among a password set's, so the user decides:
// Enter alone means the set has none. A run that cannot ask fails instead of
// guessing, naming the flag, and also naming what to drop in the mixed case.
func (p *prompter) envelopePasswords(mixed bool) ([][]byte, error) {
	if p.asked {
		return copies(p.envelope), nil
	}
	if p.opts.yes || !isInteractive() {
		if mixed {
			return nil, errors.New("some pieces did not open without a password: if this set has one, give it " +
				"with --password-env NAME; if it has none, leave out the pieces that do not open")
		}
		if len(p.opts.identities) > 0 {
			return nil, errors.New("the pieces did not open with the key given: if the set also has a password, " +
				"set it with --password-env NAME")
		}
		return nil, errors.New("no password or key given: set the password with --password-env NAME, " +
			"or give the private key with --identity FILE")
	}
	var pws [][]byte
	var err error
	if mixed {
		fmt.Println("\nSome pieces opened without a password and some did not.")
		pws, err = readLayerPasswords("Layer 1 password (press Enter if this set has none): ", false)
	} else {
		fmt.Println("\nEnter the password for each layer, outermost first.")
		pws, err = readLayerPasswords("Layer 1 password: ", true)
	}
	if errors.Is(err, errNoPassword) && len(p.opts.identities) == 0 {
		return nil, errors.New("no password entered: a set protected by a private key needs --identity FILE")
	}
	if err != nil {
		return nil, err
	}
	p.envelope, p.asked = pws, true
	return copies(pws), nil
}

// errNoPassword is a required password left empty.
var errNoPassword = errors.New("no password entered")

// readLayerPasswords asks for one password per layer until an empty entry. The
// first prompt is given; required refuses an empty first answer.
func readLayerPasswords(first string, required bool) ([][]byte, error) {
	var pws [][]byte
	prompt := first
	for i := 2; ; i++ {
		pw, err := readPasswordMasked(prompt)
		if err != nil {
			memory.FreeAll(pws)
			return nil, err
		}
		if len(pw) == 0 {
			if len(pws) == 0 && required {
				return nil, errNoPassword
			}
			return pws, nil
		}
		pws = append(pws, pw)
		prompt = fmt.Sprintf("Layer %d password (press Enter if there are no more layers): ", i)
	}
}

// layerPasswords asks for the passwords of a set once it has said how many it
// needs. Those typed for the envelope are kept as the first layers': a protected
// envelope takes the first layer's alone, so only the rest are asked for.
func (p *prompter) layerPasswords(n int) ([][]byte, error) {
	if len(p.layers) == n {
		return copies(p.layers), nil
	}
	var known [][]byte
	if p.asked && len(p.envelope) <= n {
		known = p.envelope
	}
	// Every layer's password may already have been typed for the envelope.
	if len(known) == n {
		return copies(known), nil
	}
	pws, err := askSetPasswords(p.opts, n, copies(known))
	if err != nil {
		return nil, err
	}
	memory.FreeAll(p.layers)
	p.layers = pws
	return copies(pws), nil
}

// askSetPasswords asks for the passwords of n layers, outermost first, after the
// known ones, which it takes over.
func askSetPasswords(opts *cliOptions, n int, known [][]byte) ([][]byte, error) {
	if opts.yes || !isInteractive() {
		memory.FreeAll(known)
		return nil, fmt.Errorf("this set needs %d password(s): give them with --password-env NAME, outermost first", n)
	}
	switch len(known) {
	case 0:
		fmt.Printf("\nThis set needs %d password(s), outermost layer first.\n", n)
	case 1:
		fmt.Printf("\nThis set needs %d password(s). Layer 1 is the one entered above.\n", n)
	default:
		fmt.Printf("\nThis set needs %d password(s). Layers 1 to %d are the ones entered above.\n", n, len(known))
	}
	pws := append(make([][]byte, 0, n), known...)
	for i := len(known) + 1; i <= n; i++ {
		pw, err := readPasswordMasked(fmt.Sprintf("Layer %d password: ", i))
		if err != nil {
			memory.FreeAll(pws)
			return nil, err
		}
		pws = append(pws, pw)
	}
	return pws, nil
}

// askParams asks for the Argon2 cost. certain means the set says it did not
// record one; otherwise a piece did not open and an unrecorded cost may be why,
// so the question is optional and a run that cannot ask leaves the error as it
// was.
func (p *prompter) askParams(certain bool) (*kdf.Params, error) {
	if p.params != nil {
		c := *p.params
		return &c, nil
	}
	var params *kdf.Params
	var err error
	if certain {
		params, err = askMissingKDFFor(p.opts, "This set did not record its Argon2 cost, so it has to be supplied.")
		if err == nil && params == nil {
			err = fmt.Errorf("%w; supply it with --kdf", core.ErrParamsRequired)
		}
	} else {
		params, err = askMissingKDF(p.opts)
	}
	if err != nil || params == nil {
		return nil, err
	}
	p.params = params
	c := *params
	return &c, nil
}

// askSchemes asks for the algorithms of a set that did not record them.
func (p *prompter) askSchemes(layers int) ([]uint8, error) {
	if len(p.schemes) == layers {
		return p.schemes, nil
	}
	ids, err := askMissingAlgos(p.opts, layers)
	if err != nil {
		return nil, err
	}
	p.schemes = ids
	return ids, nil
}

// resolveOpenKeys loads every private key named with --identity.
func resolveOpenKeys(opts *cliOptions) ([]*kem.PrivateKey, error) {
	var keys []*kem.PrivateKey
	for _, path := range opts.identities {
		k, err := readPrivateKey(path)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// costWarnThreshold is the declared memory size, in KiB, above which opening is
// slow enough to be worth announcing.
const costWarnThreshold = 256 * 1024

// noteCost warns, just before envelope keys are derived, when the pieces declare
// a costly derivation, so a slow open does not read as a hang. The cost is not
// authenticated, so it also flags a file of unknown origin asking for a lot of
// work. core calls it only when a key is about to be derived, so a keyless
// piece's noise never turns into a figure.
func noteCost(worst kdf.Params) {
	if !isInteractive() || worst.Memory < costWarnThreshold {
		return
	}
	fmt.Printf("  these pieces ask for %s per piece, so this takes a moment.\n", worst.Describe())
}
