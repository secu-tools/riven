// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"fmt"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/pieceio"
)

// validateSplitOptions rejects contradictory combinations before any work starts,
// so a mistake is reported plainly instead of being silently resolved one way or
// the other. Each message names the flags involved and what to do about it.
func validateSplitOptions(opts *cliOptions) error {
	for _, check := range []func(*cliOptions) error{
		validateSplitInput,
		validateNameRecording,
		validateKeylessConflicts,
		validateAlgorithms,
		validateSplitValues,
		validatePaddingChoice,
		validateCounts,
	} {
		if err := check(opts); err != nil {
			return err
		}
	}
	return nil
}

// validateSplitInput checks the split has exactly one source of data.
func validateSplitInput(opts *cliOptions) error {
	if opts.textSet && len(opts.files) > 0 {
		return fmt.Errorf("give either a file or --text, not both")
	}
	if len(opts.files) > 1 {
		return fmt.Errorf("split takes one input, but %d were given", len(opts.files))
	}
	return nil
}

// validateKeylessConflicts rejects the flags that have no meaning without a key,
// rather than accepting them and quietly doing nothing.
func validateKeylessConflicts(opts *cliOptions) error {
	if !opts.keyless {
		return nil
	}
	switch {
	case len(opts.passwordEnvs()) > 0:
		return fmt.Errorf("--keyless takes no password: drop --password-env, or drop --keyless")
	case countRecipientSources(opts) > 0:
		return fmt.Errorf("--keyless takes no recipient key: drop --recipient, or drop --keyless")
	case opts.algoSet:
		return fmt.Errorf("--keyless does not encrypt, so --algo does not apply")
	case opts.kdfSpec != "":
		return fmt.Errorf("--keyless derives no key, so --kdf does not apply")
	case opts.generate:
		return fmt.Errorf("--keyless uses no password, so --generate does not apply")
	case opts.recordKDFSet:
		return fmt.Errorf("--keyless derives no key, so the --record-kdf options do not apply")
	}
	return nil
}

// validateNameRecording refuses --record-name where there is no name to record,
// rather than accepting the flag and quietly doing nothing.
func validateNameRecording(opts *cliOptions) error {
	if !opts.recordNameSet || !opts.recordName {
		return nil
	}
	if opts.textSet || (len(opts.files) == 1 && opts.files[0] == "-") {
		return fmt.Errorf("--record-name true needs a file: text and standard input have no name of their own")
	}
	return nil
}

// validateAlgorithms checks the algorithm list parses and fits the layers given.
func validateAlgorithms(opts *cliOptions) error {
	if !opts.algoSet {
		return nil
	}
	ids, err := ciphers.ParseList(opts.algo)
	if err != nil {
		return err
	}
	if n := len(opts.layerSources); n > 0 && len(ids) > n {
		return fmt.Errorf("--algo names %d algorithms but only %d layers were given; add more --password-env or --recipient flags",
			len(ids), n)
	}
	return nil
}

// validateSplitValues checks the values that are parsed by another package.
func validateSplitValues(opts *cliOptions) error {
	if opts.kdfSpec != "" {
		if _, err := kdf.Parse(opts.kdfSpec); err != nil {
			return err
		}
	}
	if opts.format != "" {
		if _, err := pieceio.ParseFormats(opts.format); err != nil {
			return err
		}
	}
	return nil
}

// validatePaddingChoice checks the padding value, and refuses padding for a
// split that cannot benefit from it.
//
// Padding hides the length inside the encrypted metadata. Without a password
// that metadata is sealed with a public key, so the length is readable either
// way and asking for padding would be answered by silently doing nothing.
func validatePaddingChoice(opts *cliOptions) error {
	if !opts.padSet {
		return nil
	}
	pad, err := parsePadding(opts.pad)
	if err != nil {
		return err
	}
	if pad.Off {
		return nil
	}
	if opts.keyless {
		return fmt.Errorf("--keyless uses no password, so the piece metadata is public and padding cannot hide the content length: drop --pad")
	}
	if n := countRecipientSources(opts); n > 0 && n == len(opts.layerSources) {
		return fmt.Errorf("a split addressed only to recipient keys uses no password, so the piece metadata is public and padding cannot hide the content length: add a password layer with --password-env, or drop --pad")
	}
	return nil
}

// validateCounts checks the piece count, threshold and QR scale.
func validateCounts(opts *cliOptions) error {
	if opts.qrScale < 0 {
		return fmt.Errorf("--qr-scale must be positive")
	}
	if opts.nSet && (opts.n < 1 || opts.n > 255) {
		return fmt.Errorf("-n must be between 1 and 255")
	}
	if opts.kSet && opts.k < 1 {
		return fmt.Errorf("-k must be at least 1")
	}
	if opts.nSet && opts.kSet && opts.k > opts.n {
		return fmt.Errorf("-k (%d) cannot exceed -n (%d)", opts.k, opts.n)
	}
	return nil
}

// validateOpenOptions checks the flags that apply when opening pieces.
func validateOpenOptions(opts *cliOptions) error {
	if opts.keyless {
		return fmt.Errorf("--keyless applies to splitting, not to opening pieces")
	}
	if opts.textSet {
		return fmt.Errorf("--text applies to splitting, not to opening pieces")
	}
	if countRecipientSources(opts) > 0 {
		return fmt.Errorf("--recipient names a public key for splitting; use --identity with your private key to open pieces")
	}
	if opts.generate {
		return fmt.Errorf("--generate applies to splitting, not to opening pieces")
	}
	if opts.algoSet {
		if _, err := ciphers.ParseList(opts.algo); err != nil {
			return err
		}
	}
	if opts.kdfSpec != "" {
		if _, err := kdf.Parse(opts.kdfSpec); err != nil {
			return err
		}
	}
	return nil
}

// validateKeygenOptions rejects the flags that mean nothing when generating a
// key pair, so a mistake is reported instead of being silently dropped.
func validateKeygenOptions(opts *cliOptions) error {
	switch {
	case opts.outDir != "" && opts.pubOut != "" && opts.privOut != "":
		return fmt.Errorf("--pub and --priv already name both files, so --out has nothing to place")
	case len(opts.passwordEnvs()) > 0:
		return fmt.Errorf("keygen takes no password: a key pair is not password-protected")
	case countRecipientSources(opts) > 0:
		return fmt.Errorf("--recipient names a key for splitting; keygen creates one instead")
	case opts.keyless:
		return fmt.Errorf("--keyless applies to splitting, not to generating a key pair")
	case opts.textSet || len(opts.files) > 0:
		return fmt.Errorf("keygen takes no input: use 'riven keygen [TYPE]'")
	case opts.nSet || opts.kSet:
		return fmt.Errorf("-n and -k apply to splitting, not to generating a key pair")
	case opts.algoSet:
		return fmt.Errorf("--algo applies to splitting, not to generating a key pair")
	case opts.format != "":
		return fmt.Errorf("--format applies to splitting, not to generating a key pair")
	case opts.padSet:
		return fmt.Errorf("--pad applies to splitting, not to generating a key pair")
	case opts.kdfSpec != "":
		return fmt.Errorf("--kdf applies to splitting, not to generating a key pair")
	case opts.generate:
		return fmt.Errorf("--generate makes a password; keygen makes a key pair")
	case opts.name != "":
		return fmt.Errorf("--name names pieces; use --pub and --priv to name key files")
	case opts.qrScale != 0:
		return fmt.Errorf("--qr-scale applies to QR export, not to generating a key pair")
	case opts.recordAlgoSet || opts.recordKDFSet || opts.recordNameSet:
		return fmt.Errorf("the --record-* options apply to splitting, not to generating a key pair")
	case opts.verifySet:
		return fmt.Errorf("--verify checks written pieces, not a generated key pair")
	case len(opts.identities) > 0:
		return fmt.Errorf("--identity opens pieces with an existing private key; keygen creates a new pair")
	}
	return nil
}
