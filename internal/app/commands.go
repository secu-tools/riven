// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/pieceio"
)

// msgWriter returns where human-readable messages go. Under -y standard output is
// reserved for machine-readable results (generated passwords, or recovered data),
// so commentary goes to standard error and cannot corrupt a pipeline.
func msgWriter(opts *cliOptions) io.Writer {
	if opts.yes {
		return os.Stderr
	}
	return os.Stdout
}

// ensureDir creates dir if it does not exist.
func ensureDir(dir string) error {
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}

func cmdSplit(opts *cliOptions) error {
	if err := validateSplitOptions(opts); err != nil {
		return err
	}
	out := msgWriter(opts)

	in, err := readSplitInput(opts)
	if err != nil {
		return err
	}
	input := in.data
	defer memory.Zero(input)

	plan, err := planSplit(opts, in.dir)
	if err != nil {
		return err
	}
	defer wipeAll(plan.verifyPasswords)
	plan.opts.Name = recordedName(opts, in.origName)
	plan.opts.CreatorVersion = creatorVersion()
	plan.opts.CreatorCommit = creatorCommit()

	fmt.Fprintln(out, "\nSplitting...")
	noteLargeSplit(out, len(input), plan.opts.N)

	if err := ensureDir(plan.outDir); err != nil {
		return err
	}

	written, formats, err := exportSplit(out, plan, opts, input, in.baseName)
	if err != nil {
		return err
	}

	if opts.verifyEnabled() {
		verifyPaths := written[pieceio.Binary]
		if len(verifyPaths) == 0 {
			verifyPaths = written[formats[0]]
		}
		if err := verifySplit(out, input, verifyPaths, plan); err != nil {
			fmt.Fprintf(out, "\nWARNING: verification failed: %v\n", err)
			fmt.Fprintln(out, "The pieces were written but could NOT be verified. Do not rely on them.")
			return err
		}
	}

	printSplitSummary(out, plan, formats, written, opts.verifyEnabled())
	return reportGeneratedPasswords(opts, plan)
}

// verifyEnabled reports whether the post-split self-check should run. It is on
// unless the user turned it off with --verify false or --no-verify.
func (o *cliOptions) verifyEnabled() bool {
	if !o.verifySet {
		return true
	}
	return o.verify
}

// splitInput is what a split reads.
type splitInput struct {
	data     []byte
	baseName string // what to call the piece files
	dir      string // where the pieces go unless --out says otherwise
	origName string // the input file's own name, empty when there was no file
}

// readSplitInput resolves what to split: a file, standard input when the path is
// "-", or a string given with --text / --text-env.
func readSplitInput(opts *cliOptions) (splitInput, error) {
	name := func(def string) string {
		if opts.name != "" {
			return opts.name
		}
		return def
	}

	switch {
	// validateSplitOptions rejects this earlier with a friendlier message; the
	// check is repeated so this function is safe to call on its own.
	case opts.textSet && len(opts.files) > 0:
		return splitInput{}, errors.New("give either a file or --text, not both")

	case opts.textSet:
		return splitInput{data: []byte(opts.text), baseName: name("secret"), dir: "."}, nil

	case len(opts.files) == 0:
		return splitInput{}, errors.New("split needs an input: a file path, \"-\" for standard input, or --text")

	case opts.files[0] == "-":
		// Standard input carries the data, so it can no longer answer prompts.
		if !opts.yes && isInteractive() {
			return splitInput{}, errors.New("reading data from standard input needs -y, since prompts cannot share it")
		}
		buf, err := io.ReadAll(os.Stdin)
		if err != nil {
			return splitInput{}, err
		}
		return splitInput{data: buf, baseName: name("secret"), dir: "."}, nil

	default:
		path := opts.files[0]
		st, err := os.Stat(path)
		if err != nil {
			return splitInput{}, err
		}
		if st.IsDir() {
			return splitInput{}, errSplitDirectory
		}
		buf, err := os.ReadFile(path)
		if err != nil {
			return splitInput{}, err
		}
		base := filepath.Base(path)
		return splitInput{data: buf, baseName: name(base), dir: filepath.Dir(path), origName: base}, nil
	}
}

// recordedName decides what file name goes inside the pieces. Only a real file
// has one: text and standard input are named "secret" by this tool, which is not
// worth carrying. --record-name false leaves it out.
func recordedName(opts *cliOptions, orig string) string {
	if opts.recordNameSet && !opts.recordName {
		return ""
	}
	return core.SafeName(orig)
}

// exportSplit produces the pieces and writes each one in every requested format.
//
// Pieces are written as they are produced and released immediately, so the
// memory a split needs does not grow with the piece count. The export question
// needs a piece size to answer, which is only known once a piece exists, so it
// is settled from the first one and applied to the rest; every piece of a set is
// the same size.
func exportSplit(out io.Writer, plan *splitPlan, opts *cliOptions, input []byte, base string) (map[pieceio.Format][]string, []pieceio.Format, error) {
	written := make(map[pieceio.Format][]string, len(pieceio.All()))
	width := len(strconv.Itoa(plan.opts.N))
	var formats []pieceio.Format
	var sizes []int

	err := core.SplitTo(input, plan.opts, func(serial int, piece []byte) error {
		if formats == nil {
			chosen, ferr := resolveFormats(opts, plan, len(piece))
			if ferr != nil {
				return ferr
			}
			formats = chosen
		}
		sizes = append(sizes, len(piece))

		name := fmt.Sprintf("%s.%0*d", base, width, serial)
		for _, f := range formats {
			path := pieceio.Path(plan.outDir, name, f)
			data, _, err := encodeOne(piece, f, plan, base, serial)
			if err != nil {
				return fmt.Errorf("%s export: %w", f, err)
			}
			err = pieceio.Write(path, data)
			memory.Zero(data)
			if err != nil {
				return err
			}
			written[f] = append(written[f], path)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	reportSizeNotes(out, formats, sizes)
	return written, formats, nil
}

// reportSizeNotes says what the chosen formats cost at the size the pieces came
// out. Both QR and sheet carry a code, but the report is about the pieces rather
// than the formats, so it is made once.
func reportSizeNotes(out io.Writer, formats []pieceio.Format, sizes []int) {
	if len(sizes) == 0 {
		return
	}
	wantQR, wantSheet := false, false
	for _, f := range formats {
		switch f {
		case pieceio.QR:
			wantQR = true
		case pieceio.Sheet:
			wantSheet = true
		}
	}
	if wantQR || wantSheet {
		reportQRSizes(out, sizes)
	}
	if wantSheet {
		if pages := pieceio.SheetPages(sizes[0]); pages > 1 {
			fmt.Fprintf(out, "  sheet: about %d printed pages per piece, %d in all\n",
				pages, pages*len(sizes))
		}
	}
}

// noteLargeSplit warns before a split that will need a lot of memory. The shares
// are N copies of the input, which is not obvious from the file size.
func noteLargeSplit(out io.Writer, inputLen, n int) {
	const quiet = 64 << 20
	if inputLen < quiet {
		return
	}
	fmt.Fprintf(out, "  %d MiB into %d pieces needs about %d MiB of memory.\n",
		inputLen>>20, n, core.MemoryEstimate(inputLen, n)>>20)
}

// encodeOne renders one piece in one format. A recovery sheet needs to say which
// piece it is, so it takes the extra arguments the other formats do not.
func encodeOne(piece []byte, f pieceio.Format, plan *splitPlan, base string, serial int) ([]byte, string, error) {
	if f == pieceio.Sheet {
		return pieceio.EncodeSheet(piece, pieceio.SheetInfo{
			Serial: serial, Total: plan.opts.N, Needed: plan.opts.K, Name: base,
		}, plan.qrScale)
	}
	return pieceio.Encode(piece, f, plan.qrScale)
}

// reportQRSizes summarises the error correction the pieces received, from their
// sizes. It is derived per piece rather than assumed, so a set that did land on
// two levels is reported as it is.
func reportQRSizes(out io.Writer, sizes []int) {
	largest := 0
	for _, n := range sizes {
		if n > largest {
			largest = n
		}
	}
	counts := map[string]int{}
	recovery := map[string]int{}
	weakest := false
	for _, n := range sizes {
		name, rec, weak, ok := pieceio.QRLevelFor(n)
		if !ok {
			continue
		}
		counts[name]++
		recovery[name] = rec
		if weak {
			weakest = true
		}
	}
	if len(counts) == 0 {
		return
	}

	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	// Strongest first, which is the order the capacity table uses.
	order := map[string]int{"H": 0, "Q": 1, "M": 2, "L": 3}
	sort.Slice(names, func(i, j int) bool { return order[names[i]] < order[names[j]] })

	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s for %d piece(s), ~%d%% recoverable", n, counts[n], recovery[n]))
	}
	fmt.Fprintf(out, "  qr: error correction %s\n", strings.Join(parts, "; "))
	if weakest {
		fmt.Fprintln(out, "  qr: pieces are near capacity and use the weakest correction; print at high quality")
	}
	// A large symbol has small modules, which a photograph may not resolve. Say so
	// while the user can still choose more, smaller pieces.
	if largest > pieceio.QRPhotoFriendlyBytes {
		fmt.Fprintf(out, "  qr: pieces are %d bytes; a code over %d needs a flat, sharp photo\n",
			largest, pieceio.QRPhotoFriendlyBytes)
	}
}

// verifySplit re-reads K pieces from disk and reconstructs, confirming the result
// matches the original. When a recipient private key is missing the payload cannot
// be decrypted, so it verifies as far as it can instead.
func verifySplit(out io.Writer, input []byte, paths []string, plan *splitPlan) error {
	k := plan.opts.K
	if len(paths) < k {
		return fmt.Errorf("only %d pieces available to verify, need %d", len(paths), k)
	}
	reRead := make([][]byte, 0, k)
	for i := 0; i < k; i++ {
		piece, _, err := pieceio.Load(paths[i])
		if err != nil {
			return err
		}
		reRead = append(reRead, piece)
	}
	defer wipeAll(reRead)

	open := core.OpenOptions{
		Passwords:   plan.verifyPasswords,
		PrivateKeys: plan.privateKeys,
		Params:      &plan.opts.Params,
	}
	if !plan.opts.RecordAlgo {
		open.Schemes = plan.schemeIDs
	}

	recovered, err := core.Combine(reRead, open)
	if err != nil {
		if errors.Is(err, core.ErrKeyRequired) {
			// Every piece must still open and agree about the set.
			for _, piece := range reRead {
				if _, ierr := core.Info(piece, open); ierr != nil {
					return ierr
				}
			}
			fmt.Fprintln(out, "Verification: pieces open and are consistent (full decrypt needs the recipient key).")
			return nil
		}
		return err
	}
	defer memory.Zero(recovered)
	if !bytes.Equal(recovered, input) {
		return errors.New("reconstructed data does not match the original")
	}
	return nil
}

func printSplitSummary(out io.Writer, plan *splitPlan, formats []pieceio.Format, written map[pieceio.Format][]string, verified bool) {
	fmt.Fprintf(out, "\nDone. %d pieces written, any %d reconstruct the original.\n", plan.opts.N, plan.opts.K)

	if plan.opts.Keyless {
		fmt.Fprintln(out, "Mode: split only, no encryption and no password.")
		fmt.Fprintf(out, "Anyone holding any %d pieces can rebuild the file. Fewer reveal no content,\n", plan.opts.K)
		fmt.Fprintln(out, "but a piece's metadata is readable to anyone with this tool, and nothing")
		fmt.Fprintln(out, "authenticates the set. Add a password layer if either matters.")
	} else {
		fmt.Fprintln(out, "Layers (outer to inner):")
		for i, l := range plan.opts.Layers {
			algo := core.SchemeName(plan.schemeIDs[i])
			if l.Kind == core.RecipientLayer {
				fmt.Fprintf(out, "  %d. %-18s recipient key (%s)\n", i+1, algo, l.Recipient.Scheme().Name())
			} else {
				fmt.Fprintf(out, "  %d. %-18s password\n", i+1, algo)
			}
		}
		if plan.hasRecipient() {
			fmt.Fprintln(out, "Every recipient private key listed above is required to decrypt.")
		}
		if len(plan.verifyPasswords) > 0 {
			fmt.Fprintln(out, "Key derivation: "+plan.opts.Params.Describe())
		} else {
			fmt.Fprintln(out, "No password: the recipient private keys alone decrypt this.")
		}
		if !plan.opts.RecordAlgo {
			fmt.Fprintln(out, "Algorithms are NOT recorded: keep note of them, --algo is required to decrypt.")
		}
		if !plan.opts.RecordKDF && len(plan.verifyPasswords) > 0 {
			fmt.Fprintln(out, "Argon2 cost is NOT recorded: keep note of it, --kdf is required to decrypt.")
		}
	}

	printPaddingLine(out, plan)
	if plan.opts.Name != "" {
		fmt.Fprintf(out, "File name: %q is recorded inside the pieces, so combine restores it.\n", plan.opts.Name)
	}
	if verified {
		fmt.Fprintln(out, "Verification: PASSED (re-read pieces reconstruct the original).")
	} else {
		fmt.Fprintln(out, "Verification: SKIPPED (--no-verify); the pieces were not checked.")
	}
	for _, f := range formats {
		fmt.Fprintf(out, "Pieces (%s):\n", f)
		for _, p := range written[f] {
			fmt.Fprintln(out, "  "+p)
		}
	}
}

// printPaddingLine states what the piece size does and does not reveal. When a
// split has no password the manifest is sealed with the public keyless key, so
// the length is readable by anyone holding this tool and padding is skipped;
// saying so is better than leaving the user to assume the size is covered.
func printPaddingLine(out io.Writer, plan *splitPlan) {
	switch {
	case core.PaddingApplies(plan.opts):
		fmt.Fprintf(out, "Piece size: padded to a %d percent size class, so it gives only a range.\n",
			plan.opts.Padding.Width())
	case plan.opts.Padding.Off:
		fmt.Fprintln(out, "Piece size: not padded, so it reveals the length of the content.")
	default:
		fmt.Fprintln(out, "Piece size: not padded. Without a password the piece metadata is readable,")
		fmt.Fprintln(out, "so padding could not hide the content length anyway.")
	}
}

// reportGeneratedPasswords delivers a password Riven invented, which is the only
// way to recover the data.
//
// Under -y they are the only thing on standard output, one per line in layer
// order, so a script can capture them; interactive runs show a marked block.
// They are never written beside the pieces.
func reportGeneratedPasswords(opts *cliOptions, plan *splitPlan) error {
	if len(plan.generated) == 0 {
		return nil
	}

	if opts.yes {
		for _, pw := range plan.generated {
			if _, err := os.Stdout.Write(append(pw, '\n')); err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stderr,
			"riven: %d password(s) were generated and printed to standard output, one per line.\n",
			len(plan.generated))
		fmt.Fprintln(os.Stderr, "riven: they are stored nowhere else. Capture them now or the data is lost.")
		return nil
	}

	w := secretOut()
	fmt.Fprintln(w, "\n=== GENERATED PASSWORD(S) - THE ONLY WAY TO RECOVER THIS DATA ===")
	for i, pw := range plan.generated {
		fmt.Fprintf(w, "  %d: %s\n", i+1, string(pw))
	}
	fmt.Fprintln(w, "Write these down now. They are not stored anywhere.")
	return nil
}

// resolveOpenCredentials gathers everything an open needs from opts over the
// given pieces: the passwords, the KDF parameters and schemes, and the recipient
// private keys, assembled into a core.OpenOptions. The returned cleanup wipes the
// passwords; the caller still owns the pieces. It deliberately does not call
// noteExpensiveOpen, which each command places where its own output belongs.
func resolveOpenCredentials(opts *cliOptions, pieces [][]byte) (core.OpenOptions, func(), error) {
	pws, err := gatherOpenPasswords(opts, pieces)
	if err != nil {
		return core.OpenOptions{}, nil, err
	}
	params, schemes, err := resolveOpenParams(opts)
	if err != nil {
		wipeAll(pws)
		return core.OpenOptions{}, nil, err
	}
	keys, err := resolveOpenKeys(opts)
	if err != nil {
		wipeAll(pws)
		return core.OpenOptions{}, nil, err
	}
	open := core.OpenOptions{Passwords: pws, PrivateKeys: keys, Params: params, Schemes: schemes}
	return open, func() { wipeAll(pws) }, nil
}

func cmdInfo(opts *cliOptions) error {
	if err := validateOpenOptions(opts); err != nil {
		return err
	}
	if len(opts.files) == 0 {
		return errors.New("info needs at least one piece: riven info PIECE...")
	}

	// Load first, so a keyless set can be recognised before asking anything.
	items, err := loadInputs(msgWriter(opts), opts.files, false)
	if err != nil {
		return err
	}
	raw := pieceBytes(items)
	defer wipeAll(raw)

	open, wipe, err := resolveOpenCredentials(opts, raw)
	if err != nil {
		return err
	}
	defer wipe()

	seen := map[string][]int{}
	for _, it := range items {
		noteExpensiveOpen([][]byte{it.bytes}, open.Params)
		info, err := core.Info(it.bytes, open)
		if err != nil {
			retried, rerr := retryWithKDF(opts, it.bytes, open, err)
			if rerr != nil || retried == nil {
				fmt.Printf("%q: cannot open (%v)\n", it.det.Path, err)
				continue
			}
			info = retried
		}
		printPieceInfo(it.det.Path, it.det, info)
		seen[info.SetID] = append(seen[info.SetID], info.Serial)
	}
	if len(items) > 1 && len(seen) > 0 {
		fmt.Println("\nGrouping:")
		for set, serials := range seen {
			fmt.Printf("  set %s...: pieces %v\n", set[:16], serials)
		}
	}
	return nil
}

// retryWithKDF gives an interactive user one chance to supply cost parameters
// that the piece did not record.
func retryWithKDF(opts *cliOptions, piece []byte, open core.OpenOptions, cause error) (*core.PieceInfo, error) {
	if open.Params != nil || !errors.Is(cause, format.ErrWrongPassword) {
		return nil, nil
	}
	p, err := askMissingKDF(opts)
	if err != nil || p == nil {
		return nil, err
	}
	open.Params = p
	return core.Info(piece, open)
}

func printPieceInfo(path string, det pieceio.Detected, info *core.PieceInfo) {
	fmt.Printf("\n%s\n", path)
	fmt.Printf("  input form : %s\n", det.Format)
	fmt.Printf("  set id     : %s\n", info.SetID)
	fmt.Printf("  piece      : %d of %d (need any %d to reconstruct)\n", info.Serial, info.N, info.K)
	if info.CreatorVersion != "" {
		fmt.Printf("  created by : riven %s (%s)\n", info.CreatorVersion, info.CreatorCommit)
	}
	fmt.Printf("  intact     : %t\n", info.Intact)

	payloadKind := "encrypted payload"
	if !info.Encrypted {
		payloadKind = "payload"
	}
	fmt.Printf("  content    : %d bytes (%s)\n", info.PayloadLen, payloadKind)
	fmt.Printf("  payload id : %s...\n", info.PayloadHashHex[:16])
	if info.Name != "" {
		fmt.Printf("  file name  : %s\n", info.Name)
	}

	switch {
	case !info.Encrypted:
		fmt.Printf("  encryption : none, and no password (any %d pieces rebuild it)\n", info.K)
	case info.AlgoStored:
		fmt.Printf("  layers     : %s\n", strings.Join(info.Algorithms, ", "))
	default:
		fmt.Printf("  layers     : %d, algorithms not recorded\n", info.LayerCount)
	}
	if info.Encrypted && info.Keyless {
		fmt.Printf("  password   : none; a recipient private key is required\n")
	}
	if info.Encrypted && !info.Keyless {
		if info.KDFStored {
			fmt.Printf("  kdf        : %s\n", info.Params.Describe())
		} else {
			fmt.Printf("  kdf        : %s (not recorded; supplied)\n", info.Params.Describe())
		}
	}
	if info.Hybrid {
		fmt.Printf("  recipients : %d layer(s) need a private key\n", info.KEMLayers)
	}
}

func cmdCombine(opts *cliOptions) error {
	if err := validateOpenOptions(opts); err != nil {
		return err
	}
	if len(opts.files) == 0 {
		return errors.New("combine needs pieces: riven combine PIECE...")
	}
	items, err := loadInputs(msgWriter(opts), opts.files, true)
	if err != nil {
		return err
	}
	for _, it := range items {
		if isInteractive() && !opts.yes {
			fmt.Printf("  read %q as %s\n", filepath.Base(it.det.Path), it.det.Format)
		}
		warnUnverified(msgWriter(opts), it.det)
	}
	pieces := pieceBytes(items)
	defer wipeAll(pieces)

	open, wipe, err := resolveOpenCredentials(opts, pieces)
	if err != nil {
		return err
	}
	defer wipe()

	noteExpensiveOpen(pieces, open.Params)
	recovered, name, err := combineWithRecovery(opts, pieces, open)
	if err != nil {
		return err
	}
	defer memory.Zero(recovered)

	return writeRecovered(opts, recovered, name)
}

// writeRecovered delivers the reconstructed bytes. In automation the default is
// standard output, byte for byte with nothing else mixed in, so the result can be
// piped into another program. Interactive runs write a file: the name the pieces
// recorded when there is one, otherwise a name the user is asked for.
func writeRecovered(opts *cliOptions, recovered []byte, name string) error {
	outPath := opts.outDir

	if outPath == "" {
		switch {
		case opts.yes || !isInteractive():
			outPath = "-"
		case name != "":
			// The name came out of the piece, so it was chosen by whoever wrote
			// it rather than typed here. Creating it unasked would let a piece
			// decide the file name, and a name that does not exist yet would not
			// even reach the overwrite prompt below. Offer it as the default of a
			// question instead.
			v, err := readLine("Write recovered data to", name)
			if err != nil {
				return err
			}
			outPath = v
		default:
			v, err := readLine("Write recovered data to", "riven-recovered.out")
			if err != nil {
				return err
			}
			outPath = v
		}
	}

	if outPath == "-" {
		if _, err := os.Stdout.Write(recovered); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "riven: recovered %d bytes\n", len(recovered))
		return nil
	}

	if err := confirmOverwrite(opts, outPath); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, recovered, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(msgWriter(opts), "Recovered %d bytes -> %s\n", len(recovered), outPath)
	return nil
}

// refuseKeyOverwrite stops a keygen from replacing an existing key file.
//
// Losing a private key loses everything sealed to it, and the default base name
// means a second `riven keygen` aims straight at the first one's files. So this
// asks when it can and fails when it cannot, rather than assuming consent the
// way confirmOverwrite does: -y is documented as failing instead of asking, and
// this is the case where that matters most.
func refuseKeyOverwrite(opts *cliOptions, path string) error {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	if opts.yes || !isInteractive() {
		return fmt.Errorf("%s already exists; refusing to overwrite a key file. "+
			"Name another with --pub/--priv or -o, or remove it first", path)
	}
	ok, err := confirm(fmt.Sprintf("%s already exists. Replace it? Anything sealed to the old key becomes unrecoverable.", path), false)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not overwriting the key file")
	}
	return nil
}

// confirmOverwrite asks before replacing a file. It matters most for the name a
// piece recorded, which is chosen without the user typing it.
func confirmOverwrite(opts *cliOptions, path string) error {
	if opts.yes || !isInteractive() {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	ok, err := confirm(fmt.Sprintf("%s already exists. Overwrite it?", path), false)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not overwriting; use --out to name another file")
	}
	return nil
}

// combineWithRecovery attempts reconstruction and, when a set omitted its
// algorithms or cost, asks for them (interactive) or explains the flag (not). It
// returns the recovered bytes and the file name the pieces recorded, if any.
func combineWithRecovery(opts *cliOptions, pieces [][]byte, open core.OpenOptions) ([]byte, string, error) {
	out, name, err := core.CombineFile(pieces, open)
	if err == nil {
		return out, name, nil
	}

	if errors.Is(err, core.ErrSchemesRequired) {
		layers, lerr := layerCount(pieces, open)
		if lerr != nil {
			return nil, "", err
		}
		ids, aerr := askMissingAlgos(opts, layers)
		if aerr != nil {
			return nil, "", aerr
		}
		open.Schemes = ids
		return core.CombineFile(pieces, open)
	}

	// Only a failure to open a piece can be explained by unrecorded cost
	// parameters. Threshold and consistency errors must not send the user there.
	if open.Params == nil && errors.Is(err, format.ErrWrongPassword) {
		p, kerr := askMissingKDF(opts)
		if kerr == nil && p != nil {
			open.Params = p
			if out2, name2, err2 := core.CombineFile(pieces, open); err2 == nil {
				return out2, name2, nil
			}
		}
	}
	return nil, "", err
}

// layerCount reads the cascade layer count from the first piece that opens.
func layerCount(pieces [][]byte, open core.OpenOptions) (int, error) {
	for _, p := range pieces {
		if info, err := core.Info(p, open); err == nil {
			return info.LayerCount, nil
		}
	}
	return 0, errors.New("no piece could be opened")
}

func cmdKeygen(opts *cliOptions) error {
	if err := validateKeygenOptions(opts); err != nil {
		return err
	}
	scheme, err := resolveKeyScheme(opts)
	if err != nil {
		return err
	}
	priv, err := kem.Generate(scheme)
	if err != nil {
		return err
	}
	pubPath, privPath := opts.pubOut, opts.privOut
	if pubPath == "" || privPath == "" {
		base := "riven-key"
		if isInteractive() && !opts.yes {
			base, err = readLine("Key file base name", base)
			if err != nil {
				return err
			}
		}
		pubPath, privPath = keyPaths(opts.outDir, base, pubPath, privPath)
	}
	// Create the directory each file lands in, however that path was arrived at,
	// so naming a path under a directory that does not exist yet works the same
	// whether it came from --out or from --pub/--priv.
	for _, p := range []string{pubPath, privPath} {
		if err := ensureDir(filepath.Dir(p)); err != nil {
			return err
		}
	}
	// Overwriting a private key destroys access to everything sealed to it, and
	// the default base name means a second keygen aims at the first one's files.
	for _, p := range []string{pubPath, privPath} {
		if err := refuseKeyOverwrite(opts, p); err != nil {
			return err
		}
	}
	if err := writePublicKey(pubPath, priv.Public()); err != nil {
		return err
	}
	if err := writePrivateKey(privPath, priv); err != nil {
		return err
	}
	out := msgWriter(opts)
	fmt.Fprintf(out, "Wrote %s keys:\n  %s  (public - share with senders)\n  %s  (private - keep secret)\n",
		scheme.Name(), pubPath, privPath)
	fmt.Fprintf(out, "Each piece sent to this key carries %d extra bytes.\n", scheme.CiphertextSize())
	if !scheme.PostQuantum() {
		fmt.Fprintln(out, "Note: this key type is not post-quantum. It is for compatibility and small pieces.")
	}
	return nil
}

func cmdMenu(opts *cliOptions) error {
	if !isInteractive() {
		printUsage()
		return nil
	}
	fmt.Println("riven " + Version())
	fmt.Println("1) Split a file into pieces")
	fmt.Println("2) Split a piece of text into pieces")
	fmt.Println("3) Inspect a piece")
	fmt.Println("4) Reconstruct from pieces")
	fmt.Println("5) Generate a post-quantum key pair")
	choice, err := readInt("Choose", 1, 1, 5)
	if err != nil {
		return err
	}
	switch choice {
	case 1:
		path, err := readLine("File to split", "")
		if err != nil {
			return err
		}
		if path == "" {
			return errors.New("no file given")
		}
		opts.files = []string{path}
		return cmdSplit(opts)
	case 2:
		// Read the text without echoing it: it is the secret being protected.
		text, err := readPasswordMasked("Text to split: ")
		if err != nil {
			return err
		}
		if len(text) == 0 {
			return errors.New("no text given")
		}
		opts.text = string(text)
		opts.textSet = true
		memory.Zero(text)
		return cmdSplit(opts)
	case 3:
		path, err := readLine("Piece file to inspect", "")
		if err != nil {
			return err
		}
		opts.files = []string{path}
		return cmdInfo(opts)
	case 4:
		fmt.Println("Enter piece paths separated by spaces:")
		line, err := readLine("Pieces", "")
		if err != nil {
			return err
		}
		opts.files = splitFields(line)
		return cmdCombine(opts)
	default:
		return cmdKeygen(opts)
	}
}

// looksKeyless reports whether the pieces open with no password at all. The check
// costs one hash, so it is safe to try before asking the user for anything.
func looksKeyless(pieces [][]byte) bool {
	if len(pieces) == 0 {
		return false
	}
	m, _, err := format.Decode(pieces[0], nil, nil)
	return err == nil && m.Keyless
}

// gatherOpenPasswords collects passwords for info and combine: from the
// environment in automation, otherwise prompting until an empty entry. A set with
// no password envelope short-circuits this entirely.
func gatherOpenPasswords(opts *cliOptions, pieces [][]byte) ([][]byte, error) {
	envs := opts.passwordEnvs()
	if len(envs) > 0 {
		var out [][]byte
		for _, name := range envs {
			pw, err := passwordFromEnv(name)
			if err != nil {
				return nil, err
			}
			out = append(out, pw)
		}
		return out, nil
	}
	if looksKeyless(pieces) {
		return nil, nil
	}
	if opts.yes || !isInteractive() {
		return nil, errors.New("no password given: set one with --password-env NAME")
	}
	fmt.Println("\nEnter the password for each layer, outermost first.")
	var pws [][]byte
	for i := 1; ; i++ {
		prompt := fmt.Sprintf("Layer %d password: ", i)
		if i > 1 {
			prompt = fmt.Sprintf("Layer %d password (press Enter if there are no more layers): ", i)
		}
		p, err := readPasswordMasked(prompt)
		if err != nil {
			return nil, err
		}
		if len(p) == 0 {
			break
		}
		pws = append(pws, p)
	}
	if len(pws) == 0 {
		return nil, errors.New("no password entered")
	}
	return pws, nil
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

func wipeAll(bufs [][]byte) {
	memory.FreeAll(bufs)
}

// costWarnThreshold is the declared memory size, in KiB, above which opening is
// slow enough to be worth announcing.
const costWarnThreshold = 256 * 1024

// noteExpensiveOpen warns when the pieces declare a costly derivation, so a slow
// open does not read as a hang. The cost is not authenticated, so it also flags a
// file of unknown origin asking for a lot of work.
func noteExpensiveOpen(pieces [][]byte, override *kdf.Params) {
	if !isInteractive() {
		return
	}
	worst := kdf.Params{}
	for _, p := range pieces {
		params := override
		if params == nil {
			peeked, ok := format.PeekParams(p)
			if !ok {
				continue
			}
			params = &peeked
		}
		if params.Memory > worst.Memory {
			worst = *params
		}
	}
	if worst.Memory >= costWarnThreshold {
		fmt.Printf("  these pieces ask for %s per piece, so this takes a moment.\n", worst.Describe())
	}
}

// splitFields splits an answer on spaces, tabs and commas, dropping empties, so
// "a,b", "a b" and "a, b" all read the same.
func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '	' || r == ',' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// warnUnverified reports text that did not carry a matching checksum. The piece
// may still open, so this is a warning rather than a refusal; when the open fails
// afterwards, this is the line that explains why.
func warnUnverified(out io.Writer, det pieceio.Detected) {
	if det.Verified {
		return
	}
	fmt.Fprintf(out, "  warning: %s carries no matching checksum, so the text may have been mistyped or damaged\n",
		filepath.Base(det.Path))
}
