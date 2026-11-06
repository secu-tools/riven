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
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
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
	defer memory.FreeAll(plan.verifyPasswords)
	plan.opts.Name = recordedName(opts, in.origName)
	plan.opts.CreatorVersion = creatorVersion()
	plan.opts.CreatorCommit = creatorCommit()

	noteLargeSplit(out, len(input), plan.opts)

	if err := ensureDir(plan.outDir); err != nil {
		return err
	}

	written, formats, err := exportSplit(out, plan, opts, input, in.baseName)
	if err != nil {
		return err
	}

	verified := verifiedSkipped
	if opts.verifyEnabled() {
		verifyPaths := written[pieceio.Binary]
		if len(verifyPaths) == 0 {
			verifyPaths = written[formats[0]]
		}
		if verified, err = verifySplit(input, verifyPaths, plan); err != nil {
			fmt.Fprintln(out)
			warn(out, "the pieces were written but did not rebuild the original. Do not rely on them.")
			return err
		}
	}

	printSplitSummary(out, plan, formats, written, verified)
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

	pieceName := func(serial int) string { return fmt.Sprintf("%s.%0*d", base, width, serial) }

	err := core.SplitTo(input, plan.opts, func(serial int, piece []byte) error {
		if formats == nil {
			chosen, ferr := resolveFormats(opts, plan, len(piece))
			if ferr != nil {
				return ferr
			}
			if ferr := confirmReplacePieces(opts, plan, chosen, pieceName); ferr != nil {
				return ferr
			}
			formats = chosen
		}
		sizes = append(sizes, len(piece))

		name := pieceName(serial)
		for _, f := range formats {
			path := pieceio.Path(plan.outDir, name, f)
			data, _, err := encodeOne(piece, f, plan, serial)
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

	plan.pieceSizes = sizes
	return written, formats, nil
}

// confirmReplacePieces asks before a split writes over files that have the
// names its pieces take. They are most likely an earlier set's pieces, and
// replacing some of them destroys that set. Like confirmOverwrite, a run that
// cannot ask goes ahead: a script that names where its pieces go means it.
func confirmReplacePieces(opts *cliOptions, plan *splitPlan, formats []pieceio.Format, pieceName func(int) string) error {
	if opts.yes || !isInteractive() {
		return nil
	}
	var existing []string
	for serial := 1; serial <= plan.opts.N; serial++ {
		for _, f := range formats {
			if p := pieceio.Path(plan.outDir, pieceName(serial), f); fileExists(p) {
				existing = append(existing, p)
			}
		}
	}
	if len(existing) == 0 {
		return nil
	}
	ok, err := confirm(fmt.Sprintf("%d file(s) already have these names, such as %q. "+
		"Replacing them destroys that set. Replace them?", len(existing), existing[0]), false)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not replacing existing files; use --out or --name to write the pieces elsewhere")
	}
	return nil
}

// fileExists reports whether anything is at path.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// reportSizeNotes says what the chosen formats cost at the size the pieces came
// out. Both QR and sheet carry a code, but the report is about the pieces rather
// than the formats, so it is made once.
func reportSizeNotes(out io.Writer, formats []pieceio.Format, sizes []int) {
	if len(sizes) == 0 {
		return
	}
	wantSheet := slices.Contains(formats, pieceio.Sheet)
	if wantSheet || slices.Contains(formats, pieceio.QR) {
		reportQRSizes(out, sizes)
	}
	if wantSheet {
		if pages := pieceio.SheetPages(sizes[0]); pages > 1 {
			summaryRow(out, "sheet", fmt.Sprintf("about %d printed pages per piece, %d in all",
				pages, pages*len(sizes)))
		}
	}
}

// noteLargeSplit warns before a split that will need a lot of memory. With the
// full method the shares are N copies of the input, which is not obvious from the
// file size.
func noteLargeSplit(out io.Writer, inputLen int, opts core.SplitOptions) {
	const quiet = 64 << 20
	if inputLen < quiet {
		return
	}
	writeWrapped(out, "", fmt.Sprintf("Splitting %d MiB into %d pieces, which needs about %d MiB of memory...",
		inputLen>>20, opts.N, core.MemoryEstimate(inputLen, opts.N, opts.K, opts.Method)>>20))
}

// encodeOne renders one piece in one format. A recovery sheet needs to say which
// piece it is, so it takes the extra arguments the other formats do not. It
// names the file only when the pieces record it: a sheet is printed and left
// where others can read it, so --record-name false and --info none must reach
// it too.
func encodeOne(piece []byte, f pieceio.Format, plan *splitPlan, serial int) ([]byte, string, error) {
	if f == pieceio.Sheet {
		// A set that hides its details must not print them either.
		info, _ := core.EffectiveInfo(plan.opts)
		return pieceio.EncodeSheet(piece, pieceio.SheetInfo{
			Serial: serial, Total: plan.opts.N, Needed: plan.opts.K, Name: plan.opts.Name,
			Hidden: info == core.InfoHidden,
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
	summaryRow(out, "qr", "error correction "+strings.Join(parts, "; "))
	if weakest {
		warn(out, "the QR codes are near capacity and use the weakest correction; print them at high quality.")
	}
	// A large symbol has small modules, which a photograph may not resolve. Say so
	// while the user can still choose more, smaller pieces.
	if largest > pieceio.QRPhotoFriendlyBytes {
		warn(out, fmt.Sprintf("the QR codes hold %d bytes each; a code over %d needs a flat, sharp photo "+
			"to scan.", largest, pieceio.QRPhotoFriendlyBytes))
	}
}

// verifySplit re-reads K pieces from disk and reconstructs, confirming the result
// matches the original, and returns how far that got. When a recipient private
// key is missing the payload cannot be decrypted, so it verifies as far as it
// can instead.
func verifySplit(input []byte, paths []string, plan *splitPlan) (string, error) {
	k := plan.opts.K
	if len(paths) < k {
		return "", fmt.Errorf("only %d pieces available to verify, need %d", len(paths), k)
	}
	reRead := make([][]byte, 0, k)
	for i := 0; i < k; i++ {
		piece, _, err := pieceio.Load(paths[i])
		if err != nil {
			return "", err
		}
		reRead = append(reRead, piece)
	}
	defer memory.FreeAll(reRead)
	if sealedWithoutKey(plan) {
		return verifiedSealed, nil
	}

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
		// The key is asked for only after the K pieces have all opened, agreed
		// about the set and rebuilt to the recorded hash, so that much is checked.
		if errors.Is(err, core.ErrKeyRequired) {
			return verifiedPartly, nil
		}
		return "", err
	}
	defer memory.Zero(recovered)
	if !bytes.Equal(recovered, input) {
		return "", errors.New("reconstructed data does not match the original")
	}
	return verifiedYes, nil
}

// sealedWithoutKey reports a set whose pieces open only with a private key the
// split was not given with --identity, so they can be read back but not opened.
func sealedWithoutKey(plan *splitPlan) bool {
	recipients, err := core.EnvelopeRecipients(plan.opts)
	if err != nil {
		return false
	}
	have := make(map[string]bool, len(plan.privateKeys))
	for _, k := range plan.privateKeys {
		have[string(k.Public().Bytes())] = true
	}
	for _, r := range recipients {
		if !have[string(r.Bytes())] {
			return true
		}
	}
	return false
}

// Verification outcomes, as the summary states them.
const (
	verifiedYes     = "yes, the pieces read back rebuild the original"
	verifiedPartly  = "partly: the pieces open and agree; a full rebuild needs the private key"
	verifiedSealed  = "partly: the pieces read back; opening them needs the private key (--identity)"
	verifiedSkipped = "skipped (--no-verify)"
)

// printSplitSummary reports a finished split in a few aligned lines: what
// protects it, how it was spread, what one piece shows, whether it was checked,
// and where the pieces are. Anything that needs the user's attention follows as a
// warning; docs/usage.md explains each choice at length.
func printSplitSummary(out io.Writer, plan *splitPlan, formats []pieceio.Format, written map[pieceio.Format][]string, verified string) {
	fmt.Fprintln(out)
	what := fmt.Sprintf("%d pieces written, any %d rebuild the original", plan.opts.N, plan.opts.K)
	if plan.opts.Name != "" {
		what = fmt.Sprintf("%d pieces of %q written, any %d rebuild it", plan.opts.N, plan.opts.Name, plan.opts.K)
	}
	writeLabeled(out, "Done:", toneGood, what)
	row := func(label, value string) { summaryRow(out, label, value) }
	row("layers", layerSummary(plan))
	row("method", methodSummary(plan))
	if s := infoSummary(plan); s != "" {
		row("details", s)
	}
	if plan.opts.Padding.Off {
		row("size", "not padded, so the piece size gives the content length away")
	}
	row("verified", verified)
	for i, f := range formats {
		label := ""
		if i == 0 {
			label = "pieces"
		}
		row(label, pieceRange(written[f])+" ("+f.String()+")")
	}
	reportSizeNotes(out, formats, plan.pieceSizes)
	splitWarnings(out, plan)
}

// summaryRow prints one aligned line of a report: a short label and its value,
// folded under the value rather than the label.
func summaryRow(out io.Writer, label, value string) {
	writeWrapped(out, fmt.Sprintf("  %-9s ", label), value)
}

// layerSummary lists the layers outermost first, or says there are none.
func layerSummary(plan *splitPlan) string {
	if plan.opts.Keyless {
		return "none: no password"
	}
	parts := make([]string, len(plan.opts.Layers))
	for i, l := range plan.opts.Layers {
		algo := ciphers.Name(plan.schemeIDs[i])
		if l.Kind == core.RecipientLayer {
			parts[i] = fmt.Sprintf("%s recipient key (%s)", l.Recipient.Scheme().Name(), algo)
		} else {
			parts[i] = "password (" + algo + ")"
		}
	}
	s := strings.Join(parts, ", ")
	if plan.hasRecipient() {
		s += "; every private key is needed to rebuild"
	}
	return s
}

// methodSummary says how the content was spread and what keeps fewer than K
// pieces from revealing it: a proof for the full method, the ciphers for the
// compact one. At a threshold of one there is no such promise to make.
func methodSummary(plan *splitPlan) string {
	k := plan.opts.K
	if plan.opts.Method == core.MethodCompact {
		if k == 1 {
			return "compact; any one piece rebuilds it"
		}
		return fmt.Sprintf("compact: pieces 1/%d of the file; fewer than %d are safe while "+
			"AES-256 and ChaCha20 hold", k, k)
	}
	if k == 1 {
		return "full; any one piece rebuilds it"
	}
	return fmt.Sprintf("full: fewer than %d pieces reveal nothing, proven", k)
}

// infoSummary says what one piece shows, and whether one piece is enough to try
// passwords against.
func infoSummary(plan *splitPlan) string {
	mode, err := core.EffectiveInfo(plan.opts)
	if err != nil {
		return ""
	}
	guess := ""
	if len(plan.verifyPasswords) > 0 {
		guess = fmt.Sprintf("; trying passwords needs %d pieces", plan.opts.K)
	}
	switch mode {
	case core.InfoProtected:
		first, isPassword := plan.firstSecret()
		if isPassword {
			return "readable with " + first + "; one piece can test guesses"
		}
		return "readable with " + first
	case core.InfoStrict:
		if g := plan.strictGuessing(); g != "" {
			return "readable with " + plan.secrets() + "; " + g
		}
		return "readable with " + plan.secrets()
	case core.InfoPublic:
		return "readable by anyone with riven" + guess
	default:
		return "hidden: one piece shows nothing" + guess
	}
}

// pieceRange names the first and last piece of a set, which says where all of
// them are without a line each.
func pieceRange(paths []string) string {
	switch len(paths) {
	case 0:
		return ""
	case 1:
		return paths[0]
	}
	return paths[0] + " ... " + paths[len(paths)-1]
}

// splitWarnings states what the user has to act on or keep in mind: anything
// left out of the pieces that rebuilding will ask for, and a set no password
// protects.
func splitWarnings(out io.Writer, plan *splitPlan) {
	if plan.opts.Keyless {
		warn(out, fmt.Sprintf("no password: anyone with %d pieces can rebuild the file, "+
			"and nothing proves a piece is genuine.", plan.opts.K))
	}
	if !plan.opts.RecordAlgo && len(plan.schemeIDs) > 0 {
		names := make([]string, len(plan.schemeIDs))
		for i, id := range plan.schemeIDs {
			names[i] = ciphers.Name(id)
		}
		warn(out, "the algorithms are not recorded. Keep a note: rebuilding needs --algo "+
			strings.Join(names, ","))
	}
	if !plan.opts.RecordKDF && len(plan.verifyPasswords) > 0 {
		warn(out, "the Argon2id cost is not recorded. Keep a note: rebuilding needs --kdf "+
			plan.opts.Params.String())
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
		warn(os.Stderr, fmt.Sprintf("%d generated password(s) went to standard output, one per line. "+
			"They are stored nowhere else: capture them now, or the data is lost.", len(plan.generated)))
		return nil
	}

	w := secretOut()
	fmt.Fprintln(w)
	writeLabeled(w, "GENERATED PASSWORD(S):", toneWarning, "the only way to recover this data. "+
		"Write them down now; they are stored nowhere.")
	for i, pw := range plan.generated {
		fmt.Fprintf(w, "  layer %d: %s\n", i+1, string(pw))
	}
	return nil
}

func cmdInfo(opts *cliOptions) error {
	if err := validateOpenOptions(opts); err != nil {
		return err
	}
	if len(opts.files) == 0 {
		return errors.New("info needs a piece: a piece file, or a folder of pieces")
	}

	items, err := loadInputs(msgWriter(opts), opts.files, false)
	if err != nil {
		return err
	}
	raw := pieceBytes(items)
	defer memory.FreeAll(raw)

	open, wipe, err := resolveOpenCredentials(opts, raw)
	if err != nil {
		return err
	}
	defer wipe()

	seen := map[string][]int{}
	for _, it := range items {
		info, err := core.Info(it.bytes, open)
		if err != nil {
			fmt.Println()
			writeLabeled(os.Stdout, "error:", toneError, pieceFailure(it.det.Path, err))
			continue
		}
		printPieceInfo(it.det.Path, it.det, info)
		seen[info.SetID] = append(seen[info.SetID], info.Serial)
	}
	if len(items) > 1 && len(seen) > 0 {
		fmt.Println("\nGrouping:")
		for set, serials := range seen {
			// A piece with hidden details has no serial to show.
			if serials[0] == 0 {
				fmt.Printf("  set %s...: %d piece(s), details hidden\n", set[:16], len(serials))
				continue
			}
			fmt.Printf("  set %s...: pieces %v\n", set[:16], serials)
		}
	}
	// Each failure was printed beside its piece; the exit status still has to
	// say that nothing could be read, so a script can tell.
	if len(seen) == 0 {
		return errors.New("no piece could be opened; check the password, the key and the files")
	}
	return nil
}

func printPieceInfo(path string, det pieceio.Detected, info *core.PieceInfo) {
	fmt.Printf("\n%q\n", path)
	fmt.Printf("  input form : %s\n", det.Format)
	fmt.Printf("  set id     : %s\n", info.SetID)
	if info.Hidden {
		fmt.Printf("  intact     : %t\n", info.Intact)
		fmt.Printf("  details    : hidden until the set is combined (--info none)\n")
		return
	}
	fmt.Printf("  piece      : %d of %d (need any %d to reconstruct)\n", info.Serial, info.N, info.K)
	if info.CreatorVersion != "" {
		fmt.Printf("  created by : riven %s (%s)\n", info.CreatorVersion, info.CreatorCommit)
	}
	fmt.Printf("  intact     : %t\n", info.Intact)
	if info.Compact {
		fmt.Printf("  method     : compact (this piece holds 1/%d of it)\n", info.K)
	} else {
		fmt.Printf("  method     : full (this piece holds a share of all of it)\n")
	}
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
	switch {
	case info.Encrypted && info.PasswordLayers() == 0:
		fmt.Printf("  password   : none; a recipient private key is required\n")
	case info.Encrypted && info.Keyless:
		fmt.Printf("  password   : %d needed to combine; these details need none (--info public)\n", info.PasswordLayers())
	}
	switch {
	case info.PasswordLayers() == 0:
	case info.KDFStored:
		fmt.Printf("  kdf        : %s\n", info.Params.Describe())
	case info.Params != (kdf.Params{}):
		fmt.Printf("  kdf        : %s (not recorded; supplied)\n", info.Params.Describe())
	default:
		fmt.Printf("  kdf        : not recorded; give it with --kdf to combine\n")
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
		return errors.New("combine needs pieces: the piece files, or a folder of them")
	}
	items, err := loadInputs(msgWriter(opts), opts.files, true)
	if err != nil {
		return err
	}
	if isInteractive() && !opts.yes {
		fmt.Println(readSummary(items))
	}
	for _, it := range items {
		warnUnverified(msgWriter(opts), it.det)
	}
	pieces := pieceBytes(items)
	defer memory.FreeAll(pieces)

	recovered, name, err := combinePieces(opts, pieces, func(i int, _ error) {
		warn(msgWriter(opts), fmt.Sprintf("%q is damaged: it did not open although other pieces did. "+
			"Rebuilding from the rest.", items[i].det.Path))
	})
	if err != nil {
		return namePiece(err, itemPaths(items))
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
		writeLabeled(os.Stderr, "Done:", toneGood, fmt.Sprintf("%d bytes written to standard output", len(recovered)))
		return nil
	}

	if err := confirmOverwrite(opts, outPath); err != nil {
		return err
	}
	// The recovered data is the secret itself, so it gets the same treatment as a
	// private key: private even when it replaces an existing, readable file.
	if err := pieceio.Write(outPath, recovered); err != nil {
		return err
	}
	writeLabeled(msgWriter(opts), "Done:", toneGood, fmt.Sprintf("%d bytes written to %s", len(recovered), outPath))
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
	// The encapsulated key rides once for the layer, and once more when the
	// envelope that keeps the details is sealed to the key as well.
	writeLabeled(out, "Done:", toneGood, fmt.Sprintf("%s key pair written; a piece sealed to it grows by "+
		"%d bytes (%d when the details are too)", scheme.Name(), scheme.CiphertextSize(), 2*scheme.CiphertextSize()))
	fmt.Fprintf(out, "  public   %s  (give to whoever splits for you)\n", pubPath)
	fmt.Fprintf(out, "  private  %s  (keep secret: it opens the pieces)\n", privPath)
	if !scheme.PostQuantum() {
		warn(out, "this key type is not post-quantum; it is for existing keys and small pieces.")
	}
	return nil
}

func cmdMenu(opts *cliOptions) error {
	if !isInteractive() {
		printUsage()
		return nil
	}
	heading(os.Stdout, "riven "+Version())
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
		line, err := readLine("Pieces (paths separated by spaces)", "")
		if err != nil {
			return err
		}
		opts.files = splitFields(line)
		return cmdCombine(opts)
	default:
		return cmdKeygen(opts)
	}
}

// splitFields splits an answer on spaces, tabs and commas, dropping empties, so
// "a,b", "a b" and "a, b" all read the same.
func splitFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
}

// warnUnverified reports text that did not carry a matching checksum. The piece
// may still open, so this is a warning rather than a refusal; when the open fails
// afterwards, this is the line that explains why.
func warnUnverified(out io.Writer, det pieceio.Detected) {
	if det.Verified {
		return
	}
	warn(out, fmt.Sprintf("%q has no matching checksum, so the text may be mistyped or damaged.",
		filepath.Base(det.Path)))
}

// readSummary says how many pieces were read and in which forms, in one line
// rather than one per piece.
func readSummary(items []heldPiece) string {
	var forms []string
	for _, it := range items {
		if f := it.det.Format.String(); !slices.Contains(forms, f) {
			forms = append(forms, f)
		}
	}
	return fmt.Sprintf("Read %d piece(s): %s.", len(items), strings.Join(forms, ", "))
}

// itemPaths is the path of each piece read, in order.
func itemPaths(items []heldPiece) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.det.Path
	}
	return out
}
