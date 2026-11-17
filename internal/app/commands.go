// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/parallel"
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
	defer startProgress()()

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
	plan.opts.Progress = progress

	noteLargeSplit(out, len(input), plan.opts)

	if err := ensureDir(plan.outDir); err != nil {
		return err
	}

	written, formats, err := exportSplit(out, plan, opts, input, in.baseName)
	if err != nil {
		return err
	}

	verified := verifiedSkipped
	if opts.verify != verifyOff {
		if verified, err = verifySplit(opts.verify, input, written, formats, plan); err != nil {
			fmt.Fprintln(out)
			warn(out, "the pieces were written but failed the check after writing. Do not rely on them.")
			return err
		}
	}

	printSplitSummary(out, plan, formats, written, verified)
	return reportGeneratedPasswords(opts, plan)
}

// verifyMode is how thoroughly a split checks what it wrote.
type verifyMode uint8

const (
	verifyFull verifyMode = iota // every file and every piece: the default
	verifyFast                   // one rebuild, from the first K pieces of one format
	verifyOff
)

// verifyModes lists the modes in the order help and completion give them.
var verifyModes = []verifyMode{verifyFull, verifyFast, verifyOff}

func (m verifyMode) String() string {
	switch m {
	case verifyFast:
		return "fast"
	case verifyOff:
		return "off"
	}
	return "full"
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
		var buf []byte
		err := during("reading the input", os.Stdin, func() (err error) {
			buf, err = io.ReadAll(os.Stdin)
			return err
		})
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
		var buf []byte
		err = during("reading the input", nil, func() (err error) {
			buf, err = os.ReadFile(path)
			return err
		})
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
// Pieces are written as they are produced, several files at a time, and
// released once written, so the memory a split needs does not grow with the
// piece count. The export question needs the piece size, which core works out
// from the options, so it is settled before anything is encrypted: a form the
// pieces would not fit is refused before the work, not after the first piece.
func exportSplit(out io.Writer, plan *splitPlan, opts *cliOptions, input []byte, base string) (map[pieceio.Format][]string, []pieceio.Format, error) {
	width := len(strconv.Itoa(plan.opts.N))
	pieceName := func(serial int) string { return fmt.Sprintf("%s.%0*d", base, width, serial) }

	size, err := core.PieceLen(len(input), plan.opts)
	if err != nil {
		return nil, nil, err
	}
	formats, err := resolveFormats(opts, plan, size)
	if err == nil {
		err = confirmReplacePieces(opts, plan, formats, pieceName)
	}
	if err != nil {
		return nil, nil, err
	}
	w := newPieceWriter(plan, formats, pieceName, size, opts.verify == verifyFull)
	err = core.SplitTo(input, plan.opts, func(serial int, piece []byte) error {
		return w.add(serial, piece)
	})
	// The failure the split stopped on is whichever a writer had recorded when
	// the next piece was handed over. Another writer may have failed an earlier
	// piece since, and the earliest is the one reported, so the error is the same
	// whichever writer got there first.
	werr := w.wait()
	progress("", 0, 0)
	if werr != nil {
		err = werr
	}
	if err != nil {
		return nil, nil, err
	}

	plan.pieceSize, plan.pieceSums = w.size, w.sums
	return w.written, w.formats, nil
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
func reportSizeNotes(out io.Writer, formats []pieceio.Format, size, count int) {
	if size == 0 {
		return
	}
	wantSheet := slices.Contains(formats, pieceio.Sheet)
	if wantSheet || slices.Contains(formats, pieceio.QR) {
		reportQRLevel(out, size, count)
	}
	if wantSheet {
		if pages := pieceio.SheetPages(size); pages > 1 {
			summaryRow(out, "sheet", fmt.Sprintf("about %d printed pages per piece, %d in all",
				pages, pages*count))
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
func encodeOne(piece []byte, f pieceio.Format, plan *splitPlan, serial int) ([]byte, error) {
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

// reportQRLevel says which error correction the codes of count pieces of size
// bytes received. Every piece of a set is the same size, so they share a level.
func reportQRLevel(out io.Writer, size, count int) {
	name, recovery, weakest, ok := pieceio.QRLevelFor(size)
	if !ok {
		return
	}
	summaryRow(out, "qr", fmt.Sprintf("error correction %s for %d piece(s), ~%d%% recoverable", name, count, recovery))
	if weakest {
		warn(out, "the QR codes are near capacity and use the weakest correction; print them at high quality.")
	}
	// A large symbol has small modules, which a photograph may not resolve. Say so
	// while the user can still choose more, smaller pieces.
	if size > pieceio.QRPhotoFriendlyBytes {
		warn(out, fmt.Sprintf("the QR codes hold %d bytes each; a code over %d needs a flat, sharp photo "+
			"to scan.", size, pieceio.QRPhotoFriendlyBytes))
	}
}

// verifySplit checks the pieces a split wrote, as thoroughly as mode says, and
// returns how far that got.
//
// Fast rebuilds the original from the first K pieces of one format. Full reads
// back every file in every format, and the code on every sheet, against the
// piece it was written from, and rebuilds from the pieces of one format K at a
// time as they are read, the last ones with the first again, until every piece
// has been in a rebuild. A fault in one piece or one format then shows, not only
// one that spoils them all, and each file is read once, but for the few the last
// group borrows.
func verifySplit(mode verifyMode, input []byte, written map[pieceio.Format][]string, formats []pieceio.Format, plan *splitPlan) (string, error) {
	rebuilt := pieceio.Binary
	if len(written[rebuilt]) == 0 {
		rebuilt = formats[0]
	}
	paths := written[rebuilt]
	k := plan.opts.K
	if len(paths) < k {
		return "", fmt.Errorf("only %d pieces available to verify, need %d", len(paths), k)
	}
	// The rebuilds leave the line as it is when they end: see checkStep.
	defer checking("", 0, 0)
	if mode == verifyFast {
		return rebuildFrom(input, paths[:k], plan)
	}
	c := newGroupCheck(input, plan)
	err := readBack(written, formats, plan, func(f pieceio.Format, path string, piece []byte) error {
		if f != rebuilt {
			memory.Zero(piece)
			return nil
		}
		return c.add(path, piece)
	})
	if err == nil {
		err = c.finish(paths)
	}
	// A rebuild still running is of pieces read before anything that failed
	// since, so what it finds comes first.
	if rerr := c.wait(); rerr != nil {
		err = rerr
	}
	if err != nil {
		return "", err
	}
	if c.outcome == verifiedFast {
		return verifiedFull, nil
	}
	return c.outcome, nil
}

// groupCheck rebuilds from the pieces a full check reads, K at a time. The first
// rebuild decrypts and compares; the rest stop at the hash, which the first tied
// to the original. Those run alongside the reading, several at once when a group
// is few and small pieces: a group of two password pieces has a key derivation
// for each, and on its own would leave most of the cores idle. A group too large
// for the budget is rebuilt where it completes, as the first is, so the reading
// does not gather the next one meanwhile.
type groupCheck struct {
	input   []byte
	plan    *splitPlan
	pieces  [][]byte
	paths   []string
	outcome string

	slots        chan struct{} // a token for each rebuild that may run at once; nil for none
	running      sync.WaitGroup
	groups       int // groups started
	firstFailure     // by group
}

// newGroupCheck checks the pieces of plan's split. Where opening a piece derives
// a key, as many groups are rebuilt at once as share the derivations a combine
// would make of one group; where it derives none, as many as there are cores.
// Either way they stay within the budget for pieces in flight, which also holds
// the next group as the reading gathers it.
func newGroupCheck(input []byte, plan *splitPlan) *groupCheck {
	c := &groupCheck{input: input, plan: plan}
	k := plan.opts.K
	if fits := fileBudget/max(1, k*plan.pieceSize) - 1; fits > 0 {
		atOnce := parallel.Workers(fits)
		if core.EnvelopeDerives(plan.opts) {
			atOnce = core.DerivationsAtOnce(plan.opts.Params) / k
		}
		c.slots = make(chan struct{}, max(1, min(atOnce, fits)))
	}
	return c
}

// add takes the next piece read, and rebuilds once it completes a group.
func (c *groupCheck) add(path string, piece []byte) error {
	if err := c.failure(); err != nil || c.outcome == verifiedSealed {
		memory.Zero(piece)
		return err // none of the pieces can be opened here, when there is no error
	}
	c.pieces, c.paths = append(c.pieces, piece), append(c.paths, path)
	if len(c.pieces) < c.plan.opts.K {
		return nil
	}
	pieces, paths, group := c.pieces, c.paths, c.groups
	c.pieces, c.paths, c.groups = nil, nil, c.groups+1
	if c.outcome == "" || c.slots == nil {
		defer memory.FreeAll(pieces)
		got, err := rebuildPieces(c.input, pieces, c.plan, c.outcome != "", checkStep)
		if err != nil {
			return fmt.Errorf("rebuilding from %s: %w", fileNames(paths), err)
		}
		if c.outcome == "" {
			c.outcome = got
		}
		return nil
	}
	c.slots <- struct{}{}
	c.running.Add(1)
	go func() {
		defer memory.GuardPanic()
		defer func() {
			memory.FreeAll(pieces)
			<-c.slots
			c.running.Done()
		}()
		// The reading is what the line follows meanwhile, so these say nothing.
		if _, err := rebuildPieces(c.input, pieces, c.plan, true, nil); err != nil {
			c.fail(group, fmt.Errorf("rebuilding from %s: %w", fileNames(paths), err))
		}
	}()
	return nil
}

// finish completes the last group, when the pieces left over do not fill one,
// with the first pieces again, read from paths. They are read a second time, so
// they are held to the digest again, as the first reading was.
func (c *groupCheck) finish(paths []string) error {
	for i, path := range paths[:c.plan.opts.K] {
		if len(c.pieces) == 0 || c.outcome == verifiedSealed {
			return nil
		}
		piece, _, err := pieceio.Load(path)
		if err != nil {
			return err
		}
		if err := matchesPiece(path, [][]byte{piece}, c.plan.pieceSums[i]); err != nil {
			memory.Zero(piece)
			return err
		}
		if err := c.add(path, piece); err != nil {
			return err
		}
	}
	return nil
}

// wait lets the rebuilds under way finish, wipes the pieces of a group never
// completed, and returns the first group's failure.
func (c *groupCheck) wait() error {
	c.running.Wait()
	memory.FreeAll(c.pieces)
	c.pieces, c.paths = nil, nil
	return c.failure()
}

// readBack checks every file the split wrote holds the piece it was written
// from, byte for byte, and hands each piece read to each, in order, which owns
// it from then on and wipes it unless it keeps it. It needs no key, so it covers
// every format of every piece at little cost. The files are read and decoded
// several at a time, ahead of the one each is looking at.
func readBack(written map[pieceio.Format][]string, formats []pieceio.Format, plan *splitPlan,
	each func(f pieceio.Format, path string, piece []byte) error) error {
	type file struct {
		f     pieceio.Format
		piece int
		path  string
	}
	var files []file
	for _, f := range formats {
		for i, path := range written[f] {
			files = append(files, file{f, i, path})
		}
	}
	read := make([][][]byte, len(files))
	defer func() {
		for _, copies := range read {
			memory.FreeAll(copies)
		}
	}()
	reading := readingFile(checking, len(files))
	return parallel.Ordered(len(files), workersFor(int64(plan.pieceSize)), func(n int) error {
		file := files[n]
		copies, err := pieceio.LoadAll(file.path)
		if err != nil {
			return err
		}
		read[n] = copies
		return matchesPiece(file.path, copies, plan.pieceSums[file.piece])
	}, func(n int) error {
		reading(n)
		copies := read[n]
		read[n] = nil
		memory.FreeAll(copies[1:])
		return each(files[n].f, files[n].path, copies[0])
	}, reading)
}

// matchesPiece checks every copy of a piece read from path is the piece whose
// digest is sum. The second copy is a sheet's QR code.
func matchesPiece(path string, copies [][]byte, sum [sha256.Size]byte) error {
	for i, c := range copies {
		if sha256.Sum256(c) == sum {
			continue
		}
		if i > 0 {
			return fmt.Errorf("the QR code on %s does not read back as written", path)
		}
		return fmt.Errorf("%s does not read back as written", path)
	}
	return nil
}

// fileNames lists paths by their file names, for a message. More than a few are
// given as the first and the last, as pieceRange does: a group is as many files
// as the threshold, which can be thousands.
func fileNames(paths []string) string {
	names := make([]string, len(paths))
	for i, p := range paths {
		names[i] = filepath.Base(p)
	}
	const few = 4
	if len(names) > few {
		return fmt.Sprintf("%s (%d files)", pieceRange(names), len(names))
	}
	return strings.Join(names, ", ")
}

// rebuildFrom reads the pieces at paths back from disk and rebuilds the original
// from them, as rebuildPieces does.
func rebuildFrom(input []byte, paths []string, plan *splitPlan) (string, error) {
	reRead := make([][]byte, 0, len(paths))
	defer func() { memory.FreeAll(reRead) }()
	// verifySplit blanks the line when the check is over, however it ends.
	checking("reading pieces", 0, 0)
	for _, p := range paths {
		piece, _, err := pieceio.Load(p)
		if err != nil {
			return "", err
		}
		reRead = append(reRead, piece)
	}
	return rebuildPieces(input, reRead, plan, false, checkStep)
}

// rebuildPieces rebuilds the original from pieces read back, confirming it
// matches what was split. When a recipient private key is missing the payload
// cannot be decrypted, so it checks as far as it can. checkOnly stops at the
// hash the pieces carry, for a set already decrypted once. p is told its steps.
func rebuildPieces(input []byte, reRead [][]byte, plan *splitPlan, checkOnly bool, p core.Progress) (string, error) {
	if sealedWithoutKey(plan) {
		return verifiedSealed, nil
	}

	open := core.OpenOptions{
		Passwords:   plan.verifyPasswords,
		PrivateKeys: plan.privateKeys,
		Params:      &plan.opts.Params,
		Progress:    p,
		CheckOnly:   checkOnly,
	}
	if !plan.opts.RecordAlgo {
		open.Schemes = plan.schemeIDs
	}

	recovered, err := core.Combine(reRead, open)
	if checkOnly && err == nil {
		return verifiedFast, nil
	}
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
	return verifiedFast, nil
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
	verifiedFull    = "yes, every file reads back and every piece rebuilds the original"
	verifiedFast    = "yes, the pieces read back rebuild the original (fast check)"
	verifiedPartly  = "partly: the pieces open and agree; a full rebuild needs the private key"
	verifiedSealed  = "partly: the pieces read back; opening them needs the private key (--identity)"
	verifiedSkipped = "skipped (--verify off)"
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
	reportSizeNotes(out, formats, plan.pieceSize, plan.opts.N)
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

// serialRuns lists piece numbers in order, a run of consecutive ones as its ends,
// so a folder of thousands of pieces reads as "1-65535" rather than every number.
func serialRuns(serials []int) string {
	s := slices.Clone(serials)
	slices.Sort(s)
	s = slices.Compact(s)
	var runs []string
	for i := 0; i < len(s); {
		j := i
		for j+1 < len(s) && s[j+1] == s[j]+1 {
			j++
		}
		if j == i {
			runs = append(runs, strconv.Itoa(s[i]))
		} else {
			runs = append(runs, fmt.Sprintf("%d-%d", s[i], s[j]))
		}
		i = j + 1
	}
	return strings.Join(runs, ", ")
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
	defer startProgress()()
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

	open, wipe, err := resolveOpenCredentials(opts)
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
			fmt.Printf("  set %s...: pieces %s\n", set[:16], serialRuns(serials))
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
	defer startProgress()()
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
	// The pieces are held only here from now on, so that the combine can let
	// them go once they have opened.
	pieces := pieceBytes(items)
	for i := range items {
		items[i].bytes = nil
	}
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
		if opts.yes || !isInteractive() {
			outPath = "-"
		} else {
			// A name that came out of the piece was chosen by whoever wrote it
			// rather than typed here. Creating it unasked would let a piece
			// decide the file name, and a name that does not exist yet would not
			// even reach the overwrite prompt below. Offer it as the default of a
			// question instead.
			v, err := readLine("Write recovered data to", cmp.Or(name, "riven-recovered.out"))
			if err != nil {
				return err
			}
			outPath = v
		}
	}

	if outPath == "-" {
		err := during("writing the result", os.Stdout, func() error {
			_, err := os.Stdout.Write(recovered)
			return err
		})
		if err != nil {
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
	err := during("writing the result", nil, func() error { return pieceio.Write(outPath, recovered) })
	if err != nil {
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
	if !fileExists(path) {
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
	if opts.yes || !isInteractive() || !fileExists(path) {
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
	if err := writeKeyPair(opts, priv, pubPath, privPath); err != nil {
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
