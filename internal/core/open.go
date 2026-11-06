// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/secu-tools/riven/internal/cascade"
	"github.com/secu-tools/riven/internal/compact"
	"github.com/secu-tools/riven/internal/disperse"
	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/parallel"
	"github.com/secu-tools/riven/internal/split"
)

// ErrParamsRequired indicates a set whose envelopes take no password did not
// record the Argon2 cost its password layers need, and none was supplied.
var ErrParamsRequired = errors.New("core: the Argon2 cost was not recorded and none was supplied")

// ErrTooFewPieces indicates the pieces given are not enough to rebuild the set.
var ErrTooFewPieces = errors.New("core: not enough pieces")

// errIntegrity is a rebuild that does not match what the set recorded.
var errIntegrity = errors.New("core: reconstruction failed integrity check (wrong or corrupt pieces)")

// SchemesRequiredError is ErrSchemesRequired with the number of layers that need
// an algorithm, which a set with hidden details only reveals once rebuilt.
type SchemesRequiredError struct{ Layers int }

func (e *SchemesRequiredError) Error() string {
	return fmt.Sprintf("%v (%d layer(s))", ErrSchemesRequired, e.Layers)
}

func (e *SchemesRequiredError) Unwrap() error { return ErrSchemesRequired }

// PieceError is a problem with one of the pieces given, by its position among
// them counted from 1, so a caller that knows the files can name the one meant.
// Err says what happened, phrased to follow the piece: "did not open: ...".
type PieceError struct {
	Piece int
	Err   error
}

func (e *PieceError) Error() string { return fmt.Sprintf("core: piece %d %v", e.Piece, e.Err) }

func (e *PieceError) Unwrap() error { return e.Err }

// damaged is a piece that did not open although another did. The reason it
// failed is kept for errors.Is but left out of the message: among pieces that
// opened, "wrong password" is not the explanation, damage is.
type damaged struct{ cause error }

func (e damaged) Error() string {
	return "did not open although other pieces did, so the file is damaged"
}

func (e damaged) Unwrap() error { return e.cause }

// tooFew is an ErrTooFewPieces with a message of its own.
type tooFew string

func (e tooFew) Error() string        { return string(e) }
func (e tooFew) Is(target error) bool { return target == ErrTooFewPieces }

// PieceInfo is the human-readable description of a single piece.
type PieceInfo struct {
	SetID          string
	Serial, K, N   int
	Encrypted      bool
	Hybrid         bool
	AlgoStored     bool
	KDFStored      bool
	Keyless        bool // the envelope takes no password
	SealedToKeys   bool // the envelope takes the recipient keys too
	Compact        bool
	Hidden         bool // the piece shows nothing of its set but its id
	PayloadHashHex string
	Name           string // original file name, empty when it was not recorded

	// CreatorVersion and CreatorCommit identify the build that wrote the piece,
	// empty when none was recorded.
	CreatorVersion string
	CreatorCommit  string

	Algorithms []string // outermost first
	Params     kdf.Params
	LayerCount int
	KEMLayers  int // layers needing a recipient private key
	Intact     bool
}

// PasswordLayers is how many layers need a password.
func (p *PieceInfo) PasswordLayers() int { return p.LayerCount - p.KEMLayers }

// Piece is a piece opened once, so it can be described and then rebuilt from
// without its envelope key being derived again. What it carries for a rebuild is
// as large as the input for a full set; Wipe releases that.
type Piece struct {
	Info   *PieceInfo
	m      *format.Manifest
	params kdf.Params
}

// Wipe clears what the piece carries for a rebuild. Info stays readable.
func (p *Piece) Wipe() { p.m.Wipe() }

// Open opens one piece and describes it, keeping it open for CombineOpened. It
// needs what the envelope takes: nothing for public or hidden details, the first
// layer's password or private key for protected ones, and every one for strict
// ones. A piece with hidden details describes nothing beyond its set id and
// method.
func Open(piece []byte, opts OpenOptions) (*Piece, error) {
	opts, wipe := canonicalizeOpen(opts)
	defer wipe()

	m, params, _, _, err := openPieces([][]byte{piece}, &opts)
	if err != nil {
		return nil, err
	}
	return &Piece{Info: describe(m, params), m: m, params: params}, nil
}

// Info opens one piece and describes it, keeping nothing open.
func Info(piece []byte, opts OpenOptions) (*PieceInfo, error) {
	p, err := Open(piece, opts)
	if err != nil {
		return nil, err
	}
	p.Wipe()
	return p.Info, nil
}

// describe says what an opened manifest shows.
func describe(m *format.Manifest, params kdf.Params) *PieceInfo {
	info := &PieceInfo{
		SetID:          fmt.Sprintf("%x", m.SetID),
		Serial:         m.Serial,
		K:              m.K,
		N:              m.N,
		Encrypted:      m.Encrypted,
		Hybrid:         m.Hybrid,
		AlgoStored:     m.AlgoStored,
		KDFStored:      m.KDFStored,
		Keyless:        m.Keyless,
		SealedToKeys:   m.SealedToKeys,
		Compact:        m.Compact,
		Hidden:         m.Hidden,
		PayloadHashHex: fmt.Sprintf("%x", m.PayloadHash),
		Name:           SafeName(m.Name),
		CreatorVersion: m.CreatorVersion,
		CreatorCommit:  m.CreatorCommit,
		Params:         params,
		LayerCount:     len(m.Layers),
		Intact:         true, // the AEAD tag authenticated the whole piece
	}
	_, info.KEMLayers = countLayers(m.Layers)
	if m.AlgoStored {
		for _, d := range m.Layers {
			info.Algorithms = append(info.Algorithms, describeLayer(d))
		}
	}
	return info
}

// Combine reconstructs the original input from a set of pieces.
func Combine(pieces [][]byte, opts OpenOptions) ([]byte, error) {
	out, _, err := CombineFile(pieces, opts)
	return out, err
}

// CombineFile is Combine plus the file name the pieces recorded, already reduced
// to something safe to write; it is empty when no usable name was recorded. The
// name comes out of the same open that reconstructs, so asking for it costs
// nothing extra.
func CombineFile(pieces [][]byte, opts OpenOptions) ([]byte, string, error) {
	if len(pieces) == 0 {
		return nil, "", errors.New("core: no pieces provided")
	}

	opts, wipe := canonicalizeOpen(opts)
	defer wipe()

	first, params, opened, damaged, err := openPieces(pieces, &opts)
	if err != nil {
		return nil, "", err
	}
	defer forget(opened)
	return combineOpened(first, params, opened, damaged, &opts)
}

// CombineOpened is CombineFile for pieces already opened with Open, so none is
// opened again. They must be of one set, and they are spent: each is wiped by
// the time it returns.
func CombineOpened(pieces []*Piece, opts OpenOptions) ([]byte, string, error) {
	if len(pieces) == 0 {
		return nil, "", errors.New("core: no pieces provided")
	}

	opts, wipe := canonicalizeOpen(opts)
	defer wipe()

	opened := make([]*format.Manifest, len(pieces))
	for i, p := range pieces {
		opened[i] = p.m
	}
	defer forget(opened)
	if err := checkSet(opened, 0); err != nil {
		return nil, "", err
	}
	// An envelope that opened with a password was given the passwords, and Open
	// did not keep them. The callback that gave them is asked again, which a
	// caller that remembers its answer, as a prompt does, gives without asking
	// twice. A protected envelope takes only the first, and peelCredentials asks
	// for the rest.
	pwLayers, _ := countLayers(opened[0].Layers)
	if opened[0].PasswordOpened && pwLayers > 0 && len(opts.Passwords) == 0 && opts.EnvelopePasswords != nil {
		pws, err := opts.EnvelopePasswords(false)
		if err != nil {
			return nil, "", err
		}
		opts.Passwords = pws
	}
	return combineOpened(opened[0], pieces[0].params, opened, nil, &opts)
}

// combineOpened rebuilds and decrypts a set whose pieces are open.
func combineOpened(first *format.Manifest, params kdf.Params, opened []*format.Manifest, damaged []error, opts *OpenOptions) ([]byte, string, error) {
	set, err := assembleSet(first, params, opened, damaged, *opts)
	if err != nil {
		return nil, "", err
	}

	// Everything the set may have withheld is settled once the details are
	// known, before the rebuild and before any password is asked for, so each
	// question is asked once and nothing is redone for an answer.
	layers := set.details.Layers
	if err := settleSchemes(layers, set.details.AlgoStored, opts); err != nil {
		return nil, "", err
	}
	cparams, err := set.cascadeParams(layers, opts)
	if err != nil {
		return nil, "", err
	}

	payload, buf, err := set.rebuild()
	if err != nil {
		return nil, "", err
	}
	// The shares have done their job; drop them rather than hold K of them,
	// each as large as the input, through the decryption.
	forget(opened)

	cascadePws, decaps, err := peelCredentials(layers, *opts)
	if err != nil {
		memory.Zero(buf)
		return nil, "", err
	}
	plaintext, err := cascade.Decrypt(payload, cascadePws, decaps, cparams, opts.Schemes)
	if err != nil {
		memory.Zero(buf)
		return nil, "", err
	}
	return keep(buf, plaintext), SafeName(set.details.Name), nil
}

// keep moves plaintext, which lies inside buf, to the start of buf and wipes the
// rest, so the result is all that buf still holds.
func keep(buf, plaintext []byte) []byte {
	n := copy(buf, plaintext)
	memory.Zero(buf[n:])
	return buf[:n]
}

// settleSchemes makes sure a set that did not record its algorithms has them,
// asking when it can.
func settleSchemes(layers []cascade.Descriptor, recorded bool, opts *OpenOptions) error {
	if recorded || len(layers) == 0 || len(opts.Schemes) > 0 {
		return nil
	}
	if opts.AskSchemes == nil {
		return &SchemesRequiredError{Layers: len(layers)}
	}
	ids, err := opts.AskSchemes(len(layers))
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return &SchemesRequiredError{Layers: len(layers)}
	}
	opts.Schemes = ids
	return nil
}

// forget wipes and drops what the opened manifests carry for the rebuild, which
// is as large as the input for every piece of a full set.
func forget(opened []*format.Manifest) {
	for _, m := range opened {
		if m != nil {
			m.Wipe()
		}
	}
}

// openedSet is what the pieces of one set agree on, wherever the details came
// from, and the pieces a rebuild uses.
type openedSet struct {
	details     format.Details
	hash        []byte
	compact     bool
	stretched   bool       // the envelope opened with a password
	envelopeKDF kdf.Params // the cost it opened with, which is the set's
	use         []*format.Manifest
}

// assembleSet settles the details, from the reference manifest or by rebuilding
// a hidden set's shared details, and picks K distinct pieces to rebuild from.
func assembleSet(first *format.Manifest, params kdf.Params, opened []*format.Manifest, damaged []error, opts OpenOptions) (*openedSet, error) {
	set := &openedSet{details: first.Details, hash: first.PayloadHash, compact: first.Compact,
		stretched: first.PasswordOpened, envelopeKDF: params}

	// One of each piece: a second copy adds nothing to a rebuild. A piece is
	// known by its serial, or by its details share when the serials are hidden.
	var distinct []*format.Manifest
	seen := map[string]bool{}
	for _, m := range opened {
		if m == nil {
			continue
		}
		id := strconv.Itoa(m.Serial)
		if first.Hidden {
			id = string(m.DetailsShare)
		}
		if !seen[id] {
			seen[id] = true
			distinct = append(distinct, m)
		}
	}
	if first.Hidden {
		d, err := revealDetails(distinct)
		if err != nil {
			return nil, firstDamage(damaged, err)
		}
		set.details = *d
	} else if len(distinct) < first.K {
		return nil, firstDamage(damaged, tooFew(fmt.Sprintf("core: need %d distinct pieces, have %d", first.K, len(distinct))))
	}

	for i, derr := range damaged {
		if derr != nil && opts.Damaged != nil {
			opts.Damaged(i, derr)
		}
	}
	set.use = distinct[:set.details.K]
	return set, nil
}

// firstDamage prefers a damaged piece to the shortfall it caused, since the
// damaged file is what to replace.
func firstDamage(damagedErrs []error, shortfall error) error {
	for i, derr := range damagedErrs {
		if derr != nil {
			return &PieceError{Piece: i + 1, Err: damaged{derr}}
		}
	}
	return shortfall
}

// revealDetails rebuilds a hidden set's details from the distinct pieces given.
// The threshold is one of the hidden details, so every share is used: more shares
// than the threshold still interpolate to the same secret, and fewer give noise
// that the details' own hash refuses.
func revealDetails(distinct []*format.Manifest) (*format.Details, error) {
	short := tooFew("core: these pieces do not rebuild the set: it needs more of them, or one is not " +
		"from this set, and how many it needs is one of the details it hides")
	if len(distinct) == 0 {
		return nil, short
	}
	// At a threshold of one each share is the details themselves.
	if d, ok := format.DecodeDetails(distinct[0].DetailsShare); ok && d.K == 1 {
		return d, nil
	}
	if len(distinct) < 2 {
		return nil, short
	}
	shares := make([][]byte, len(distinct))
	for i, m := range distinct {
		shares[i] = m.DetailsShare
	}
	secret, err := split.Combine(shares, len(shares))
	if err != nil {
		return nil, short
	}
	defer memory.Zero(secret)
	d, ok := format.DecodeDetails(secret)
	if !ok || d.K > len(distinct) {
		return nil, short
	}
	return d, nil
}

// rebuild reconstructs the cascade payload from the chosen pieces. The payload
// lies inside buf, which the caller wipes.
func (s *openedSet) rebuild() (payload, buf []byte, err error) {
	k := s.details.K
	shares := make([][]byte, len(s.use))
	for i, m := range s.use {
		shares[i] = m.Share
	}
	shared, err := split.Combine(shares, k)
	if err != nil {
		return nil, nil, err
	}
	body, ok := format.UnwrapPayload(shared, s.hash)
	if !ok {
		memory.Zero(shared)
		return nil, nil, errIntegrity
	}
	if !s.compact {
		return body, shared, nil
	}
	defer memory.Zero(shared)

	frags := make([][]byte, len(s.use))
	for i, m := range s.use {
		frags[i] = m.Fragment
	}
	data, err := disperse.Combine(frags, k)
	if err != nil {
		return nil, nil, err
	}
	if payload, err = compact.Open(data, body); err != nil {
		memory.Zero(data)
		return nil, nil, err
	}
	return payload, data, nil
}

// cascadeParams decides the Argon2 cost for the password layers: the one that
// opened the envelope with a password, otherwise the override, the recorded
// cost, an answer from AskParams, or an error when a password layer needs one
// and none is known. An answer is kept in opts, so it is asked for once.
func (s *openedSet) cascadeParams(layers []cascade.Descriptor, opts *OpenOptions) (kdf.Params, error) {
	if s.stretched {
		return s.envelopeKDF, nil
	}
	switch {
	case opts.Params != nil:
		return *opts.Params, nil
	case s.details.KDFStored && s.details.Params != (kdf.Params{}):
		return s.details.Params, nil
	}
	if pw, _ := countLayers(layers); pw == 0 {
		return kdf.Params{}, nil
	}
	if opts.AskParams != nil {
		p, err := opts.AskParams(true)
		if err != nil {
			return kdf.Params{}, err
		}
		if p != nil {
			opts.Params = p
			return *p, nil
		}
	}
	return kdf.Params{}, ErrParamsRequired
}

// countLayers counts the password and recipient layers.
func countLayers(layers []cascade.Descriptor) (pw, kem int) {
	for _, d := range layers {
		switch d.Kind {
		case cascade.Password:
			pw++
		case cascade.KEM:
			kem++
		}
	}
	return pw, kem
}

// peelCredentials matches the supplied passwords and private keys to the layers,
// so a wrong number of passwords or a missing key is reported before any key is
// derived. Passwords that are not one per layer, such as the first alone that
// opened a protected envelope, are asked for again when AskPasswords is set.
// canonicalizeOpen has already wrapped AskPasswords, so what it returns is
// canonical and wiped with the rest.
func peelCredentials(layers []cascade.Descriptor, opts OpenOptions) ([][]byte, []cascade.Decapsulator, error) {
	pwLayers, kemLayers := countLayers(layers)
	passwords := opts.Passwords
	if pwLayers > 0 && len(passwords) != pwLayers && opts.AskPasswords != nil {
		asked, err := opts.AskPasswords(pwLayers)
		if err != nil {
			return nil, nil, err
		}
		passwords = asked
	}
	// A password the set does not take is refused rather than ignored, so a set
	// with none is never mistaken for one the password unlocked.
	if len(passwords) != pwLayers {
		return nil, nil, fmt.Errorf("core: this set needs %d password(s), got %d", pwLayers, len(passwords))
	}
	var decaps []cascade.Decapsulator
	if kemLayers > 0 {
		if len(opts.PrivateKeys) == 0 {
			return nil, nil, fmt.Errorf("%w: this set has %d recipient layer(s) and no private key was given",
				ErrKeyRequired, kemLayers)
		}
		for _, key := range opts.PrivateKeys {
			decaps = append(decaps, func(ct []byte) ([]byte, error) { return key.Decapsulate(ct) })
		}
	}
	return passwords, decaps, nil
}

// openBudget returns the cost to size the concurrent opens against.
//
// Each piece declares its own Argon2 cost, and that byte is not authenticated
// before it is used, so sizing the pool from the first piece alone would let a
// cheap piece 1 authorise a full set of workers that then each meet a piece
// declaring a gibibyte. The worst declaration in the set is what has to fit.
func openBudget(pieces [][]byte, opts OpenOptions, first kdf.Params) kdf.Params {
	// No password means no derivation, so nothing to budget for.
	if len(opts.Passwords) == 0 {
		return kdf.Params{}
	}
	// An override replaces every recorded cost, so it is the only one that runs.
	if opts.Params != nil {
		return *opts.Params
	}
	worst := first
	for _, p := range pieces[1:] {
		if declared, ok := format.PeekParams(p); ok && declared.Memory > worst.Memory {
			worst = declared
		}
	}
	return worst
}

// openWorkers is how many of the remaining pieces are derived at once. It is
// the whole of that decision, so the budget cannot be bypassed by changing one
// call site without the tests noticing.
func openWorkers(pieces [][]byte, opts OpenOptions, first kdf.Params, rest int) int {
	return derivationWorkers(openBudget(pieces, opts, first), rest)
}

// openPieces opens every piece once and checks they describe one set. It
// returns the manifest of the piece the others are measured against, the cost
// that opened it, the manifests by index, and, by index, why each piece that did
// not open failed. Passwords and a cost it had to ask for are left in o.
//
// What derives nothing is tried on every piece at once: the public key, then the
// recipient keys on the pieces that left closed. Only if some piece needs more
// is a password asked for, and then only those pieces are opened again; telling
// the callback whether any piece did open is what stops a crafted keyless piece,
// put in front of a password set, from switching the question off.
//
// A piece that fails once another has opened is damaged rather than wrongly
// keyed, and is set aside rather than failing the set, since spare pieces exist
// for exactly this. Consistency is checked in index order, so an inconsistent
// set names the same piece whatever the scheduling.
func openPieces(pieces [][]byte, o *OpenOptions) (*format.Manifest, kdf.Params, []*format.Manifest, []error, error) {
	op := &opening{pieces: pieces, o: o,
		opened: make([]*format.Manifest, len(pieces)),
		params: make([]kdf.Params, len(pieces)),
		failed: make([]error, len(pieces)),
	}
	op.tryKeyless(op.closed())
	if len(o.PrivateKeys) > 0 {
		op.tryKeys(op.closed())
	}
	if open := op.count(); open < len(pieces) && len(o.Passwords) == 0 && o.EnvelopePasswords != nil {
		pws, err := o.EnvelopePasswords(open > 0)
		if err != nil {
			return nil, kdf.Params{}, nil, nil, err
		}
		o.Passwords = pws
	}
	if len(o.Passwords) > 0 {
		op.ways = op.passwordWays()
		if err := op.withPasswords(); err != nil {
			return nil, kdf.Params{}, nil, nil, err
		}
	}
	return op.result()
}

// opening is one call of openPieces in progress.
type opening struct {
	pieces    [][]byte
	o         *OpenOptions
	opened    []*format.Manifest
	params    []kdf.Params
	failed    []error
	ways      []decoder // how a piece may open with the passwords
	announced bool
}

// decoder opens a piece one way.
type decoder func(piece []byte) (*format.Manifest, kdf.Params, error)

// closed returns the pieces not yet open that could still open: a piece that
// failed for any reason but the key is malformed, and no key will change that.
func (op *opening) closed() []int {
	var idx []int
	for i, m := range op.opened {
		if m == nil && (op.failed[i] == nil || errors.Is(op.failed[i], format.ErrWrongPassword)) {
			idx = append(idx, i)
		}
	}
	return idx
}

func (op *opening) count() int {
	n := 0
	for _, m := range op.opened {
		if m != nil {
			n++
		}
	}
	return n
}

// tryKeyless tries the public key on the pieces at idx, all at once, since it
// derives nothing.
func (op *opening) tryKeyless(idx []int) {
	_ = parallel.Do(len(idx), parallel.Workers(len(idx)), func(j int) error {
		i := idx[j]
		op.opened[i], op.params[i], op.failed[i] = format.Decode(op.pieces[i], nil, op.o.Params)
		return nil
	})
}

// tryKeys tries the recipient keys alone on the pieces at idx, all at once, since
// they derive nothing.
func (op *opening) tryKeys(idx []int) {
	_ = parallel.Do(len(idx), parallel.Workers(len(idx)), func(j int) error {
		i := idx[j]
		op.opened[i], op.params[i], op.failed[i] = format.DecodeSealed(op.pieces[i], nil, op.o.PrivateKeys, op.o.Params)
		return nil
	})
}

// passwordWays lists how a piece may open with the passwords, and the recipient
// keys when there are any. A protected envelope takes the first password alone,
// and a strict one every password, so with more than one both are tried, the
// default first. Each reads the cost when it runs, so one asked for counts.
func (op *opening) passwordWays() []decoder {
	o := op.o
	var ways []decoder
	if len(o.Passwords) > 1 {
		ways = append(ways, func(p []byte) (*format.Manifest, kdf.Params, error) {
			return format.DecodePassword(p, o.Passwords[:1], o.Params)
		})
	}
	if len(o.PrivateKeys) > 0 {
		return append(ways, func(p []byte) (*format.Manifest, kdf.Params, error) {
			return format.DecodeSealed(p, o.Passwords, o.PrivateKeys, o.Params)
		})
	}
	return append(ways, func(p []byte) (*format.Manifest, kdf.Params, error) {
		return format.DecodePassword(p, o.Passwords, o.Params)
	})
}

// decode opens piece i each way in turn, stopping at a failure that is not a
// wrong key, and returns the way that opened it, or -1.
func (op *opening) decode(i int) int {
	for w, way := range op.ways {
		op.opened[i], op.params[i], op.failed[i] = way(op.pieces[i])
		if op.opened[i] != nil {
			return w
		}
		if !errors.Is(op.failed[i], format.ErrWrongPassword) {
			break
		}
	}
	return -1
}

// withPasswords opens the pieces still closed, now that there are passwords.
//
// A reference piece is opened first and alone, because its cost bounds how many
// of the rest may be derived at once. It is the first closed piece, or the next
// when that one does not open, so one damaged file is not taken for a wrong
// password. When neither opens and no other piece did, the credentials or the
// cost are what is wrong, and AskParams may supply the cost; with others open,
// these are damaged, and a cost asked for could only replace the one they
// recorded.
//
// A set has one cost, so the rest are tried at the one the reference opened
// with. A set that did not record it has noise in every cost byte, which is the
// cost one time in 256: the reference opening at its own byte says nothing of
// the others'.
func (op *opening) withPasswords() error {
	closed := op.closed()
	if len(closed) == 0 {
		return nil
	}
	ref := op.openReference(closed)
	if ref < 0 && op.count() == 0 && op.o.Params == nil && op.o.AskParams != nil &&
		errors.Is(op.failed[closed[0]], format.ErrWrongPassword) {
		p, err := op.o.AskParams(false)
		if err != nil {
			return err
		}
		if p != nil {
			op.o.Params = p
			ref = op.openReference(closed)
		}
	}
	if ref < 0 {
		return nil
	}
	if op.o.Params == nil {
		cost := op.params[ref]
		op.o.Params = &cost
	}

	// A password piece among keyless ones has to open, to be refused as
	// inconsistent, and is bounded by the budget like any other.
	var rest []int
	for _, i := range closed {
		if op.opened[i] == nil && i > ref {
			rest = append(rest, i)
		}
	}
	if len(rest) == 0 {
		return nil
	}
	op.announce()
	budget := [][]byte{op.pieces[ref]}
	for _, i := range rest {
		budget = append(budget, op.pieces[i])
	}
	_ = parallel.Do(len(rest), openWorkers(budget, *op.o, op.params[ref], len(rest)), func(j int) error {
		op.decode(rest[j])
		return nil
	})
	return nil
}

// openReference opens the first of the closed pieces, or the second when the
// first does not, and returns its index, or -1 when neither opens. The pieces of
// a set are sealed alike, so the rest are then tried only the way it opened.
func (op *opening) openReference(closed []int) int {
	for _, i := range closed[:min(2, len(closed))] {
		op.announce()
		if w := op.decode(i); w >= 0 {
			op.ways = op.ways[w : w+1]
			return i
		}
	}
	return -1
}

// announce tells BeforeDerive, once, the worst cost the closed pieces declare.
func (op *opening) announce() {
	if op.announced || op.o.BeforeDerive == nil {
		return
	}
	op.announced = true
	worst := kdf.Params{}
	if op.o.Params != nil {
		worst = *op.o.Params
	} else {
		for i, p := range op.pieces {
			if op.opened[i] != nil {
				continue
			}
			if d, ok := format.PeekParams(p); ok && d.Memory > worst.Memory {
				worst = d
			}
		}
	}
	op.o.BeforeDerive(worst)
}

// result picks the reference, the first piece that opened, and checks every
// other piece agrees with it.
func (op *opening) result() (*format.Manifest, kdf.Params, []*format.Manifest, []error, error) {
	ref := -1
	for i, m := range op.opened {
		if m != nil {
			ref = i
			break
		}
	}
	if ref < 0 {
		cause := op.failed[0]
		if cause == nil {
			cause = format.ErrWrongPassword
		}
		return nil, kdf.Params{}, nil, nil, &PieceError{Piece: 1, Err: fmt.Errorf("did not open: %w", cause)}
	}
	if err := checkSet(op.opened, ref); err != nil {
		forget(op.opened)
		return nil, kdf.Params{}, nil, nil, err
	}
	// A piece that did not open has its error kept; one that opened has none.
	for i := range op.failed {
		if op.opened[i] != nil {
			op.failed[i] = nil
		}
	}
	return op.opened[ref], op.params[ref], op.opened, op.failed, nil
}

// checkSet returns an error naming the first piece that does not agree with the
// one at ref; pieces that did not open are skipped.
func checkSet(opened []*format.Manifest, ref int) error {
	m0 := opened[ref]
	for idx, m := range opened {
		if m == nil || idx == ref {
			continue
		}
		if !bytes.Equal(m.SetID, m0.SetID) {
			return &PieceError{Piece: idx + 1, Err: errors.New("belongs to a different set")}
		}
		if !sameSet(m, m0) {
			return &PieceError{Piece: idx + 1, Err: errors.New("is inconsistent with the set")}
		}
	}
	return nil
}

// sameSet reports whether two manifests describe the same set in every field a
// set shares. A keyless envelope can be opened and sealed again by anyone, so a
// field one piece alone could change, such as the name it offers, has to agree
// with the others rather than be taken from the first.
func sameSet(m, m0 *format.Manifest) bool {
	return m.Details.Equal(&m0.Details) && bytes.Equal(m.PayloadHash, m0.PayloadHash) &&
		m.Keyless == m0.Keyless && m.SealedToKeys == m0.SealedToKeys &&
		m.Compact == m0.Compact && m.Hidden == m0.Hidden &&
		len(m.Share) == len(m0.Share) && len(m.Fragment) == len(m0.Fragment) &&
		len(m.DetailsShare) == len(m0.DetailsShare)
}
