// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package core orchestrates the full pipeline: cascade-encrypt, Shamir-split,
// and wrap each share in a stealth piece; and the reverse for reconstruction and
// single-piece inspection.
package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/secu-tools/riven/internal/cascade"
	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/parallel"
	"github.com/secu-tools/riven/internal/password"
	"github.com/secu-tools/riven/internal/split"
)

// canonicalPasswords returns NFC-canonical copies of pws so that a password
// entered in a different Unicode composition or character encoding still derives
// the same key (see internal/password). The returned cleanup wipes the copies;
// the inputs are left for their owner to wipe.
func canonicalPasswords(pws [][]byte) (out [][]byte, cleanup func()) {
	out = password.CanonicalAll(pws)
	return out, func() { memory.FreeAll(out) }
}

// canonicalizeOpen returns opts with its passwords replaced by canonical copies,
// so Info and CombineFile need not each repeat the substitution. The returned
// cleanup wipes the copies.
func canonicalizeOpen(opts OpenOptions) (OpenOptions, func()) {
	pws, wipe := canonicalPasswords(opts.Passwords)
	opts.Passwords = pws
	return opts, wipe
}

// canonicalizeSpecs copies specs with every password-layer password replaced by
// its canonical form, so key derivation never depends on how the password was
// typed or encoded. The returned cleanup wipes the copies.
func canonicalizeSpecs(specs []LayerSpec) (out []LayerSpec, cleanup func()) {
	out = make([]LayerSpec, len(specs))
	copy(out, specs)
	var copies [][]byte
	for i := range out {
		if out[i].Kind == PasswordLayer && len(out[i].Password) > 0 {
			c := password.Canonical(out[i].Password)
			out[i].Password = c
			copies = append(copies, c)
		}
	}
	return out, func() { memory.FreeAll(copies) }
}

// Padding rounds a piece up to the next size class, so its length gives only
// the class rather than the content length. The class depends on the length
// alone, so every piece of a set is the same size and extra pieces reveal
// nothing further. The zero value pads at DefaultPadPercent.
//
// The padding is random fill shared with the payload, so it works without a
// password too: fewer than k pieces cannot tell content from fill. Every set
// carries at least format.MinFill bytes of it, padding or not.
type Padding struct {
	// Off leaves only the minimum fill, which reveals the content length.
	Off bool

	// Percent is the class width, and so the worst-case storage cost. Zero means
	// DefaultPadPercent.
	Percent int
}

// Padding widths. The default is the narrowest: it costs little, everything small
// still lands in the floor class, and a larger piece gives a range, not a length.
const (
	DefaultPadPercent = 1
	MinPadPercent     = 1
	MaxPadPercent     = 500
)

// PadNone returns padding switched off.
func PadNone() Padding { return Padding{Off: true} }

// PadPercent returns padding with size classes of the given width.
func PadPercent(p int) Padding { return Padding{Percent: p} }

// Width returns the class width in percent, resolving the zero value.
func (p Padding) Width() int {
	if p.Percent == 0 {
		return DefaultPadPercent
	}
	return p.Percent
}

// Validate rejects a width outside the supported range.
func (p Padding) Validate() error {
	if p.Off {
		return nil
	}
	if p.Percent != 0 && (p.Percent < MinPadPercent || p.Percent > MaxPadPercent) {
		return fmt.Errorf("core: padding width must be between %d and %d percent, got %d",
			MinPadPercent, MaxPadPercent, p.Percent)
	}
	return nil
}

// bucketFloor is the smallest size class. Everything below it rounds up to it, so
// small secrets do not stand out by being small.
const bucketFloor = 256

// BucketFor returns the size class a piece of n bytes is padded up to, given a
// class width in percent. It is a pure function of its arguments, so it is
// deterministic and safe to publish: knowing the classes tells an observer only
// which class a piece is in.
func BucketFor(n, percent int) int {
	if percent < MinPadPercent {
		percent = DefaultPadPercent
	}
	if n <= bucketFloor {
		return bucketFloor
	}
	size := bucketFloor
	for size < n {
		step := size * percent / 100
		if step < 1 {
			step = 1
		}
		size += step
	}
	return size
}

// fillLen returns how much random fill to share after a payload of payloadLen
// bytes: format.MinFill, plus whatever brings the piece up to its size class.
// Every share has the same length and every manifest the same shape, so one fill
// length covers the whole set.
func fillLen(payloadLen, layerCount int, opts SplitOptions) int {
	if opts.Padding.Off {
		return format.MinFill
	}
	overhead := format.PieceLen(0, layerCount, len(opts.Name)+len(opts.CreatorVersion)+len(opts.CreatorCommit))
	secret := format.SharedLen(payloadLen, format.MinFill)
	target := BucketFor(overhead+split.ShareLen(secret, opts.K), opts.Padding.Width())
	return format.MinFill + split.SecretLen(target-overhead, opts.K) - secret
}

// LayerKind says how a cascade layer is keyed.
type LayerKind uint8

const (
	// PasswordLayer derives its key from a password.
	PasswordLayer LayerKind = iota
	// RecipientLayer derives its key by encapsulating to a recipient public key,
	// so only the holder of the matching private key can peel it.
	RecipientLayer
)

// LayerSpec is one cascade layer. Layers apply in order, so the first entry is
// the outermost and is peeled first. Password and recipient layers can be mixed
// freely: a set with two recipient layers needs both private keys, which is how
// two people can be required to cooperate.
type LayerSpec struct {
	Kind LayerKind

	// SchemeID selects the AEAD. Zero means assign one automatically, avoiding
	// the algorithm used by the layer above.
	SchemeID uint8

	Password  []byte         // PasswordLayer
	Recipient *kem.PublicKey // RecipientLayer
}

// SplitOptions configures a split.
type SplitOptions struct {
	N, K   int
	Layers []LayerSpec
	Params kdf.Params

	// Padding hides the length of the content. The zero value pads at the default
	// width, so forgetting the field cannot silently leave the length exposed.
	Padding Padding

	RecordAlgo bool // write cascade algorithm ids into each piece
	RecordKDF  bool // write Argon2 cost parameters into each piece

	// Name is the original file name, recorded inside the encrypted manifest so
	// a reconstruction can restore it. Empty records none. Nothing else about the
	// file is kept: no path, no permissions, no timestamps.
	Name string

	// CreatorVersion and CreatorCommit identify the build writing the piece, for
	// diagnosing a version mismatch later via Info. Always recorded; there is no
	// flag to withhold them since they carry no information about the input.
	CreatorVersion string
	CreatorCommit  string

	// Keyless splits with no password at all: only the threshold protects the
	// content, and any K pieces rebuild it with nothing else supplied. It cannot
	// be combined with any cascade layers.
	Keyless bool
}

// OpenOptions configures inspection and reconstruction.
type OpenOptions struct {
	Passwords [][]byte

	// PrivateKeys are the recipient keys to try. Every recipient layer must be
	// matched by one of them, so a set built for two recipients needs both.
	PrivateKeys []*kem.PrivateKey

	Params  *kdf.Params // non-nil overrides the recorded cost parameters
	Schemes []uint8     // cascade algorithms, for pieces that omit them

	// Damaged, when set, is told about each piece that did not open although
	// another did, by its index among the pieces given. Such a piece is set aside
	// and the set rebuilt from the rest, provided enough of them remain.
	Damaged func(index int, err error)
}

// ErrSchemesRequired indicates the set did not record its algorithms and none
// were supplied.
var ErrSchemesRequired = cascade.ErrSchemesRequired

// ErrKeyRequired indicates a recipient layer could not be opened by any of the
// supplied private keys.
var ErrKeyRequired = cascade.ErrKeyRequired

// splitPrep is everything a split needs before the pieces are built: the shares
// and the metadata every piece repeats.
type splitPrep struct {
	shares          [][]byte
	setID           []byte
	payloadHash     []byte
	descs           []cascade.Descriptor
	envPasswords    [][]byte
	encrypted       bool
	hybrid          bool
	envelopeKeyless bool
	cleanup         func()
}

// prepare runs the pipeline up to the shares. The returned cleanup wipes the
// payload and any shares still held, and is safe to call after an error.
func prepare(input []byte, opts SplitOptions) (*splitPrep, error) {
	if err := checkSplitOptions(&opts); err != nil {
		return nil, err
	}

	// Put every password into canonical form before it becomes a key, so the same
	// password opens the pieces however it is later re-entered. The copies live as
	// long as the envelope passwords, so they are wiped by prep.cleanup, or by the
	// deferred guard below on any early error.
	specs, wipeCanon := canonicalizeSpecs(opts.Layers)
	opts.Layers = specs
	committed := false
	defer func() {
		if !committed {
			wipeCanon()
		}
	}()

	// Resolve the algorithm for every layer, then build the cascade in order.
	schemeIDs, err := AssignSchemes(opts.Layers)
	if err != nil {
		return nil, err
	}

	layers, envPasswords, hybrid, layerCleanup, err := buildLayers(opts.Layers, schemeIDs)
	if err != nil {
		layerCleanup()
		return nil, err
	}
	encrypted := len(layers) > 0

	// The envelope needs a key. A password layer supplies one; otherwise it falls
	// back to the public keyless derivation, which is correct in two cases:
	// split-only mode, and recipient layers alone, where by definition the reader
	// holds a private key rather than a password.
	envelopeKeyless := opts.Keyless
	if len(envPasswords) == 0 && !opts.Keyless {
		if !hybrid {
			layerCleanup()
			return nil, errors.New("core: a split needs at least one password layer, a recipient layer, or keyless mode")
		}
		envelopeKeyless = true
	}

	payload, err := cascade.Encrypt(input, layers, opts.Params, opts.RecordAlgo)
	layerCleanup()
	if err != nil {
		return nil, err
	}
	shared, payloadHash, err := format.WrapPayload(payload, fillLen(len(payload), len(layers), opts))
	memory.Zero(payload)
	if err != nil {
		return nil, err
	}
	if err := split.ValidateParams(opts.N, opts.K, len(shared)); err != nil {
		memory.Zero(shared)
		return nil, err
	}

	shares, err := split.Split(shared, opts.N, opts.K)
	memory.Zero(shared)
	if err != nil {
		return nil, err
	}

	setID := make([]byte, format.SetIDLen)
	if _, err := rand.Read(setID); err != nil {
		return nil, err
	}

	descs := make([]cascade.Descriptor, len(layers))
	for i, l := range layers {
		descs[i] = cascade.Descriptor{Kind: l.Kind, SchemeID: l.SchemeID, Recorded: opts.RecordAlgo}
	}

	prep := &splitPrep{
		shares: shares, setID: setID, payloadHash: payloadHash, descs: descs,
		envPasswords: envPasswords, encrypted: encrypted, hybrid: hybrid,
		envelopeKeyless: envelopeKeyless,
	}
	prep.cleanup = func() {
		wipeCanon()
		memory.FreeAll(prep.shares)
	}
	committed = true
	return prep, nil
}

// Split runs the full pipeline and returns N piece blobs (piece i has serial
// i+1). The input slice is not modified.
//
// Every piece is held at once, which is N times the payload on top of the shares.
// For a large input use SplitTo, which releases each piece as it is written.
func Split(input []byte, opts SplitOptions) ([][]byte, error) {
	prep, err := prepare(input, opts)
	if err != nil {
		return nil, err
	}
	defer prep.cleanup()

	// Each piece has its own salt, so each needs its own Argon2 derivation. They
	// are independent, so they run concurrently.
	pieces := make([][]byte, opts.N)
	err = parallel.Do(opts.N, derivationWorkers(opts.Params, opts.N), func(i int) error {
		piece, perr := prep.encode(i, opts)
		if perr != nil {
			return perr
		}
		pieces[i] = piece
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pieces, nil
}

// SplitTo is Split without holding every piece at once: each piece is handed to
// write and released before the next is built.
//
// This is what a large input needs. The pieces are N times the payload on top of
// the shares, so collecting them all roughly doubles what a split already costs.
// Pieces are built in order rather than concurrently, because the caller is
// writing them out and the derivations stop being the slow part once the input
// is large.
func SplitTo(input []byte, opts SplitOptions, write func(serial int, piece []byte) error) error {
	prep, err := prepare(input, opts)
	if err != nil {
		return err
	}
	defer prep.cleanup()

	for i := 0; i < opts.N; i++ {
		piece, err := prep.encode(i, opts)
		if err != nil {
			return err
		}
		err = write(i+1, piece)
		memory.Zero(piece)
		if err != nil {
			return err
		}
		// The share is spent, so release it rather than holding N of them.
		memory.Zero(prep.shares[i])
		prep.shares[i] = nil
	}
	return nil
}

// encode seals share i into a piece.
func (p *splitPrep) encode(i int, opts SplitOptions) ([]byte, error) {
	return format.Encode(format.EncodeInput{
		SetID:          p.setID,
		K:              opts.K,
		N:              opts.N,
		Serial:         i + 1,
		Encrypted:      p.encrypted,
		Hybrid:         p.hybrid,
		RecordAlgo:     opts.RecordAlgo,
		RecordKDF:      opts.RecordKDF,
		Keyless:        p.envelopeKeyless,
		PayloadHash:    p.payloadHash,
		Layers:         p.descs,
		Share:          p.shares[i],
		Name:           opts.Name,
		CreatorVersion: opts.CreatorVersion,
		CreatorCommit:  opts.CreatorCommit,
		Passwords:      p.envPasswords,
		Params:         opts.Params,
	})
}

// MemoryEstimate reports roughly how much memory a split of this size needs, in
// bytes. Shamir gives every share the full length of the payload, so the shares
// alone are N times the input; the caller pays that whatever it does with the
// pieces afterwards.
func MemoryEstimate(inputLen, n int) int64 {
	// input + payload + N shares + one piece in flight, with a little slack for
	// the transient buffers inside the AEAD.
	return int64(inputLen) * int64(n+3)
}

// derivationWorkers decides how many envelope keys to derive at once. Argon2 is
// deliberately memory-hungry, so the count is bounded by a memory budget as well
// as by the available parallelism.
func derivationWorkers(p kdf.Params, n int) int {
	w := parallel.Workers(n)
	if p.Memory > 0 {
		w = min(w, max(1, int(parallelMemoryBudgetKiB/p.Memory)))
	}
	return w
}

// parallelMemoryBudgetKiB caps the memory held by concurrent derivations. One
// gibibyte keeps the default cost fully parallel while stopping the largest
// preset from allocating several gibibytes at once.
const parallelMemoryBudgetKiB = 1 << 20

// PieceInfo is the human-readable description of a single piece.
type PieceInfo struct {
	SetID          string
	Serial, K, N   int
	Encrypted      bool
	Hybrid         bool
	AlgoStored     bool
	KDFStored      bool
	Keyless        bool
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

// Info opens one piece and describes it. It needs the envelope passwords but not
// the KEM private key, since metadata is gated on the envelope only.
func Info(piece []byte, opts OpenOptions) (*PieceInfo, error) {
	opts, wipe := canonicalizeOpen(opts)
	defer wipe()

	m, params, err := format.Decode(piece, opts.Passwords, opts.Params)
	if err != nil {
		return nil, err
	}
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
		PayloadHashHex: fmt.Sprintf("%x", m.PayloadHash),
		Name:           SafeName(m.Name),
		CreatorVersion: m.CreatorVersion,
		CreatorCommit:  m.CreatorCommit,
		Params:         params,
		LayerCount:     len(m.Layers),
		Intact:         true, // the AEAD tag authenticated the whole piece
	}
	for _, d := range m.Layers {
		if d.Kind == cascade.KEM {
			info.KEMLayers++
		}
		if m.AlgoStored {
			info.Algorithms = append(info.Algorithms, describeLayer(d))
		}
	}
	return info, nil
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

	first, usedParams, bySerial, damaged, err := openPieces(pieces, opts)
	if err != nil {
		return nil, "", err
	}
	name := SafeName(first.Name)

	shares, err := pickShares(first.K, bySerial, damaged, opts.Damaged)
	if err != nil {
		return nil, "", err
	}
	shared, err := split.Combine(shares, first.K)
	if err != nil {
		return nil, "", err
	}
	defer memory.Zero(shared)

	payload, ok := format.UnwrapPayload(shared, first.PayloadHash)
	if !ok {
		return nil, "", errors.New("core: reconstruction failed integrity check (wrong or corrupt pieces)")
	}

	cascadePws, decaps, err := peelCredentials(first.Layers, opts)
	if err != nil {
		return nil, "", err
	}
	schemes := opts.Schemes
	if !first.AlgoStored && len(first.Layers) > 0 && len(schemes) == 0 {
		return nil, "", ErrSchemesRequired
	}

	plaintext, err := cascade.Decrypt(payload, cascadePws, decaps, usedParams, schemes)
	if err != nil {
		return nil, "", err
	}
	return plaintext, name, nil
}

// pickShares returns k shares of distinct pieces. Damaged pieces are reported
// through onDamaged when enough intact ones remain to rebuild without them; when
// too few remain, the first damaged piece is the error, since it is what to
// replace.
func pickShares(k int, bySerial map[int]*format.Manifest, damaged []error, onDamaged func(int, error)) ([][]byte, error) {
	if len(bySerial) < k {
		for i, derr := range damaged {
			if derr != nil {
				return nil, fmt.Errorf("core: piece %d did not open although another did, so that file is damaged: %w",
					i+1, derr)
			}
		}
		return nil, fmt.Errorf("core: need %d distinct pieces, have %d", k, len(bySerial))
	}
	for i, derr := range damaged {
		if derr != nil && onDamaged != nil {
			onDamaged(i, derr)
		}
	}
	shares := make([][]byte, 0, k)
	for _, m := range bySerial {
		shares = append(shares, m.Share)
		if len(shares) == k {
			break
		}
	}
	return shares, nil
}

// peelCredentials matches the supplied passwords and private keys to the layers,
// so a wrong number of passwords or a missing key is reported before any key is
// derived.
func peelCredentials(layers []cascade.Descriptor, opts OpenOptions) ([][]byte, []cascade.Decapsulator, error) {
	pwLayers, kemLayers := 0, 0
	for _, d := range layers {
		switch d.Kind {
		case cascade.Password:
			pwLayers++
		case cascade.KEM:
			kemLayers++
		}
	}
	var passwords [][]byte
	if pwLayers > 0 {
		if len(opts.Passwords) != pwLayers {
			return nil, nil, fmt.Errorf("core: this set needs %d password(s), got %d", pwLayers, len(opts.Passwords))
		}
		passwords = opts.Passwords
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

// AssignSchemes resolves the algorithm for every layer. A layer that names one
// keeps it; a layer that leaves it zero gets the default, stepping to another
// registry entry when the default would repeat the layer above. Two adjacent
// layers sharing an algorithm is rejected, so a break in one algorithm cannot
// carry through the whole cascade.
//
// Both the split path and the callers that must name the algorithms afterwards go
// through this, so they cannot disagree about what was used.
func AssignSchemes(layers []LayerSpec) ([]uint8, error) {
	out := make([]uint8, len(layers))
	var prev uint8
	for i, l := range layers {
		id := l.SchemeID
		if id == 0 {
			id = ciphers.Avoiding(ciphers.Default().ID, prev)
		}
		if _, ok := ciphers.ByID(id); !ok {
			return nil, fmt.Errorf("core: layer %d names unknown algorithm id %d", i+1, id)
		}
		if i > 0 && id == prev {
			return nil, fmt.Errorf("core: layer %d (%s) must use a different algorithm than layer %d",
				i+1, ciphers.Name(id), i)
		}
		out[i] = id
		prev = id
	}
	return out, nil
}

// describeLayer names a layer's algorithm and what keys it. A piece does not
// carry the encapsulated key, which lives in the payload, so the recipient key
// type cannot be named from one piece.
func describeLayer(d cascade.Descriptor) string {
	name := ciphers.Name(d.SchemeID)
	if d.Kind == cascade.KEM {
		return name + " (recipient key)"
	}
	return name + " (password)"
}

// checkSplitOptions validates and normalises the options a split was asked for.
func checkSplitOptions(opts *SplitOptions) error {
	if opts.Keyless {
		if len(opts.Layers) > 0 {
			return errors.New("core: keyless mode cannot be combined with encryption layers")
		}
		if opts.K < 2 {
			return errors.New("core: keyless mode needs a threshold of at least 2, otherwise a single piece is the whole file")
		}
		// No key is derived, so the cost parameters are unused. Set them to the
		// default so the rest of the pipeline has a valid value to carry.
		opts.Params = kdf.Default()
	}
	if err := opts.Params.Validate(); err != nil {
		return err
	}
	return opts.Padding.Validate()
}

// buildLayers turns the caller's layer list into cascade layers, encapsulating
// to every recipient key on the way. It returns the passwords that key the
// envelope, whether any recipient layer is present, and a cleanup that wipes the
// shared secrets; the cleanup is always safe to call, including after an error.
func buildLayers(specs []LayerSpec, schemeIDs []uint8) (layers []cascade.Layer, envPasswords [][]byte, hybrid bool, cleanup func(), err error) {
	var secrets [][]byte
	cleanup = func() {
		memory.FreeAll(secrets)
	}

	for i, l := range specs {
		switch l.Kind {
		case PasswordLayer:
			if len(l.Password) == 0 {
				return nil, nil, false, cleanup, fmt.Errorf("core: layer %d is a password layer with no password", i+1)
			}
			if l.Recipient != nil {
				return nil, nil, false, cleanup, fmt.Errorf("core: layer %d is a password layer but also names a recipient key", i+1)
			}
			layers = append(layers, cascade.Layer{
				Kind: cascade.Password, SchemeID: schemeIDs[i], Password: l.Password,
			})
			envPasswords = append(envPasswords, l.Password)

		case RecipientLayer:
			if l.Recipient == nil {
				return nil, nil, false, cleanup, fmt.Errorf("core: layer %d is a recipient layer with no key", i+1)
			}
			if len(l.Password) > 0 {
				return nil, nil, false, cleanup, fmt.Errorf("core: layer %d is a recipient layer but also carries a password", i+1)
			}
			ss, ct, eerr := l.Recipient.Encapsulate()
			if eerr != nil {
				return nil, nil, false, cleanup, fmt.Errorf("core: layer %d: %w", i+1, eerr)
			}
			secrets = append(secrets, ss)
			layers = append(layers, cascade.Layer{
				Kind: cascade.KEM, SchemeID: schemeIDs[i], KEMSecret: ss, KEMCiphertext: ct,
			})
			hybrid = true

		default:
			return nil, nil, false, cleanup, fmt.Errorf("core: layer %d has an unknown kind %d", i+1, l.Kind)
		}
	}
	return layers, envPasswords, hybrid, cleanup, nil
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

// openPieces opens the pieces and checks they describe one set. It returns the
// manifest of the piece the others are measured against, the cost that opened
// it, the manifests keyed by serial, and, by index, why each piece that did not
// open failed.
//
// That reference piece is opened alone, because its recorded cost bounds how
// many of the rest may be derived at once. It is the first piece, or the second
// when the first does not open, so one damaged file is not taken for a wrong
// password; when neither opens, the credentials are what is wrong. A piece that
// fails once the reference has opened is damaged rather than wrongly keyed, and
// is set aside rather than failing the set, since spare pieces exist for exactly
// this. Consistency is checked in index order, so an inconsistent set names the
// same piece whatever the scheduling.
func openPieces(pieces [][]byte, opts OpenOptions) (*format.Manifest, kdf.Params, map[int]*format.Manifest, []error, error) {
	opened := make([]*format.Manifest, len(pieces))
	failed := make([]error, len(pieces))

	ref := 0
	m0, p0, err := format.Decode(pieces[0], opts.Passwords, opts.Params)
	if err != nil && len(pieces) > 1 {
		if m1, p1, err1 := format.Decode(pieces[1], opts.Passwords, opts.Params); err1 == nil {
			failed[0] = err
			ref, m0, p0, err = 1, m1, p1, nil
		}
	}
	if err != nil {
		return nil, kdf.Params{}, nil, nil, fmt.Errorf("core: piece 1: %w", err)
	}
	opened[ref] = m0

	if rest := len(pieces) - ref - 1; rest > 0 {
		_ = parallel.Do(rest, openWorkers(pieces, opts, p0, rest), func(i int) error {
			idx := ref + 1 + i
			opened[idx], _, failed[idx] = format.Decode(pieces[idx], opts.Passwords, opts.Params)
			return nil
		})
	}

	bySerial := make(map[int]*format.Manifest, len(pieces))
	for idx, m := range opened {
		if m == nil {
			continue
		}
		if idx != ref {
			if !bytes.Equal(m.SetID, m0.SetID) {
				return nil, kdf.Params{}, nil, nil, fmt.Errorf("core: piece %d belongs to a different set", idx+1)
			}
			if m.K != m0.K || m.N != m0.N || !bytes.Equal(m.PayloadHash, m0.PayloadHash) {
				return nil, kdf.Params{}, nil, nil, fmt.Errorf("core: piece %d is inconsistent with the set", idx+1)
			}
		}
		bySerial[m.Serial] = m
	}
	return m0, p0, bySerial, failed, nil
}
