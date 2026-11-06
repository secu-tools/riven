// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package core orchestrates the full pipeline: cascade-encrypt, Shamir-split or
// disperse, and wrap each share in a stealth piece; and the reverse for
// reconstruction and single-piece inspection.
package core

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/secu-tools/riven/internal/cascade"
	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/compact"
	"github.com/secu-tools/riven/internal/disperse"
	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/parallel"
	"github.com/secu-tools/riven/internal/password"
	"github.com/secu-tools/riven/internal/split"
)

// canonicalizeOpen returns opts with its passwords replaced by NFC-canonical
// copies, so that a password entered in a different Unicode composition or
// character encoding still derives the same key (see internal/password), and its
// password callbacks wrapped to do the same, so Info and CombineFile
// need not each repeat the substitution. The returned cleanup wipes every copy,
// including those the callbacks hand over later.
func canonicalizeOpen(opts OpenOptions) (OpenOptions, func()) {
	copies := [][][]byte{password.CanonicalAll(opts.Passwords)}
	opts.Passwords = copies[0]
	canonical := func(ask func() ([][]byte, error)) ([][]byte, error) {
		pws, err := ask()
		if err != nil || len(pws) == 0 {
			memory.FreeAll(pws)
			return nil, err
		}
		c := password.CanonicalAll(pws)
		memory.FreeAll(pws)
		copies = append(copies, c)
		return c, nil
	}
	if ask := opts.EnvelopePasswords; ask != nil {
		opts.EnvelopePasswords = func(mixed bool) ([][]byte, error) {
			return canonical(func() ([][]byte, error) { return ask(mixed) })
		}
	}
	if ask := opts.AskPasswords; ask != nil {
		opts.AskPasswords = func(n int) ([][]byte, error) {
			return canonical(func() ([][]byte, error) { return ask(n) })
		}
	}
	return opts, func() {
		for _, c := range copies {
			memory.FreeAll(c)
		}
	}
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

// Method is how the content is spread over the pieces.
type Method uint8

const (
	// MethodFull gives every piece a Shamir share of the whole payload. Each piece
	// is as large as the input, and fewer than K of them reveal nothing. That is
	// proven, not assumed: K-1 shares are equally consistent with every possible
	// content, so there is no ciphertext to break and no computation, present or
	// future, helps. It is the safer method.
	MethodFull Method = iota

	// MethodCompact seals the payload under fresh random keys and an
	// all-or-nothing transform, disperses the result so each piece carries 1/K of
	// it, and shares only the keys. Pieces are about 1/K of the input. Fewer than K
	// reveal nothing only while AES-256 and ChaCha20 stay unbroken: the pieces hold
	// ciphertext, so the guarantee rests on the ciphers rather than on a proof.
	MethodCompact
)

// String names the method as the command line spells it.
func (m Method) String() string {
	if m == MethodCompact {
		return "compact"
	}
	return "full"
}

// InfoMode is what one piece shows about its set, and so whether a single piece
// can be used to test password guesses.
type InfoMode uint8

const (
	// InfoAuto is InfoProtected for a set with a password or a recipient key,
	// InfoPublic otherwise.
	InfoAuto InfoMode = iota

	// InfoProtected seals each piece's envelope with the first layer's secret
	// alone: its password, or to its recipient key. Reading the details takes
	// that one secret. When it is a password, one piece is enough to test a guess
	// of it; the other layers' passwords still need K pieces.
	InfoProtected

	// InfoPublic seals the envelopes with the public keyless key. Anyone with
	// this tool can read a piece's details, and a guess needs K pieces.
	InfoPublic

	// InfoHidden keeps the details out of the manifests and shares them like the
	// content, so a piece shows nothing even with the password, and a guess
	// needs K pieces.
	InfoHidden

	// InfoStrict seals each piece's envelope with every password and to every
	// recipient key the set has, so reading the details takes what reading the
	// content takes. One piece can test a guess only of every password at once,
	// and only by someone who also holds every key.
	InfoStrict
)

// String names the mode as the command line spells it.
func (m InfoMode) String() string {
	switch m {
	case InfoPublic:
		return "public"
	case InfoHidden:
		return "none"
	case InfoProtected:
		return "protected"
	case InfoStrict:
		return "strict"
	}
	return "auto"
}

// EffectiveInfo resolves InfoAuto for a split, and refuses protected or strict
// details for a set with nothing to protect them with.
func EffectiveInfo(opts SplitOptions) (InfoMode, error) {
	// Every layer is either a password or a recipient key, so any layer at all
	// is something to protect the details with.
	hasSecret := len(opts.Layers) > 0
	switch opts.Info {
	case InfoAuto:
		if hasSecret {
			return InfoProtected, nil
		}
		return InfoPublic, nil
	case InfoProtected, InfoStrict:
		if !hasSecret {
			return 0, fmt.Errorf("core: %s details need a password or a recipient layer", opts.Info)
		}
	case InfoHidden:
		// A share at a threshold of one is a plain copy, so each piece would carry
		// its details in the clear under the public envelope.
		if opts.K == 1 {
			return 0, errors.New("core: details cannot be hidden at a threshold of one: each piece is the whole set")
		}
	case InfoPublic:
	default:
		return 0, fmt.Errorf("core: unknown info mode %d", opts.Info)
	}
	return opts.Info, nil
}

// envelopeSecrets returns what a set's envelopes are sealed with: the first
// layer's password or recipient key for a protected set, every password and
// every key for a strict one, and nothing for the public key.
func envelopeSecrets(layers []LayerSpec, info InfoMode) (passwords [][]byte, recipients []*kem.PublicKey) {
	switch info {
	case InfoProtected:
		layers = layers[:min(1, len(layers))]
	case InfoStrict:
	default:
		return nil, nil
	}
	for _, l := range layers {
		if l.Kind == RecipientLayer {
			recipients = append(recipients, l.Recipient)
		} else {
			passwords = append(passwords, l.Password)
		}
	}
	return passwords, recipients
}

// EnvelopeRecipients returns the recipient keys a split's envelopes are sealed
// to, so a caller can tell whether it holds what reading a piece back takes.
func EnvelopeRecipients(opts SplitOptions) ([]*kem.PublicKey, error) {
	info, err := EffectiveInfo(opts)
	if err != nil {
		return nil, err
	}
	_, recipients := envelopeSecrets(opts.Layers, info)
	return recipients, nil
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

	// Method is how the content is spread over the pieces; the zero value is
	// MethodFull.
	Method Method

	// Info is what one piece shows about the set; the zero value is InfoAuto.
	Info InfoMode

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

	// The callbacks below let a caller ask for what a set needs at the point it
	// turns out to need it, so every piece is opened once and nothing is redone.
	// Each is optional; without one the need is an error instead. Passwords they
	// return are put in canonical form and wiped, so they must be copies.

	// EnvelopePasswords is called when no Passwords were given and some piece does
	// not open without one. mixed reports that other pieces did, which is how a
	// damaged piece of a keyless set looks, and also a crafted keyless piece among
	// a password set's. Returning none treats the set as having no password.
	// Without this callback such pieces are taken to be damaged. CombineOpened
	// calls it again, with mixed false, for the passwords of a set whose pieces
	// Open opened with them, so a caller should give the same answer again.
	EnvelopePasswords func(mixed bool) ([][]byte, error)

	// AskPasswords is called once with the number of passwords a set needs, if it
	// needs some and none were given. A set whose envelopes take no password says
	// so only once it is open, or for hidden details once they are rebuilt, so a
	// caller cannot know beforehand how many to ask for.
	AskPasswords func(count int) ([][]byte, error)

	// AskParams is called when Params is nil and a cost is needed: certain is true
	// when the set says it did not record its cost, false when a piece did not
	// open with its password and an unrecorded cost may be the reason. Nil params
	// leaves the error as it was.
	AskParams func(certain bool) (*kdf.Params, error)

	// AskSchemes is called when Schemes is empty and the set did not record its
	// algorithms, with how many layers need one.
	AskSchemes func(layers int) ([]uint8, error)

	// BeforeDerive is told the worst cost a set declares just before its envelope
	// keys are derived, so a caller can say a slow open is coming. It is not
	// called for envelopes that take no password, which derive nothing.
	BeforeDerive func(worst kdf.Params)
}

// ErrSchemesRequired indicates the set did not record its algorithms and none
// were supplied. The error returned is a *SchemesRequiredError, which also says
// how many layers need one.
var ErrSchemesRequired = cascade.ErrSchemesRequired

// ErrKeyRequired indicates a recipient layer could not be opened by any of the
// supplied private keys.
var ErrKeyRequired = cascade.ErrKeyRequired

// splitPrep is everything a split needs before the pieces are built: the shares
// and the metadata every piece repeats.
type splitPrep struct {
	details         format.Details // what every manifest, or the shared details, says
	shares          [][]byte
	data            []byte              // compact sets only: the sealed package and its fill
	disp            *disperse.Disperser // compact sets only: computes each piece's fragment
	detailShares    [][]byte            // sets with hidden details only
	setID           []byte
	payloadHash     []byte
	envPasswords    [][]byte
	envRecipients   []*kem.PublicKey
	envelopeKeyless bool
	stretched       bool
	cleanup         func()
}

// prepare runs the pipeline up to the shares. The returned cleanup wipes the
// payload and any shares still held, and is safe to call after an error.
func prepare(input []byte, opts SplitOptions) (*splitPrep, error) {
	if err := checkSplitOptions(&opts); err != nil {
		return nil, err
	}
	info, err := EffectiveInfo(opts)
	if err != nil {
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
	defer layerCleanup()
	if err != nil {
		return nil, err
	}
	if len(envPasswords) == 0 && !opts.Keyless && !hybrid {
		return nil, errors.New("core: a split needs at least one password layer, a recipient layer, or keyless mode")
	}
	payloadLen, err := cascade.Len(len(input), layers)
	if err != nil {
		return nil, err
	}

	// A protected envelope takes the first layer's secret and a strict one every
	// secret. Otherwise it uses the public keyless derivation, which is also what
	// a split-only set uses.
	stretched := len(envPasswords) > 0
	envelopeKeyless := info != InfoProtected && info != InfoStrict

	descs := make([]cascade.Descriptor, len(layers))
	for i, l := range layers {
		descs[i] = cascade.Descriptor{Kind: l.Kind, SchemeID: l.SchemeID, Recorded: opts.RecordAlgo}
	}
	prep := &splitPrep{
		details: format.Details{
			K: opts.K, N: opts.N,
			Encrypted: len(layers) > 0, Hybrid: hybrid,
			AlgoStored: opts.RecordAlgo, KDFStored: opts.RecordKDF && stretched,
			Params: opts.Params, Layers: descs,
			Name: opts.Name, CreatorVersion: opts.CreatorVersion, CreatorCommit: opts.CreatorCommit,
		},
		envelopeKeyless: envelopeKeyless, stretched: stretched,
	}
	prep.envPasswords, prep.envRecipients = envelopeSecrets(opts.Layers, info)
	prep.cleanup = func() {
		wipeCanon()
		memory.FreeAll(prep.shares)
		memory.Zero(prep.data)
		memory.FreeAll(prep.detailShares)
	}
	fail := func(err error) (*splitPrep, error) {
		prep.cleanup()
		committed = true
		return nil, err
	}

	shape := format.Shape{Encaps: format.EncapsLen(prep.envRecipients), Layers: len(descs), Meta: prep.details.TextLen()}
	if info == InfoHidden {
		if prep.detailShares, err = prep.shareDetails(); err != nil {
			return fail(err)
		}
		shape = format.Shape{Details: len(prep.detailShares[0])}
	}

	// The payload is encrypted straight into the buffer the method shares or
	// disperses, so the split never holds it twice.
	encrypt := func(dst []byte) error {
		return cascade.EncryptTo(dst, input, layers, opts.Params, opts.RecordAlgo)
	}
	if opts.Method == MethodCompact {
		err = prep.disperse(payloadLen, encrypt, opts, shape)
	} else {
		err = prep.share(payloadLen, encrypt, opts, shape)
	}
	if err != nil {
		return fail(err)
	}

	prep.setID = make([]byte, format.SetIDLen)
	if _, err := rand.Read(prep.setID); err != nil {
		return fail(err)
	}
	committed = true
	return prep, nil
}

// share is the full method: the payload itself, padded with fill, is shared.
// encrypt writes the payload of payloadLen bytes into the buffer that is shared.
func (p *splitPrep) share(payloadLen int, encrypt func([]byte) error, opts SplitOptions, shape format.Shape) error {
	shared := make([]byte, format.SharedLen(payloadLen, fillLen(payloadLen, opts, shape)))
	defer memory.Zero(shared)
	if err := split.ValidateParams(opts.N, opts.K, len(shared)); err != nil {
		return err
	}
	if err := encrypt(shared[format.PayloadAt : format.PayloadAt+payloadLen]); err != nil {
		return err
	}
	hash, err := format.Wrap(shared, payloadLen)
	if err != nil {
		return err
	}
	shares, err := split.Split(shared, opts.N, opts.K)
	if err != nil {
		return err
	}
	p.shares, p.payloadHash = shares, hash
	return nil
}

// disperse is the compact method: the payload is sealed, the package padded to
// the size class and dispersed, and only the short secret that opens it is
// shared. encrypt writes the payload of payloadLen bytes into the buffer that
// is sealed and dispersed.
func (p *splitPrep) disperse(payloadLen int, encrypt func([]byte) error, opts SplitOptions, shape format.Shape) error {
	pkgLen := compact.PackageLen(payloadLen)
	keyed := format.SharedLen(compact.SecretLen, format.MinFill)
	if err := split.ValidateParams(opts.N, opts.K, keyed); err != nil {
		return err
	}
	shape.Share = split.ShareLen(keyed, opts.K)

	// The fragment is one coordinate byte and 1/K of the dispersed data, so the
	// data grows by K bytes for every byte the piece needs to reach its class.
	groups := (pkgLen + opts.K - 1) / opts.K
	if !opts.Padding.Off {
		shape.Fragment = disperse.FragmentLen(groups*opts.K, opts.K)
		natural := format.PieceLen(shape)
		groups += BucketFor(natural, opts.Padding.Width()) - natural
	}

	// The data is kept, and each fragment computed as its piece is written, so a
	// split holds one fragment at a time rather than all N. prep.cleanup wipes it.
	p.data = make([]byte, groups*opts.K)
	if err := encrypt(p.data[compact.PayloadAt : compact.PayloadAt+payloadLen]); err != nil {
		return err
	}
	secret, err := compact.Seal(p.data, payloadLen)
	if err != nil {
		return err
	}
	shared, hash, err := format.WrapPayload(secret, format.MinFill)
	memory.Zero(secret)
	if err != nil {
		return err
	}
	defer memory.Zero(shared)

	if p.shares, err = split.Split(shared, opts.N, opts.K); err != nil {
		return err
	}
	if p.disp, err = disperse.New(p.data, opts.N, opts.K); err != nil {
		return err
	}
	p.payloadHash = hash
	return nil
}

// shareDetails shares what the manifests would otherwise show, for a set that
// hides its details.
func (p *splitPrep) shareDetails() ([][]byte, error) {
	secret, err := format.EncodeDetails(p.details)
	if err != nil {
		return nil, err
	}
	defer memory.Zero(secret)
	return split.Split(secret, p.details.N, p.details.K)
}

// fillLen returns how much random fill to share after a payload of payloadLen
// bytes: format.MinFill, plus whatever brings the piece up to its size class.
// shape holds everything in the piece but the share. Every share has the same
// length and every manifest the same shape, so one fill length covers the set.
func fillLen(payloadLen int, opts SplitOptions, shape format.Shape) int {
	if opts.Padding.Off {
		return format.MinFill
	}
	overhead := format.PieceLen(shape)
	secret := format.SharedLen(payloadLen, format.MinFill)
	target := BucketFor(overhead+split.ShareLen(secret, opts.K), opts.Padding.Width())
	return format.MinFill + split.SecretLen(target-overhead, opts.K) - secret
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
	// Only an envelope that takes passwords derives a key from them, so only that
	// is bounded by the derivation memory budget.
	workers := parallel.Workers(opts.N)
	if len(prep.envPasswords) > 0 {
		workers = derivationWorkers(opts.Params, opts.N)
	}
	err = parallel.Do(opts.N, workers, func(i int) error {
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
		prep.release(i)
	}
	return nil
}

// release wipes and drops what piece i carried.
func (p *splitPrep) release(i int) {
	for _, set := range [][][]byte{p.shares, p.detailShares} {
		if i < len(set) {
			memory.Zero(set[i])
			set[i] = nil
		}
	}
}

// encode seals share i into a piece.
func (p *splitPrep) encode(i int, opts SplitOptions) ([]byte, error) {
	in := format.EncodeInput{
		Details:     p.details,
		SetID:       p.setID,
		Serial:      i + 1,
		Keyless:     p.envelopeKeyless,
		Stretched:   p.stretched,
		PayloadHash: p.payloadHash,
		Share:       p.shares[i],
		Passwords:   p.envPasswords,
		Recipients:  p.envRecipients,
	}
	if p.disp != nil {
		in.Fragment = p.disp.Fragment(i)
		defer memory.Zero(in.Fragment)
	}
	if p.detailShares != nil {
		in.DetailsShare = p.detailShares[i]
	}
	return format.Encode(in)
}

// MemoryEstimate reports roughly how much memory a split of this size needs, in
// bytes, using SplitTo.
//
// The payload is encrypted straight into what is shared or dispersed, so it is
// never held twice. The full method gives every share the full length of the
// payload, so the shares alone are N times the input: the input, the shared
// payload and N shares, then the input, N shares and one piece in flight. The
// compact method holds the input and the sealed data, then also one fragment and
// one piece of 1/K each, since fragments are computed as pieces are written.
func MemoryEstimate(inputLen, n, k int, m Method) int64 {
	in := int64(inputLen)
	if m != MethodCompact || k < 1 {
		return in * int64(n+2)
	}
	return 2*in + 2*in/int64(k)
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

// AssignSchemes resolves the algorithm for every layer. A layer that names one
// keeps it; a layer that leaves it zero gets the one suggested for its place,
// which never shares a design with the layer above. Two adjacent layers sharing
// an algorithm is rejected, so a break in one algorithm cannot carry through the
// whole cascade.
//
// Both the split path and the callers that must name the algorithms afterwards go
// through this, so they cannot disagree about what was used.
func AssignSchemes(layers []LayerSpec) ([]uint8, error) {
	out := make([]uint8, len(layers))
	var prev uint8
	for i, l := range layers {
		id := l.SchemeID
		if id == 0 {
			id = ciphers.Suggested(i, prev)
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
	if opts.Method != MethodFull && opts.Method != MethodCompact {
		return fmt.Errorf("core: unknown method %d", opts.Method)
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
