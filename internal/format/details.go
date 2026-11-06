// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package format

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/crypto/blake2b"

	"github.com/secu-tools/riven/internal/cascade"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/wire"
)

// Details is what a manifest says about its set. A set written with its details
// hidden keeps them out of every manifest and shares them like the content, so
// they are read back only from k pieces. Nothing on one piece then depends on a
// password, which is what stops a single piece being used to test guesses.
type Details struct {
	K, N       int
	Encrypted  bool
	Hybrid     bool
	AlgoStored bool
	KDFStored  bool
	Params     kdf.Params // meaningful when KDFStored
	Layers     []cascade.Descriptor

	// Name is the original file name, empty when it was not recorded. It is
	// untrusted: it comes from whoever wrote the piece. Callers that turn it into
	// a path must reduce it to a base name first.
	Name string

	// CreatorVersion and CreatorCommit identify the build that wrote the piece.
	// They are diagnostic only: they let a version mismatch be reported to the
	// user instead of failing with no explanation.
	CreatorVersion string
	CreatorCommit  string
}

// TextLen returns the length of the name and the creator strings together, which
// is what they add to a piece or to the details.
func (d *Details) TextLen() int { return len(d.Name) + len(d.CreatorVersion) + len(d.CreatorCommit) }

// Equal reports whether d and o describe the same set in every field.
func (d *Details) Equal(o *Details) bool {
	return d.K == o.K && d.N == o.N && d.flags() == o.flags() && d.Params == o.Params &&
		slices.Equal(d.Layers, o.Layers) && d.Name == o.Name &&
		d.CreatorVersion == o.CreatorVersion && d.CreatorCommit == o.CreatorCommit
}

// validate rejects details no piece can carry.
func (d *Details) validate() error {
	if d.K < 1 || d.N < d.K || d.N > 255 {
		return errors.New("format: invalid k/n/serial")
	}
	if len(d.Name) > MaxNameLen {
		return fmt.Errorf("format: recorded name is %d bytes, the limit is %d", len(d.Name), MaxNameLen)
	}
	if len(d.CreatorVersion) > MaxCreatorLen || len(d.CreatorCommit) > MaxCreatorLen {
		return fmt.Errorf("format: creator version/commit exceed %d bytes", MaxCreatorLen)
	}
	return nil
}

// empty reports whether d says nothing, as a manifest with hidden details must.
func (d *Details) empty() bool {
	return d.K == 0 && d.N == 0 && d.flags() == 0 && len(d.Layers) == 0 && d.TextLen() == 0
}

// flags packs the flags that describe the set.
func (d *Details) flags() uint8 {
	var f uint8
	for _, b := range []struct {
		on   bool
		flag uint8
	}{{d.Encrypted, flagEncrypted}, {d.Hybrid, flagHybrid}, {d.AlgoStored, flagAlgoRecorded}, {d.KDFStored, flagKDFRecorded}} {
		if b.on {
			f |= b.flag
		}
	}
	return f
}

// setFlags unpacks the flags that describe the set.
func (d *Details) setFlags(f uint8) {
	d.Encrypted = f&flagEncrypted != 0
	d.Hybrid = f&flagHybrid != 0
	d.AlgoStored = f&flagAlgoRecorded != 0
	d.KDFStored = f&flagKDFRecorded != 0
}

// writeMeta writes what the manifest and the details both carry after their
// fixed fields: a layer count, one descriptor per layer with the algorithm id or
// zero when it is not recorded, then the name and the two creator strings.
func (d *Details) writeMeta(w *wire.Writer) {
	w.U8(uint8(len(d.Layers)))
	for _, l := range d.Layers {
		w.U8(uint8(l.Kind))
		if d.AlgoStored {
			w.U8(l.SchemeID)
		} else {
			w.U8(0)
		}
	}
	w.Bytes([]byte(d.Name))
	w.Bytes([]byte(d.CreatorVersion))
	w.Bytes([]byte(d.CreatorCommit))
}

// detailsFixedLen is the details overhead that does not depend on the layers or
// the strings: flags, k, n, cost, layer count, three length prefixes, and the
// closing hash.
const detailsFixedLen = 5 + 12 + hashLen

// detailsStep is what the details are padded to a multiple of. The length of a
// details share is the one thing a hidden piece shows of them, so without the
// padding it would give away the name's length and the layer count. One step
// holds a few layers and a name of a hundred or so bytes, which is every
// ordinary set.
const detailsStep = 256

// DetailsLen returns the encoded length of details with that many layers and
// that much name and creator text, padding included, so the share length is
// known before the details exist.
func DetailsLen(layers, text int) int {
	n := detailsFixedLen + 2*layers + text
	return (n + detailsStep - 1) / detailsStep * detailsStep
}

// EncodeDetails returns the bytes a set shares to hide its details:
//
//	flags || k || n || cost || layer count || layers || name || version || commit
//	      || zero padding || hash
//
// in the field order of the manifest, with the cost unmasked, padded with zeros
// to a multiple of 256 bytes with the BLAKE2b-256 hash of everything before it
// last. The hash is what tells a rebuild from fewer than k shares, which
// interpolates to noise, from a real one.
func EncodeDetails(d Details) ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	var cost byte
	if d.KDFStored {
		c, err := d.Params.Encode()
		if err != nil {
			return nil, err
		}
		cost = c
	}
	size := DetailsLen(len(d.Layers), d.TextLen())
	w := wire.NewWriter(size)
	w.U8(d.flags())
	w.U8(uint8(d.K))
	w.U8(uint8(d.N))
	w.U8(cost)
	d.writeMeta(w)
	body := w.Result()
	body = append(body, make([]byte, size-hashLen-len(body))...)
	return append(body, detailsHash(body)...), nil
}

// DecodeDetails reads details written by EncodeDetails, reporting false when the
// hash does not match or the fields do not parse.
func DecodeDetails(b []byte) (*Details, bool) {
	if len(b) < detailsFixedLen {
		return nil, false
	}
	body, sum := b[:len(b)-hashLen], b[len(b)-hashLen:]
	if !bytes.Equal(detailsHash(body), sum) {
		return nil, false
	}
	r := newReader(body)
	flags, k, n, cost := r.u8(), r.u8(), r.u8(), r.u8()
	d := &Details{K: int(k), N: int(n)}
	d.setFlags(flags)
	r.meta(d)
	if r.err != nil || flags&^detailFlags != 0 || k < 1 || n < k {
		return nil, false
	}
	if d.KDFStored {
		d.Params = kdf.DecodeParams(cost)
	}
	// Whatever follows the fields is padding, and padding is zeros.
	for _, b := range r.RestView() {
		if b != 0 {
			return nil, false
		}
	}
	return d, true
}

func detailsHash(body []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("riven-details-v1"))
	h.Write(body)
	return h.Sum(nil)
}

// reader reads fields in order and keeps the first error, so a layout reads as
// the list of its fields with one check at the end. Once it has failed, every
// read returns zero.
type reader struct {
	*wire.Reader
	err error
}

func newReader(b []byte) *reader { return &reader{Reader: wire.NewReader(b)} }

func (r *reader) u8() uint8 {
	if r.err != nil {
		return 0
	}
	v, err := r.U8()
	r.err = err
	return v
}

func (r *reader) u16() uint16 {
	if r.err != nil {
		return 0
	}
	v, err := r.U16()
	r.err = err
	return v
}

// raw reads n bytes as a copy.
func (r *reader) raw(n int) []byte {
	if r.err != nil {
		return nil
	}
	v, err := r.Raw(n)
	r.err = err
	return v
}

// view reads a length-prefixed field of at most max bytes (none when max is
// zero) as a sub-slice of the buffer.
func (r *reader) view(max int) []byte {
	if r.err != nil {
		return nil
	}
	v, err := r.View(max)
	r.err = err
	return v
}

// meta reads what writeMeta wrote into d, whose flags are already set.
func (r *reader) meta(d *Details) {
	d.Layers = make([]cascade.Descriptor, r.u8())
	for i := range d.Layers {
		kind, id := r.u8(), r.u8()
		d.Layers[i] = cascade.Descriptor{Kind: cascade.Kind(kind), SchemeID: id, Recorded: d.AlgoStored}
	}
	name, cv, cc := r.view(MaxNameLen), r.view(MaxCreatorLen), r.view(MaxCreatorLen)
	d.Name, d.CreatorVersion, d.CreatorCommit = string(name), safeCreator(cv), safeCreator(cc)
}
