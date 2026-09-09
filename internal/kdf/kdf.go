// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package kdf derives keys from passwords with Argon2id.
//
// Cost parameters pack into a single byte so a piece can record them without
// leaking a fingerprint: memory, passes, and parallelism are each restricted to
// a small set of realistic values, so every one of the 256 byte values decodes
// to a plausible configuration. Random data therefore decodes to a valid
// configuration as well, leaving no way to tell a recorded byte from noise.
package kdf

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

const (
	// KeyLen is the derived key length in bytes (256-bit; quantum-resistant
	// under Grover to a 128-bit effective security level).
	KeyLen = 32
	// SaltLen is the per-derivation salt length in bytes.
	SaltLen = 16
	// ParamsLen is the encoded length of a Params value in bytes.
	ParamsLen = 1
)

// memTable lists the selectable memory sizes in KiB, indexed by a 3-bit code.
var memTable = [8]uint32{
	8 * 1024, 16 * 1024, 32 * 1024, 64 * 1024,
	128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024,
}

// parTable lists the selectable parallelism degrees, indexed by a 2-bit code.
var parTable = [4]uint8{1, 2, 4, 8}

// Params is an Argon2id cost configuration.
type Params struct {
	Memory uint32 // KiB, must be one of memTable
	Time   uint32 // passes, 1..8
	Par    uint8  // parallelism, must be one of parTable
}

// Presets. Recommended is RFC 9106's second recommended option; the stronger
// presets cost proportionally more because a key is derived per piece.
var (
	Recommended = Params{Memory: 64 * 1024, Time: 3, Par: 4}
	Paranoid    = Params{Memory: 256 * 1024, Time: 4, Par: 4}
	Max         = Params{Memory: 1024 * 1024, Time: 4, Par: 4}
)

// presets maps preset names to values. Names are stable and case-insensitive.
var presets = map[string]Params{
	"recommended": Recommended,
	"paranoid":    Paranoid,
	"max":         Max,
}

// Default returns the configuration used when the user does not choose one.
func Default() Params { return Recommended }

// PresetNames returns the preset names in increasing cost order.
func PresetNames() []string {
	names := make([]string, 0, len(presets))
	for n := range presets {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		return presets[names[i]].Memory < presets[names[j]].Memory
	})
	return names
}

// MaxMemory is the largest selectable memory size, in KiB. A caller that has to
// budget for a derivation before reading its recorded cost assumes this.
var MaxMemory = memTable[len(memTable)-1]

// MemoryChoices returns the selectable memory sizes in MiB, ascending.
func MemoryChoices() []uint32 {
	out := make([]uint32, len(memTable))
	for i, m := range memTable {
		out[i] = m / 1024
	}
	return out
}

// ParChoices returns the selectable parallelism degrees, ascending.
func ParChoices() []uint8 {
	out := make([]uint8, len(parTable))
	copy(out[:], parTable[:])
	return out
}

// MaxTime is the highest number of passes that can be encoded.
const MaxTime = 8

// Validate reports whether p can be encoded.
func (p Params) Validate() error {
	if _, ok := memCode(p.Memory); !ok {
		return fmt.Errorf("kdf: memory must be one of %v MiB", MemoryChoices())
	}
	if p.Time < 1 || p.Time > MaxTime {
		return fmt.Errorf("kdf: passes must be between 1 and %d", MaxTime)
	}
	if _, ok := parCode(p.Par); !ok {
		return fmt.Errorf("kdf: parallelism must be one of %v", ParChoices())
	}
	return nil
}

// Encode packs p into one byte.
func (p Params) Encode() (byte, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	m, _ := memCode(p.Memory)
	q, _ := parCode(p.Par)
	return m<<5 | byte(p.Time-1)<<2 | q, nil
}

// DecodeParams unpacks a byte produced by Encode. Every byte value is valid.
func DecodeParams(b byte) Params {
	return Params{
		Memory: memTable[b>>5],
		Time:   uint32((b>>2)&0x07) + 1,
		Par:    parTable[b&0x03],
	}
}

func memCode(kib uint32) (byte, bool) {
	for i, m := range memTable {
		if m == kib {
			return byte(i), true
		}
	}
	return 0, false
}

func parCode(p uint8) (byte, bool) {
	for i, v := range parTable {
		if v == p {
			return byte(i), true
		}
	}
	return 0, false
}

// MaskParams hides an encoded params byte behind a keystream derived from salt.
// It is its own inverse. The mask is public, so unmasking noise still yields a
// valid configuration and reveals nothing.
func MaskParams(encoded byte, salt []byte) byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("riven-kdf-mask-v1"))
	h.Write(salt)
	return encoded ^ h.Sum(nil)[0]
}

// Derive runs Argon2id and returns a KeyLen-byte key. The caller owns key and
// should wipe it when done.
func (p Params) Derive(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Par, KeyLen)
}

// String renders p in the same syntax Parse accepts.
func (p Params) String() string {
	for _, n := range PresetNames() {
		if presets[n] == p {
			return n
		}
	}
	return fmt.Sprintf("m=%d,t=%d,p=%d", p.Memory/1024, p.Time, p.Par)
}

// Describe renders p for display, always showing the numbers.
func (p Params) Describe() string {
	return fmt.Sprintf("Argon2id %d MiB, %d passes, %d lanes", p.Memory/1024, p.Time, p.Par)
}

// Parse accepts a preset name or an explicit "m=<MiB>,t=<passes>,p=<lanes>"
// specification. Any subset of the explicit keys may be given; the rest come
// from the recommended preset.
func Parse(s string) (Params, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return Default(), nil
	}
	if p, ok := presets[s]; ok {
		return p, nil
	}
	if !strings.ContainsAny(s, "=") {
		return Params{}, fmt.Errorf("kdf: unknown preset %q (choose from %v, or use m=..,t=..,p=..)", s, PresetNames())
	}
	p := Default()
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, val, ok := strings.Cut(field, "=")
		if !ok {
			return Params{}, fmt.Errorf("kdf: cannot parse %q", field)
		}
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || n < 0 {
			return Params{}, fmt.Errorf("kdf: bad value in %q", field)
		}
		switch strings.TrimSpace(key) {
		case "m", "memory":
			p.Memory = uint32(n) * 1024
		case "t", "time", "passes":
			p.Time = uint32(n)
		case "p", "par", "lanes":
			p.Par = uint8(n)
		default:
			return Params{}, fmt.Errorf("kdf: unknown key %q (use m, t, p)", key)
		}
	}
	if err := p.Validate(); err != nil {
		return Params{}, err
	}
	return p, nil
}

// MixPasswords combines an ordered list of passwords into a single high-entropy
// seed such that every password is required to reproduce it. Order matters.
func MixPasswords(passwords [][]byte) []byte {
	h, _ := blake2b.New256(nil)
	var lenbuf [4]byte
	// Domain separation and length prefixing prevent concatenation ambiguity,
	// so {"ab","c"} and {"a","bc"} never collide.
	h.Write([]byte("riven-pw-mix-v1"))
	for _, pw := range passwords {
		lenbuf[0] = byte(len(pw) >> 24)
		lenbuf[1] = byte(len(pw) >> 16)
		lenbuf[2] = byte(len(pw) >> 8)
		lenbuf[3] = byte(len(pw))
		h.Write(lenbuf[:])
		h.Write(pw)
	}
	return h.Sum(nil)
}
