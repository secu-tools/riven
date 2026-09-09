// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package format

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/secu-tools/riven/internal/cascade"
	"github.com/secu-tools/riven/internal/kdf"
)

// TestPieceMatchesTheSpecification parses a piece using only what docs/format.md
// states, with no help from this package beyond the constructors. If the format
// drifts from the document, this fails.
func TestPieceMatchesTheSpecification(t *testing.T) {
	const (
		specHeaderLen = 41 // salt 16 + cost 1 + nonce 24
		specTagLen    = 16
		specFixedBody = 83 // version 2 + set id 16 + k/n/serial/flags 4 + len 8 + hash 32 + count 1 + five u32 prefixes 20 (name, creator version, creator commit, share, padding)
	)

	setID := []byte("0123456789abcdef")
	share := []byte{0x11, 0x22, 0x33, 0x44, 0x55}
	name := "spec.bin"
	hash := blake2b.Sum256([]byte("payload"))
	params := kdf.Params{Memory: 32 * 1024, Time: 3, Par: 2}
	password := []byte("spec password")
	const padLen = 9

	creatorVersion := "1.2.3"
	creatorCommit := "abc1234"

	piece, err := Encode(EncodeInput{
		SetID: setID, K: 3, N: 5, Serial: 2,
		PayloadLen: 7, PayloadHash: hash[:],
		Share: share, PadLen: padLen, Name: name,
		CreatorVersion: creatorVersion, CreatorCommit: creatorCommit,
		Encrypted: true, RecordAlgo: true, RecordKDF: true,
		Layers: []cascade.Descriptor{
			{Kind: cascade.Password, SchemeID: 2, Recorded: true},
			{Kind: cascade.KEM, SchemeID: 1, Recorded: true},
		},
		Passwords: [][]byte{password}, Params: params,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Section 2: the piece length formula.
	wantLen := specHeaderLen + specFixedBody + 2*2 + len(name) + len(creatorVersion) + len(creatorCommit) + len(share) + padLen + specTagLen
	if len(piece) != wantLen {
		t.Fatalf("piece is %d bytes, the specification says %d", len(piece), wantLen)
	}

	salt := piece[0:16]
	costByte := piece[16]
	nonce := piece[17:41]
	sealed := piece[41:]

	// Section 4: the cost byte unmasks to the recorded configuration.
	mask, _ := blake2b.New256(nil)
	mask.Write([]byte("riven-kdf-mask-v1"))
	mask.Write(salt)
	encoded := costByte ^ mask.Sum(nil)[0]
	gotMem := uint32(8<<((encoded>>5)&0x07)) * 1024
	gotTime := uint32((encoded>>2)&0x07) + 1
	gotPar := []uint8{1, 2, 4, 8}[encoded&0x03]
	if gotMem != params.Memory || gotTime != params.Time || gotPar != params.Par {
		t.Fatalf("cost byte decoded to m=%d t=%d p=%d, want m=%d t=%d p=%d",
			gotMem, gotTime, gotPar, params.Memory, params.Time, params.Par)
	}

	// Section 5.1: the envelope key, built from the document alone.
	seed, _ := blake2b.New256(nil)
	seed.Write([]byte("riven-pw-mix-v1"))
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(password)))
	seed.Write(lenbuf[:])
	seed.Write(password)
	key := params.Derive(seed.Sum(nil), salt)

	// Section 2: the associated data.
	ad := append(append([]byte("riven-piece-v1"), salt...), costByte)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := aead.Open(nil, nonce, sealed, ad)
	if err != nil {
		t.Fatalf("the envelope did not open with the documented key: %v", err)
	}

	// Section 3: the manifest field order.
	pos := 0
	u16 := func() uint16 { v := binary.BigEndian.Uint16(body[pos:]); pos += 2; return v }
	u8 := func() byte { v := body[pos]; pos++; return v }
	u64 := func() uint64 { v := binary.BigEndian.Uint64(body[pos:]); pos += 8; return v }
	raw := func(n int) []byte { v := body[pos : pos+n]; pos += n; return v }
	blob := func() []byte {
		n := int(binary.BigEndian.Uint32(body[pos:]))
		pos += 4
		v := body[pos : pos+n]
		pos += n
		return v
	}

	if v := u16(); v != 1 {
		t.Fatalf("version is %d, the specification says 1", v)
	}
	if got := raw(16); !bytes.Equal(got, setID) {
		t.Fatalf("set id is %x", got)
	}
	if k, n, serial := u8(), u8(), u8(); k != 3 || n != 5 || serial != 2 {
		t.Fatalf("k/n/serial are %d/%d/%d, want 3/5/2", k, n, serial)
	}

	// Section 3.1: the flag bits.
	flags := u8()
	const (
		flagEnc     = 0x01
		flagHyb     = 0x02
		flagAlgoRec = 0x04
		flagKDFRec  = 0x08
		flagKeyless = 0x10
	)
	if flags&flagEnc == 0 || flags&flagAlgoRec == 0 || flags&flagKDFRec == 0 {
		t.Fatalf("flags are %#02x, want encrypted and both recording bits", flags)
	}
	if flags&flagKeyless != 0 {
		t.Fatalf("flags are %#02x, this piece has a password", flags)
	}
	if flags&0xE0 != 0 {
		t.Fatalf("flags are %#02x, bits 5 to 7 are reserved and must be zero", flags)
	}

	if got := u64(); got != 7 {
		t.Fatalf("payload length is %d, want 7", got)
	}
	if got := raw(32); !bytes.Equal(got, hash[:]) {
		t.Fatalf("payload hash is %x", got)
	}

	// Section 3.2: two bytes per layer, outermost first.
	if count := u8(); count != 2 {
		t.Fatalf("layer count is %d, want 2", count)
	}
	if kind, algo := u8(), u8(); kind != 0 || algo != 2 {
		t.Fatalf("layer 1 is kind %d algorithm %d, want 0 and 2", kind, algo)
	}
	if kind, algo := u8(), u8(); kind != 1 || algo != 1 {
		t.Fatalf("layer 2 is kind %d algorithm %d, want 1 and 1", kind, algo)
	}

	if got := blob(); string(got) != name {
		t.Fatalf("name is %q, want %q", got, name)
	}
	if got := blob(); string(got) != creatorVersion {
		t.Fatalf("creator version is %q, want %q", got, creatorVersion)
	}
	if got := blob(); string(got) != creatorCommit {
		t.Fatalf("creator commit is %q, want %q", got, creatorCommit)
	}
	if got := blob(); !bytes.Equal(got, share) {
		t.Fatalf("share is %x, want %x", got, share)
	}
	if got := blob(); len(got) != padLen {
		t.Fatalf("padding is %d bytes, want %d", len(got), padLen)
	}
	if pos != len(body) {
		t.Fatalf("%d bytes left after the documented fields", len(body)-pos)
	}
}

// TestKeylessEnvelopeMatchesTheSpecification checks the public derivation of
// section 5.2, which is what lets anyone read the metadata of a set that has no
// password.
func TestKeylessEnvelopeMatchesTheSpecification(t *testing.T) {
	piece, err := Encode(EncodeInput{
		SetID: make([]byte, 16), K: 2, N: 3, Serial: 1,
		PayloadLen: 4, PayloadHash: make([]byte, 32),
		Share: []byte{1, 2, 3, 4, 5}, Keyless: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	salt, costByte, nonce, sealed := piece[0:16], piece[16], piece[17:41], piece[41:]

	h, _ := blake2b.New256(nil)
	h.Write([]byte("riven-keyless-envelope-v1"))
	h.Write(salt)
	aead, err := chacha20poly1305.NewX(h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	ad := append(append([]byte("riven-piece-v1"), salt...), costByte)
	body, err := aead.Open(nil, nonce, sealed, ad)
	if err != nil {
		t.Fatalf("the keyless envelope did not open with the documented key: %v", err)
	}
	if flags := body[21]; flags&0x10 == 0 {
		t.Fatalf("flags are %#02x, the keyless bit should be set", flags)
	}
}
