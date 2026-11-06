// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package compact seals a payload so it can be dispersed rather than shared: the
// compact split method. Each piece then carries 1/k of the sealed data and a
// Shamir share of a short secret, instead of a share as long as the whole payload.
//
// The payload is sealed in two layers under fresh random keys, padded with random
// fill, and put through an all-or-nothing transform:
//
//	inner = nonce1(12) || AES-256-GCM(key1, nonce1, payload, "riven-compact-v1" || 1)
//	outer = nonce2(24) || XChaCha20-Poly1305(key2, nonce2, inner, "riven-compact-v1" || 3)
//	c     = (outer || fill) XOR ChaCha20(key3, nonce = 0)
//	data  = c || (key3 XOR BLAKE2b-256("riven-aont-v1" || c))
//
// The data is what is dispersed, and the secret shared is the length of outer,
// key1 and key2. key3 is recovered from the data itself, but only from all of it:
// without every byte of c its hash is unknown, so is key3, and so is every byte
// of outer. A reader holding fewer fragments than the threshold therefore has
// nothing that decrypts, even before the two keyed layers are reached. The layers
// use different cipher families, so reading a fragment would need both broken as
// well.
//
// That is a computational guarantee: the fragments are ciphertext, and they stay
// unreadable as long as AES-256 and ChaCha20 hold. The full method's Shamir shares
// are not ciphertext at all, and fewer than k of them are proven to reveal
// nothing, which is why it is the safer of the two.
//
// The transform also makes every byte count. A changed byte anywhere, the fill
// and the tail included, changes the hash or the tail, so key3 comes out wrong,
// all of outer decrypts to noise, and its authentication fails.
package compact

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/memory"
	"github.com/secu-tools/riven/internal/parallel"
)

const (
	keyLen = 32

	// KeysLen is the length of key1 and key2 together.
	KeysLen = 2 * keyLen

	// SecretLen is the length of the secret Seal returns for sharing: the length
	// of outer (8 bytes, big-endian), key1 and key2.
	SecretLen = 8 + KeysLen

	nonce1Len = 12
	nonce2Len = 24
	tagLen    = 16
	aontLen   = 32

	// PayloadAt is where Seal expects the payload in its buffer: after the two
	// nonces, so that both layers seal in place.
	PayloadAt = nonce2Len + nonce1Len

	// sealedOverhead is what the two layers add: outer is the payload plus this.
	sealedOverhead = nonce2Len + nonce1Len + 2*tagLen

	// Overhead is what the data adds to the payload at the least: the two layers
	// and the transform's tail.
	Overhead = sealedOverhead + aontLen

	innerID = 1 // aes-256-gcm, docs/format.md section 8.1
	outerID = 3 // xchacha20-poly1305
)

// ErrIntegrity is returned when the data does not open with the secret: a wrong
// key, a wrong fragment, or a damaged byte anywhere in the data, fill included.
var ErrIntegrity = errors.New("compact: the package did not open (wrong or damaged pieces)")

// PackageLen returns the least data a payload of payloadLen bytes seals into.
func PackageLen(payloadLen int) int { return payloadLen + Overhead }

// Seal seals the payloadLen bytes the caller wrote at data[PayloadAt:], in place,
// fills the room after them with random bytes and transforms the lot, so that all
// of data is what gets dispersed. It returns the secret to share. len(data) must
// be at least PackageLen(payloadLen); on an error data is wiped.
func Seal(data []byte, payloadLen int) (secret []byte, err error) {
	if payloadLen < 0 || len(data) < PackageLen(payloadLen) {
		return nil, fmt.Errorf("compact: %d bytes do not hold a package of %d", len(data), PackageLen(payloadLen))
	}
	outerLen := payloadLen + sealedOverhead
	secret = make([]byte, SecretLen)
	key3 := make([]byte, keyLen)
	defer memory.Zero(key3)
	fail := func(err error) ([]byte, error) {
		memory.Zero(data)
		memory.Zero(secret)
		return nil, err
	}
	keys := secret[8:]
	for _, b := range [][]byte{keys, key3, data[:PayloadAt], data[outerLen:]} {
		if _, err := rand.Read(b); err != nil {
			return fail(err)
		}
	}

	// Each AEAD seals in place: its plaintext starts where its output starts.
	nonce1 := data[nonce2Len:PayloadAt]
	if err := seal(innerID, keys[:keyLen], nonce1, data[PayloadAt:PayloadAt+payloadLen]); err != nil {
		return fail(err)
	}
	nonce2 := data[:nonce2Len]
	if err := seal(outerID, keys[keyLen:], nonce2, data[nonce2Len:outerLen-tagLen]); err != nil {
		return fail(err)
	}

	c, tail := split(data)
	if err := keystream(key3, c); err != nil {
		return fail(err)
	}
	mask := aontMask(c)
	for i := range tail {
		tail[i] = key3[i] ^ mask[i]
	}
	binary.BigEndian.PutUint64(secret, uint64(outerLen))
	return secret, nil
}

// Open reverses Seal: data is everything that was dispersed and secret is what
// Seal returned. It works in place and returns the payload as a sub-slice of data.
func Open(data, secret []byte) ([]byte, error) {
	if len(secret) != SecretLen {
		return nil, errors.New("compact: the shared secret is malformed")
	}
	if len(data) < Overhead {
		return nil, ErrIntegrity
	}
	c, tail := split(data)
	outerLen := binary.BigEndian.Uint64(secret)
	if outerLen < sealedOverhead || outerLen > uint64(len(c)) {
		return nil, ErrIntegrity
	}
	keys := secret[8:]

	mask := aontMask(c)
	key3 := make([]byte, keyLen)
	defer memory.Zero(key3)
	for i := range key3 {
		key3[i] = tail[i] ^ mask[i]
	}
	if err := keystream(key3, c); err != nil {
		return nil, err
	}

	outer := c[:outerLen]
	inner, err := open(outerID, keys[keyLen:], outer[:nonce2Len], outer[nonce2Len:])
	if err != nil {
		return nil, err
	}
	return open(innerID, keys[:keyLen], inner[:nonce1Len], inner[nonce1Len:])
}

// split separates the transformed bytes from the transform's tail, which ends
// the data.
func split(data []byte) (c, tail []byte) {
	return data[:len(data)-aontLen], data[len(data)-aontLen:]
}

// seal encrypts buf in place with the scheme id, writing the tag after it. buf
// must be followed by room for the tag in its backing array.
func seal(id uint8, key, nonce, buf []byte) error {
	aead, err := newAEAD(id, key)
	if err != nil {
		return err
	}
	aead.Seal(buf[:0], nonce, buf, ad(id))
	return nil
}

// open decrypts ct in place and returns the plaintext.
func open(id uint8, key, nonce, ct []byte) ([]byte, error) {
	aead, err := newAEAD(id, key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(ct[:0], nonce, ct, ad(id))
	if err != nil {
		return nil, ErrIntegrity
	}
	return pt, nil
}

func newAEAD(id uint8, key []byte) (cipher.AEAD, error) {
	scheme, ok := ciphers.ByID(id)
	if !ok {
		return nil, fmt.Errorf("compact: unknown scheme %d", id)
	}
	return scheme.New(key)
}

func ad(id uint8) []byte { return append([]byte("riven-compact-v1"), id) }

// streamChunk is how much of the keystream one worker produces. ChaCha20 can
// start at any 64-byte block, so the chunks are independent and the result is
// byte for byte the single stream, however many cores run it.
const streamChunk = 1 << 20

// maxStream is the most one ChaCha20 stream covers: its block counter is 32 bits.
const maxStream = 1 << 38

// keystream XORs buf with ChaCha20 under key and an all-zero nonce, a chunk per
// core. The key is fresh for every package, so the nonce never repeats under it.
// This pass has no assembly in x/crypto, so on one core it would be the slowest
// step of the compact method.
func keystream(key, buf []byte) error {
	if len(buf) > maxStream {
		return fmt.Errorf("compact: %d bytes is more than one keystream covers", len(buf))
	}
	chunks := (len(buf) + streamChunk - 1) / streamChunk
	return parallel.Do(chunks, parallel.Workers(chunks), func(i int) error {
		s, err := chacha20.NewUnauthenticatedCipher(key, make([]byte, chacha20.NonceSize))
		if err != nil {
			return err
		}
		lo := i * streamChunk
		s.SetCounter(uint32(lo / 64))
		part := buf[lo:min(lo+streamChunk, len(buf))]
		s.XORKeyStream(part, part)
		return nil
	})
}

func aontMask(c []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("riven-aont-v1"))
	h.Write(c)
	return h.Sum(nil)
}
