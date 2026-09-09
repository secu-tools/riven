// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// ctrHMAC implements cipher.AEAD as AES-256-CTR followed by HMAC-SHA-256
// (Encrypt-then-MAC). It provides a construction distinct from the Poly1305 and
// GCM families so a cascade can alternate authentication designs. The input key
// is split into independent encryption and MAC keys with HKDF-SHA-512.
type ctrHMAC struct {
	block   cipher.Block
	macKey  []byte
	nonceSz int
	tagSz   int
}

const (
	ctrHMACNonceSize = 16
	ctrHMACTagSize   = sha256.Size // 32
)

func newAESCTRHMAC(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("ciphers: aes-ctr-hmac requires a 32-byte key")
	}
	r := hkdf.New(sha512.New, key, nil, []byte("riven-aes-ctr-hmac-v1"))
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	if _, err := io.ReadFull(r, encKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, macKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	for i := range encKey {
		encKey[i] = 0
	}
	if err != nil {
		return nil, err
	}
	return &ctrHMAC{block: block, macKey: macKey, nonceSz: ctrHMACNonceSize, tagSz: ctrHMACTagSize}, nil
}

func (c *ctrHMAC) NonceSize() int { return c.nonceSz }
func (c *ctrHMAC) Overhead() int  { return c.tagSz }

// tag computes HMAC-SHA-256 over a length-prefixed encoding of the associated
// data, the nonce, and the ciphertext, binding all three together.
func (c *ctrHMAC) tag(nonce, ciphertext, additionalData []byte) []byte {
	mac := hmac.New(sha256.New, c.macKey)
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(additionalData)))
	mac.Write(l[:])
	mac.Write(additionalData)
	binary.BigEndian.PutUint64(l[:], uint64(len(nonce)))
	mac.Write(l[:])
	mac.Write(nonce)
	mac.Write(ciphertext)
	return mac.Sum(nil)
}

func (c *ctrHMAC) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.nonceSz {
		panic("ciphers: incorrect nonce length given to aes-ctr-hmac")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+c.tagSz)
	ct := out[:len(plaintext)]
	stream := cipher.NewCTR(c.block, nonce)
	stream.XORKeyStream(ct, plaintext)
	t := c.tag(nonce, ct, additionalData)
	copy(out[len(plaintext):], t)
	return ret
}

func (c *ctrHMAC) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.nonceSz {
		return nil, errors.New("ciphers: incorrect nonce length")
	}
	if len(ciphertext) < c.tagSz {
		return nil, errAuthFailed
	}
	ct := ciphertext[:len(ciphertext)-c.tagSz]
	tag := ciphertext[len(ciphertext)-c.tagSz:]
	expected := c.tag(nonce, ct, additionalData)
	if subtle.ConstantTimeCompare(expected, tag) != 1 {
		return nil, errAuthFailed
	}
	ret, out := sliceForAppend(dst, len(ct))
	stream := cipher.NewCTR(c.block, nonce)
	stream.XORKeyStream(out, ct)
	return ret, nil
}

var errAuthFailed = errors.New("ciphers: message authentication failed")

// sliceForAppend extends in by n bytes and returns the extended slice plus the
// tail to write into, mirroring the pattern used by the stdlib AEADs.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
