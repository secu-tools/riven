// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/twofish"
)

// This file reads what the binary writes using nothing but docs/format.md and the
// standard primitives it names, the way someone without this tool would. From
// there it checks two promises: the document is enough to rebuild a set from the
// threshold and the keys, and someone below the threshold learns nothing about
// the content, even holding every password.

// specManifest is what section 3 says a sealed manifest holds.
type specManifest struct {
	body   []byte // the whole manifest, for searching
	setID  []byte
	k, n   int
	serial int
	hash   []byte
	share  []byte
}

func blake(parts ...[]byte) []byte {
	h, _ := blake2b.New256(nil)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// specReader reads section 3 and section 8 fields, recording the first overrun
// rather than panicking on a malformed body.
type specReader struct {
	b   []byte
	err error
}

func (r *specReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.b) {
		r.err = errors.New("field runs past the end")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *specReader) u8() byte {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *specReader) blob() []byte {
	if n := r.take(4); n != nil {
		return r.take(int(binary.BigEndian.Uint32(n)))
	}
	return nil
}

// specCost decodes the masked cost byte of section 4.
type specCost struct {
	memKiB, passes uint32
	lanes          uint8
}

func costOf(piece []byte) specCost {
	enc := piece[16] ^ blake([]byte("riven-kdf-mask-v1"), piece[:16])[0]
	return specCost{
		memKiB: uint32(8<<(enc>>5)) * 1024,
		passes: uint32((enc>>2)&7) + 1,
		lanes:  []uint8{1, 2, 4, 8}[enc&3],
	}
}

// openBySpec opens a piece as sections 2, 3 and 5 describe. No passwords means
// the keyless envelope of section 5.2.
func openBySpec(piece []byte, passwords [][]byte) (*specManifest, error) {
	if len(piece) < 57 {
		return nil, errors.New("shorter than a piece")
	}
	salt, cost, nonce := piece[:16], piece[16], piece[17:41]
	var key []byte
	if len(passwords) == 0 {
		key = blake([]byte("riven-keyless-envelope-v1"), salt)
	} else {
		mix := [][]byte{[]byte("riven-pw-mix-v1")}
		for _, pw := range passwords {
			mix = append(mix, binary.BigEndian.AppendUint32(nil, uint32(len(pw))), pw)
		}
		c := costOf(piece)
		key = argon2.IDKey(blake(mix...), salt, c.passes, c.memKiB, c.lanes, 32)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	ad := append(append([]byte("riven-piece-v1"), salt...), cost)
	body, err := aead.Open(nil, nonce, piece[41:], ad)
	if err != nil {
		return nil, err
	}

	r := &specReader{b: body}
	r.take(2) // version
	m := &specManifest{body: body, setID: r.take(16)}
	m.k, m.n, m.serial = int(r.u8()), int(r.u8()), int(r.u8())
	r.take(1) // flags
	m.hash = r.take(32)
	r.take(2 * int(r.u8())) // layer descriptors
	r.blob()                // file name
	r.blob()                // creator version
	r.blob()                // creator commit
	m.share = r.blob()
	return m, r.err
}

// gfMul multiplies in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, as section 6 states.
func gfMul(a, b byte) byte {
	var p byte
	for ; b != 0; b >>= 1 {
		if b&1 != 0 {
			p ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1B
		}
	}
	return p
}

// gfInv returns a^254, which is the inverse of a for non-zero a.
func gfInv(a byte) byte {
	r := byte(1)
	for i := 0; i < 254; i++ {
		r = gfMul(r, a)
	}
	return r
}

// interpolateBySpec rebuilds a payload from shares of threshold two or more, chunk
// by chunk, with the formula of section 6. Given fewer shares than the threshold
// it still returns bytes, which is what an attacker would work with.
func interpolateBySpec(shares [][]byte) []byte {
	const chunkShare = 524288 + 1
	total := len(shares[0])
	var out []byte
	for lo := 0; lo < total; lo += chunkShare {
		hi := min(lo+chunkShare, total)
		coef := make([]byte, len(shares))
		for i := range shares {
			xi := shares[i][hi-1]
			coef[i] = 1
			for j := range shares {
				if j != i {
					xj := shares[j][hi-1]
					coef[i] = gfMul(coef[i], gfMul(xj, gfInv(xi^xj)))
				}
			}
		}
		for pos := lo; pos < hi-1; pos++ {
			var s byte
			for i, sh := range shares {
				s ^= gfMul(sh[pos], coef[i])
			}
			out = append(out, s)
		}
	}
	return out
}

// unwrapBySpec checks interpolated shared bytes against the payload hash and
// returns the payload: an 8-byte big-endian length, then the payload, then at
// least 32 bytes of fill (sections 6 and 10).
func unwrapBySpec(t *testing.T, shared, hash []byte) []byte {
	t.Helper()
	if len(shared) < 8+32 || !bytes.Equal(blake(shared), hash) {
		t.Fatal("the interpolated bytes do not match the payload hash (section 10, step 5)")
	}
	n := binary.BigEndian.Uint64(shared)
	if n > uint64(len(shared)-8-32) {
		t.Fatalf("the recorded length %d leaves less than 32 bytes of fill", n)
	}
	return shared[8 : 8+n]
}

// openLayerBySpec opens one cascade layer with the algorithm of section 8.1.
func openLayerBySpec(algo byte, key, nonce, sealed, ad []byte) ([]byte, error) {
	var aead cipher.AEAD
	var err error
	switch algo {
	case 1:
		var block cipher.Block
		if block, err = aes.NewCipher(key); err == nil {
			aead, err = cipher.NewGCM(block)
		}
	case 2:
		aead, err = chacha20poly1305.New(key)
	case 3:
		aead, err = chacha20poly1305.NewX(key)
	case 4:
		var block cipher.Block
		if block, err = twofish.NewCipher(key); err == nil {
			aead, err = cipher.NewGCM(block)
		}
	case 5:
		return openCTRHMACBySpec(key, nonce, sealed, ad)
	default:
		return nil, fmt.Errorf("algorithm %d is not in section 8.1", algo)
	}
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("nonce length does not fit the algorithm")
	}
	return aead.Open(nil, nonce, sealed, ad)
}

// openCTRHMACBySpec is the aes-256-ctr-hmac construction of section 8.1.
func openCTRHMACBySpec(key, nonce, sealed, ad []byte) ([]byte, error) {
	if len(nonce) != 16 || len(sealed) < 32 {
		return nil, errors.New("malformed aes-256-ctr-hmac layer")
	}
	keys := make([]byte, 64)
	if _, err := io.ReadFull(hkdf.New(sha512.New, key, nil, []byte("riven-aes-ctr-hmac-v1")), keys); err != nil {
		return nil, err
	}
	ct, tag := sealed[:len(sealed)-32], sealed[len(sealed)-32:]
	mac := hmac.New(sha256.New, keys[32:])
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(ad))))
	mac.Write(ad)
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(nonce))))
	mac.Write(nonce)
	mac.Write(ct)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, errors.New("aes-256-ctr-hmac tag does not match")
	}
	block, err := aes.NewCipher(keys[:32])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCTR(block, nonce).XORKeyStream(out, ct)
	return out, nil
}

// peelBySpec removes the cascade of section 8, outermost layer first. Password
// layers take the passwords in order at the envelope's cost; recipient layers are
// opened with priv, an x25519 key, through HPKE as section 8.2 describes.
func peelBySpec(payload []byte, passwords [][]byte, cost specCost, priv hpke.PrivateKey) ([]byte, error) {
	r := &specReader{b: payload}
	if v := r.take(2); v == nil || binary.BigEndian.Uint16(v) != 1 {
		return nil, errors.New("not a version 1 cascade header")
	}
	type layer struct {
		kind, algo        byte
		salt, nonce, encK []byte
	}
	layers := make([]layer, r.u8())
	for i := range layers {
		layers[i] = layer{kind: r.u8(), algo: r.u8(), salt: r.blob(), nonce: r.blob(), encK: r.blob()}
	}
	if r.err != nil {
		return nil, r.err
	}

	data := r.b
	for _, l := range layers {
		var key []byte
		switch l.kind {
		case 0:
			if len(passwords) == 0 {
				return nil, errors.New("more password layers than passwords")
			}
			key = argon2.IDKey(passwords[0], l.salt, cost.passes, cost.memKiB, cost.lanes, 32)
			passwords = passwords[1:]
		case 1:
			if priv == nil {
				return nil, errors.New("a recipient layer needs a private key")
			}
			rcpt, err := hpke.NewRecipient(l.encK, priv, hpke.HKDFSHA256(), hpke.ExportOnly(),
				[]byte("riven-recipient-v1:x25519"))
			if err != nil {
				return nil, err
			}
			secret, err := rcpt.Export("riven-layer-key-v1", 32)
			if err != nil {
				return nil, err
			}
			key = make([]byte, 32)
			if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte("riven-kem-layer-v1")), key); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("layer kind %d is not in section 8", l.kind)
		}
		var err error
		if data, err = openLayerBySpec(l.algo, key, l.nonce, data, append([]byte("riven-casc"), l.algo)); err != nil {
			return nil, err
		}
	}
	return data, nil
}

// readPrivateKeyBySpec reads an x25519 private key file as section 11 describes.
func readPrivateKeyBySpec(t *testing.T, path string) hpke.PrivateKey {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(string(body), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if len(lines) != 2 || lines[0] != "riven-x25519-private" {
		t.Fatalf("%s does not have the layout of section 11: %q", path, lines)
	}
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	priv, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func readPieces(t *testing.T, dir, base string, serials ...int) [][]byte {
	t.Helper()
	out := make([][]byte, len(serials))
	for i, s := range serials {
		b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%s.%d", base, s)))
		if err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}

// TestSpecAloneRebuildsTheFile splits with the binary and rebuilds with nothing
// but the document: a cascade of every algorithm with a recipient layer among the
// passwords, over more than one 512 KiB chunk, and a keyless set.
func TestSpecAloneRebuildsTheFile(t *testing.T) {
	dir := t.TempDir()
	input := randomBytes(600 << 10)
	in := writeFile(t, dir, "big.bin", input)
	pub, priv := filepath.Join(dir, "r.pub"), filepath.Join(dir, "r.key")
	if o, err := riven(t, nil, "keygen", "x25519", "--pub", pub, "--priv", priv, "-y"); err != nil {
		t.Fatalf("keygen: %v\n%s", err, o)
	}

	env := []string{"SPEC_P1=first", "SPEC_P2=second", "SPEC_P3=third", "SPEC_P4=fourth"}
	passwords := [][]byte{[]byte("first"), []byte("second"), []byte("third"), []byte("fourth")}
	out := filepath.Join(dir, "o")
	if o, err := riven(t, env, "split", in, "-n", "3", "-k", "2",
		"--password-env", "SPEC_P1", "--recipient", pub, "--password-env", "SPEC_P2",
		"--password-env", "SPEC_P3", "--password-env", "SPEC_P4",
		"--algo", "aes-256-gcm,chacha20-poly1305,xchacha20-poly1305,twofish-256-gcm,aes-256-ctr-hmac",
		"--identity", priv, "--kdf", "m=8,t=1,p=1", "--out", out, "-y"); err != nil {
		t.Fatalf("split: %v\n%s", err, o)
	}

	pieces := readPieces(t, out, "big.bin", 1, 3)
	a, err := openBySpec(pieces[0], passwords)
	if err != nil {
		t.Fatalf("piece 1 did not open by the document: %v", err)
	}
	b, err := openBySpec(pieces[1], passwords)
	if err != nil {
		t.Fatalf("piece 3 did not open by the document: %v", err)
	}
	if a.k != 2 || a.n != 3 || a.serial != 1 || b.serial != 3 {
		t.Fatalf("manifests read k=%d n=%d serials %d and %d", a.k, a.n, a.serial, b.serial)
	}
	if !bytes.Equal(a.setID, b.setID) || !bytes.Equal(a.hash, b.hash) {
		t.Fatal("two pieces of one set disagree about the set")
	}

	payload := unwrapBySpec(t, interpolateBySpec([][]byte{a.share, b.share}), a.hash)
	got, err := peelBySpec(payload, passwords, costOf(pieces[0]), readPrivateKeyBySpec(t, priv))
	if err != nil {
		t.Fatalf("the cascade did not peel by the document: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("the document rebuilt different content")
	}

	// A keyless set: no password, no layers, the public envelope key.
	small := []byte("keyless content, read without the tool")
	in = writeFile(t, dir, "k.bin", small)
	out = filepath.Join(dir, "k")
	if o, err := riven(t, nil, "split", in, "-n", "3", "-k", "2", "--keyless", "--out", out, "-y"); err != nil {
		t.Fatalf("keyless split: %v\n%s", err, o)
	}
	var shares [][]byte
	var hash []byte
	for _, p := range readPieces(t, out, "k.bin", 2, 3) {
		m, err := openBySpec(p, nil)
		if err != nil {
			t.Fatalf("a keyless piece did not open by the document: %v", err)
		}
		shares, hash = append(shares, m.share), m.hash
	}
	got, err = peelBySpec(unwrapBySpec(t, interpolateBySpec(shares), hash), nil, specCost{}, nil)
	if err != nil {
		t.Fatalf("a zero-layer payload did not parse: %v", err)
	}
	if !bytes.Equal(got, small) {
		t.Fatalf("the document rebuilt %q", got)
	}
}

// TestBelowThresholdRevealsNothingToAnAttacker plays someone holding two pieces
// of a 3-of-5 set who reads them with the document: once for a set with no
// password, and once for a set whose password they also hold. The content is as
// structured as a file gets, so any leak would stand out.
//
// The attacker succeeds if any of these hold: the content, or a run of it,
// appears in anything they can open; a piece's payload hash confirms a guess of
// the content; their best interpolation agrees with the real payload more often
// than chance; a share, or that interpolation, can be told apart from uniform
// noise; their interpolation opens with the password; or the binary itself
// rebuilds anything from the two pieces.
func TestBelowThresholdRevealsNothingToAnAttacker(t *testing.T) {
	marker := []byte("CONFIDENTIAL-")
	input := bytes.Repeat(append(append([]byte(nil), marker...), "line of a very regular file\n"...), 1100)

	modes := []struct {
		name      string
		env       []string
		flags     []string
		passwords [][]byte
	}{
		{"keyless", nil, []string{"--keyless"}, nil},
		{"password known to the attacker", env1,
			[]string{"--password-env", flagPw1, "--kdf", "m=8,t=1,p=1"},
			[][]byte{[]byte("layer-one-password")}},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeFile(t, dir, "secret.txt", input)
			out := filepath.Join(dir, "o")
			if o, err := riven(t, mode.env, append([]string{"split", in, "-n", "5", "-k", "3",
				"--out", out, "-y"}, mode.flags...)...); err != nil {
				t.Fatalf("split: %v\n%s", err, o)
			}

			pieces := readPieces(t, out, "secret.txt", 1, 2, 3, 4, 5)
			opened := make([]*specManifest, len(pieces))
			for i, p := range pieces {
				m, err := openBySpec(p, mode.passwords)
				if err != nil {
					t.Fatalf("piece %d did not open: %v", i+1, err)
				}
				if bytes.Contains(m.body, marker) {
					t.Fatalf("piece %d carries the content where the attacker can read it", i+1)
				}
				// A keyless payload is a fixed header and the content, so this is
				// the hash an attacker who guessed the content exactly would expect.
				if bytes.Equal(m.hash, blake(append([]byte{0, 1, 0}, input...))) {
					t.Fatalf("piece %d confirms a guess of the content", i+1)
				}
				if chi := chiSquare(m.share[:len(m.share)-1]); chi > 400 {
					t.Fatalf("the share in piece %d is not uniform (chi-square %.0f)", i+1, chi)
				}
				opened[i] = m
			}

			// The real payload, which the attacker never sees, to compare against.
			truth := interpolateBySpec([][]byte{opened[0].share, opened[1].share, opened[2].share})
			payloadLen := len(unwrapBySpec(t, truth, opened[0].hash))

			for i := range opened {
				for j := i + 1; j < len(opened); j++ {
					guess := interpolateBySpec([][]byte{opened[i].share, opened[j].share})
					if bytes.Contains(guess, marker) {
						t.Fatalf("pieces %d and %d interpolate to content", i+1, j+1)
					}
					same := 0
					for p := range guess {
						if guess[p] == truth[p] {
							same++
						}
					}
					if same > len(truth)/20 {
						t.Fatalf("pieces %d and %d agree with the payload on %d of %d bytes", i+1, j+1, same, len(truth))
					}
					if chi := chiSquare(guess); chi > 400 {
						t.Fatalf("pieces %d and %d interpolate to a skewed value (chi-square %.0f)", i+1, j+1, chi)
					}
					if mode.passwords != nil {
						if _, err := peelBySpec(guess[8:8+payloadLen], mode.passwords, costOf(pieces[0]), nil); err == nil {
							t.Fatalf("pieces %d and %d decrypted with the password", i+1, j+1)
						}
					}
				}
			}

			args := []string{"combine", filepath.Join(out, "secret.txt.1"), filepath.Join(out, "secret.txt.4"), "-y"}
			if mode.passwords != nil {
				args = append(args, "--password-env", flagPw1)
			}
			stdout, _, err := rivenRaw(t, mode.env, args...)
			if err == nil || len(stdout) != 0 {
				t.Fatalf("the binary rebuilt %d bytes from two pieces of a 3-of-5 set (err %v)", len(stdout), err)
			}
		})
	}
}

// chiSquare measures how far the byte distribution of b is from uniform. With 255
// degrees of freedom a uniform source lands near 255; 400 is over six standard
// deviations above that.
func chiSquare(b []byte) float64 {
	var counts [256]int
	for _, v := range b {
		counts[v]++
	}
	expect := float64(len(b)) / 256
	chi := 0.0
	for _, c := range counts {
		d := float64(c) - expect
		chi += d * d / expect
	}
	return chi
}
