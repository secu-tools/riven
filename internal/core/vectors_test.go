// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/kdf"
	"github.com/secu-tools/riven/internal/kem"
)

// Known-answer vectors are pieces written once and kept in testdata/vectors,
// which every later build must still open to the recorded content. They catch a
// change to the piece format that nothing else would notice until someone's
// pieces stopped opening: a reordered field, a changed domain string, a different
// password normalisation. If the format is changed on purpose, raise its version
// (docs/format.md section 12) and write them again:
//
//	go test ./internal/core -run TestKnownAnswerVectors -update-vectors
var updateVectors = flag.Bool("update-vectors", false, "rewrite the pieces in testdata/vectors")

const vectorDir = "testdata/vectors"

// vectorKeyFile holds the x25519 private key the hybrid vector was sealed to.
// The extension keeps it clear of the .gitignore rule for real key files.
var vectorKeyFile = filepath.Join(vectorDir, "hybrid.x25519")

type vector struct {
	name     string
	content  string
	fileName string // the name the pieces recorded, if any
	serials  []int  // the pieces kept, exactly the threshold
	split    func(key *kem.PrivateKey) SplitOptions
	open     func(key *kem.PrivateKey) OpenOptions
}

func vectorCascade() ([]LayerSpec, [][]byte, []uint8) {
	var layers []LayerSpec
	var pws [][]byte
	var ids []uint8
	for i, s := range ciphers.All() {
		pw := []byte(fmt.Sprintf("layer %d", i+1))
		layers = append(layers, LayerSpec{Kind: PasswordLayer, SchemeID: s.ID, Password: pw})
		pws = append(pws, pw)
		ids = append(ids, s.ID)
	}
	return layers, pws, ids
}

var vectorCost = kdf.Params{Memory: 8 * 1024, Time: 2, Par: 1}

// The password vector was split with the decomposed form of a password and is
// opened with the composed form, so a change in normalisation shows up too.
var (
	vectorPasswordDecomposed = "cafe" + string(rune(0x0301)) + " au lait"
	vectorPasswordComposed   = "caf" + string(rune(0x00E9)) + " au lait"
)

var vectors = []vector{
	{
		name: "password", content: "one password, everything recorded", fileName: "notes.txt", serials: []int{1, 3},
		split: func(*kem.PrivateKey) SplitOptions {
			return SplitOptions{N: 3, K: 2, Name: "notes.txt", Params: testParams, RecordAlgo: true, RecordKDF: true,
				Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte(vectorPasswordDecomposed)}}}
		},
		open: func(*kem.PrivateKey) OpenOptions {
			return OpenOptions{Passwords: [][]byte{[]byte(vectorPasswordComposed)}}
		},
	},
	{
		name: "cascade-unrecorded", content: "every algorithm, nothing recorded", serials: []int{2, 3, 4},
		split: func(*kem.PrivateKey) SplitOptions {
			layers, _, _ := vectorCascade()
			return SplitOptions{N: 4, K: 3, Params: vectorCost, Layers: layers}
		},
		open: func(*kem.PrivateKey) OpenOptions {
			_, pws, ids := vectorCascade()
			cost := vectorCost
			return OpenOptions{Passwords: pws, Schemes: ids, Params: &cost}
		},
	},
	{
		name: "keyless", content: "no password, the threshold alone", fileName: "seed.txt", serials: []int{2, 3},
		split: func(*kem.PrivateKey) SplitOptions {
			return SplitOptions{N: 3, K: 2, Name: "seed.txt", Keyless: true}
		},
		open: func(*kem.PrivateKey) OpenOptions { return OpenOptions{} },
	},
	{
		name: "hybrid", content: "a password and a recipient key", serials: []int{1, 2},
		split: func(key *kem.PrivateKey) SplitOptions {
			return SplitOptions{N: 2, K: 2, Params: testParams, RecordAlgo: true, RecordKDF: true,
				Layers: []LayerSpec{
					{Kind: PasswordLayer, Password: []byte("outer")},
					{Kind: RecipientLayer, Recipient: key.Public()},
				}}
		},
		open: func(key *kem.PrivateKey) OpenOptions {
			return OpenOptions{Passwords: [][]byte{[]byte("outer")}, PrivateKeys: []*kem.PrivateKey{key}}
		},
	},
}

func vectorPath(name string, serial int) string {
	return filepath.Join(vectorDir, fmt.Sprintf("%s-%d.piece", name, serial))
}

// TestKnownAnswerVectors opens the pieces kept in testdata/vectors and checks
// each set gives back exactly what was split.
func TestKnownAnswerVectors(t *testing.T) {
	if *updateVectors {
		writeVectors(t)
	}
	raw, err := os.ReadFile(vectorKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := kem.PrivateFromBytes(raw, kem.X25519)
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		var pieces [][]byte
		for _, s := range v.serials {
			p, err := os.ReadFile(vectorPath(v.name, s))
			if err != nil {
				t.Fatal(err)
			}
			pieces = append(pieces, p)
		}
		got, name, err := CombineFile(pieces, v.open(key))
		if err != nil {
			t.Fatalf("%s: pieces written by an earlier build no longer open: %v", v.name, err)
		}
		if string(got) != v.content || name != v.fileName {
			t.Fatalf("%s: pieces written by an earlier build open to %q named %q", v.name, got, name)
		}
		// One short of the threshold must still fail.
		if _, err := Combine(pieces[1:], v.open(key)); err == nil {
			t.Fatalf("%s: %d of the pieces opened a %d-piece threshold", v.name, len(pieces)-1, len(pieces))
		}
	}
}

func writeVectors(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(vectorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorKeyFile, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		pieces, err := Split([]byte(v.content), v.split(key))
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		for _, s := range v.serials {
			if err := os.WriteFile(vectorPath(v.name, s), pieces[s-1], 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}
