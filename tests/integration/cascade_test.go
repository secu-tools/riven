// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
	"github.com/secu-tools/riven/internal/core"
	"github.com/secu-tools/riven/internal/kem"
)

// permutations returns every ordering of ids.
func permutations(ids []uint8) [][]uint8 {
	if len(ids) <= 1 {
		return [][]uint8{append([]uint8(nil), ids...)}
	}
	var out [][]uint8
	for i, first := range ids {
		rest := append(append([]uint8(nil), ids[:i]...), ids[i+1:]...)
		for _, tail := range permutations(rest) {
			out = append(out, append([]uint8{first}, tail...))
		}
	}
	return out
}

// TestEveryCascadeOrderRecovers runs a cascade of one layer per registered
// algorithm through the whole pipeline in every order: 120 of them for five
// algorithms. Half the orders carry one password layer, at a position that moves
// from order to order, with recipient layers around it; the rest are keyed by
// recipient keys alone. Across both halves, half the orders withhold the
// algorithms, so the reader has to name them in exactly the order used. Every set
// must come back byte for byte.
//
// The recipient key is x25519, the cheapest real one, so the 120 orders cost
// little more than the password layers do.
func TestEveryCascadeOrderRecovers(t *testing.T) {
	var ids []uint8
	for _, s := range ciphers.All() {
		ids = append(ids, s.ID)
	}
	key, err := kem.Generate(kem.X25519)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("the order the layers went on is the reverse of the order they come off")

	for i, order := range permutations(ids) {
		withPassword := i%2 == 0
		record := (i/2)%2 == 0
		pwAt := (i / 2) % len(order)

		layers := make([]core.LayerSpec, len(order))
		var pws [][]byte
		for j, id := range order {
			if withPassword && j == pwAt {
				pw := []byte(fmt.Sprintf("password for layer %d", j+1))
				layers[j] = core.LayerSpec{Kind: core.PasswordLayer, SchemeID: id, Password: pw}
				pws = append(pws, pw)
				continue
			}
			layers[j] = core.LayerSpec{Kind: core.RecipientLayer, SchemeID: id, Recipient: key.Public()}
		}

		pieces, err := core.Split(input, core.SplitOptions{
			N: 3, K: 2, Layers: layers, Params: fast, RecordAlgo: record, RecordKDF: true,
		})
		if err != nil {
			t.Fatalf("order %v: split: %v", order, err)
		}
		open := core.OpenOptions{Passwords: pws, PrivateKeys: []*kem.PrivateKey{key}}
		if !record {
			open.Schemes = order
		}
		got, err := core.Combine([][]byte{pieces[2], pieces[0]}, open)
		if err != nil {
			t.Fatalf("order %v (password=%v, recorded=%v): %v", order, withPassword, record, err)
		}
		if !bytes.Equal(got, input) {
			t.Fatalf("order %v: content changed", order)
		}
	}
}
