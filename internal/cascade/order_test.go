// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package cascade

import (
	"bytes"
	"errors"
	"testing"

	"github.com/secu-tools/riven/internal/ciphers"
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

// TestEveryLayerOfEveryOrderIsLoadBearing stacks every registered algorithm in
// every order and checks each layer is really applied: the cascade opens with
// every key, and fails when any one layer is given the wrong key, or when the
// algorithms are named in an order other than the one used. A layer skipped both
// on the way in and on the way out would still round-trip, so a round trip alone
// cannot show this.
//
// The layers are keyed as recipient layers with fixed shared secrets, so no key
// derivation runs and all 120 orderings stay cheap. How a layer key is obtained
// is covered elsewhere; the order logic is the same for both kinds of layer.
func TestEveryLayerOfEveryOrderIsLoadBearing(t *testing.T) {
	var ids []uint8
	for _, s := range ciphers.All() {
		ids = append(ids, s.ID)
	}
	plaintext := []byte("every layer must carry its weight")

	for _, order := range permutations(ids) {
		layers := make([]Layer, len(order))
		for i, id := range order {
			layers[i] = Layer{
				Kind: KEM, SchemeID: id,
				KEMSecret:     bytes.Repeat([]byte{byte(i + 1)}, 32),
				KEMCiphertext: []byte{'l', 'a', 'y', 'e', 'r', byte(i)},
			}
		}
		// keyFor plays the private key holder, with one layer optionally given a
		// key that does not match.
		keyFor := func(wrong int) Decapsulator {
			return func(ct []byte) ([]byte, error) {
				for i, l := range layers {
					if bytes.Equal(ct, l.KEMCiphertext) {
						if i == wrong {
							return bytes.Repeat([]byte{0xEE}, 32), nil
						}
						return l.KEMSecret, nil
					}
				}
				return nil, errors.New("no such layer")
			}
		}

		for _, record := range []bool{true, false} {
			payload, err := Encrypt(plaintext, layers, fastProfile, record)
			if err != nil {
				t.Fatalf("%v: %v", order, err)
			}
			var named []uint8
			if !record {
				named = order
			}
			got, err := Decrypt(payload, nil, []Decapsulator{keyFor(-1)}, fastProfile, named)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("%v recorded=%v: did not open with every key: %v", order, record, err)
			}

			for i := range layers {
				if _, err := Decrypt(payload, nil, []Decapsulator{keyFor(i)}, fastProfile, named); err == nil {
					t.Fatalf("%v recorded=%v: opened with a wrong key for layer %d", order, record, i+1)
				}
			}

			if !record {
				for i := 0; i+1 < len(order); i++ {
					swapped := append([]uint8(nil), order...)
					swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
					if _, err := Decrypt(payload, nil, []Decapsulator{keyFor(-1)}, fastProfile, swapped); err == nil {
						t.Fatalf("%v: opened with layers %d and %d named the wrong way round", order, i+1, i+2)
					}
				}
			}
		}
	}
}
