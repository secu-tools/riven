// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package cascade

import "testing"

// FuzzDecrypt ensures arbitrary payloads and password counts never panic.
func FuzzDecrypt(f *testing.F) {
	good, _ := Encrypt([]byte("hello"), []Layer{{Kind: Password, SchemeID: 1, Password: []byte("p")}}, fastProfile, true)
	f.Add(good, []byte("p"))
	f.Add([]byte{}, []byte{})
	f.Add([]byte{1, 0}, []byte("x"))
	f.Fuzz(func(t *testing.T, payload, pw []byte) {
		_, _ = Decrypt(payload, [][]byte{pw}, nil, fastProfile, nil)
		_, _ = Descriptors(payload)
	})
}
