// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import "testing"

// FuzzInfo feeds arbitrary bytes as a "piece": must never panic, since inputs
// are usually files of unknown origin.
func FuzzInfo(f *testing.F) {
	pieces, _ := Split([]byte("seed"), SplitOptions{N: 2, K: 2, Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("p")}}, Params: testParams, RecordAlgo: true, RecordKDF: true})
	if len(pieces) > 0 {
		f.Add(pieces[0], []byte("p"))
	}
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 200), []byte("x"))
	// The cost is pinned so the fuzzer explores parsing rather than spending its
	// time in Argon2 with whatever parameters random bytes happen to select.
	f.Fuzz(func(t *testing.T, data, pw []byte) {
		opts := OpenOptions{Passwords: [][]byte{pw}, Params: &testParams}
		_, _ = Info(data, opts)
		_, _ = Combine([][]byte{data}, opts)
	})
}
