// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package split

import (
	"crypto/rand"
	"testing"
)

// TestShareLayoutMatchesTheSpecification checks the share lengths of
// docs/format.md section 6, including the chunk count a reader has to derive
// from the length alone.
func TestShareLayoutMatchesTheSpecification(t *testing.T) {
	cases := []struct{ secret, wantShare int }{
		{1, 2},                           // one chunk: secret + one tag
		{1000, 1001},                     //
		{chunkBytes, chunkBytes + 1},     // exactly one chunk
		{chunkBytes + 1, chunkBytes + 3}, // two chunks: secret + two tags
		{3 * chunkBytes, 3*chunkBytes + 3},
	}
	for _, c := range cases {
		secret := make([]byte, c.secret)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		shares, err := Split(secret, 3, 2)
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range shares {
			if len(s) != c.wantShare {
				t.Fatalf("secret %d: share %d is %d bytes, the specification says %d",
					c.secret, i+1, len(s), c.wantShare)
			}
		}
		// m = ceil(shareLength / (chunkBytes+1)), as documented.
		wantChunks := (c.secret + chunkBytes - 1) / chunkBytes
		if got := chunkCount(c.wantShare); got != wantChunks {
			t.Fatalf("secret %d: the documented formula gives %d chunks, want %d",
				c.secret, got, wantChunks)
		}
	}

	// A threshold of one is a plain copy, with no tag.
	secret := []byte("copy me")
	shares, err := Split(secret, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range shares {
		if len(s) != len(secret) {
			t.Fatalf("k=1 share %d is %d bytes, want %d", i+1, len(s), len(secret))
		}
	}
}
