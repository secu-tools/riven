// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package split wraps the vendored Shamir implementation with the semantics
// Riven needs: parameter validation and a k==1 fast path (a single required
// piece is just a self-sufficient copy, which Shamir itself cannot express
// because it requires a threshold of at least two).
package split

import (
	"errors"
	"fmt"

	"github.com/secu-tools/riven/internal/parallel"
	"github.com/secu-tools/riven/internal/shamir"
)

const (
	// MaxParts is the hard limit imposed by the GF(2^8) field: at most 255
	// distinct non-zero x-coordinates exist.
	MaxParts = 255
	// MinParts is the smallest legal number of parts.
	MinParts = 1
)

// ErrInsufficientShares is returned when fewer than the threshold shares are
// supplied to Combine.
var ErrInsufficientShares = errors.New("split: fewer shares than the threshold")

// ValidateParams checks that n (total parts) and k (threshold) form a legal
// split for a secret of the given length.
func ValidateParams(n, k, secretLen int) error {
	if secretLen < 1 {
		return errors.New("split: secret must be at least one byte")
	}
	if k < 1 {
		return errors.New("split: threshold must be at least 1")
	}
	if n < k {
		return fmt.Errorf("split: total parts (%d) cannot be less than threshold (%d)", n, k)
	}
	if n > MaxParts {
		return fmt.Errorf("split: total parts (%d) cannot exceed %d", n, MaxParts)
	}
	return nil
}

// chunkBytes is how much of the secret one Shamir call handles. Sharing is
// independent per byte, so a large secret is cut into chunks that are shared
// concurrently; the chunk size trades the one-byte-per-chunk overhead against
// how many cores a split can use. At 512 KiB the overhead is under two parts per
// million and a few megabytes already saturate a desktop.
const chunkBytes = 512 << 10

// chunkCount returns how many chunks a share of the given length carries.
//
// Every chunk but the last is exactly chunkBytes, and each contributes one
// x-coordinate tag byte, so a share of m chunks covering s secret bytes is
// s+m long with (m-1)*chunkBytes < s <= m*chunkBytes. Those bounds leave exactly
// one possible m, which is what this computes; no chunk count has to be stored.
func chunkCount(shareLen int) int {
	if shareLen <= 0 {
		return 0
	}
	m := shareLen / (chunkBytes + 1)
	if shareLen%(chunkBytes+1) != 0 {
		m++
	}
	return m
}

// Split divides secret into n parts, k of which are required to reconstruct it.
//
// For k == 1 each part is an independent full copy of the secret. For k >= 2 the
// vendored Shamir implementation is used. A secret larger than chunkBytes is
// shared one chunk at a time, and a share is the concatenation of its chunk
// shares, so a share is one byte longer than the secret per chunk.
func Split(secret []byte, n, k int) ([][]byte, error) {
	if err := ValidateParams(n, k, len(secret)); err != nil {
		return nil, err
	}

	if k == 1 {
		out := make([][]byte, n)
		for i := range out {
			cp := make([]byte, len(secret))
			copy(cp, secret)
			out[i] = cp
		}
		return out, nil
	}

	chunks := (len(secret) + chunkBytes - 1) / chunkBytes
	if chunks <= 1 {
		return shamir.Split(secret, n, k)
	}

	// Share every chunk independently and write the results straight into the
	// final shares, so that share i is chunk share i of every chunk, in order.
	//
	// Writing in place matters: a set of shares is n times the secret, and
	// assembling them from a second full copy would double that for a large
	// input. Each worker owns a disjoint span of every share, so no lock is
	// needed.
	out := make([][]byte, n)
	for i := range out {
		out[i] = make([]byte, len(secret)+chunks)
	}
	chunkShare := chunkBytes + 1
	err := parallel.Do(chunks, parallel.Workers(chunks), func(c int) error {
		lo := c * chunkBytes
		hi := lo + chunkBytes
		if hi > len(secret) {
			hi = len(secret)
		}
		part, serr := shamir.Split(secret[lo:hi], n, k)
		if serr != nil {
			return serr
		}
		at := c * chunkShare
		for i := range out {
			copy(out[i][at:], part[i])
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Combine reconstructs a secret from shares produced by Split. The threshold k
// must match the value used at split time. At least k shares must be supplied;
// supplying more is allowed. Supplying fewer than k for a k >= 2 split cannot be
// detected here (Shamir interpolation would silently yield garbage), so callers
// MUST verify the result against an authenticated hash.
func Combine(shares [][]byte, k int) ([]byte, error) {
	if k < 1 {
		return nil, errors.New("split: threshold must be at least 1")
	}
	if len(shares) < k {
		return nil, ErrInsufficientShares
	}

	if k == 1 {
		if len(shares[0]) == 0 {
			return nil, errors.New("split: empty share")
		}
		out := make([]byte, len(shares[0]))
		copy(out, shares[0])
		return out, nil
	}

	// Every share of a set has the same length, which is what makes the chunk
	// layout readable. A mismatch means the shares are not from one set.
	for _, s := range shares {
		if len(s) != len(shares[0]) {
			return nil, errors.New("split: shares differ in length")
		}
	}

	chunks := chunkCount(len(shares[0]))
	if chunks <= 1 {
		return shamir.Combine(shares)
	}

	// Recover each chunk from the matching chunk share of every supplied share.
	recovered := make([][]byte, chunks)
	last := len(shares[0]) - (chunks-1)*(chunkBytes+1)
	err := parallel.Do(chunks, parallel.Workers(chunks), func(c int) error {
		size := chunkBytes + 1
		if c == chunks-1 {
			size = last
		}
		lo := c * (chunkBytes + 1)
		part := make([][]byte, len(shares))
		for i, s := range shares {
			part[i] = s[lo : lo+size]
		}
		out, cerr := shamir.Combine(part)
		if cerr != nil {
			return cerr
		}
		recovered[c] = out
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(shares[0])-chunks)
	for _, r := range recovered {
		out = append(out, r...)
	}
	return out, nil
}
