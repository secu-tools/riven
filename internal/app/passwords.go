// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/secu-tools/riven/internal/memory"
)

// pwCharset excludes visually ambiguous characters (0/O, 1/l/I).
const pwCharset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+?"

const (
	pwLen = byte(len(pwCharset))
	// pwLimit is the largest multiple of pwLen below 256. Bytes at or above it
	// are rejected, so every character is equally likely.
	pwLimit = byte(256 - 256%len(pwCharset))
)

const defaultGenLen = 28

// generatePassword returns a cryptographically strong random password of n
// characters using unbiased rejection sampling.
func generatePassword(n int) ([]byte, error) {
	if n <= 0 {
		n = defaultGenLen
	}
	out := memory.Bytes(n)
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			memory.Free(out)
			return nil, err
		}
		if buf[0] >= pwLimit {
			continue // reject to avoid modulo bias
		}
		out[i] = pwCharset[buf[0]%pwLen]
		i++
	}
	return out, nil
}

// passwordFromEnv reads a password from an environment variable. Environment
// variables are the only non-interactive source: unlike a file they leave no
// copy on disk, and unlike an argument they do not appear in the process list.
func passwordFromEnv(name string) ([]byte, error) {
	v, ok := os.LookupEnv(name)
	if !ok {
		return nil, fmt.Errorf("environment variable %q is not set", name)
	}
	if v == "" {
		return nil, fmt.Errorf("environment variable %q is empty", name)
	}
	// The variable itself stays in the process environment, which is the caller's
	// to manage; this copy is the one Riven then carries around.
	return memory.Copy([]byte(v)), nil
}

// isDistinct reports whether candidate differs from every password in prior.
func isDistinct(candidate []byte, prior [][]byte) bool {
	for _, p := range prior {
		if string(p) == string(candidate) {
			return false
		}
	}
	return true
}

var errPasswordReused = errors.New("password must differ from the previous layers")
