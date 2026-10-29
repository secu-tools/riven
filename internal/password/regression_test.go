// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package password

import (
	"bytes"
	"testing"
)

// One test per defect found during development, so a fix cannot quietly
// regress. Each states the original faulty behaviour.

// Defect: a password that is not valid UTF-8 was transcoded as GB18030, whose
// decoder replaces a byte it cannot decode with U+FFFD instead of failing.
// Different passwords therefore derived the same key: a Latin-1 "cafe" with an
// acute accent opened a set sealed with a grave one, and passwords differing only
// in undecodable bytes were interchangeable.
func TestRegressionUndecodableBytesStayDistinct(t *testing.T) {
	for _, pair := range [][2]string{
		{"caf\xe9", "caf\xe8"},
		{"pw\xff\xff", "pw\xfe\xff"},
		{"\xff", "\xfe"},
	} {
		if bytes.Equal(Canonical([]byte(pair[0])), Canonical([]byte(pair[1]))) {
			t.Errorf("%q and %q canonicalize to the same bytes", pair[0], pair[1])
		}
	}
}
