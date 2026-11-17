// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"runtime/debug"
	"strings"
	"testing"

	"github.com/secu-tools/riven/internal/format"
)

// A pseudo-version ends with the commit that is recorded separately, and both
// strings sit in every piece, where their length comes off the QR budget. A real
// tag is short and says something the commit does not, so it is kept.
func TestPseudoVersion(t *testing.T) {
	pseudo := []string{
		"v0.0.0-20260901064216-cea8ee0c0cad",
		"v0.0.0-20260901064216-cea8ee0c0cad+dirty",
		"v1.2.4-0.20260901064216-abcdef123456",
	}
	for _, v := range pseudo {
		if !pseudoVersion(v) {
			t.Errorf("pseudoVersion(%q) = false, want true", v)
		}
	}

	real := []string{
		"v1.2.3", "v1.2.3+dirty", "v0.1.0-beta.1", "1.0.0", "dev", "",
		"v1.2.3-20260901064216-tooshort",     // commit prefix not 12 chars
		"v1.2.3-2026090106421-cea8ee0c0cad",  // timestamp not 14 digits
		"v1.2.3-2026090x064216-cea8ee0c0cad", // timestamp not all digits
	}
	for _, v := range real {
		if pseudoVersion(v) {
			t.Errorf("pseudoVersion(%q) = true, want false", v)
		}
	}
}

// Every piece carries these strings, and format.Encode rejects one over the
// limit, so a long module version must not be able to fail a split.
func TestCreatorFieldsFitTheFormat(t *testing.T) {
	if got := clampCreator(strings.Repeat("x", format.MaxCreatorLen+50)); len(got) > format.MaxCreatorLen {
		t.Fatalf("clampCreator returned %d bytes, over the %d limit", len(got), format.MaxCreatorLen)
	}
	if got := clampCreator("v1.2.3.9"); got != "v1.2.3.9" {
		t.Fatalf("clampCreator changed a short value: %q", got)
	}
	if len(creatorVersion()) > format.MaxCreatorLen {
		t.Fatalf("creatorVersion() is %d bytes, over the limit", len(creatorVersion()))
	}
	if len(creatorCommit()) > format.MaxCreatorLen {
		t.Fatalf("creatorCommit() is %d bytes, over the limit", len(creatorCommit()))
	}
}

// TestBuildInfoNamesTheBuild checks what a binary built without the release
// scripts records about itself: a tagged version as it is, a pseudo-version
// not at all, since its commit is recorded anyway, and the revision cut to
// twelve characters and marked when the tree had changes.
func TestBuildInfoNamesTheBuild(t *testing.T) {
	oldVersion, oldCommit := version, commit
	t.Cleanup(func() { version, commit = oldVersion, oldCommit })
	info := func(v, rev, modified string) *debug.BuildInfo {
		bi := &debug.BuildInfo{Main: debug.Module{Version: v}}
		if rev != "" {
			bi.Settings = []debug.BuildSetting{{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: modified}}
		}
		return bi
	}
	for _, c := range []struct {
		bi              *debug.BuildInfo
		version, commit string
	}{
		{info("v1.2.0", "0123456789abcdef0123", "false"), "v1.2.0", "0123456789ab"},
		{info("v0.0.0-20260101120000-0123456789ab", "0123456789abcdef", "true"), "dev", "0123456789ab+dirty"},
		{info("(devel)", "abc123", "false"), "dev", "abc123"},
		{info("", "", ""), "dev", "none"},
	} {
		version, commit = "dev", "none"
		applyBuildInfo(c.bi)
		if version != c.version || commit != c.commit {
			t.Errorf("%q: got %q and %q, want %q and %q", c.bi.Main.Version, version, commit, c.version, c.commit)
		}
	}
}
