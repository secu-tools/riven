// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/secu-tools/riven/internal/format"
)

// Injected at build time via -ldflags -X (see build scripts).
var (
	version     = "dev"
	commit      = "none"
	buildNumber = "0"
)

// resolveOnce guards the fallback below, which reads build info once.
var resolveOnce sync.Once

// resolveBuildInfo fills in the version and commit for a binary built without
// the release scripts, which is what `go install` and a plain `go build`
// produce. Go records the module version and the VCS revision in the binary
// itself, so the build is still identifiable. Every piece carries these strings
// and the README tells the reader to use them to find the binary that wrote a
// piece, so leaving them at "dev" and "none" would make that promise empty for
// the documented install route.
func resolveBuildInfo() {
	if version != "dev" {
		return // the build scripts injected real values
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" && !pseudoVersion(v) {
		version = v
	}
	var revision string
	var modified bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision != "" {
		if len(revision) > 12 {
			revision = revision[:12]
		}
		if modified {
			revision += "+dirty"
		}
		commit = revision
	}
}

// pseudoVersion reports whether v is a Go pseudo-version: a base version, then
// a 14-digit UTC timestamp and a 12-character commit prefix.
//
// Such a version is skipped because the commit it ends with is recorded in the
// commit field anyway, and both strings sit in every piece, where their length
// comes straight off the QR and word-list budgets. A real tag (v1.2.0) is short
// and says something the commit does not, so it is kept.
func pseudoVersion(v string) bool {
	// Go appends "+dirty" to the version of a modified tree; that is build
	// metadata, not part of the pseudo-version form.
	if k := strings.Index(v, "+"); k >= 0 {
		v = v[:k]
	}
	i := strings.LastIndex(v, "-")
	if i < 0 || len(v)-i-1 != 12 {
		return false
	}
	j := strings.LastIndex(v[:i], "-")
	if j < 0 {
		return false
	}
	// The timestamp is the last dot-separated part of this segment: bare in
	// "v0.0.0-<ts>-<commit>", and after a "0." in "v1.2.4-0.<ts>-<commit>".
	seg := v[j+1 : i]
	if k := strings.LastIndex(seg, "."); k >= 0 {
		seg = seg[k+1:]
	}
	if len(seg) != 14 {
		return false
	}
	for _, r := range seg {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Version returns the human-readable version string.
func Version() string {
	return fmt.Sprintf("%s (%s)", creatorVersion(), creatorCommit())
}

// creatorVersion and creatorCommit are what a piece records about the build that
// wrote it. Both are clamped to the field width the format allows, so an unusual
// module version cannot make a split fail on a field nobody asked for.
func creatorVersion() string {
	resolveOnce.Do(resolveBuildInfo)
	return clampCreator(version + "." + buildNumber)
}

func creatorCommit() string {
	resolveOnce.Do(resolveBuildInfo)
	return clampCreator(commit)
}

func clampCreator(s string) string {
	if len(s) <= format.MaxCreatorLen {
		return s
	}
	return strings.ToValidUTF8(s[:format.MaxCreatorLen], "")
}
