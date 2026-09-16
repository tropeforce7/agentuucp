// Package buildinfo says what version a binary was built from.
//
// There is one answer and four programs, so it lives here rather than four
// times over. Go records the main module's version in every binary it
// links: a tagged build says its tag, a build from a clone says what the
// version control system knows, and a build from a copied tree with no
// repository says nothing at all. The last is a state, not a failure — an
// operator may have been handed a binary built any way — so a version that
// cannot be read comes back empty and every caller says so in its own
// words rather than refusing to run.
package buildinfo

import (
	"debug/buildinfo"
	"io"
	"runtime/debug"
)

// unknown is what every caller prints for a binary that carries no version.
const unknown = "unknown"

// Version is the version this binary was built from, or unknown.
func Version() string { return orUnknown(mainVersion()) }

// mainVersion reads this binary's own build information.
func mainVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return clean(info.Main.Version)
}

// Of is the version another Go binary was built from, read from the file
// itself: the kit uses it to say what relay it is carrying, which the
// running program cannot be asked. An empty string is a binary with no
// build information — not a Go binary, or one built from a copied tree —
// and is never an error the caller needs to report.
func Of(r io.ReaderAt) string {
	info, err := buildinfo.Read(r)
	if err != nil || info == nil {
		return ""
	}
	return clean(info.Main.Version)
}

// clean drops what Go writes when it has nothing: an empty version, and
// the "(devel)" a build with no version control information carries.
func clean(v string) string {
	if v == "(devel)" {
		return ""
	}
	return v
}

// orUnknown is a version as a person reads it.
func orUnknown(v string) string {
	if v == "" {
		return unknown
	}
	return v
}
