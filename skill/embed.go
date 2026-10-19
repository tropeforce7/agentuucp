// Package skill carries the three Claude Code skills inside the binary, so
// that 'auu skill install' can write them out on a machine that has the
// binary and nothing else. The files are the tree's, byte for byte: the
// embed directive reads this directory, and a test compares the two.
//
// The package lives here rather than under internal/ because an embed
// directive can only reach files at or below its own package, and the
// skills stay where they are so that 'make install-skill' and the
// dispatch test keep reading the tree. It has no other code, so a program
// that imports it takes on nothing but bytes.
package skill

import "embed"

// Files holds NAME/SKILL.md for each skill and reference.md, the shared
// reference every installed skill gets a copy of.
//
//go:embed */SKILL.md reference.md
var Files embed.FS

// Names is every skill carried, in the order they are installed and
// listed: the messaging agent first, then the user's own setup, then the
// relay operator's.
func Names() []string { return []string{"auu-connect", "auu-setup", "auu-relay"} }

// Reference is the name of the shared reference in Files, and the name
// 'auu skill show' takes for it.
const Reference = "reference.md"
