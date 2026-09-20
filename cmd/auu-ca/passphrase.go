package main

import (
	"fmt"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/term"
)

// MinPassphrase is the shortest passphrase auu-ca will set: term's, which
// auu's home shares, so a passphrase good enough for one is good enough
// for the other.
const MinPassphrase = term.MinPassphrase

// cost is what new key files are written with. Its zero value is
// keyfile's own defaults, which is what auu-ca ships; a test turns the
// derivation down so that a suite which creates dozens of authorities does
// not spend minutes deriving keys nobody is attacking.
//
// Nothing else assigns it. What proves the shipped value is the real one is
// a test that runs init at this cost and reads the headers of the file it
// wrote, rather than an assertion about this variable.
var cost keyfile.Passphrase

// withSecret is cost, for this passphrase.
func withSecret(secret []byte) keyfile.Passphrase {
	p := cost
	p.Secret = secret
	return p
}

// The readers live in internal/term, shared with auu; these names are what
// the commands here have always called them.
var (
	readPassphrase    = term.ReadPassphrase
	readNewPassphrase = term.ReadNewPassphrase
	fromFile          = term.FromFile
)

// unlock gets the passphrase for an existing authority. The directory is
// read locked first, so that one that is not an authority, or holds a key
// file from before they were encrypted, is refused by name before anybody
// is asked for a passphrase it would not open.
func unlock(dir, file string) ([]byte, error) {
	if _, err := pki.OpenLocked(dir); err != nil {
		return nil, err
	}
	return readPassphrase(fmt.Sprintf("Passphrase for %s: ", dir), file)
}
