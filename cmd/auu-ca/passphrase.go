package main

import (
	"fmt"
	"strings"

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

// unlock gets the passphrase for an existing authority, if it has one. A
// directory from before key files were encrypted needs none, and must not be
// asked for one.
func unlock(dir, file string) ([]byte, error) {
	locked, err := pki.OpenLocked(dir)
	if err != nil {
		return nil, err
	}
	if !locked.Encrypted() {
		return nil, nil
	}
	return readPassphrase(fmt.Sprintf("Passphrase for %s: ", dir), file)
}

// legacyWarning is what show and every command that opens an unencrypted
// authority prints, once, on stderr.
func legacyWarning(dir string) string {
	return strings.TrimSpace(fmt.Sprintf(
		"the private keys in %s are not encrypted; run 'auu-ca passphrase' to encrypt them", dir))
}
