package store

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/regular"
)

// anchorFile holds the trust anchor this machine pinned for one relay: the
// root of that relay's private certificate authority. It lives in the relay's
// own directory, because pinning one relay says nothing about another.
//
// It is the transport's trust anchor and nothing else. Who may send this
// machine mail is still authorized_peers, and pinning a relay says nothing
// about that.
const anchorFile = "trust_anchor.pem"

// ErrNoAnchor means this machine pinned none for that relay, which is what a
// relay with a publicly trusted certificate wants.
var ErrNoAnchor = errors.New("no trust anchor pinned for this relay")

// Anchor is what a machine remembers about a relay it trusts.
type Anchor struct {
	Cert *x509.Certificate
	SPKI string
}

// AnchorFor loads a relay's pinned trust anchor, checking it against the hash
// the relay's record holds.
//
// Both are read: the certificate could be swapped by anything that can write
// the directory, and the hash is what an enrolment token actually vouched
// for. A file that does not hash to it is refused rather than used.
func (s *Store) AnchorFor(r *Relay) (*Anchor, error) {
	path := s.relayPath(r, anchorFile)
	if r.TrustAnchorSPKI == "" {
		// No record is what a relay under a public authority, or a plain
		// HTTP one, looks like, and pinning is simply off. With the pinned
		// file still beside it, though, the record was there and has been
		// edited out — the one line that made the file count — and
		// carrying on unpinned would be exactly what the edit was for.
		// The container suite's K13 found it carried on, with advice that
		// read as if the machine had never pinned.
		if _, err := os.Stat(path); err == nil {
			return nil, &damagedFile{msg: fmt.Sprintf("%s records no trust anchor but %s is here; %s has been "+
				"edited. Enrol again with a token, or run 'auu anchor pin HASH' with the hash from the relay's operator",
				s.relayPath(r, relayFile), path, relayFile)}
		}
		return nil, ErrNoAnchor
	}
	raw, err := regular.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, &damagedFile{msg: fmt.Sprintf("%s records a trust anchor for %s but %s is missing; "+
			"enrol again with a token", relayFile, r.Name, path)}
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, damaged(path, "is not a PEM certificate", nil, "enrol again with a token")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, damaged(path, "does not hold a certificate", err, "enrol again with a token")
	}
	if got := pki.SPKI(cert); got != r.TrustAnchorSPKI {
		return nil, &damagedFile{msg: fmt.Sprintf("%s holds a different trust anchor than %s records "+
			"(%s, not %s); it has been replaced, so nothing here should be trusted "+
			"until you enrol again", path, relayFile, got[:16], r.TrustAnchorSPKI[:16])}
	}
	return &Anchor{Cert: cert, SPKI: r.TrustAnchorSPKI}, nil
}

// SaveAnchorFor pins a relay's trust anchor, recording its hash beside it so
// a swapped file is noticed rather than used.
func (s *Store) SaveAnchorFor(r *Relay, cert *x509.Certificate) error {
	if err := os.MkdirAll(s.relayDir(r.Name), dirMode); err != nil {
		return err
	}
	if err := writeFileAtomic(s.relayPath(r, anchorFile),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), fileMode); err != nil {
		return err
	}
	r.TrustAnchorSPKI = pki.SPKI(cert)
	// A new anchor is a different authority, so what this machine remembers
	// about the old one's certificate chain means nothing.
	r.ServerIntSPKI = ""
	r.ServerIntNotBefore = time.Time{}
	return s.SaveRelay(r)
}

// RemoveAnchorFor forgets a relay's pinned anchor and everything recorded
// about its own certificates.
func (s *Store) RemoveAnchorFor(r *Relay) error {
	if err := os.Remove(s.relayPath(r, anchorFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	r.TrustAnchorSPKI = ""
	r.ServerIntSPKI = ""
	r.ServerIntNotBefore = time.Time{}
	return s.SaveRelay(r)
}

// SeenIntermediateFor records the server signing intermediate this machine
// last accepted from one relay, which is what tells a rotation from a replay.
func (s *Store) SeenIntermediateFor(r *Relay, spki string, notBefore time.Time) error {
	current, err := s.readRelay(r.Name)
	if err != nil {
		return err
	}
	current.ServerIntSPKI = spki
	current.ServerIntNotBefore = notBefore
	r.ServerIntSPKI = spki
	r.ServerIntNotBefore = notBefore
	return s.SaveRelay(current)
}

// HasAnyAnchor reports whether this home has pinned an anchor anywhere. It is
// for advice at the single exit, where the command that failed is no longer
// in hand and the question is only whether pinning is something this person
// does at all.
func (s *Store) HasAnyAnchor() bool {
	relays, err := s.Relays()
	if err != nil {
		return false
	}
	for _, r := range relays {
		if r.TrustAnchorSPKI != "" {
			return true
		}
	}
	return false
}
