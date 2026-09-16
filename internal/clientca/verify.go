package clientca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// Errors from checking a client certificate.
var (
	ErrCertUntrusted = errors.New("client certificate was not issued by this relay")
	ErrCertSubject   = errors.New("client certificate does not name an identity")
)

// Verify checks a leaf against this authority.
//
// A certificate that arrived in a handshake has already been checked this way
// by crypto/tls, against the same pool and the same key usage; only Subject
// remains, and CommonName covers it. This is the same check for a caller
// holding a leaf on its own.
func (c *CA) Verify(leaf *x509.Certificate, now time.Time) error {
	if leaf == nil {
		return ErrCertUntrusted
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       c.pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: now,
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrCertUntrusted, err)
	}
	return Subject(leaf)
}

// SPKI is the hex SHA-256 of a certificate's SubjectPublicKeyInfo: the same
// value ParseCSR records for a request, so a certificate can be checked
// against the key it was issued for.
func SPKI(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// Subject returns the fingerprint a leaf names, refusing one that names
// anything else.
//
// Every certificate this project issues has a fingerprint for its common
// name. Checking it here means no caller has to decide what to do with a
// certificate whose subject is something unexpected.
func Subject(leaf *x509.Certificate) error {
	if !identity.ValidFingerprint(leaf.Subject.CommonName) {
		return ErrCertSubject
	}
	return nil
}
