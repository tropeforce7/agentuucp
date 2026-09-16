package clientca

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tropeforce7/agentuucp/internal/pki"
)

// Issuer signs client certificates from the relay's client signing
// intermediate. It is the one key on a relay that can issue anything, and it
// can issue only this: the intermediate carries clientAuth and a path length
// of zero, which Go's verifier enforces.
type Issuer struct {
	int    *pki.Key
	params mldsa.Parameters
}

// NewIssuer wraps a bundle's client intermediate.
func NewIssuer(l *pki.Loaded) *Issuer {
	return &Issuer{int: l.ClientInt, params: l.Params}
}

// Parameters is the ML-DSA parameter set every client key must have.
func (i *Issuer) Parameters() mldsa.Parameters { return i.params }

// NotAfter is when this issuer stops being able to issue.
func (i *Issuer) NotAfter() time.Time { return i.int.Cert.NotAfter }

// SPKI identifies the intermediate's key.
func (i *Issuer) SPKI() string { return pki.SPKI(i.int.Cert) }

// Issue signs a client certificate for the key in req, naming fp.
//
// Nothing from the request but its key reaches the certificate: the subject is
// the relay's to set, so a machine cannot ask to be issued for an identity
// that is not its own, and the token it carried is spent rather than recorded.
func (i *Issuer) Issue(req *Request, fp string, now time.Time, lifetime time.Duration) (*Issued, error) {
	if req == nil || req.Key == nil {
		return nil, errors.New("clientca: no certificate request")
	}
	if lifetime <= 0 {
		return nil, fmt.Errorf("clientca: certificate lifetime must be positive, got %v", lifetime)
	}
	if !now.Before(i.int.Cert.NotAfter) {
		return nil, fmt.Errorf("%w: the client signing intermediate expired on %s",
			ErrCALifetime, i.int.Cert.NotAfter.Format(time.DateOnly))
	}
	notBefore := now.Add(-backdate).Truncate(time.Second)
	notAfter := now.Add(lifetime).Truncate(time.Second)
	// A leaf outliving its issuer would verify until the intermediate
	// expired and then stop, on a date nothing warned about.
	if notAfter.After(i.int.Cert.NotAfter) {
		notAfter = i.int.Cert.NotAfter.Truncate(time.Second)
	}
	return issueLeaf(i.int, req, fp, notBefore, notAfter)
}

// Verifier decides whether a client certificate is one this relay's authority
// issued. It holds only public certificates.
type Verifier struct {
	roots  *x509.CertPool
	inter  *x509.CertPool
	anchor *x509.Certificate
}

// NewVerifier builds the verifier from a bundle: the trust anchor as the only
// root, and every client intermediate — current and retired — as
// intermediates.
//
// Retired ones are there deliberately, so that rotating the relay's signing
// key does not invalidate the certificates it already issued. What stops a
// stolen retired key mattering is not this pool but the certs table: a leaf
// with a serial the relay never recorded is refused, and one with a recorded
// serial must carry the key that row records.
func NewVerifier(l *pki.Loaded) *Verifier {
	roots := x509.NewCertPool()
	roots.AddCert(l.Anchor)
	inter := x509.NewCertPool()
	for _, c := range l.ClientPool {
		inter.AddCert(c)
	}
	return &Verifier{roots: roots, inter: inter, anchor: l.Anchor}
}

// Anchor is the trust anchor, which a client pins and a token names.
func (v *Verifier) Anchor() *x509.Certificate { return v.anchor }

// AnchorSPKI identifies the anchor's key.
func (v *Verifier) AnchorSPKI() string { return pki.SPKI(v.anchor) }

// Verify checks a leaf against this relay's authority and requires its subject
// to be a fingerprint.
//
// The handshake comes through here, where the relay supplies the
// intermediates so a client need only send its leaf.
func (v *Verifier) Verify(leaf *x509.Certificate, now time.Time) error {
	if leaf == nil {
		return ErrCertUntrusted
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: v.inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   now,
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrCertUntrusted, err)
	}
	return Subject(leaf)
}

// TLSConfig applies the client half to a server configuration.
//
// ClientAuth is RequestClientCert rather than VerifyClientCertIfGiven: that
// mode has crypto/tls verify the chain with ClientCAs as roots and only what
// the client presented as intermediates, and there is no field for
// intermediates the server holds. Asking for a certificate and verifying it
// here lets a client send its leaf alone — 5.5 KB instead of 16.6.
//
// A handshake carrying no certificate is admitted, because enrolment must be
// reachable by a machine that has none. Which routes need one is the relay's
// decision, not the handshake's.
func (v *Verifier) TLSConfig(cfg *tls.Config) *tls.Config {
	cfg.ClientAuth = tls.RequestClientCert
	cfg.MinVersion = tls.VersionTLS13
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return nil
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrCertUntrusted, err)
		}
		return v.Verify(leaf, time.Now())
	}
	return cfg
}

// Server holds the relay's own certificate and mints a fresh one before the
// old one expires.
//
// The key is generated in memory and never written. That is not tidiness: it
// is the one secret a reader of the relay's disk does not obtain, so an
// impostor holding the relay's intermediates must mint a leaf of its own,
// which is what a witness on another network path can tell apart. Nothing
// here depends on that yet; PLAN-ATTEST.md is what will.
type Server struct {
	int    *pki.Key
	chain  [][]byte
	hosts  []string
	params mldsa.Parameters

	mu   sync.RWMutex
	leaf *tls.Certificate
	// notAfter is the current leaf's expiry, read without parsing.
	notAfter time.Time
}

// NewServer mints the relay's first leaf.
//
// The chain served with it is the signing intermediate and then everything
// above it up to but excluding the anchor: a client holds the anchor and
// nothing else, so every certificate between the two has to be on the wire or
// no chain can be built. Leaving the intermediate out is invisible to the
// relay and fatal to every client, which is exactly the sort of thing only an
// end-to-end run finds.
func NewServer(l *pki.Loaded, now time.Time) (*Server, error) {
	chain := make([][]byte, 0, len(l.ServerChain)+1)
	chain = append(chain, l.ServerInt.Cert.Raw)
	for _, c := range l.ServerChain {
		chain = append(chain, c.Raw)
	}
	s := &Server{int: l.ServerInt, chain: chain, hosts: l.Hosts, params: l.Params}
	if err := s.mint(now); err != nil {
		return nil, err
	}
	return s, nil
}

// mint replaces the current leaf with a fresh one.
func (s *Server) mint(now time.Time) error {
	leaf, err := pki.ServerLeaf(s.int, s.hosts, s.params, now)
	if err != nil {
		return fmt.Errorf("minting this relay's certificate: %w", err)
	}
	certs := append([][]byte{leaf.Cert.Raw}, s.chain...)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaf = &tls.Certificate{Certificate: certs, PrivateKey: leaf.Key, Leaf: leaf.Cert}
	s.notAfter = leaf.Cert.NotAfter
	return nil
}

// GetCertificate is what the TLS server calls. A renewal takes over between
// one handshake and the next, with no restart and nothing dropped.
func (s *Server) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.leaf, nil
}

// NotAfter is when the current leaf expires.
func (s *Server) NotAfter() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.notAfter
}

// SPKI identifies the current leaf's key, which is what a witness attests.
func (s *Server) SPKI() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return pki.SPKI(s.leaf.Leaf)
}

// IntermediateNotAfter is when the server signing intermediate expires, which
// is the one an operator has to make a trip to the offline machine for.
func (s *Server) IntermediateNotAfter() time.Time { return s.int.Cert.NotAfter }

// RenewIfDue mints a fresh leaf when the current one is close to expiry, and
// reports whether it did.
func (s *Server) RenewIfDue(now time.Time, before time.Duration) (bool, error) {
	if now.Add(before).Before(s.NotAfter()) {
		return false, nil
	}
	if err := s.mint(now); err != nil {
		return false, err
	}
	return true, nil
}
