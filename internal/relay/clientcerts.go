package relay

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// ClientCertPolicy turns on client certificates. Nil is off: the relay issues
// none and requires none, and every route behaves as it did before.
//
// Issuer and Verifier come from an auu-ca bundle and are the shape this
// project settled on: the relay holds one signing key and the public
// certificates needed to check a chain to an anchor it never had the key for.
type ClientCertPolicy struct {
	// Issuer signs client certificates at enrolment and renewal.
	Issuer *clientca.Issuer
	// Verifier decides whether a presented certificate is one this relay's
	// authority issued.
	Verifier *clientca.Verifier
	// Lifetime is how long an issued certificate lives.
	Lifetime time.Duration
}

// Refusals a client turns into advice, so their exact words are pinned by
// tests on both sides.
const (
	msgCertRequired     = "this relay requires a client certificate"
	msgCertUnknown      = "client certificate is not known to this relay"
	msgCertRevoked      = "client certificate has been revoked"
	msgCertExpired      = "client certificate has expired"
	msgCertMismatch     = "client certificate does not belong to the signing identity"
	msgCertRefused      = "client certificate was refused"
	msgNoTokenOnRenewal = "a renewal carries no token"
	msgNoTrustAnchor    = "this relay does not use a private trust anchor"
)

// clientCerts reports whether this relay requires a certificate.
func (s *Server) clientCerts() bool { return s.cfg.ClientCerts != nil }

// clientCert finds the certificate this connection presented and checks that
// the relay still honours it.
//
// Everything here happens before the request's own signature is verified, so
// a refusal is charged to the address bucket like any other unauthenticated
// request and never to the identity the header claims. An attacker cannot
// spend somebody else's budget by naming them.
func (s *Server) clientCert(w http.ResponseWriter, r *http.Request) (*CertRow, bool) {
	if !s.clientCerts() {
		return nil, true
	}
	leaf, err := s.presentedCert(r)
	if err != nil {
		s.certFailed(w, r, msgCertRefused+": "+err.Error())
		return nil, false
	}
	if leaf == nil {
		s.certFailed(w, r, msgCertRequired)
		return nil, false
	}
	// The subject is the identity the relay named when it issued. A
	// certificate naming anything else is not one of ours whatever signed it.
	if err := clientca.Subject(leaf); err != nil {
		s.certFailed(w, r, msgCertRefused+": "+err.Error())
		return nil, false
	}
	serial := clientca.FormatSerial(leaf.SerialNumber)
	// The real clock, deliberately. A certificate's validity is an agreement
	// with the machine holding it, not something this relay's tests may bend.
	row, err := s.store.LiveCert(serial, time.Now())
	switch {
	case err == nil:
	case errors.Is(err, ErrNoCert):
		s.certFailed(w, r, msgCertUnknown)
		return nil, false
	case errors.Is(err, ErrCertRevoked):
		s.certFailed(w, r, msgCertRevoked)
		return nil, false
	case errors.Is(err, ErrCertExpired):
		s.certFailed(w, r, msgCertExpired)
		return nil, false
	default:
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return nil, false
	}
	// Belt and braces: the row and the certificate must agree about who this
	// is, or the relay would trust a subject it did not write.
	if row.FP != leaf.Subject.CommonName {
		s.certFailed(w, r, msgCertUnknown)
		return nil, false
	}
	// And about which key. The row records the key the certificate was
	// issued for; a leaf carrying this serial and this subject but another
	// key was minted by somebody holding a signing key — a retired
	// intermediate's, say — and not by this relay at enrolment. Refused, so
	// that a stolen signing key mints nothing the relay honours: a fresh
	// serial has no row, and a known serial has the wrong key.
	if row.SPKI != clientca.SPKI(leaf) {
		s.certFailed(w, r, msgCertUnknown)
		return nil, false
	}
	return row, true
}

// presentedCert returns the certificate this request's handshake carried,
// or nil. crypto/tls has already verified the chain and the key usage
// against this relay's authority; there is no other way a certificate
// arrives, since the relay terminates TLS itself.
func (s *Server) presentedCert(r *http.Request) (*x509.Certificate, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0], nil
	}
	return nil, nil
}

// certMatches checks that the certificate and the signature name the same
// identity. Two credentials that do not agree are worth less than one.
func (s *Server) certMatches(w http.ResponseWriter, r *http.Request, cert *CertRow, fp string) bool {
	if cert == nil || cert.FP == fp {
		return true
	}
	s.certFailed(w, r, msgCertMismatch)
	return false
}

// certFailed answers a certificate refusal, charged to the address.
func (s *Server) certFailed(w http.ResponseWriter, r *http.Request, msg string) {
	if ok, retry := s.lim.unauthenticated.Allow(s.clientIP(r)); !ok {
		s.rateLimited(w, limitUnauthenticated, retry, "")
		return
	}
	s.fail(w, http.StatusUnauthorized, msg)
}

// issueCert signs a certificate for a parsed request. The subject is fp,
// always: what a machine asked to be called is not consulted.
func (s *Server) issueCert(req *clientca.Request, fp string, now time.Time) (*clientca.Issued, error) {
	return s.cfg.ClientCerts.Issuer.Issue(req, fp, now, s.cfg.ClientCerts.Lifetime)
}

// certResponse is the shape both issuing routes answer with.
//
// CA carries the trust anchor rather than the intermediate that signed: the
// anchor is what a token pins and what a machine can usefully display, and it
// does not change when the relay's signing key is rotated.
func (s *Server) certResponse(issued *clientca.Issued) relayapi.CertResponse {
	return relayapi.CertResponse{
		Cert:     issued.Cert,
		CA:       s.cfg.ClientCerts.Verifier.Anchor().Raw,
		NotAfter: issued.NotAfter,
	}
}

// handleTrustAnchor serves the root a machine pins at enrolment.
//
// Unauthenticated and exempt from the certificate requirement: it is the one
// thing a machine must be able to fetch before it can verify anything. Serving
// it to anybody is safe because the anchor is public and because a client
// checks what comes back against the hash in its enrolment token before
// believing a byte of it.
func (s *Server) handleTrustAnchor(w http.ResponseWriter, r *http.Request) {
	if ok, retry := s.lim.unauthenticated.Allow(s.clientIP(r)); !ok {
		s.rateLimited(w, limitUnauthenticated, retry, "")
		return
	}
	if s.cfg.TrustAnchor == nil {
		// No bundle, so nothing to pin. This is decided by the anchor, not
		// by whether client certificates are required: those are off in
		// the shipped settings, and the anchor is needed all the same.
		s.fail(w, http.StatusNotFound, msgNoTrustAnchor)
		return
	}
	s.writeJSON(w, http.StatusOK, relayapi.TrustAnchorResponse{
		TrustAnchor: s.cfg.TrustAnchor.Raw,
		SPKI:        pki.SPKI(s.cfg.TrustAnchor),
	})
}

// readCSR pulls a certificate request out of a body and checks it, writing its
// own refusal. wantToken says whether one may carry an enrolment token.
func (s *Server) readCSR(w http.ResponseWriter, body []byte, wantToken bool) (*clientca.Request, bool) {
	var req relayapi.CertRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "malformed certificate request")
		return nil, false
	}
	return s.parseCSR(w, req.CSR, wantToken)
}

// parseCSR checks a certificate request and writes its own refusal.
func (s *Server) parseCSR(w http.ResponseWriter, csr []byte, wantToken bool) (*clientca.Request, bool) {
	if len(csr) == 0 {
		s.fail(w, http.StatusBadRequest, "a certificate request is required")
		return nil, false
	}
	// The parameter set is the authority's, when there is one. With client
	// certificates off the request is read only for the token inside it,
	// and any ML-DSA key will do.
	want := clientca.AnyParameters
	if s.clientCerts() {
		want = s.cfg.ClientCerts.Issuer.Parameters()
	}
	parsed, err := clientca.ParseCSR(csr, want)
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	// A renewal is authenticated by the certificate it arrives on, so a token
	// in one would be spent for nothing. Refused rather than ignored: a
	// client that sends one has misunderstood something.
	if !wantToken && parsed.Token != "" {
		s.fail(w, http.StatusBadRequest, msgNoTokenOnRenewal)
		return nil, false
	}
	return parsed, true
}

// handleIssueCert renews a machine's certificate.
//
// It is an authenticated route, so the caller already holds a live
// certificate and has signed this request with their identity key. That is
// why no token is needed: they have proved both halves of what a token would
// have bought them.
func (s *Server) handleIssueCert(w http.ResponseWriter, r *http.Request, body []byte, callerFP string, current *CertRow) {
	if fp := r.PathValue("fp"); fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	if !s.clientCerts() {
		s.fail(w, http.StatusNotFound, "this relay does not issue client certificates")
		return
	}
	req, ok := s.readCSR(w, body, false)
	if !ok {
		return
	}
	now := time.Now()
	issued, err := s.issueCert(req, callerFP, now)
	if err != nil {
		s.log.Error("issuing a client certificate", "err", err)
		s.fail(w, http.StatusInternalServerError, "could not issue a certificate")
		return
	}
	old := ""
	if current != nil {
		old = current.Serial
	}
	if err := s.store.RenewCert(callerFP, old, NewCertRow(issued, callerFP, now), now); err != nil {
		s.log.Error("recording a renewed certificate", "err", err)
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	s.audit("cert renew", "", callerFP, "ok", "serial", issued.Serial, "replaced", old)
	s.writeJSON(w, http.StatusOK, s.certResponse(issued))
}

// handleListCerts is a machine asking what certificates its identity has.
func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request, _ []byte, callerFP string, current *CertRow) {
	if fp := r.PathValue("fp"); fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	if !s.clientCerts() {
		s.fail(w, http.StatusNotFound, "this relay does not issue client certificates")
		return
	}
	rows, err := s.store.Certs(callerFP, true, time.Now())
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	out := make([]relayapi.CertRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.View(current != nil && row.Serial == current.Serial))
	}
	s.writeJSON(w, http.StatusOK, relayapi.CertsResponse{Certs: out})
}

// handleAdminCerts lists issued certificates, optionally for one identity.
func (s *Server) handleAdminCerts(w http.ResponseWriter, r *http.Request, _ []byte, _ string) {
	if !s.clientCerts() {
		s.fail(w, http.StatusNotFound, "this relay does not issue client certificates")
		return
	}
	all := r.URL.Query().Get("all") == "true"
	now := time.Now()

	var rows []CertRow
	var err error
	if fp := r.URL.Query().Get("fp"); fp != "" {
		if !identity.ValidFingerprint(fp) {
			s.fail(w, http.StatusBadRequest, "bad fingerprint")
			return
		}
		rows, err = s.store.Certs(fp, all, now)
	} else {
		rows, err = s.store.AllCerts(all, now)
	}
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	out := make([]relayapi.CertRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.View(false))
	}
	s.writeJSON(w, http.StatusOK, relayapi.CertsResponse{Certs: out})
}

// handleAdminRevokeCert withdraws one certificate. The machine holding it
// loses the relay on its very next request: every authenticated route resolves
// the serial, so there is nothing to distribute and nothing to wait for.
func (s *Server) handleAdminRevokeCert(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	if !s.clientCerts() {
		s.fail(w, http.StatusNotFound, "this relay does not issue client certificates")
		return
	}
	serial := r.PathValue("serial")
	if !clientca.ValidSerial(serial) {
		s.fail(w, http.StatusBadRequest, "bad certificate serial")
		return
	}
	var req relayapi.RevokeCertRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			s.fail(w, http.StatusBadRequest, "malformed revoke request")
			return
		}
	}
	// A reason is optional here, unlike a block's: revoking a certificate is
	// often housekeeping rather than a judgement about somebody. When there
	// is one it gets the same bound, because it reaches an administrator's
	// terminal and the operator's log.
	reason := strings.TrimSpace(req.Reason)
	if reason != "" {
		if err := token.ValidateNote(reason); err != nil {
			s.fail(w, http.StatusBadRequest, "reason "+err.Error())
			return
		}
	}
	// Read before the update so the audit line can name whose machine this
	// was. An administrator revoking by serial may not know.
	row, err := s.store.CertBySerial(serial)
	if errors.Is(err, ErrNoCert) {
		s.fail(w, http.StatusNotFound, "no such certificate")
		return
	}
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	revoked, err := s.store.RevokeCert(serial, adminFP, reason, time.Now())
	if err != nil {
		s.audit("cert.revoke", adminFP, row.FP, "error", "serial", serial)
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	if !revoked {
		// Already revoked. Not an error, but not a change either.
		s.fail(w, http.StatusNotFound, "no such certificate")
		return
	}
	s.audit("cert.revoke", adminFP, row.FP, "ok", "serial", serial, "label", row.Label)
	s.writeJSON(w, http.StatusOK, relayapi.RevokeCertResponse{Revoked: true})
}
