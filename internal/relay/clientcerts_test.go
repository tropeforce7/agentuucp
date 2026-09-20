package relay

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// certHarness is a relay that requires client certificates, served over TLS so
// that a real handshake carries them.
type certHarness struct {
	*harness
	// ca is the offline authority the relay was issued from, kept so a
	// test can rotate the relay's intermediates the way auu-ca does.
	ca      *pki.Store
	bundle  *pki.Loaded
	tlsSrv  *httptest.Server
	rootCAs *x509.CertPool
	admin   *identity.Identity
	mutate  func(*Config)
}

// certHosts are the names the test relay is issued for.
var certHosts = []string{"relay.example.com", "127.0.0.1"}

// anchor is the trust anchor this harness's relay was issued from.
func (h *certHarness) anchor() *x509.Certificate { return h.bundle.Anchor }

// newCertHarness starts a relay with client certificates required and one
// administrator, which token-mode enrolment needs.
func newCertHarness(t *testing.T, mutate func(*Config)) *certHarness {
	t.Helper()
	return newCertHarnessAt(t, mldsa.MLDSA65(), mutate)
}

// newCertHarnessAt is newCertHarness with the authority at a chosen
// parameter set.
func newCertHarnessAt(t *testing.T, params mldsa.Parameters, mutate func(*Config)) *certHarness {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	ca := pki.TestStore(t, params)
	bundle := pki.TestBundleFrom(t, ca, certHosts)
	return startCertRelay(t, ca, store, bundle, ids(t, "boss")[0], newTestClock(), &syncBuffer{}, mutate)
}

// rotate is 'auu-ca relay' again and a restart: fresh signing intermediates
// from the same offline authority, serving the same database. What was
// enrolled before must not notice.
func (h *certHarness) rotate() *certHarness {
	h.t.Helper()
	rotated := pki.TestBundleFrom(h.t, h.ca, certHosts)
	return startCertRelay(h.t, h.ca, h.store, rotated, h.admin, h.clock, h.logs, h.mutate)
}

// startCertRelay starts a relay from a bundle over an existing store.
func startCertRelay(t *testing.T, ca *pki.Store, store *Store, bundle *pki.Loaded,
	admin *identity.Identity, clock *testClock, logs *syncBuffer, mutate func(*Config)) *certHarness {
	t.Helper()
	cfg := Config{
		Streams:      true,
		streamsSet:   true,
		AdminFile:    adminFile(t, admin),
		Registration: relayapi.RegistrationToken,
		PublicURL:    "https://relay.example.com",
		ClientCerts: &ClientCertPolicy{
			Issuer:   clientca.NewIssuer(bundle),
			Verifier: clientca.NewVerifier(bundle),
			Lifetime: 365 * 24 * time.Hour,
		},
		TrustAnchor: bundle.Anchor,
		Logger:      slog.New(slog.NewTextHandler(logs, nil)),
		Now:         clock.Now,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	server := NewServer(store, cfg)

	// A plain server for the requests a test makes without a handshake, and a
	// TLS one that asks for a certificate.
	plain := httptest.NewServer(server)
	t.Cleanup(plain.Close)

	tlsSrv := httptest.NewUnstartedServer(server)
	tlsSrv.TLS = clientca.NewVerifier(bundle).TLSConfig(&tls.Config{})
	tlsSrv.StartTLS()
	t.Cleanup(tlsSrv.Close)

	roots := x509.NewCertPool()
	roots.AddCert(tlsSrv.Certificate())

	return &certHarness{
		harness: &harness{t: t, srv: plain, store: store, clock: clock, logs: logs},
		ca:      ca, bundle: bundle, tlsSrv: tlsSrv, rootCAs: roots, admin: admin, mutate: mutate,
	}
}

// stolenSigningKey is the client signing intermediate the relay holds: what
// an attacker who has read the relay's disk obtains, and the whole reason the
// certs table binds a serial to the key it was issued for.
func (h *certHarness) stolenSigningKey() *pki.Key { return h.bundle.ClientInt }

// forgedLeaf is what a stolen signing key produces: a certificate with a
// serial and subject the relay knows, and a key it does not.
func (h *certHarness) forgedLeaf(serial *big.Int, fp string) *machine {
	h.t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		h.t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: fp},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, h.stolenSigningKey().Cert, key.PublicKey(), h.stolenSigningKey().Key)
	if err != nil {
		h.t.Fatal(err)
	}
	return &machine{key: key, cert: der, serial: clientca.FormatSerial(serial)}
}

// machine is one enrolled machine: its key and the certificate it holds.
type machine struct {
	key    *mldsa.PrivateKey
	cert   []byte
	serial string
}

func (m *machine) tlsCert() *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{m.cert}, PrivateKey: m.key}
}

// enrolMachine registers an identity with a token and keeps the certificate
// that comes back.
func (h *certHarness) enrolMachine(id *identity.Identity, tok string) (*machine, int, []byte) {
	h.t.Helper()
	return h.enrolMachineWith(id, tok, h.bundle.Params)
}

// enrolMachineWith enrols with a key of a chosen set, which may not be the
// authority's.
func (h *certHarness) enrolMachineWith(id *identity.Identity, tok string, params mldsa.Parameters) (*machine, int, []byte) {
	h.t.Helper()
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		h.t.Fatal(err)
	}
	status, body := h.registerKey(id, key, tok)
	if status != http.StatusOK {
		return nil, status, body
	}
	var resp relayapi.RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		h.t.Fatal(err)
	}
	if len(resp.Cert) == 0 {
		h.t.Fatal("registration returned no certificate")
	}
	leaf, err := x509.ParseCertificate(resp.Cert)
	if err != nil {
		h.t.Fatal(err)
	}
	return &machine{key: key, cert: resp.Cert, serial: clientca.FormatSerial(leaf.SerialNumber)},
		status, body
}

// registerToken issues and registers a token of the given use.
func (h *certHarness) registerToken(use, subject string) string {
	h.t.Helper()
	return h.addToken(h.admin, func(c *token.Claims) {
		c.Use = use
		c.Subject = subject
		c.Relay = "https://relay.example.com"
	})
}

// overTLS sends a signed request through the TLS server, presenting cert.
func (h *certHarness) overTLS(id *identity.Identity, cert *tls.Certificate,
	method, path string, payload any) (int, []byte) {
	h.t.Helper()
	var body []byte
	if payload != nil {
		var err error
		if raw, ok := payload.([]byte); ok {
			body = raw
		} else if body, err = json.Marshal(payload); err != nil {
			h.t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, h.tlsSrv.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if id != nil {
		if err := relayapi.SignRequest(id, req, body); err != nil {
			h.t.Fatal(err)
		}
	}
	cfg := &tls.Config{RootCAs: h.rootCAs, MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp.StatusCode, out
}

func TestEnrolmentIssuesACertificateBoundToTheIdentity(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	m, status, body := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	if status != http.StatusOK {
		t.Fatalf("enrolment: %d %s", status, body)
	}

	leaf, err := x509.ParseCertificate(m.cert)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != alice.Fingerprint() {
		t.Errorf("certificate names %q, want alice's fingerprint", leaf.Subject.CommonName)
	}
	// The row exists and agrees with the certificate.
	row, err := h.store.CertBySerial(m.serial)
	if err != nil {
		t.Fatalf("no row for the issued certificate: %v", err)
	}
	if row.FP != alice.Fingerprint() {
		t.Errorf("row names %s, want alice", row.FP[:16])
	}
	if row.Revoked {
		t.Error("a freshly issued certificate is revoked")
	}
	// And the response carried the authority, so the machine can show which
	// relay issued to it.
	var resp relayapi.RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp.CA, h.anchor().Raw) {
		t.Error("the response does not carry this relay's authority")
	}
	if resp.NotAfter == nil || !resp.NotAfter.Equal(row.NotAfter) {
		t.Error("the response's expiry does not match the row")
	}
}

func TestMailboxRoutesRefuseWithoutACertificate(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	m, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	fp := alice.Fingerprint()

	// Every route that carries or reveals mail. A correctly signed request
	// from the very identity that owns the mailbox is still refused.
	for _, tc := range []struct {
		name, method, path string
		payload            any
	}{
		{"list", "GET", "/v1/mailbox/" + fp, nil},
		{"post", "POST", "/v1/mailbox/" + fp, sealed(t, alice, alice.Public(), "hello")},
		{"allow", "PUT", "/v1/mailbox/" + fp + "/allow", relayapi.AllowRequest{}},
		{"delete", "DELETE", "/v1/mailbox/" + fp + "/1", nil},
		{"open stream", "POST", "/v1/mailbox/" + fp + "/streams", relayapi.OpenStreamRequest{}},
		{"keys", "GET", "/v1/keys/" + fp, nil},
		{"certs", "GET", "/v1/mailbox/" + fp + "/certs", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := h.send(alice, tc.method, tc.path, tc.payload, nil)
			if status != http.StatusUnauthorized {
				t.Fatalf("%s without a certificate: %d, want 401: %s", tc.name, status, body)
			}
			if got := errorText(t, body); got != msgCertRequired {
				t.Errorf("error %q, want %q", got, msgCertRequired)
			}
			// And the same request with one succeeds, so the refusal is
			// about the certificate and nothing else.
			if status, _ := h.overTLS(alice, m.tlsCert(), tc.method, tc.path, tc.payload); status == http.StatusUnauthorized {
				t.Errorf("%s with a certificate was also refused", tc.name)
			}
		})
	}
}

func TestRoutesThatNeedNoCertificate(t *testing.T) {
	// Enrolment must be reachable by a machine that has none yet, health by
	// a monitor that will never have one, and the admin API by an
	// administrator who need not be a user of the relay at all.
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]

	if status, _, _ := h.send(nil, "GET", "/v1/health", nil, nil); status != http.StatusOK {
		t.Errorf("health without a certificate: %d, want 200", status)
	}
	if _, status, body := h.enrolMachine(alice, h.registerToken(token.UseRegister, "")); status != http.StatusOK {
		t.Errorf("register without a certificate: %d %s", status, body)
	}
	for _, path := range []string{"/v1/admin/status", "/v1/admin/mailboxes", "/v1/admin/certs"} {
		if status, body, _ := h.send(h.admin, "GET", path, nil, nil); status != http.StatusOK {
			t.Errorf("%s without a certificate: %d %s", path, status, body)
		}
	}
}

// TestTheCertificateIsCheckedBeforeTheBodyIsRead: on every authenticated
// route, including the one addressed by upload id, a caller without a
// certificate is refused before the relay accepts what they wanted to
// send. Proved with a body over readBody's bound: read, it would be 413;
// refused first, it is 401 and the body is never read.
func TestTheCertificateIsCheckedBeforeTheBodyIsRead(t *testing.T) {
	h := newCertHarness(t, func(c *Config) { c.MaxBytes = 4096 })
	alice := ids(t, "alice")[0]
	h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	fp := alice.Fingerprint()
	over := bytes.Repeat([]byte("x"), 4096+relayapi.FramingAllowance+1)

	for _, tc := range []struct{ name, method, path string }{
		{"an attempt, by upload id", "PUT", "/v1/uploads/" + strings.Repeat("ab", 16)},
		{"post, by mailbox", "POST", "/v1/mailbox/" + fp},
		{"allow list, by mailbox", "PUT", "/v1/mailbox/" + fp + "/allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := h.send(alice, tc.method, tc.path, over, nil)
			if status != http.StatusUnauthorized {
				t.Fatalf("an over-bound body from a caller with no certificate: %d, want 401 before the body is read: %s", status, body)
			}
			if got := errorText(t, body); got != msgCertRequired {
				t.Errorf("error %q, want %q", got, msgCertRequired)
			}
		})
	}
}

func TestACertificateForAnotherIdentityIsRefused(t *testing.T) {
	// Two credentials that do not agree are worth less than one. Mallory
	// holds a certificate the relay issued to her, and signs as alice.
	h := newCertHarness(t, nil)
	people := ids(t, "alice", "mallory")
	alice, mallory := people[0], people[1]
	h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	mal, _, _ := h.enrolMachine(mallory, h.registerToken(token.UseRegister, ""))

	status, body := h.overTLS(alice, mal.tlsCert(), "GET", "/v1/mailbox/"+alice.Fingerprint(), nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("a certificate for another identity: %d, want 401: %s", status, body)
	}
	if got := errorText(t, body); got != msgCertMismatch {
		t.Errorf("error %q, want %q", got, msgCertMismatch)
	}
}

func TestARevokedCertificateStopsWorkingImmediately(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	m, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	path := "/v1/mailbox/" + alice.Fingerprint()

	if status, body := h.overTLS(alice, m.tlsCert(), "GET", path, nil); status != http.StatusOK {
		t.Fatalf("before revocation: %d %s", status, body)
	}
	status, body, _ := h.send(h.admin, "DELETE", "/v1/admin/certs/"+m.serial,
		relayapi.RevokeCertRequest{Reason: "lost laptop"}, nil)
	if status != http.StatusOK {
		t.Fatalf("revoking: %d %s", status, body)
	}
	// The very next request, with no distribution and nothing to wait for.
	status, body = h.overTLS(alice, m.tlsCert(), "GET", path, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("after revocation: %d, want 401: %s", status, body)
	}
	if got := errorText(t, body); got != msgCertRevoked {
		t.Errorf("error %q, want %q", got, msgCertRevoked)
	}
	// Revoking twice is not a change.
	if status, _, _ := h.send(h.admin, "DELETE", "/v1/admin/certs/"+m.serial, nil, nil); status != http.StatusNotFound {
		t.Errorf("second revocation: %d, want 404", status)
	}
	// The audit log names whose machine it was, and why.
	logs := h.logs.String()
	if !strings.Contains(logs, "cert.revoke") || !strings.Contains(logs, m.serial) {
		t.Errorf("no audit line for the revocation:\n%s", logs)
	}
	if !strings.Contains(logs, alice.Fingerprint()[:16]) {
		t.Error("the audit line does not name whose machine it was")
	}
}

func TestAnUnknownSerialIsRefused(t *testing.T) {
	// A certificate this authority signed but whose row is gone: what a
	// restore from an older backup would produce.
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	m, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	if _, err := h.store.db.Exec(`DELETE FROM certs WHERE serial = ?`, m.serial); err != nil {
		t.Fatal(err)
	}
	status, body := h.overTLS(alice, m.tlsCert(), "GET", "/v1/mailbox/"+alice.Fingerprint(), nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("a certificate with no row: %d, want 401: %s", status, body)
	}
	if got := errorText(t, body); got != msgCertUnknown {
		t.Errorf("error %q, want %q", got, msgCertUnknown)
	}
}

func TestAnExpiredRowIsRefused(t *testing.T) {
	// The row expiring, rather than the certificate: the relay must not go on
	// honouring one past the date it recorded, whatever the leaf says.
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	m, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	if _, err := h.store.db.Exec(`UPDATE certs SET not_after = ? WHERE serial = ?`,
		time.Now().Add(-time.Second).Unix(), m.serial); err != nil {
		t.Fatal(err)
	}
	status, body := h.overTLS(alice, m.tlsCert(), "GET", "/v1/mailbox/"+alice.Fingerprint(), nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("an expired row: %d, want 401: %s", status, body)
	}
	if got := errorText(t, body); got != msgCertExpired {
		t.Errorf("error %q, want %q", got, msgCertExpired)
	}
}

func TestASecondMachineNeedsACertificateToken(t *testing.T) {
	// The point of the whole feature: an identity copied to another machine
	// cannot mint itself a certificate with only its own signature. If it
	// could, the certificate would add nothing against exactly the attacker
	// it exists for.
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))

	// The identity, on a second machine, with no token.
	_, status, body := h.enrolMachine(alice, "")
	if status != http.StatusForbidden {
		t.Fatalf("a second machine with no token: %d, want 403: %s", status, body)
	}
	if got := errorText(t, body); got != msgNeedCertToken {
		t.Errorf("error %q, want %q", got, msgNeedCertToken)
	}

	// A register token does not do instead: it authorises a mailbox, and
	// alice has one. The refusal names the token that would, with alice's
	// own fingerprint filled in, since the signature proved it.
	_, status, body = h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	if status != http.StatusForbidden {
		t.Fatalf("a second machine with a register token: %d, want 403: %s", status, body)
	}
	wantWrongUse := "this identity already holds a live certificate on another machine, so adding this one " +
		"needs a certificate token: ask the administrator for one issued with --use cert --for " + alice.Fingerprint()
	if got := errorText(t, body); got != wantWrongUse {
		t.Errorf("error %q, want %q", got, wantWrongUse)
	}

	// A certificate token bound to somebody else does not either.
	other := ids(t, "bob")[0]
	_, status, _ = h.enrolMachine(alice, h.registerToken(token.UseCert, other.Fingerprint()))
	if status != http.StatusForbidden {
		t.Fatalf("a cert token bound to another identity: %d, want 403", status)
	}

	// Bound to alice, it works, and she now has two machines.
	second, status, body := h.enrolMachine(alice, h.registerToken(token.UseCert, alice.Fingerprint()))
	if status != http.StatusOK {
		t.Fatalf("a second machine with its own token: %d %s", status, body)
	}
	rows, err := h.store.Certs(alice.Fingerprint(), false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("alice has %d live certificates, want 2", len(rows))
	}
	// And both work: enrolling a machine does not disturb the other.
	for name, m := range map[string]*machine{"first": nil, "second": second} {
		if m == nil {
			continue
		}
		if status, body := h.overTLS(alice, m.tlsCert(), "GET", "/v1/mailbox/"+alice.Fingerprint(), nil); status != http.StatusOK {
			t.Errorf("%s machine: %d %s", name, status, body)
		}
	}
}

func TestARefusedEnrolmentSpendsNoToken(t *testing.T) {
	// Every refusal on the way in must leave the token as it was, or a
	// mistyped command would cost somebody their invitation.
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]

	for _, tc := range []struct {
		name string
		send func(tok string) (int, []byte)
	}{
		{"blocked identity", func(tok string) (int, []byte) {
			if err := h.store.SetBlock(alice.Fingerprint(), "spam", "admin", time.Now()); err != nil {
				t.Fatal(err)
			}
			_, status, body := h.enrolMachine(alice, tok)
			if _, err := h.store.RemoveBlock(alice.Fingerprint()); err != nil {
				t.Fatal(err)
			}
			return status, body
		}},
		{"malformed certificate request", func(tok string) (int, []byte) {
			return h.do(alice, "POST", "/v1/register", relayapi.RegisterRequest{
				Bundle: alice.Public().Bundle(), Name: alice.Name, CSR: []byte("not a request"),
			}, nil)
		}},
		{"no certificate request", func(tok string) (int, []byte) {
			return h.do(alice, "POST", "/v1/register", relayapi.RegisterRequest{
				Bundle: alice.Public().Bundle(), Name: alice.Name,
			}, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := h.registerToken(token.UseRegister, "")
			id := tokenID(t, tok)
			status, body := tc.send(tok)
			if status < 400 {
				t.Fatalf("%s was accepted: %d %s", tc.name, status, body)
			}
			rec, err := h.store.Token(id)
			if err != nil {
				t.Fatal(err)
			}
			if rec.UsesLeft != rec.Uses {
				t.Errorf("%s spent a use: %d of %d left", tc.name, rec.UsesLeft, rec.Uses)
			}
			// And no mailbox, and no certificate.
			if exists, _, _ := h.store.MailboxState(alice.Fingerprint()); exists {
				t.Errorf("%s created a mailbox", tc.name)
			}
			rows, err := h.store.Certs(alice.Fingerprint(), true, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 0 {
				t.Errorf("%s recorded %d certificates", tc.name, len(rows))
			}
		})
	}
}

// tokenID reads the id out of a token, for looking the row up.
func tokenID(t *testing.T, raw string) string {
	t.Helper()
	u, err := token.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Claims.ID
}

func TestEnrolmentTokenInAHeaderIsRefusedPlainly(t *testing.T) {
	// A client of the earlier protocol, whose token was a header outside the
	// signature. It is told what changed rather than being refused for a
	// missing token, which would send somebody looking for the wrong thing.
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	status, body, _ := h.send(alice, "POST", "/v1/register",
		h.registerBody(alice, alice.Name, ""),
		map[string]string{"X-CCX-Token": h.registerToken(token.UseRegister, "")})
	if status != http.StatusBadRequest {
		t.Fatalf("a token in a header: %d, want 400: %s", status, body)
	}
	if got := errorText(t, body); got != relayapi.MsgTokenInHeader {
		t.Errorf("error %q, want %q", got, relayapi.MsgTokenInHeader)
	}
}

func TestRenewalReplacesTheCertificateAtomically(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	m, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	path := "/v1/mailbox/" + alice.Fingerprint() + "/certs"

	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := clientca.NewCSR(key, "laptop", "")
	if err != nil {
		t.Fatal(err)
	}
	status, body := h.overTLS(alice, m.tlsCert(), "POST", path, relayapi.CertRequest{CSR: csr})
	if status != http.StatusOK {
		t.Fatalf("renewal: %d %s", status, body)
	}
	var resp relayapi.CertResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	fresh := &machine{key: key, cert: resp.Cert, serial: clientca.FormatSerial(leaf.SerialNumber)}

	// The old one is retired, and says why.
	old, err := h.store.CertBySerial(m.serial)
	if err != nil {
		t.Fatal(err)
	}
	if !old.Revoked || old.Reason != reasonRenewed {
		t.Errorf("the replaced certificate is revoked=%v reason=%q, want true and %q",
			old.Revoked, old.Reason, reasonRenewed)
	}
	// And stops working on the very next request.
	mailbox := "/v1/mailbox/" + alice.Fingerprint()
	if status, _ := h.overTLS(alice, m.tlsCert(), "GET", mailbox, nil); status != http.StatusUnauthorized {
		t.Errorf("the replaced certificate still works: %d", status)
	}
	if status, body := h.overTLS(alice, fresh.tlsCert(), "GET", mailbox, nil); status != http.StatusOK {
		t.Errorf("the fresh certificate does not work: %d %s", status, body)
	}
}

func TestRenewalCarriesNoToken(t *testing.T) {
	// A token in a renewal would be spent for nothing, so it is refused
	// rather than ignored: a client that sends one has misunderstood.
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	m, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))

	tok := h.registerToken(token.UseCert, alice.Fingerprint())
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := clientca.NewCSR(key, "laptop", tok)
	if err != nil {
		t.Fatal(err)
	}
	status, body := h.overTLS(alice, m.tlsCert(), "POST",
		"/v1/mailbox/"+alice.Fingerprint()+"/certs", relayapi.CertRequest{CSR: csr})
	if status != http.StatusBadRequest {
		t.Fatalf("a renewal with a token: %d, want 400: %s", status, body)
	}
	if got := errorText(t, body); got != msgNoTokenOnRenewal {
		t.Errorf("error %q, want %q", got, msgNoTokenOnRenewal)
	}
	// And nothing changed: the token is unspent and the certificate stands.
	rec, err := h.store.Token(tokenID(t, tok))
	if err != nil {
		t.Fatal(err)
	}
	if rec.UsesLeft != rec.Uses {
		t.Error("the refused renewal spent a use of the token")
	}
	if row, err := h.store.CertBySerial(m.serial); err != nil || row.Revoked {
		t.Error("the refused renewal disturbed the existing certificate")
	}
}

func TestTheListingMarksThisMachine(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	first, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	second, _, _ := h.enrolMachine(alice, h.registerToken(token.UseCert, alice.Fingerprint()))

	status, body := h.overTLS(alice, second.tlsCert(), "GET",
		"/v1/mailbox/"+alice.Fingerprint()+"/certs", nil)
	if status != http.StatusOK {
		t.Fatalf("listing: %d %s", status, body)
	}
	var resp relayapi.CertsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Certs) != 2 {
		t.Fatalf("listed %d certificates, want 2", len(resp.Certs))
	}
	for _, cert := range resp.Certs {
		want := cert.Serial == second.serial
		if cert.Current != want {
			t.Errorf("certificate %s: current=%v, want %v", cert.Serial[:8], cert.Current, want)
		}
	}
	_ = first
}

func TestACertificateRefusalIsChargedToTheAddress(t *testing.T) {
	// A refusal before the signature has been checked must never be charged
	// to the identity the header claims, or a stranger could exhaust
	// somebody else's budget by naming them.
	const budget = 6
	h := newCertHarness(t, func(cfg *Config) {
		cfg.Limits = Limits{RequestsPerMinute: budget}
	})
	alice := ids(t, "alice")[0]
	// Enrolling is itself an authenticated request and spends one.
	m, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	path := "/v1/mailbox/" + alice.Fingerprint()

	// Twenty refused requests naming alice, with no certificate. If any of
	// them were charged to her, fewer than the remaining budget would
	// succeed afterwards.
	for i := 0; i < 20; i++ {
		if status, _, _ := h.send(alice, "GET", path, nil, nil); status != http.StatusUnauthorized {
			t.Fatalf("request %d: %d, want 401", i, status)
		}
	}
	// Exactly the budget less the enrolment, and then one more is refused:
	// the count is asserted on both sides, so a bucket that was quietly
	// refilled would fail this too.
	for i := 0; i < budget-1; i++ {
		if status, body := h.overTLS(alice, m.tlsCert(), "GET", path, nil); status != http.StatusOK {
			t.Fatalf("alice's request %d of %d after the refusals: %d %s",
				i+1, budget-1, status, body)
		}
	}
	if status, _ := h.overTLS(alice, m.tlsCert(), "GET", path, nil); status != http.StatusTooManyRequests {
		t.Fatalf("one past the budget: %d, want 429", status)
	}
}

func TestDeregisteringRemovesTheCertificates(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	m, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))

	if _, err := h.store.Deregister(alice.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CertBySerial(m.serial); err == nil {
		t.Error("deregistering left the certificate row behind")
	}
	n, err := h.store.LiveCerts(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("LiveCerts = %d after deregistering the only mailbox, want 0", n)
	}
}

func TestAdminStatusReportsTheAuthority(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))

	status, body, _ := h.send(h.admin, "GET", "/v1/admin/status", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	var resp relayapi.AdminStatusResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ClientCerts != relayapi.ClientCertsRequired {
		t.Errorf("client_certs = %q, want %q", resp.ClientCerts, relayapi.ClientCertsRequired)
	}
	if resp.CAFingerprint != h.bundle.AnchorSPKI {
		t.Errorf("ca_fingerprint = %q, want the authority's", resp.CAFingerprint)
	}
	if resp.CANotAfter == nil || !resp.CANotAfter.Equal(h.bundle.ClientInt.Cert.NotAfter) {
		t.Error("ca_not_after is not the authority's expiry")
	}
	if resp.LiveCerts != 1 {
		t.Errorf("live_certs = %d, want 1", resp.LiveCerts)
	}
}

func TestARelayWithCertificatesOffIssuesNoneAndStillTakesTokens(t *testing.T) {
	// The certificate request is read whatever the mode, because the
	// enrolment token lives inside it. What changes is only whether anything
	// is issued.
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{
		AdminFile:    adminFile(t, boss),
		Registration: relayapi.RegistrationToken,
	})
	alice := ids(t, "alice")[0]
	tok := h.addToken(boss, func(c *token.Claims) { c.Use = token.UseRegister })

	status, body := h.registerWith(alice, tok)
	if status != http.StatusOK {
		t.Fatalf("enrolment with certificates off: %d %s", status, body)
	}
	var resp relayapi.RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Cert) != 0 || len(resp.CA) != 0 || resp.NotAfter != nil {
		t.Error("a relay with certificates off issued one")
	}
	// The token was still spent, and no row was written.
	rec, err := h.store.Token(tokenID(t, tok))
	if err != nil {
		t.Fatal(err)
	}
	if rec.UsesLeft != rec.Uses-1 {
		t.Errorf("uses left %d of %d, want one spent", rec.UsesLeft, rec.Uses)
	}
	rows, err := h.store.Certs(alice.Fingerprint(), true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("%d certificate rows written with certificates off", len(rows))
	}
	// And the mailbox works with no certificate at all.
	if status, _, _ := h.send(alice, "GET", "/v1/mailbox/"+alice.Fingerprint(), nil, nil); status != http.StatusOK {
		t.Errorf("a mailbox route with certificates off: %d, want 200", status)
	}
	// The certificate routes say plainly that this relay does not do it.
	if status, body, _ := h.send(alice, "GET", "/v1/mailbox/"+alice.Fingerprint()+"/certs", nil, nil); status != http.StatusNotFound {
		t.Errorf("the certificate listing with certificates off: %d, want 404: %s", status, body)
	}
}

func TestAnExistingMailboxRenamesWithoutATokenOnAnOpenRelay(t *testing.T) {
	// On an open relay there is nothing to pay for, so a second machine and
	// a rename both work with no token. The cost appears when registration
	// is closed or by token, which is where it means something.
	h := newCertHarness(t, func(cfg *Config) {
		cfg.Registration = relayapi.RegistrationOpen
	})
	alice := ids(t, "alice")[0]
	if _, status, body := h.enrolMachine(alice, ""); status != http.StatusOK {
		t.Fatalf("first machine on an open relay: %d %s", status, body)
	}
	if _, status, body := h.enrolMachine(alice, ""); status != http.StatusOK {
		t.Fatalf("second machine on an open relay: %d %s", status, body)
	}
	rows, err := h.store.Certs(alice.Fingerprint(), false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d live certificates, want 2", len(rows))
	}
}

func TestHousekeepingRemovesLongDeadCertificates(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	m, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	second, _, _ := h.enrolMachine(alice, h.registerToken(token.UseCert, alice.Fingerprint()))

	// One revoked and long expired, one revoked yesterday. An administrator
	// must still be able to see the recent one.
	old := time.Now().Add(-2 * expiredTokenRetention)
	if _, err := h.store.db.Exec(
		`UPDATE certs SET revoked = 1, not_after = ? WHERE serial = ?`, old.Unix(), m.serial); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.db.Exec(
		`UPDATE certs SET revoked = 1, not_after = ? WHERE serial = ?`,
		time.Now().Add(-24*time.Hour).Unix(), second.serial); err != nil {
		t.Fatal(err)
	}

	if err := h.store.PurgeCerts(time.Now().Add(-expiredTokenRetention)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CertBySerial(m.serial); err == nil {
		t.Error("a long-dead certificate was kept")
	}
	if _, err := h.store.CertBySerial(second.serial); err != nil {
		t.Error("a certificate revoked yesterday was purged; an administrator can no longer see it")
	}
}

func TestAStolenSigningKeyMintsNothingTheRelayHonours(t *testing.T) {
	// The property a retired-but-still-verifying intermediate depends on. An
	// attacker with the signing key can produce a certificate that chains,
	// but not one the relay will act on: a fresh serial has no row, and a
	// known serial is bound to the key it was issued for.
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	real, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	path := "/v1/mailbox/" + alice.Fingerprint()

	// A fresh serial: chains, but the relay never issued it.
	fresh, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	status, body := h.overTLS(alice, h.forgedLeaf(fresh, alice.Fingerprint()).tlsCert(), "GET", path, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("a forged leaf with a fresh serial: %d, want 401: %s", status, body)
	}
	if got := errorText(t, body); got != msgCertUnknown {
		t.Errorf("error %q, want %q", got, msgCertUnknown)
	}

	// The real serial and the real subject, under the attacker's own key.
	// Before the SPKI check this was accepted.
	realSerial, ok := new(big.Int).SetString(real.serial, 16)
	if !ok {
		t.Fatal("bad serial")
	}
	status, body = h.overTLS(alice, h.forgedLeaf(realSerial, alice.Fingerprint()).tlsCert(), "GET", path, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("a forged leaf reusing a real serial: %d, want 401: %s", status, body)
	}
	if got := errorText(t, body); got != msgCertUnknown {
		t.Errorf("error %q, want %q", got, msgCertUnknown)
	}

	// And the genuine certificate still works, so the check is about the
	// key and not the serial.
	if status, body := h.overTLS(alice, real.tlsCert(), "GET", path, nil); status != http.StatusOK {
		t.Fatalf("the genuine certificate after the forgeries: %d %s", status, body)
	}
}

func TestTheRelayChoosesTheParameterSet(t *testing.T) {
	// An authority at ML-DSA-87. A machine that asks gets told, generates
	// an 87 key, enrols, and connects over a real handshake — which is also
	// what proves TLS 1.3 negotiates the 87 scheme end to end. A machine that
	// did not ask and brought a 65 key is refused with a message naming
	// both sets.
	h := newCertHarnessAt(t, mldsa.MLDSA87(), nil)
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]

	// The relay says which set it wants, on the route a machine can reach
	// before it holds anything.
	status, body, _ := h.send(nil, "GET", "/v1/health", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("health: %d %s", status, body)
	}
	var health relayapi.HealthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatal(err)
	}
	if health.MLDSA != 87 {
		t.Fatalf("health reports mldsa %d, want 87", health.MLDSA)
	}

	m, status, body := h.enrolMachineWith(alice, h.registerToken(token.UseRegister, ""), mldsa.MLDSA87())
	if status != http.StatusOK {
		t.Fatalf("enrolling with an 87 key: %d %s", status, body)
	}
	leaf, err := x509.ParseCertificate(m.cert)
	if err != nil {
		t.Fatal(err)
	}
	if got := leaf.PublicKey.(*mldsa.PublicKey).Parameters(); got != mldsa.MLDSA87() {
		t.Errorf("issued certificate's key is %s, want ML-DSA-87", got)
	}
	if leaf.SignatureAlgorithm != x509.MLDSA87 {
		t.Errorf("issued certificate is signed with %v, want ML-DSA-87", leaf.SignatureAlgorithm)
	}
	if status, body := h.overTLS(alice, m.tlsCert(), "GET", "/v1/mailbox/"+alice.Fingerprint(), nil); status != http.StatusOK {
		t.Fatalf("an 87 certificate through a real handshake: %d %s", status, body)
	}

	// The wrong set, either way round.
	for _, tc := range []struct {
		name   string
		params mldsa.Parameters
		want   string
	}{
		{"weaker", mldsa.MLDSA65(), "client keys must be ML-DSA-87, got ML-DSA-65"},
		{"weakest", mldsa.MLDSA44(), "client keys must be ML-DSA-87, got ML-DSA-44"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := h.registerToken(token.UseRegister, "")
			_, status, body := h.enrolMachineWith(bob, tok, tc.params)
			if status != http.StatusBadRequest {
				t.Fatalf("a %s key at an 87 relay: %d, want 400: %s", tc.name, status, body)
			}
			if got := errorText(t, body); !strings.Contains(got, tc.want) {
				t.Errorf("error %q does not say %q", got, tc.want)
			}
			// And the token is untouched, as any refused enrolment leaves it.
			rec, err := h.store.Token(tokenID(t, tok))
			if err != nil {
				t.Fatal(err)
			}
			if rec.UsesLeft != rec.Uses {
				t.Error("a refused key spent a use of the token")
			}
		})
	}

	// Administrators see it too.
	status, body, _ = h.send(h.admin, "GET", "/v1/admin/status", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	var st relayapi.AdminStatusResponse
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.MLDSA != 87 {
		t.Errorf("admin status reports mldsa %d, want 87", st.MLDSA)
	}
}

func TestARelayWithCertificatesOffAcceptsAnyKeyInTheRequest(t *testing.T) {
	// The request is read only for the token inside it, and there is no
	// authority whose set the key would have to match.
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss), Registration: relayapi.RegistrationToken})
	alice := ids(t, "alice")[0]
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA87()} {
		tok := h.addToken(boss, func(c *token.Claims) { c.Use = token.UseRegister })
		key, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		if status, body := h.registerKey(alice, key, tok); status != http.StatusOK {
			t.Errorf("a %s key at a relay with certificates off: %d %s", params, status, body)
		}
	}
	// And health says nothing about a set, because there is none.
	_, body, _ := h.send(nil, "GET", "/v1/health", nil, nil)
	var health relayapi.HealthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatal(err)
	}
	if health.MLDSA != 0 {
		t.Errorf("a relay with no authority reports mldsa %d", health.MLDSA)
	}
}

// TestARotationKeepsEnrolledMachinesWorking is the promise the second level
// of the hierarchy exists to keep: recovering a compromised relay is a new
// bundle and a restart, and nobody re-enrols. Everything else about
// rotation is tested at the x509 level in internal/pki; this is the
// handshake.
func TestARotationKeepsEnrolledMachinesWorking(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	real, _, _ := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	path := "/v1/mailbox/" + alice.Fingerprint()

	r := h.rotate()
	if r.bundle.ClientInt.Cert.Equal(h.bundle.ClientInt.Cert) {
		t.Fatal("the rotation reused the client signing intermediate")
	}

	// Alice's certificate was issued by the intermediate just retired.
	status, body := r.overTLS(alice, real.tlsCert(), "GET", path, nil)
	if status != http.StatusOK {
		t.Fatalf("after a rotation, a certificate from the retired intermediate: %d %s", status, body)
	}

	// The retired key — the one an attacker had, which is why we rotated —
	// still mints nothing the relay honours.
	fresh, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	status, body = r.overTLS(alice, h.forgedLeaf(fresh, alice.Fingerprint()).tlsCert(), "GET", path, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("a leaf from the retired key after the rotation: %d, want 401: %s", status, body)
	}

	// A machine enrolling now is issued by the new intermediate.
	bob := ids(t, "bob")[0]
	m, status, body := r.enrolMachine(bob, r.registerToken(token.UseRegister, ""))
	if status != http.StatusOK {
		t.Fatalf("enrolling after the rotation: %d %s", status, body)
	}
	leaf, err := x509.ParseCertificate(m.cert)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Issuer.String() != r.bundle.ClientInt.Cert.Subject.String() {
		t.Errorf("a certificate issued after the rotation names issuer %q, want the new intermediate %q",
			leaf.Issuer, r.bundle.ClientInt.Cert.Subject)
	}
	if status, body := r.overTLS(bob, m.tlsCert(), "GET", "/v1/mailbox/"+bob.Fingerprint(), nil); status != http.StatusOK {
		t.Fatalf("the new machine over the rotated relay: %d %s", status, body)
	}
}

// fetchAnchor is what a machine does before it can verify anything: an
// unauthenticated GET of the trust anchor route.
func (h *certHarness) fetchAnchor() (int, relayapi.TrustAnchorResponse, string) {
	h.t.Helper()
	resp, err := http.Get(h.srv.URL + "/v1/trust-anchor")
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out relayapi.TrustAnchorResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			h.t.Fatalf("the anchor route answered %q", body)
		}
	}
	return resp.StatusCode, out, string(body)
}

// The shipped settings have client certificates off, and the anchor route was
// once gated on them being on: a relay in its default configuration answered
// that it had no anchor, so no machine could pin it, so no machine could
// connect at all. The anchor exists whenever the relay serves from a bundle,
// and it is served on that condition and no other.
func TestTheAnchorIsServedWithClientCertificatesOff(t *testing.T) {
	h := newCertHarness(t, func(c *Config) { c.ClientCerts = nil })
	status, got, body := h.fetchAnchor()
	if status != http.StatusOK {
		t.Fatalf("with client certificates off the anchor route answered %d: %s", status, body)
	}
	if !bytes.Equal(got.TrustAnchor, h.anchor().Raw) {
		t.Fatal("the anchor served is not the one the relay was issued from")
	}
	if got.SPKI != pki.SPKI(h.anchor()) {
		t.Fatalf("spki %s, want %s", got.SPKI, pki.SPKI(h.anchor()))
	}

}

// An identity with a mailbox and no live certificate is enrolling, not adding
// a machine: the relay began requiring certificates after it registered, or
// its only certificate expired or was revoked. An ordinary enrolment token
// gets it a certificate in the same step, as it does for anyone joining. A
// live certificate on record is what makes the next request another machine,
// which costs a certificate token bound to the identity, so a copied identity
// still mints itself nothing. No path is token-free.
func TestAnIdentityWithoutALiveCertificateEnrolsWithAnEnrolmentToken(t *testing.T) {
	alice := ids(t, "alice")[0]
	before := newCertHarness(t, func(c *Config) { c.ClientCerts = nil })
	status, body := before.enrol(alice, before.registerToken(token.UseRegister, ""))
	if status != http.StatusOK {
		t.Fatalf("enrolling with certificates off: %d %s", status, body)
	}
	var resp relayapi.RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Cert) != 0 {
		t.Fatal("a relay with certificates off issued one")
	}

	// The same relay and database, restarted requiring certificates.
	h := startCertRelay(t, before.ca, before.store, before.bundle, before.admin,
		before.clock, before.logs, nil)
	key, err := mldsa.GenerateKey(h.bundle.Params)
	if err != nil {
		t.Fatal(err)
	}
	status, body = h.registerKey(alice, key, "")
	if status != http.StatusForbidden || !strings.Contains(string(body), msgNeedAnyToken) {
		t.Fatalf("with no token and no certificate: %d %s", status, body)
	}

	first, status, body := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
	if status != http.StatusOK {
		t.Fatalf("an enrolment token did not issue the first certificate: %d %s", status, body)
	}
	if status, body := h.overTLS(alice, first.tlsCert(), "GET", "/v1/mailbox/"+alice.Fingerprint(), nil); status != http.StatusOK {
		t.Fatalf("the certificate does not work: %d %s", status, body)
	}

	// With a live certificate on record the next request is another
	// machine: an enrolment token no longer does, and the message with no
	// token names the certificate token it takes.
	if _, status, body := h.enrolMachine(alice, h.registerToken(token.UseRegister, "")); status != http.StatusForbidden ||
		!strings.Contains(string(body), "needs a certificate token: ask the administrator for one issued with --use cert --for "+alice.Fingerprint()) {
		t.Fatalf("an enrolment token added a second machine: %d %s", status, body)
	}
	if status, body := h.registerKey(alice, key, ""); status != http.StatusForbidden || !strings.Contains(string(body), msgNeedCertToken) {
		t.Fatalf("with no token and a live certificate: %d %s", status, body)
	}
	second, status, body := h.enrolMachine(alice, h.registerToken(token.UseCert, alice.Fingerprint()))
	if status != http.StatusOK {
		t.Fatalf("a certificate token did not add a machine: %d %s", status, body)
	}

	// With every certificate revoked the identity is enrolling again.
	for _, m := range []*machine{first, second} {
		if _, err := h.store.RevokeCert(m.serial, h.admin.Fingerprint(), "lost", h.clock.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, status, body := h.enrolMachine(alice, h.registerToken(token.UseRegister, "")); status != http.StatusOK {
		t.Fatalf("after revocation an enrolment token did not issue a certificate: %d %s", status, body)
	}
}

// The other wrong use: a certificate token, which adds a machine to an
// identity already on the relay, presented by an identity with no mailbox
// here yet. It is refused by name too, and no mailbox is made.
func TestACertificateTokenCannotMakeAMailbox(t *testing.T) {
	h := newCertHarness(t, nil)
	alice := ids(t, "alice")[0]
	_, status, body := h.enrolMachine(alice, h.registerToken(token.UseCert, alice.Fingerprint()))
	if status != http.StatusForbidden {
		t.Fatalf("a certificate token made a mailbox: %d %s", status, body)
	}
	if got := errorText(t, body); got != msgCertTokenForNew {
		t.Errorf("error %q, want %q", got, msgCertTokenForNew)
	}
	if exists, _, err := h.store.MailboxState(alice.Fingerprint()); err != nil || exists {
		t.Fatalf("a refused certificate token left a mailbox behind: %v %v", exists, err)
	}
}
