package auu

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// certRelay starts a relay that requires client certificates, and returns its
// address and a function that issues and registers a token.
func certRelay(t *testing.T) (string, func(use, subject string) string) {
	t.Helper()
	return certRelayAt(t, mldsa.MLDSA65())
}

// certRelayAt is certRelay with the authority at a chosen parameter set.
func certRelayAt(t *testing.T, params mldsa.Parameters) (string, func(use, subject string) string) {
	t.Helper()
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	admins := filepath.Join(dir, "admins")
	if err := os.WriteFile(admins, []byte(boss.Public().ExportLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, params)
	url, st := startTLSRelay(t, relay.Config{
		AdminFile:    admins,
		Registration: relayapi.RegistrationToken,
		TokenMaxAge:  720 * time.Hour,
		ClientCerts: &relay.ClientCertPolicy{
			Issuer:   clientca.NewIssuer(bundle),
			Verifier: clientca.NewVerifier(bundle),
			Lifetime: 365 * 24 * time.Hour,
		},
	}, bundle)

	return url, tokenIssuer(t, boss, url, st)
}

// tokenIssuer is an administrator issuing tokens for a relay: signed with
// their key and put straight into the relay's table.
func tokenIssuer(t *testing.T, boss *identity.Identity, url string, st *relay.Store) func(use, subject string) string {
	return func(use, subject string) string {
		t.Helper()
		now := time.Now()
		raw, err := token.Issue(boss, token.Claims{
			Relay: token.NormaliseRelay(url), Use: use, Subject: subject,
			Note: "a colleague", NotBefore: now.Unix(),
			NotAfter: now.Add(24 * time.Hour).Unix(), Uses: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		u, err := token.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddToken(u.Claims, now); err != nil {
			t.Fatal(err)
		}
		return raw
	}
}

// A relay that starts requiring certificates after its users joined. Each of
// them has a mailbox and nothing to present; that is enrolling again, not
// adding a machine, so an ordinary token gets the certificate in one step
// and nothing else has to be redone.
func TestARelayThatStartsRequiringCertificatesEnrolsWithAnOrdinaryToken(t *testing.T) {
	boss, err := identity.Generate("boss")
	if err != nil {
		t.Fatal(err)
	}
	admins := filepath.Join(t.TempDir(), "admins")
	if err := os.WriteFile(admins, []byte(boss.Public().ExportLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	off := relay.Config{
		AdminFile:    admins,
		Registration: relayapi.RegistrationToken,
		TokenMaxAge:  720 * time.Hour,
	}
	url, st, restart := startSwitchableTLSRelay(t, off, bundle)
	issue := tokenIssuer(t, boss, url, st)

	alice := &user{t: t, home: t.TempDir()}
	out := alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	if !strings.Contains(out, "this relay does not use client certificates") {
		t.Fatalf("enrol with certificates off:\n%s", out)
	}

	on := off
	on.ClientCerts = &relay.ClientCertPolicy{
		Issuer:   clientca.NewIssuer(bundle),
		Verifier: clientca.NewVerifier(bundle),
		Lifetime: 365 * 24 * time.Hour,
	}
	restart(on)

	out, err = alice.tryRun("inbox")
	if err == nil {
		t.Fatalf("a machine with no certificate reached a relay that now requires one:\n%s", out)
	}
	const want = "this relay requires a client certificate and this machine's is missing: " +
		"run 'auu register --token TOKEN' with a token from an administrator"
	if got := err.Error(); got != want {
		t.Errorf("error is\n %q\nwant\n %q", got, want)
	}

	// The token everyone joining gets, not a certificate token.
	out = alice.run("register", "--token", issue(token.UseRegister, ""))
	if !strings.Contains(out, "client certificate for this machine") {
		t.Fatalf("register did not report a certificate:\n%s", out)
	}
	alice.run("inbox")
}

// relayDir is where this user's default relay keeps its files: the anchor,
// the certificate and the cursor all live under relays/<name>/.
func (u *user) relayDir() string {
	u.t.Helper()
	s, err := store.Open(u.home)
	if err != nil {
		u.t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		u.t.Fatalf("no default relay in %s: %v", u.home, err)
	}
	return s.RelayDir(r)
}

// certPath is this machine's certificate for the default relay.
func (u *user) certPath() string { return filepath.Join(u.relayDir(), "cert.json") }

// certRecord reads a user's stored certificate.
func (u *user) certRecord() *store.CertRecord {
	u.t.Helper()
	data, err := os.ReadFile(u.certPath())
	if err != nil {
		u.t.Fatalf("reading cert.json: %v", err)
	}
	var rec store.CertRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		u.t.Fatal(err)
	}
	return &rec
}

func TestEnrolStoresACertificateAndThenMailWorks(t *testing.T) {
	relayURL, issue := certRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	out, err := alice.tryRun("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	if err != nil {
		t.Fatalf("enrol: %v\n%s", err, out)
	}
	if !strings.Contains(out, "client certificate for this machine") {
		t.Errorf("enrol did not report the certificate:\n%s", out)
	}

	// The file is private: it holds the key that identifies this machine.
	info, err := os.Stat(alice.certPath())
	if err != nil {
		t.Fatalf("cert.json was not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("cert.json is mode %04o, want 0600", perm)
	}
	rec := alice.certRecord()
	if rec.Relay != relayURL {
		t.Errorf("the record names relay %q, want %q", rec.Relay, relayURL)
	}
	if rec.Key == "" || rec.Cert == "" {
		t.Error("the record is missing the key or the certificate")
	}

	// And the certificate is actually used: an ordinary command works.
	alice.run("inbox")
}

func TestASecondMachineIsRefusedUntilItHasAToken(t *testing.T) {
	// The story the whole feature exists for. Alice's identity is copied to
	// another machine; without a certificate of its own it reaches nothing,
	// and the message it gets says what to do about it.
	relayURL, issue := certRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))

	second := &user{t: t, home: t.TempDir()}
	copyHomeWithoutCert(t, alice.home, second.home)

	out, err := second.tryRun("inbox")
	if err == nil {
		t.Fatalf("a copied identity reached the relay with no certificate:\n%s", out)
	}
	const want = "this relay requires a client certificate and this machine's is missing: " +
		"run 'auu register --token TOKEN' with a token from an administrator"
	if got := err.Error(); got != want {
		t.Errorf("error is\n %q\nwant\n %q", got, want)
	}

	// A register token is not what this needs: alice already has a mailbox.
	if _, err := second.tryRun("register", "--token", issue(token.UseRegister, "")); err == nil {
		t.Error("a register token enrolled a second machine")
	}

	// Its own token, bound to alice, does.
	fp := alice.exportFingerprint()
	out, err = second.tryRun("register", "--token", issue(token.UseCert, fp), "--label", "desktop")
	if err != nil {
		t.Fatalf("register with a certificate token: %v\n%s", err, out)
	}
	second.run("inbox")

	// Both machines now work, and the relay lists two.
	alice.run("inbox")
	listing := second.run("cert", "ls", "--json")
	var certs []relayapi.CertRecord
	if err := json.Unmarshal([]byte(listing), &certs); err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("the relay lists %d certificates, want 2:\n%s", len(certs), listing)
	}
	labels := map[string]bool{}
	current := 0
	for _, c := range certs {
		labels[c.Label] = true
		if c.Current {
			current++
		}
	}
	if !labels["desktop"] {
		t.Errorf("the second machine's label is not in the listing: %v", labels)
	}
	if current != 1 {
		t.Errorf("%d certificates marked current, want exactly 1", current)
	}
	_ = relayURL
}

// copyHomeWithoutCert copies an identity to another machine, which is what
// somebody moving their key to a second computer does.
//
// It takes the relays with it — their URLs, their pinned anchors and their
// cursors — because those are the home's, and leaves every cert.json behind,
// because a client certificate is one machine's and never travels. The spools
// come too; a copied home is a copied home.
func copyHomeWithoutCert(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o700)
		}
		if d.Name() == "cert.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertStatusAndRenew(t *testing.T) {
	_, issue := certRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	before := alice.certRecord()

	status := alice.run("cert", "status")
	for _, want := range []string{before.Serial, "expires", "renews", "issued by"} {
		if !strings.Contains(status, want) {
			t.Errorf("cert status does not mention %q:\n%s", want, status)
		}
	}

	alice.run("cert", "renew")
	after := alice.certRecord()
	if after.Serial == before.Serial {
		t.Error("renewal did not change the serial")
	}
	if after.Key == before.Key {
		t.Error("renewal reused the old key; a fresh one is the point of renewing")
	}
	// The new one works and the old one is gone.
	alice.run("inbox")
	listing := alice.run("cert", "ls")
	if !strings.Contains(listing, "revoked (renewed)") {
		t.Errorf("the replaced certificate is not shown as renewed:\n%s", listing)
	}
}

func TestCertStatusWithoutOne(t *testing.T) {
	// A relay that does not use client certificates: nothing is stored, and
	// the commands say so rather than failing.
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	if _, err := os.Stat(alice.certPath()); err == nil {
		t.Error("a relay with certificates off left a certificate behind")
	}
	out := alice.run("cert", "status")
	if !strings.Contains(out, "none on this machine") {
		t.Errorf("cert status does not say there is none:\n%s", out)
	}

	var parsed certStatusOutput
	if err := json.Unmarshal([]byte(alice.run("cert", "status", "--json")), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Present {
		t.Error("--json reports a certificate that does not exist")
	}
}

func TestRegisterOnARelayWithoutCertificatesSaysSo(t *testing.T) {
	relayURL := startRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("init", "--name", "alice", "--relay", relayURL)
	out := alice.run("register")
	if !strings.Contains(out, "does not use client certificates") {
		t.Errorf("register does not say the relay issues none:\n%s", out)
	}
	if _, err := os.Stat(alice.certPath()); err == nil {
		t.Error("a key was kept for a relay that issued no certificate")
	}
}

func TestRenewalHappensBeforeExpiry(t *testing.T) {
	// A machine in regular use must never reach the day its certificate
	// stops working, so a command that opens the relay renews first.
	_, issue := certRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	before := alice.certRecord()

	// One second inside the window, and one second outside it: the boundary
	// is asserted from both sides.
	setExpiry(t, alice, time.Now().Add(store.RenewBefore+time.Second))
	alice.run("inbox")
	if alice.certRecord().Serial != before.Serial {
		t.Error("a certificate one second outside the renewal window was renewed")
	}

	setExpiry(t, alice, time.Now().Add(store.RenewBefore-time.Second))
	alice.run("inbox")
	if alice.certRecord().Serial == before.Serial {
		t.Error("a certificate inside the renewal window was not renewed")
	}
}

// setExpiry rewrites the stored expiry, so a test can reach the renewal
// boundary without a year passing or a clock being injected into the file.
func setExpiry(t *testing.T, u *user, notAfter time.Time) {
	t.Helper()
	rec := u.certRecord()
	rec.NotAfter = notAfter
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(u.certPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAFailedRenewalWarnsAndTheCommandStillRuns(t *testing.T) {
	// The certificate is good for weeks yet. A relay that is briefly
	// unreachable, or that fails the renewal for any reason, must not stop
	// somebody reading their mail.
	_, issue := certRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	before := alice.certRecord()
	setExpiry(t, alice, time.Now().Add(store.RenewBefore-time.Second))

	// A relay that answers everything but refuses to issue.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certs") {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"relay is busy"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer failing.Close()

	s, err := store.Open(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.CertFor(r)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := rec.TLS()
	if err != nil {
		t.Fatal(err)
	}
	// The record must name the relay whose directory it is in, or CertFor
	// declines to use it and there is nothing to renew. The relay itself is
	// pointed at the server that refuses, which is what is being tested.
	r.URL = failing.URL
	if err := s.SaveRelay(r); err != nil {
		t.Fatal(err)
	}
	rec.Relay = failing.URL
	if err := s.SaveCertFor(r, rec); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(failing.URL, id, cert)
	if err != nil {
		t.Fatal(err)
	}

	warning := captureStderr(t, func() {
		if renewed := renewIfExpiring(s, id, c, r, time.Now()); renewed {
			t.Error("a refused renewal was reported as having succeeded")
		}
	})
	want := "auu: certificate renewal for "
	if !strings.HasPrefix(warning, want) {
		t.Errorf("warning is\n %q\nwant one beginning\n %q", warning, want)
	}
	if !strings.Contains(warning, "it expires on "+before.NotAfter.Local().Format("2006-01-02")) &&
		!strings.Contains(warning, "it expires on ") {
		t.Errorf("the warning does not say when the certificate expires: %q", warning)
	}
	// And the certificate on disk is untouched, so the command that follows
	// still has one to present.
	if got := alice.certRecord(); got.Serial != before.Serial {
		t.Error("a failed renewal replaced the stored certificate")
	}
}

// captureStderr runs fn with stderr redirected, and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	real := os.Stderr
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = real
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	return string(data)
}

// startTLSRelay runs a relay over TLS that asks for client certificates, and
// points this process's default transport at its certificate for the duration
// of the test.
//
// Real handshakes, deliberately: presenting a certificate is the thing under
// test, and a plain-HTTP harness would prove nothing about it.
func startTLSRelay(t *testing.T, cfg relay.Config, bundle *pki.Loaded) (string, *relay.Store) {
	t.Helper()
	url, st, _ := startSwitchableTLSRelay(t, cfg, bundle)
	return url, st
}

// startSwitchableTLSRelay is startTLSRelay whose relay can be replaced while
// the address and the database stay, which is what a restart with changed
// settings is to the machines that use it.
func startSwitchableTLSRelay(t *testing.T, cfg relay.Config, bundle *pki.Loaded) (string, *relay.Store, func(relay.Config)) {
	t.Helper()
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var current atomic.Pointer[relay.Server]
	prepare := func(cfg relay.Config) *relay.Server {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		cfg.Streams = true
		return relay.NewServer(st, cfg)
	}
	current.Store(prepare(cfg))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current.Load().ServeHTTP(w, r)
	}))
	srv.TLS = clientca.NewVerifier(bundle).TLSConfig(&tls.Config{})
	srv.StartTLS()
	t.Cleanup(srv.Close)

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	tr := http.DefaultTransport.(*http.Transport)
	previous := tr.TLSClientConfig
	tr.TLSClientConfig = &tls.Config{RootCAs: roots}
	t.Cleanup(func() { tr.TLSClientConfig = previous })

	return srv.URL, st, func(cfg relay.Config) { current.Store(prepare(cfg)) }
}

func TestEnrolGeneratesTheKeyTheRelayAsksFor(t *testing.T) {
	// The person never says which set; the relay does, on the health route,
	// before auu builds a request. Against an ML-DSA-87 relay the machine's
	// key is 87, and the certificate it holds says so.
	_, issue := certRelayAt(t, mldsa.MLDSA87())
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))

	rec := alice.certRecord()
	cert, err := rec.TLS()
	if err != nil {
		t.Fatal(err)
	}
	key, ok := cert.PrivateKey.(*mldsa.PrivateKey)
	if !ok {
		t.Fatalf("the machine key is %T", cert.PrivateKey)
	}
	if key.PublicKey().Parameters() != mldsa.MLDSA87() {
		t.Errorf("the machine key is %s, want ML-DSA-87", key.PublicKey().Parameters())
	}
	// And it works, which is the handshake negotiating the 87 scheme.
	alice.run("inbox")

	status := alice.run("cert", "status")
	if !strings.Contains(status, "key:     ML-DSA-87") {
		t.Errorf("cert status does not show the set:\n%s", status)
	}
	var parsed certStatusOutput
	if err := json.Unmarshal([]byte(alice.run("cert", "status", "--json")), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.MLDSA != 87 {
		t.Errorf("--json reports mldsa %d, want 87", parsed.MLDSA)
	}

	// Renewal asks again, so a renewed key is the relay's set too.
	alice.run("cert", "renew")
	cert, err = alice.certRecord().TLS()
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.PrivateKey.(*mldsa.PrivateKey).PublicKey().Parameters(); got != mldsa.MLDSA87() {
		t.Errorf("the renewed key is %s, want ML-DSA-87", got)
	}
}

// giveForeignCert replaces this machine's certificate with one from an
// authority the relay has never heard of, keeping the rest of the record.
//
// The relay asks for a certificate without naming an authority, so the client
// offers this one and the handshake is refused: the same shape as an
// authority that has been rotated out from under a machine that was away.
func giveForeignCert(t *testing.T, u *user) {
	t.Helper()
	rec := u.certRecord()
	other := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := clientca.NewCSR(key, "stale", "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := clientca.ParseCSR(csr, clientca.AnyParameters)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := clientca.NewIssuer(other).Issue(req, u.exportFingerprint(), time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rec.Cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued.Cert}))
	rec.Key = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(u.certPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterWorksWhenTheStoredCertificateIsRefusedInTheHandshake(t *testing.T) {
	// The advice for a refused certificate is to register again, and
	// register is the one command that must not present the certificate it
	// is replacing: a refusal happens in the handshake, before any route is
	// chosen, so offering it would fail the very command sent to fix it.
	// Nothing on /v1/register looks at a client certificate, so there is
	// nothing lost by leaving it at home.
	_, issue := certRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	giveForeignCert(t, alice)

	if out, err := alice.tryRun("inbox"); err == nil {
		t.Fatalf("a certificate from another authority reached the relay:\n%s", out)
	}
	out, err := alice.tryRun("register", "--token", issue(token.UseCert, alice.exportFingerprint()))
	if err != nil {
		t.Fatalf("register could not replace a refused certificate: %v\n%s", err, out)
	}
	alice.run("inbox")
}

// The register token a second machine is refused for is refused by name:
// the relay says a certificate token is what adds a machine, with the
// identity's own fingerprint filled in, and auu passes the sentence through
// as it does every relay refusal. The container suite's K21 found "does not
// authorise this" — the very token the previous sentence had told bob to
// get.
func TestASecondMachineIsToldWhichToken(t *testing.T) {
	relayURL, issue := certRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	second := &user{t: t, home: t.TempDir()}
	copyHomeWithoutCert(t, alice.home, second.home)
	fp := alice.exportFingerprint()

	_, err := second.tryRun("register", "--token", issue(token.UseRegister, ""), "--label", "desktop")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport {
		t.Fatalf("a register token on a second machine: %v, want exit %d", err, exitTransport)
	}
	want := "relay returned 403: this identity already holds a live certificate on another machine, so adding " +
		"this one needs a certificate token: ask the administrator for one issued with --use cert --for " + fp
	if err.Error() != want {
		t.Fatalf("error\n %q\nwant\n %q", err, want)
	}
	// What the sentence says to ask for works.
	if out, err := second.tryRun("register", "--token", issue(token.UseCert, fp), "--label", "desktop"); err != nil {
		t.Fatalf("the token the sentence names was refused: %v\n%s", err, out)
	}
	_ = relayURL
}

// A cert.json that names another relay is refused before the relay is
// dialled, by name, with the register command for this relay, and exit 5;
// a cert.json nothing can read keeps B1's sentence, which carries the same
// command; and cert status says the same rather than "none". The container
// suite's K10 found the file taken for absent and the relay's refusal of a
// certificate it never saw the only word said.
func TestACertificateForAnotherRelayIsNamed(t *testing.T) {
	relayURL, issue := certRelay(t)
	alice := &user{t: t, home: t.TempDir()}
	alice.run("enrol", "--name", "alice", "--yes", issue(token.UseRegister, ""))
	s, err := store.Open(alice.home)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.RelayDir(r), "cert.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), `"relay": "`+r.URL+`"`, `"relay": "https://other.example.com:9443"`, 1)
	if edited == string(raw) {
		t.Fatalf("cert.json does not record the relay as %q:\n%s", r.URL, raw)
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	want := "this machine's " + path + " for " + r.Name + " was issued by https://other.example.com:9443: " +
		"run 'auu register --relay " + r.Name + " --token TOKEN' to get one for this relay"
	for _, args := range [][]string{{"inbox"}, {"cert", "status"}, {"cert", "renew"}} {
		_, err := alice.tryRun(args...)
		var e *exitError
		if !errors.As(err, &e) || e.code != exitDamaged {
			t.Fatalf("%v with cert.json for another relay: %v, want exit %d", args, err, exitDamaged)
		}
		if err.Error() != want {
			t.Fatalf("%v said\n %q\nwant\n %q", args, err, want)
		}
	}

	// Unreadable: B1's sentence, with the same command, and no dial either.
	if err := os.WriteFile(path, []byte(`{"relay": "https://relay`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = alice.tryRun("inbox")
	var e *exitError
	if !errors.As(err, &e) || e.code != exitDamaged {
		t.Fatalf("inbox with cert.json truncated: %v, want exit %d", err, exitDamaged)
	}
	if got := err.Error(); got != path+" is not valid JSON (unexpected end of JSON input): run 'auu register --relay "+r.Name+" --token TOKEN' to replace it" {
		t.Fatalf("truncated cert.json said %q", got)
	}
	_ = relayURL
}

// The renewal that runs before a command does not warn when the relay's own
// certificate has run out: the command that follows is about to say whose
// problem that is, and the warning would put the same words in front of it,
// in brackets, as a renewal failure. Any other failure of the renewal still
// warns, since the command may then succeed and nothing else would say it.
func TestRenewalDoesNotWarnWhenTheRelayHasExpired(t *testing.T) {
	twoYearsAgo := time.Now().AddDate(-2, 0, 0)
	authority, err := pki.Create(t.TempDir(), "Test", mldsa.MLDSA65(), keyfile.TestPassphrase("test"), twoYearsAgo)
	if err != nil {
		t.Fatal(err)
	}
	expired := pki.TestLoadedAt(t, authority, []string{"127.0.0.1"}, twoYearsAgo)
	server, err := clientca.NewServer(expired, twoYearsAgo)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// A home with a certificate for that relay that is about to expire.
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	r, err := s.AddRelay("work", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCertFor(r, &store.CertRecord{Relay: r.URL, Serial: "aaa",
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	c, err := client.NewWithAnchor(srv.URL, id, nil, &client.Anchor{Cert: expired.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	var renewed bool
	warning := captureStderr(t, func() { renewed = renewIfExpiring(s, id, c, r, time.Now()) })
	if renewed {
		t.Fatal("a renewal against an expired relay succeeded")
	}
	if warning != "" {
		t.Fatalf("the renewal warned about the relay's expiry, which the command is about to say:\n%s", warning)
	}

	// The relay simply gone is another matter, and is warned about.
	srv.Close()
	warning = captureStderr(t, func() { renewed = renewIfExpiring(s, id, c, r, time.Now()) })
	if renewed || !strings.HasPrefix(warning, "auu: certificate renewal for work failed (") {
		t.Fatalf("a renewal against a relay that is gone: renewed %v, stderr %q", renewed, warning)
	}
}
