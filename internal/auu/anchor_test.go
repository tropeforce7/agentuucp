package auu

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// startAnchoredRelay runs a relay over TLS serving a leaf under an auu-ca
// anchor, with client certificates off, as the shipped settings have them.
//
// The process's default transport trusts the anchor for the duration, so a
// command run before anything is pinned still reaches the relay. Once a
// machine pins, its client verifies with the anchor it pinned and the
// transport's roots play no part; a test that wants to prove the pin is
// doing the verifying takes the transport's roots away again.
func startAnchoredRelay(t *testing.T) (string, *pki.Loaded) {
	t.Helper()
	ca := pki.TestStore(t, mldsa.MLDSA65())
	bundle := pki.TestBundleFrom(t, ca, []string{"relay.example.com", "127.0.0.1"})

	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := relay.Config{
		Limits:      relay.DefaultLimits(),
		TrustAnchor: bundle.Anchor,
		Streams:     true,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := clientca.NewServer(bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// In Certificates, not left to GetCertificate: httptest substitutes its
	// own certificate otherwise, and with no SNI prefers it.
	leaf, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(relay.NewServer(st, cfg))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	trustAnchorInTransport(t, bundle.Anchor)
	return srv.URL, bundle
}

// trustAnchorInTransport makes the default transport trust an anchor, or
// nothing in particular when given nil, until the test ends.
func trustAnchorInTransport(t *testing.T, anchor *x509.Certificate) {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport)
	previous := tr.TLSClientConfig
	if anchor == nil {
		tr.TLSClientConfig = nil
	} else {
		roots := x509.NewCertPool()
		roots.AddCert(anchor)
		tr.TLSClientConfig = &tls.Config{RootCAs: roots}
	}
	// A connection made under the old roots would be reused, and a reused
	// connection does not handshake, so the change would not be tested.
	tr.CloseIdleConnections()
	t.Cleanup(func() {
		tr.TLSClientConfig = previous
		tr.CloseIdleConnections()
	})
}

func (u *user) fingerprint() string {
	u.t.Helper()
	var out struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal([]byte(u.run("id", "--json")), &out); err != nil {
		u.t.Fatal(err)
	}
	return out.Fingerprint
}

func (u *user) pinned() string {
	u.t.Helper()
	var out struct {
		Anchor string `json:"anchor"`
	}
	if err := json.Unmarshal([]byte(u.run("anchor", "--json")), &out); err != nil {
		u.t.Fatal(err)
	}
	return out.Anchor
}

// The first deployment's administrator ran 'auu init --force --anchor' with
// the relay unable to serve its anchor. The init had already replaced the
// identity when the pin failed, so the administrator's line on the relay was
// dead and nothing was pinned. Nothing is written until the anchor checks.
func TestInitChecksTheAnchorBeforeItWritesAnything(t *testing.T) {
	url, bundle := startAnchoredRelay(t)
	wrong := strings.Repeat("0", 64)
	u := &user{t: t, home: t.TempDir()}

	out, err := u.tryRun("init", "--name", "alice", "--relay", url, "--anchor", wrong)
	if err == nil {
		t.Fatalf("init accepted a relay whose anchor is not the one named:\n%s", out)
	}
	if !strings.Contains(err.Error(), "not the one you were given") {
		t.Fatalf("the refusal does not say what disagreed: %v", err)
	}
	s, err := store.Open(u.home)
	if err != nil {
		t.Fatal(err)
	}
	if s.HasIdentity() {
		t.Fatal("an identity was created on the way to refusing the anchor")
	}

	u.run("init", "--name", "alice", "--relay", url, "--anchor", bundle.AnchorSPKI)
	if got := u.pinned(); got != bundle.AnchorSPKI {
		t.Fatalf("pinned %q, want the relay's anchor", got)
	}
	before := u.fingerprint()

	// Replacing an identity with a wrong anchor must not replace it.
	if out, err := u.tryRun("init", "--name", "alice", "--relay", url, "--anchor", wrong, "--force"); err == nil {
		t.Fatalf("init --force accepted a wrong anchor:\n%s", out)
	}
	if u.fingerprint() != before {
		t.Fatal("init --force discarded the identity before finding the anchor wrong")
	}
	if u.pinned() != bundle.AnchorSPKI {
		t.Fatal("the failed init disturbed what was pinned")
	}

	// And the pinned anchor is what verifies the relay from here on: with
	// the transport trusting nothing in particular, requests still work.
	trustAnchorInTransport(t, nil)
	u.run("register")
	u.run("inbox", "--no-fetch")
	u.run("inbox")
}

// An identity that exists, made before there was an anchor to give it, pins
// one without being replaced. That is what an administrator needs after
// 'auu init' in the deployment guide's order, and it is the only way to
// pin that keeps the export line the relay already has.
func TestAnchorPinKeepsTheIdentity(t *testing.T) {
	url, bundle := startAnchoredRelay(t)
	u := newUser(t, "alice", url)
	before := u.fingerprint()
	if u.pinned() != "" {
		t.Fatal("a plain init pinned something")
	}
	if !strings.Contains(u.run("anchor"), "none pinned") {
		t.Fatal("status does not say nothing is pinned")
	}

	wrong := strings.Repeat("0", 64)
	if out, err := u.tryRun("anchor", "pin", wrong); err == nil {
		t.Fatalf("pin accepted a hash the relay's anchor does not match:\n%s", out)
	}
	if u.pinned() != "" {
		t.Fatal("a refused pin left something pinned")
	}
	if _, err := u.tryRun("anchor", "pin", "not-a-hash"); err == nil {
		t.Fatal("pin accepted a malformed hash")
	}

	// A flag after the positional, as every command must take.
	var out struct{ Anchor, Relay string }
	if err := json.Unmarshal([]byte(u.run("anchor", "pin", bundle.AnchorSPKI, "--json")), &out); err != nil {
		t.Fatal(err)
	}
	if out.Anchor != bundle.AnchorSPKI || out.Relay != url {
		t.Fatalf("pin reported %+v", out)
	}
	if u.fingerprint() != before {
		t.Fatal("pinning replaced the identity")
	}
	if u.pinned() != bundle.AnchorSPKI {
		t.Fatal("the pin did not stick")
	}
	status := u.run("anchor", "status")
	if !strings.Contains(status, bundle.AnchorSPKI) || !strings.Contains(status, url) {
		t.Fatalf("status:\n%s", status)
	}

	// The pin, and nothing else, now verifies the relay.
	trustAnchorInTransport(t, nil)
	u.run("inbox")

	u.run("anchor", "forget")
	if u.pinned() != "" {
		t.Fatal("forget left the anchor pinned")
	}
	if _, err := u.tryRun("inbox"); err == nil {
		t.Fatal("with the anchor forgotten and no roots that know it, the relay still verified")
	}
	if u.fingerprint() != before {
		t.Fatal("forget touched the identity")
	}
}
