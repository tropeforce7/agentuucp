package client

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/pki"
)

// relayServing starts a TLS server presenting what a relay built from this
// bundle would present: its own leaf and the chain up to, but not including,
// the anchor.
func relayServing(t *testing.T, bundle *pki.Loaded) *httptest.Server {
	t.Helper()
	server, err := clientca.NewServer(bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The leaf is put in Certificates rather than left to GetCertificate:
	// httptest.StartTLS injects a certificate of its own when Certificates
	// is empty, and with no SNI — which is what connecting to an IP means —
	// crypto/tls prefers that to GetCertificate, so the relay's own leaf
	// would never be served.
	leaf, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216,"registration":"open"}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestAPinnedAnchorVerifiesTheRelayAndNothingElse(t *testing.T) {
	// The client holds the anchor alone: no intermediate, and not the system
	// roots either. Everything between must come off the wire.
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	srv := relayServing(t, bundle)

	c, err := NewWithAnchor(srv.URL, testIdentity(t, "alice"), nil, &Anchor{Cert: bundle.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Health(t.Context()); err != nil {
		t.Fatalf("a relay serving its own chain was not verified: %v", err)
	}

	// Another anchor does not verify it, which is what pinning means.
	other := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	c2, err := NewWithAnchor(srv.URL, testIdentity(t, "alice"), nil, &Anchor{Cert: other.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	err = c2.Health(t.Context())
	if err == nil {
		t.Fatal("a relay verified against an anchor that did not issue it")
	}
	if _, ok := ClassifyAnchorError(err, true).(*AnchorProblem); !ok {
		t.Errorf("the failure was not classified as an anchor problem: %v", err)
	}
}

func TestTheRatchetTellsARotationFromAReplay(t *testing.T) {
	// Only the operator's offline authority can issue a newer signing
	// intermediate, so a newer one is a rotation by construction and an older
	// one is a retired authority being replayed.
	store := pki.TestStore(t, mldsa.MLDSA65())
	first := pki.TestBundleFrom(t, store, []string{"127.0.0.1"})
	time.Sleep(1100 * time.Millisecond) // NotBefore has one-second precision
	second := pki.TestBundleFrom(t, store, []string{"127.0.0.1"})

	oldSrv := relayServing(t, first)
	newSrv := relayServing(t, second)

	var rotations int
	var seenSPKI string
	var seenNotBefore time.Time
	anchor := func() *Anchor {
		return &Anchor{
			Cert: first.Anchor, SeenSPKI: seenSPKI, SeenNotBefore: seenNotBefore,
			OnRotation: func(time.Time, time.Time) { rotations++ },
			OnSeen: func(spki string, nb time.Time) error {
				seenSPKI, seenNotBefore = spki, nb
				return nil
			},
		}
	}
	get := func(t *testing.T, srv *httptest.Server) error {
		t.Helper()
		c, err := NewWithAnchor(srv.URL, testIdentity(t, "alice"), nil, anchor())
		if err != nil {
			t.Fatal(err)
		}
		return c.Health(t.Context())
	}

	// First sight: recorded, and no notice, because there is nothing to
	// have rotated from.
	if err := get(t, oldSrv); err != nil {
		t.Fatalf("first connection: %v", err)
	}
	if rotations != 0 {
		t.Errorf("a first connection reported %d rotations, want 0", rotations)
	}
	if seenSPKI == "" {
		t.Fatal("the first intermediate was not recorded")
	}
	firstSeen := seenSPKI

	// The same one again: silent.
	if err := get(t, oldSrv); err != nil {
		t.Fatalf("second connection: %v", err)
	}
	if rotations != 0 || seenSPKI != firstSeen {
		t.Errorf("an unchanged authority was reported as a rotation")
	}

	// A newer one: accepted, recorded, reported once.
	if err := get(t, newSrv); err != nil {
		t.Fatalf("after a rotation: %v", err)
	}
	if rotations != 1 {
		t.Errorf("a rotation was reported %d times, want 1", rotations)
	}
	if seenSPKI == firstSeen {
		t.Error("the new authority was not recorded")
	}

	// And now the older one is a replay.
	err := get(t, oldSrv)
	if !errors.Is(err, ErrReplayedAuthority) {
		t.Fatalf("a retired authority gave %v, want ErrReplayedAuthority", err)
	}
	for _, want := range []string{"older than the one this machine accepted"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	// The record does not move backwards.
	if seenSPKI == firstSeen {
		t.Error("a refused connection rolled the record back")
	}
}

func TestFetchTrustAnchorIsUnverifiedAndItsAnswerIsRecomputed(t *testing.T) {
	// The one request that skips verification. What makes it safe is that
	// the caller checks the hash, so the relay's own claim about it is not
	// believed either.
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/trust-anchor" {
			t.Errorf("asked for %s", r.URL.Path)
		}
		if r.Header.Get("X-CCX-Auth") != "" {
			t.Error("the unverified fetch carried a signature")
		}
		// A relay lying about its own hash changes nothing.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"trust_anchor":"` + b64(bundle.Anchor.Raw) + `","spki":"` +
			strings.Repeat("f", 64) + `"}`))
	}))
	server, err := clientca.NewServer(bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()

	// No roots configured at all: this is the point of the call.
	cert, spki, err := FetchTrustAnchor(t.Context(), srv.URL)
	if err != nil {
		t.Fatalf("FetchTrustAnchor: %v", err)
	}
	if !cert.Equal(bundle.Anchor) {
		t.Error("the anchor did not survive")
	}
	if spki != pki.SPKI(bundle.Anchor) {
		t.Errorf("spki = %q; the relay's own claim was believed", spki)
	}
}

// TestLimitAnAnchorAnswerIsHeldToAMebibyte: the trust anchor answer is
// read under anchorAnswerHold, at it taken — the anchor survives the
// padding — and one byte over refused by name, not read short and failed
// as JSON.
func TestLimitAnAnchorAnswerIsHeldToAMebibyte(t *testing.T) {
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	var size atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		head := `{"trust_anchor":"` + b64(bundle.Anchor.Raw) + `","spki":"` + strings.Repeat("f", 64) + `"`
		_, _ = w.Write(paddedJSON(head, size.Load()))
	}))
	server, err := clientca.NewServer(bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()

	size.Store(anchorAnswerHold)
	cert, _, err := FetchTrustAnchor(t.Context(), srv.URL)
	if err != nil || !cert.Equal(bundle.Anchor) {
		t.Fatalf("an answer at the hold: %v; want the anchor taken", err)
	}
	size.Store(anchorAnswerHold + 1)
	_, _, err = FetchTrustAnchor(t.Context(), srv.URL)
	want := fmt.Sprintf("the relay's trust anchor answer is over %d bytes, the most this client holds; nothing of it was used", anchorAnswerHold)
	if err == nil || err.Error() != want {
		t.Fatalf("an answer one over the hold: %v; want %q", err, want)
	}
}

func b64(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		var n uint32
		var k int
		for j := 0; j < 3; j++ {
			n <<= 8
			if i+j < len(b) {
				n |= uint32(b[i+j])
				k++
			}
		}
		for j := 0; j < 4; j++ {
			if j <= k {
				out = append(out, enc[(n>>uint(18-6*j))&0x3f])
			} else {
				out = append(out, '=')
			}
		}
	}
	return string(out)
}

func TestAnchorAdviceSaysWhichSituationItIs(t *testing.T) {
	unknown := x509.UnknownAuthorityError{}
	for _, tc := range []struct {
		name   string
		pinned bool
		want   string
	}{
		{"nothing pinned", false, "has pinned no trust anchor"},
		{"pinned and wrong", true, "not signed by the trust anchor this machine pinned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := ClassifyAnchorError(unknown, tc.pinned).(*AnchorProblem)
			if !ok {
				t.Fatal("not classified")
			}
			if got := e.Advice("auu"); !strings.Contains(got, tc.want) {
				t.Errorf("advice %q does not say %q", got, tc.want)
			}
		})
	}
	// A platform verifier that has never heard of ML-DSA says this, and it
	// must not reach a user.
	opaque := errors.New(`x509: "relay" certificate is using a broken key size`)
	if _, ok := ClassifyAnchorError(opaque, false).(*AnchorProblem); !ok {
		t.Error("the platform verifier's message was not classified")
	}
	// A replay is its own thing and keeps its own message.
	if _, ok := ClassifyAnchorError(ErrReplayedAuthority, true).(*AnchorProblem); ok {
		t.Error("a replay was turned into an anchor problem")
	}
	if ClassifyAnchorError(nil, true) != nil {
		t.Error("nil became an error")
	}
}
