package client

import (
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/pki"
)

// The transport is pinned to TLS 1.3 and the hybrid post-quantum key
// exchange, on the client's requests and on the anchor fetch, and a relay
// that will not make that handshake is refused with a sentence that names
// what is wrong, not Go's alert alone.

// relayOffering is a TLS server with a real relay chain and the given
// server-side policy: the curves it offers, or a version cap.
func relayOffering(t *testing.T, bundle *pki.Loaded, alter func(*tls.Config)) *httptest.Server {
	t.Helper()
	srv := relayServing(t, bundle)
	srv.Close()
	leaf := srv.TLS.Certificates
	again := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/trust-anchor" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"anchor":""}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216,"knock_max_bytes":16777216,"registration":"open"}`))
	}))
	again.TLS = &tls.Config{Certificates: leaf}
	alter(again.TLS)
	again.StartTLS()
	t.Cleanup(again.Close)
	return again
}

const noPQ = "no TLS 1.3 with the post-quantum key exchange; what answered is not this relay, or a TLS terminator in front of it lacks X25519MLKEM768"

func TestTheClientRefusesARelayWithoutTheHybridOverTLS13(t *testing.T) {
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	for _, c := range []struct {
		label string
		alter func(*tls.Config)
		alert string
	}{
		{"a relay offering only X25519", func(cfg *tls.Config) { cfg.CurvePreferences = []tls.CurveID{tls.X25519} }, "tls: handshake failure"},
		{"a relay capped at TLS 1.2", func(cfg *tls.Config) { cfg.MaxVersion = tls.VersionTLS12 }, "tls: protocol version not supported"},
	} {
		t.Run(c.label, func(t *testing.T) {
			srv := relayOffering(t, bundle, c.alter)
			cl, err := NewWithAnchor(srv.URL, testIdentity(t, "alice"), nil, &Anchor{Cert: bundle.Anchor})
			if err != nil {
				t.Fatal(err)
			}
			err = cl.Health(t.Context())
			var refused *NoPQTransportError
			if !errors.As(err, &refused) {
				t.Fatalf("the request: %v, want NoPQTransportError", err)
			}
			if !strings.HasPrefix(refused.Error(), noPQ+" (") || !strings.Contains(refused.Error(), c.alert) {
				t.Fatalf("the sentence: %q", refused)
			}
			// The anchor fetch, which is the first thing a new user runs,
			// says the same and names the relay by its address.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _, err = FetchTrustAnchor(ctx, srv.URL)
			if !errors.As(err, &refused) || !strings.HasPrefix(err.Error(), srv.URL+": "+noPQ) {
				t.Fatalf("the anchor fetch: %v", err)
			}
		})
	}
	// The same relay serving the hybrid over 1.3 is answered, and with that
	// handshake: the refusals above are the pin, not a broken fixture.
	srv := relayOffering(t, bundle, func(cfg *tls.Config) {
		cfg.MinVersion = tls.VersionTLS13
		cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	})
	cl, err := NewWithAnchor(srv.URL, testIdentity(t, "alice"), nil, &Anchor{Cert: bundle.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Health(t.Context()); err != nil {
		t.Fatalf("a relay offering the hybrid over 1.3 was refused: %v", err)
	}
	// The client's own transport asks for nothing else.
	cfg := cl.transport.TLSClientConfig
	if cfg.MinVersion != tls.VersionTLS13 || len(cfg.CurvePreferences) != 1 || cfg.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("the client's transport is not pinned: MinVersion %x, curves %v", cfg.MinVersion, cfg.CurvePreferences)
	}
	// And a certificate that does not verify is a different refusal, with
	// its own words, never this sentence.
	other := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	cl, err = NewWithAnchor(srv.URL, testIdentity(t, "alice"), nil, &Anchor{Cert: other.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	err = cl.Health(t.Context())
	var refused *NoPQTransportError
	if err == nil || errors.As(err, &refused) {
		t.Fatalf("a certificate failure was reported as the transport pin: %v", err)
	}
}

// The client's half of the regression: on a connection that succeeds, the
// client's view of the handshake and the relay's are both TLS 1.3 with
// X25519MLKEM768, against a relay pinned the same and against one built
// with Go's defaults — the pin removed on that side — which Go's default
// still lets the pinned client hold to the hybrid. A relay that does not
// offer it is refused, above. A future Go default that dropped the hybrid,
// or an edit that lost the client's pin, fails here rather than
// negotiating less.
func TestNeitherEndAcceptsLessThanTheHybridOverTLS13(t *testing.T) {
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	for _, c := range []struct {
		label string
		alter func(*tls.Config)
	}{
		{"a relay pinned the same", func(cfg *tls.Config) {
			cfg.MinVersion = tls.VersionTLS13
			cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
		}},
		{"a relay with Go's defaults", func(*tls.Config) {}},
	} {
		t.Run(c.label, func(t *testing.T) {
			var seen tls.ConnectionState
			srv := relayServing(t, bundle)
			srv.Close()
			leaf := srv.TLS.Certificates
			again := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = *r.TLS
				_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216,"knock_max_bytes":16777216,"registration":"open"}`))
			}))
			again.TLS = &tls.Config{Certificates: leaf}
			c.alter(again.TLS)
			again.StartTLS()
			defer again.Close()

			cl, err := NewWithAnchor(again.URL, testIdentity(t, "alice"), nil, &Anchor{Cert: bundle.Anchor})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest("GET", again.URL+"/v1/health", nil)
			if err != nil {
				t.Fatal(err)
			}
			// Through the client's own transport, so the response carries
			// the handshake the client made.
			resp, err := cl.transport.RoundTrip(req)
			if err != nil {
				t.Fatalf("the pinned client against %s: %v", c.label, err)
			}
			resp.Body.Close()
			for _, end := range []struct {
				name string
				st   tls.ConnectionState
			}{{"the client's", *resp.TLS}, {"the relay's", seen}} {
				if end.st.Version != tls.VersionTLS13 || end.st.CurveID != tls.X25519MLKEM768 {
					t.Errorf("%s view of the handshake is version %x curve %v; want TLS 1.3 and X25519MLKEM768", end.name, end.st.Version, end.st.CurveID)
				}
			}
		})
	}
}

// TestThePinHoldsWithNoCertificateAndNoAnchor is the path the v0.7.0 test
// above did not take: a relay with a public certificate and no client
// certificates gives the constructor nothing to add, and for three
// releases that left the http.Client's Transport nil, which is Go's
// default handshake — TLS 1.2 and any curve. The client is built through
// the public constructor with nil for both, as auu and auu-admin build it
// for such a relay, and must refuse a relay offering less and negotiate
// the hybrid with one offering it. The refusals need no trust in the
// relay's certificate: the handshake fails at the key exchange before a
// certificate is looked at, which is also why the pin is the first thing
// a new user meets.
func TestThePinHoldsWithNoCertificateAndNoAnchor(t *testing.T) {
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	for _, c := range []struct {
		label string
		alter func(*tls.Config)
		alert string
	}{
		{"a relay offering only X25519", func(cfg *tls.Config) { cfg.CurvePreferences = []tls.CurveID{tls.X25519} }, "tls: handshake failure"},
		{"a relay capped at TLS 1.2", func(cfg *tls.Config) { cfg.MaxVersion = tls.VersionTLS12 }, "tls: protocol version not supported"},
	} {
		t.Run(c.label, func(t *testing.T) {
			srv := relayOffering(t, bundle, c.alter)
			for _, build := range []struct {
				name string
				cl   func() (*Client, error)
			}{
				{"NewWithAnchor(nil, nil)", func() (*Client, error) { return NewWithAnchor(srv.URL, testIdentity(t, "alice"), nil, nil) }},
				{"New(nil)", func() (*Client, error) { return New(srv.URL, testIdentity(t, "alice"), nil) }},
			} {
				cl, err := build.cl()
				if err != nil {
					t.Fatal(err)
				}
				if cl.transport == nil || cl.http.Transport == nil {
					t.Fatalf("%s: the client has no transport of its own, so its requests go through http.DefaultTransport and Go's handshake", build.name)
				}
				err = cl.Health(t.Context())
				var refused *NoPQTransportError
				if !errors.As(err, &refused) {
					t.Fatalf("%s against %s: %v, want NoPQTransportError", build.name, c.label, err)
				}
				if !strings.HasPrefix(refused.Error(), noPQ+" (") || !strings.Contains(refused.Error(), c.alert) {
					t.Fatalf("%s: the sentence: %q", build.name, refused)
				}
			}
		})
	}

	// A relay offering the hybrid, reached without an anchor: the root the
	// process trusts for it is supplied to the transport the constructor
	// built — the public-CA case in miniature — and the pin in that
	// transport is what makes the handshake, which both ends then see as
	// TLS 1.3 with X25519MLKEM768.
	var seen tls.ConnectionState
	again := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = *r.TLS
		_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216,"knock_max_bytes":16777216,"registration":"open"}`))
	}))
	again.StartTLS()
	defer again.Close()
	cl, err := NewWithAnchor(again.URL, testIdentity(t, "alice"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cl.transport.TLSClientConfig.RootCAs = again.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	if cfg := cl.transport.TLSClientConfig; cfg.MinVersion != tls.VersionTLS13 || len(cfg.CurvePreferences) != 1 || cfg.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("the transport built with nothing to add is not pinned: min %x curves %v", cfg.MinVersion, cfg.CurvePreferences)
	}
	if err := cl.Health(t.Context()); err != nil {
		t.Fatalf("a relay offering the hybrid, without an anchor: %v", err)
	}
	req, err := http.NewRequest("GET", again.URL+"/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, end := range []struct {
		name string
		st   tls.ConnectionState
	}{{"the client's", *resp.TLS}, {"the relay's", seen}} {
		if end.st.Version != tls.VersionTLS13 || end.st.CurveID != tls.X25519MLKEM768 {
			t.Errorf("%s view of the handshake is version %x curve %v; want TLS 1.3 and X25519MLKEM768", end.name, end.st.Version, end.st.CurveID)
		}
	}
}
