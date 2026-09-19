package main

import (
	"bytes"
	"crypto/mldsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The settings file the deployment guide tells an operator to install, with
// only its paths pointed at fixtures. A machine's first act against a relay is
// to fetch and pin its anchor, so the shipped settings must answer that
// request; the first deployment found they did not, because the route was
// gated on client certificates, which the template has off.
//
// The template names its bundle as a systemd credential, so the bundle is
// put where systemd would put it, under the name the template gives, and
// the template's own tls block is left exactly as shipped.
func TestTheShippedTemplateServesItsAnchor(t *testing.T) {
	dir := t.TempDir()
	ca := pki.TestStore(t, mldsa.MLDSA65())
	issued, err := ca.IssueRelay([]string{"relay.example.com"}, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	admins := filepath.Join(dir, "admins")
	if err := os.WriteFile(admins, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := Load(filepath.Join("..", "..", "docs", "systemd", "relay.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.BundleCredential == "" || cfg.TLS.Bundle != "" {
		t.Fatalf("this test is about the template naming a credential, and its tls block is %+v", cfg.TLS)
	}
	creds := t.TempDir()
	if err := pki.WriteBundle(filepath.Join(creds, cfg.TLS.BundleCredential), issued); err != nil {
		t.Fatal(err)
	}
	t.Setenv(credentialsDirectoryEnv, creds)
	// The server's paths, and nothing else, are replaced.
	cfg.DB = filepath.Join(dir, "relay.db")
	cfg.MessagesDir = ""
	cfg.Admin.AuthorizedFile = admins
	cfg.Resolve()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the shipped template does not validate: %v", err)
	}
	if cfg.ClientCerts.Required() {
		t.Fatal("this test is about the template having client certificates off, and it does not")
	}

	parts, err := openBundle(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rcfg, err := relayConfig(cfg, parts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	st, err := relay.OpenStore(cfg.DB, cfg.MessagesDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(relay.NewServer(st, rcfg))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/trust-anchor")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the shipped settings answer the anchor route with %d: %s", resp.StatusCode, body)
	}
	var got relayapi.TrustAnchorResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.TrustAnchor, parts.loaded.Anchor.Raw) {
		t.Fatal("the anchor served is not the bundle's")
	}
}

// Tokens name public_url and machines connect to it. When it names a port
// the relay does not listen on, nobody can enrol, and the first deployment
// did exactly that: listen on 9443, public_url without a port.
func TestTheRelayWarnsWhenPublicURLNamesAnotherPort(t *testing.T) {
	for _, tc := range []struct {
		listen, public, mode string
		warn                 bool
	}{
		{":9443", "https://relay.example.com", ModeFiles, true},
		{":9443", "https://relay.example.com:9443", ModeFiles, false},
		{":443", "https://relay.example.com", ModeFiles, false},
		{"0.0.0.0:9443", "https://relay.example.com:8443", ModeFiles, true},
		// Nothing stands in front of the relay to forward a port, so TLS
		// off is no excuse: a mismatch is a mismatch.
		{"127.0.0.1:8080", "https://relay.example.com", ModeOff, true},
		{"127.0.0.1:8080", "http://relay.example.com:8080", ModeOff, false},
		{":9443", "", ModeFiles, false},
	} {
		cfg := Defaults()
		cfg.Listen, cfg.PublicURL, cfg.TLS.Mode = tc.listen, tc.public, tc.mode
		msg := portMismatch(cfg)
		if (msg != "") != tc.warn {
			t.Errorf("listen %s public_url %q tls %s: warned %v, want %v: %q",
				tc.listen, tc.public, tc.mode, msg != "", tc.warn, msg)
		}
		if tc.warn && !strings.Contains(msg, "nobody can enrol") {
			t.Errorf("the warning does not say what it costs: %q", msg)
		}
	}
}
