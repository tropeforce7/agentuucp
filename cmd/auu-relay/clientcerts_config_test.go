package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/keyfile"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// certConfig is a configuration that would start, with client certificates
// on, from a real auu-ca bundle. Registration is token, since certificates
// beside open registration are refused: a machine could re-register with
// no token and be issued a new one.
func certConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	c := Defaults()
	c.DB = filepath.Join(dir, "relay.db")
	c.Registration = relayapi.RegistrationToken
	c.Admin.AuthorizedFile = adminFile(t, "boss")
	c.ClientCerts.Mode = relayapi.ClientCertsRequired
	c.TLS.Mode = ModeFiles
	c.TLS.Bundle = testBundlePath(t, dir)
	c.Resolve()
	return c
}

func TestClientCertsDefaultsToOff(t *testing.T) {
	c := Defaults()
	if c.ClientCerts.Mode != relayapi.ClientCertsOff {
		t.Errorf("default mode is %q, want %q", c.ClientCerts.Mode, relayapi.ClientCertsOff)
	}
	if c.ClientCerts.Required() {
		t.Error("client certificates are on by default")
	}
	d, err := c.ClientCerts.ParsedLifetime()
	if err != nil || d != defaultCertLifetime {
		t.Errorf("default lifetime %v, %v; want %v", d, err, defaultCertLifetime)
	}
}

func TestClientCertsModeIsChecked(t *testing.T) {
	for _, mode := range []string{"optional", "on", "REQUIRED", "yes"} {
		c := certConfig(t)
		c.ClientCerts.Mode = mode
		err := c.Validate()
		if err == nil {
			t.Fatalf("mode %q was accepted", mode)
		}
		// The message names both of what it will take, because "optional" is
		// the mode an operator will reach for and it does not exist.
		for _, want := range []string{relayapi.ClientCertsOff, relayapi.ClientCertsRequired} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %q", err, want)
			}
		}
	}
}

func TestClientCertLifetimeBounds(t *testing.T) {
	// One step either side of both boundaries.
	for _, tc := range []struct {
		lifetime string
		ok       bool
	}{
		{"59m59s", false},
		{"1h", true},
		{"8760h", true},
		{"87600h", true},
		{"87601h", false},
		{"0s", false},
		{"-1h", false},
		{"not a duration", false},
	} {
		t.Run(tc.lifetime, func(t *testing.T) {
			c := certConfig(t)
			c.ClientCerts.Lifetime = tc.lifetime
			err := c.Validate()
			if tc.ok && err != nil {
				t.Fatalf("lifetime %s was refused: %v", tc.lifetime, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("lifetime %s was accepted", tc.lifetime)
			}
		})
	}
}

// TestClientCertsNeedSomewhereToSeeACertificate: a relay that does not
// terminate TLS would never see a certificate and would refuse every mailbox
// request for ever, looking like one that had broken. Nothing may stand in
// front of the relay to terminate for it: reverse-proxy support was removed.
func TestClientCertsNeedSomewhereToSeeACertificate(t *testing.T) {
	dir := t.TempDir()
	c := Defaults()
	c.DB = filepath.Join(dir, "relay.db")
	c.Registration = relayapi.RegistrationClosed
	c.ClientCerts.Mode = relayapi.ClientCertsRequired
	c.TLS.Bundle = testBundlePath(t, dir)
	c.Resolve()
	c.TLS.Mode = ModeOff // files is the default; off is set by hand.

	err := c.Validate()
	if err == nil {
		t.Fatal("a relay that can never see a certificate was accepted")
	}
	const want = "client certificates are required but tls mode is off: " +
		"the relay must terminate TLS itself to see one; set tls.mode to files"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error is\n %q\nwant one containing\n %q", err, want)
	}

	// Terminating TLS itself is the only arrangement there is.
	c.TLS.Mode = ModeFiles
	if err := c.Validate(); err != nil {
		t.Errorf("a relay terminating TLS from its bundle was refused: %v", err)
	}
}

// A bundle with TLS off used to mean a reverse proxy in front. There is no
// such arrangement now, so it is refused by name rather than started as a
// relay that can never be pinned.
func TestABundleWithTLSOffIsRefused(t *testing.T) {
	dir := t.TempDir()
	c := Defaults()
	c.DB = filepath.Join(dir, "relay.db")
	c.TLS.Bundle = testBundlePath(t, dir)
	c.Resolve()
	c.TLS.Mode = ModeOff

	err := c.Validate()
	if err == nil {
		t.Fatal("tls off with a bundle was accepted")
	}
	const want = "tls mode is off but tls.bundle names a bundle; the relay serves TLS " +
		"from a bundle itself, so set tls.mode to files or remove the bundle"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error is\n %q\nwant one containing\n %q", err, want)
	}
}

// The removed setting is named, not reported as a typo.
func TestTrustedProxiesIsARemovedSetting(t *testing.T) {
	file := writeFile(t, `{"limits": {"trusted_proxies": ["10.0.0.0/8"]}}`)
	_, err := resolve(t, file)
	if err == nil {
		t.Fatal("limits.trusted_proxies was accepted")
	}
	for _, want := range []string{"limits.trusted_proxies is no longer a setting", "reverse-proxy support was removed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
}

func TestClientCertsRoundTripThroughTheConfigFile(t *testing.T) {
	// --print-config must produce something the relay will read back.
	c := certConfig(t)
	c.ClientCerts.Lifetime = (90 * 24 * time.Hour).String()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	var printed bytes.Buffer
	if err := Encode(&printed, c.Redacted()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "relay.json")
	if err := os.WriteFile(path, printed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	back, _, err := Load(path)
	if err != nil {
		t.Fatalf("reading back a printed config: %v", err)
	}
	if back.ClientCerts != c.ClientCerts {
		t.Errorf("client_certs did not survive:\n got %+v\nwant %+v", back.ClientCerts, c.ClientCerts)
	}
}

// TestTheParameterSetComesFromTheBundle: the relay does not choose it. It is
// the trust anchor's, fixed by 'auu-ca init --mldsa', and the relay reports
// what it was given.
func TestTheParameterSetComesFromTheBundle(t *testing.T) {
	for _, n := range []int{44, 65, 87} {
		params, err := pki.ParameterSet(n)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		store := pki.TestStore(t, params)
		b, err := store.IssueRelay([]string{"relay.example.com"}, 1, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "bundle.json")
		if err := pki.WriteBundle(path, b); err != nil {
			t.Fatal(err)
		}
		c := Defaults()
		c.DB = filepath.Join(dir, "relay.db")
		c.Registration = relayapi.RegistrationClosed
		c.ClientCerts.Mode = relayapi.ClientCertsRequired
		c.TLS.Bundle = path
		c.Resolve()
		if err := c.Validate(); err != nil {
			t.Fatalf("a %d bundle was refused: %v", n, err)
		}
		parts, err := openBundle(c)
		if err != nil {
			t.Fatal(err)
		}
		if got := pki.ParameterNumberOf(parts.policy.Issuer.Parameters()); got != n {
			t.Errorf("a %d bundle issues at %d", n, got)
		}
	}
}

// TestSettingsThatWereRemovedAreNamed: an operator upgrading is told where a
// setting went, not that it is unknown.
func TestSettingsThatWereRemovedAreNamed(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"tls": {"acme": {"domains": ["a.example.com"]}}}`, "ACME was removed"},
		{`{"client_certs": {"dir": "/var/lib/auu/clientca"}}`, "issued one by 'auu-ca relay'"},
		{`{"client_certs": {"mldsa": 87}}`, "auu-ca init --mldsa"},
	} {
		path := filepath.Join(t.TempDir(), "relay.json")
		if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := Load(path)
		if err == nil {
			t.Fatalf("%s was accepted", tc.body)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("error %q does not contain %q", err, tc.want)
		}
	}
}

func TestABundleIsCheckedAtStartupNotAtTheFirstHandshake(t *testing.T) {
	// Every way a bundle can be wrong, refused with the path in the message.
	// An operator who has copied the wrong file, or a truncated one, finds
	// out when the relay will not start rather than when a machine cannot
	// connect.
	dir := t.TempDir()
	good := testBundlePath(t, dir)
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}

	write := func(t *testing.T, mutate func(map[string]any)) string {
		t.Helper()
		var copy map[string]any
		if err := json.Unmarshal(raw, &copy); err != nil {
			t.Fatal(err)
		}
		mutate(copy)
		data, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "bundle.json")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	other := pki.TestHierarchy(t, []string{"relay.example.com"}, mldsa.MLDSA65())
	for _, tc := range []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{"missing", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") }, "no such file"},
		{"not JSON", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(p, []byte("not json"), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}, "invalid"},
		{"a newer version", func(t *testing.T) string {
			return write(t, func(m map[string]any) { m["v"] = 99 })
		}, "bundle version 99"},
		{"an unknown field", func(t *testing.T) string {
			return write(t, func(m map[string]any) { m["surprise"] = true })
		}, "unknown field"},
		{"the anchor hash does not match", func(t *testing.T) string {
			return write(t, func(m map[string]any) { m["trust_anchor_spki"] = strings.Repeat("a", 64) })
		}, "hashes to"},
		{"a key that is not its certificate's", func(t *testing.T) string {
			return write(t, func(m map[string]any) {
				m["client_int_key"] = base64.StdEncoding.EncodeToString(
					mustPKCS8(t, other.ClientInt.Key))
			})
		}, "does not match its certificate"},
		{"an intermediate from another anchor", func(t *testing.T) string {
			return write(t, func(m map[string]any) {
				m["client_int_cert"] = base64.StdEncoding.EncodeToString(other.ClientInt.Cert.Raw)
				m["client_int_key"] = base64.StdEncoding.EncodeToString(
					mustPKCS8(t, other.ClientInt.Key))
			})
		}, "does not chain to the trust anchor"},
		{"no hosts", func(t *testing.T) string {
			return write(t, func(m map[string]any) { m["hosts"] = []string{} })
		}, "no hosts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Defaults()
			c.DB = filepath.Join(t.TempDir(), "relay.db")
			c.TLS.Mode = ModeFiles
			c.TLS.Bundle = tc.path(t)
			c.Resolve()
			err := c.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), c.TLS.Bundle) {
				t.Errorf("error %q does not name the file", err)
			}
		})
	}
	_ = b
}

func mustPKCS8(t *testing.T, key *mldsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestARelayMintsItsOwnCertificateAndRenewsIt(t *testing.T) {
	// The relay's leaf is short-lived because it makes it itself, and its key
	// is never written: that is what a witness will one day use to tell the
	// real relay from an impostor holding its intermediates.
	c := certConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	parts, err := openBundle(c)
	if err != nil {
		t.Fatal(err)
	}
	if parts == nil || parts.policy == nil {
		t.Fatal("a bundle with client certificates required produced no policy")
	}
	first, err := parts.server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Until(first.Leaf.NotAfter); got > pki.LeafDays*24*time.Hour+time.Hour {
		t.Errorf("the relay's own certificate lives %v, want about %d days", got, pki.LeafDays)
	}
	// It is served with its chain, so a client can verify to the anchor
	// without holding the intermediate.
	if len(first.Certificate) < 2 {
		t.Errorf("the relay serves %d certificates, want its leaf and a chain", len(first.Certificate))
	}

	// One day either side of the renewal boundary.
	renewed, err := parts.server.RenewIfDue(time.Now(), leafRenewBefore)
	if err != nil {
		t.Fatal(err)
	}
	if renewed {
		t.Error("a certificate outside the renewal window was renewed")
	}
	// A window wider than the certificate's whole life must renew it.
	renewed, err = parts.server.RenewIfDue(time.Now(), (pki.LeafDays+1)*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !renewed {
		t.Fatal("a certificate inside the renewal window was not renewed")
	}
	second, err := parts.server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Error("renewal did not change the certificate")
	}
	if parts.server.SPKI() == pki.SPKI(first.Leaf) {
		t.Error("renewal reused the key; a fresh one is the point")
	}
}

func TestClientCertsRequiredNeedsABundle(t *testing.T) {
	// cert_file and key_file carry no authority to issue from.
	c := Defaults()
	c.DB = filepath.Join(t.TempDir(), "relay.db")
	c.ClientCerts.Mode = relayapi.ClientCertsRequired
	c.TLS.Mode = ModeFiles
	c.TLS.CertFile, c.TLS.KeyFile, _ = selfSigned(t, t.TempDir())
	c.Resolve()
	err := c.Validate()
	if err == nil {
		t.Fatal("client certificates were required with no bundle")
	}
	const want = "client certificates need the signing intermediate from an auu-ca bundle: " +
		"set tls.bundle or tls.bundle_credential"
	if err.Error() != want {
		t.Errorf("error is\n %q\nwant\n %q", err, want)
	}
}

// TestTheRelayWarnsBeforeItsIntermediatesExpire: the one date an operator has
// to plan a trip to the offline machine around, said while there is still
// time, and again once it is too late.
func TestTheRelayWarnsBeforeItsIntermediatesExpire(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name      string
		issuedAgo time.Duration
		want      int
		contains  string
	}{
		{"freshly issued", 0, 0, ""},
		{"a month from expiry", 11 * 30 * 24 * time.Hour, 2, "expires soon"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issued := now.Add(-tc.issuedAgo)
			ca, err := pki.Create(t.TempDir(), "Test", mldsa.MLDSA65(), keyfile.TestPassphrase("test passphrase"), issued)
			if err != nil {
				t.Fatal(err)
			}
			b, err := ca.IssueRelay([]string{"relay.example.com"}, 1, issued)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "bundle.json")
			if err := pki.WriteBundle(path, b); err != nil {
				t.Fatal(err)
			}
			c := Defaults()
			c.TLS.Mode = ModeFiles
			c.TLS.Bundle = path
			parts, err := openBundle(c)
			if err != nil {
				t.Fatal(err)
			}
			got := intermediateWarnings(parts, now)
			if len(got) != tc.want {
				t.Fatalf("%d warnings, want %d: %+v", len(got), tc.want, got)
			}
			for _, w := range got {
				if !strings.Contains(w.msg, tc.contains) || !strings.Contains(w.msg, "auu-ca relay") {
					t.Errorf("warning %q does not say what is wrong and what to do", w.msg)
				}
			}
		})
	}
	// Once it has expired the relay cannot mint a leaf, and says which
	// intermediate rather than failing a handshake with no explanation.
	long := now.AddDate(-1, -1, 0)
	ca, err := pki.Create(t.TempDir(), "Test", mldsa.MLDSA65(), keyfile.TestPassphrase("test passphrase"), long)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.IssueRelay([]string{"relay.example.com"}, 1, long)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := pki.WriteBundle(path, b); err != nil {
		t.Fatal(err)
	}
	c := Defaults()
	c.TLS.Mode = ModeFiles
	c.TLS.Bundle = path
	if _, err := openBundle(c); err == nil || !strings.Contains(err.Error(), "auu-ca relay") {
		t.Fatalf("an expired bundle at startup: %v, want a refusal naming 'auu-ca relay'", err)
	}
}

// TestOpenRegistrationWithRequiredCertificatesIsRefused: registration
// consults no presented certificate — it is how a machine gets one — so
// with registration open, any holder of the identity key re-registers with
// no token and is issued a fresh certificate, and revoking a machine's
// certificate revokes nothing. The pair cancels the guarantee certificates
// exist for, and is refused at startup in one sentence; open without
// certificates, and token or closed with them, are the pairs that stand.
func TestOpenRegistrationWithRequiredCertificatesIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name         string
		registration string
		certs        string
		ok           bool
	}{
		{"open with certificates required", relayapi.RegistrationOpen, relayapi.ClientCertsRequired, false},
		{"open without certificates", relayapi.RegistrationOpen, relayapi.ClientCertsOff, true},
		{"token with certificates required", relayapi.RegistrationToken, relayapi.ClientCertsRequired, true},
		{"closed with certificates required", relayapi.RegistrationClosed, relayapi.ClientCertsRequired, true},
		{"token without certificates", relayapi.RegistrationToken, relayapi.ClientCertsOff, true},
		{"closed without certificates", relayapi.RegistrationClosed, relayapi.ClientCertsOff, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := certConfig(t)
			c.Registration = tc.registration
			c.ClientCerts.Mode = tc.certs
			err := c.Validate()
			if tc.ok && err != nil {
				t.Fatalf("%s was refused: %v", tc.name, err)
			}
			if !tc.ok && (err == nil || err.Error() != msgOpenWithCerts) {
				t.Fatalf("%s: %v, want %q", tc.name, err, msgOpenWithCerts)
			}
		})
	}
}
