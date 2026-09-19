package store

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/pki"
)

// testAnchor makes a self-signed ML-DSA certificate to stand in for a relay's
// trust anchor. The parameter set is the smallest one, because these tests
// care where the bytes go and not how strong they are.
func testAnchor(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// oldHome writes a home in the layout that came before a home could know more
// than one relay: the relay in config.json, and the anchor, the certificate
// and the cursor loose in the root.
func oldHome(t *testing.T, root, relayURL string, anchor *x509.Certificate) (anchorPEM, certJSON []byte) {
	t.Helper()
	anchorPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw})
	certJSON, err := json.MarshalIndent(&CertRecord{
		Relay: relayURL, Serial: "abc123" + strings.Repeat("0", 26), Label: "laptop",
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(300 * 24 * time.Hour),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{
		"name":                  "ada",
		"relay":                 relayURL,
		"trust_anchor_spki":     pki.SPKI(anchor),
		"server_int_spki":       "aa" + pki.SPKI(anchor)[2:],
		"server_int_not_before": time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339),
	}
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, dirMode); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		configFile: cfgJSON,
		anchorFile: anchorPEM,
		certFile:   certJSON,
		cursorFile: []byte("17\n"),
	} {
		if err := os.WriteFile(filepath.Join(root, name), data, fileMode); err != nil {
			t.Fatal(err)
		}
	}
	return anchorPEM, certJSON
}

func TestAnOldHomeIsMovedUnderItsRelayAndNothingIsRewritten(t *testing.T) {
	const relayURL = "https://relay.example:9443"
	root := t.TempDir()
	anchor := testAnchor(t, "old home")
	anchorPEM, certJSON := oldHome(t, root, relayURL, anchor)

	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}

	// The relay is there, named for its host, and it is the default.
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatalf("the migrated home has no default relay: %v", err)
	}
	if r.Name != "relay.example" || r.URL != relayURL {
		t.Fatalf("migrated relay is %q at %q", r.Name, r.URL)
	}

	// The anchor and the certificate were moved, not rewritten. That matters
	// more than it looks: a re-encoded anchor is a different file to reason
	// about at exactly the moment somebody is least able to check it.
	dir := s.RelayDir(r)
	for name, want := range map[string][]byte{anchorFile: anchorPEM, certFile: certJSON} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s was not moved: %v", name, err)
		}
		if string(got) != string(want) {
			// The bytes are a certificate and a key record; printing them
			// would bury the point in eight kilobytes of base64.
			t.Errorf("%s was rewritten rather than moved: %d bytes hashing %x, "+
				"want %d bytes hashing %x",
				name, len(got), sha256.Sum256(got), len(want), sha256.Sum256(want))
		}
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			t.Errorf("%s is still in the root as well", name)
		}
	}
	if n, err := s.CursorFor(r); err != nil || n != 17 {
		t.Errorf("cursor %d %v, want 17", n, err)
	}
	if !s.Registered(r) {
		t.Error("the migrated relay is not marked registered, so 'auu inbox' would skip it")
	}
	if rec, err := s.AnchorFor(r); err != nil || rec.SPKI != pki.SPKI(anchor) {
		t.Errorf("the migrated anchor does not load: %v", err)
	}
	if r.ServerIntSPKI == "" || r.ServerIntNotBefore.IsZero() {
		t.Error("the rotation ratchet was not carried across")
	}

	// The old fields are gone from config.json, and the new one is set.
	raw, err := os.ReadFile(filepath.Join(root, configFile))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk map[string]any
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"relay", "trust_anchor_spki", "server_int_spki", "server_int_not_before"} {
		if _, ok := onDisk[gone]; ok {
			t.Errorf("config.json still has %q", gone)
		}
	}
	if onDisk["default_relay"] != "relay.example" {
		t.Errorf("default_relay is %v", onDisk["default_relay"])
	}

	// Opening again changes nothing.
	before, err := os.ReadFile(filepath.Join(root, configFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(root, configFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("a second open moved the home again")
	}
	relays, err := s.Relays()
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 1 {
		t.Fatalf("a second open left %d relays", len(relays))
	}
}

// The move writes the directory first and config.json last, so a crash between
// them leaves a home that still looks unmigrated. Opening it must finish the
// job rather than doing it twice.
func TestAnInterruptedMoveIsFinishedNotRedone(t *testing.T) {
	const relayURL = "https://relay.example:9443"
	anchor := testAnchor(t, "interrupted")

	for _, tc := range []struct {
		name string
		// crash simulates how far the move had got before the power went.
		crash func(t *testing.T, root string)
	}{
		{
			name: "the directory exists and nothing has moved",
			crash: func(t *testing.T, root string) {
				if err := os.MkdirAll(filepath.Join(root, relaysDir, "relay.example"), dirMode); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "the anchor moved and the rest did not",
			crash: func(t *testing.T, root string) {
				dir := filepath.Join(root, relaysDir, "relay.example")
				if err := os.MkdirAll(dir, dirMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filepath.Join(root, anchorFile), filepath.Join(dir, anchorFile)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "everything moved and the record was written",
			crash: func(t *testing.T, root string) {
				dir := filepath.Join(root, relaysDir, "relay.example")
				if err := os.MkdirAll(dir, dirMode); err != nil {
					t.Fatal(err)
				}
				for _, f := range []string{anchorFile, certFile, cursorFile} {
					if err := os.Rename(filepath.Join(root, f), filepath.Join(dir, f)); err != nil {
						t.Fatal(err)
					}
				}
				rec, err := json.MarshalIndent(&Relay{
					Name: "relay.example", URL: relayURL, Added: time.Unix(1000000, 0).UTC(),
					TrustAnchorSPKI: pki.SPKI(anchor),
				}, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, relayFile), append(rec, '\n'), fileMode); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			anchorPEM, certJSON := oldHome(t, root, relayURL, anchor)
			tc.crash(t, root)

			s, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			relays, err := s.Relays()
			if err != nil {
				t.Fatal(err)
			}
			if len(relays) != 1 {
				t.Fatalf("finished with %d relays, want 1", len(relays))
			}
			r := relays[0]
			dir := s.RelayDir(r)
			for name, want := range map[string][]byte{anchorFile: anchorPEM, certFile: certJSON} {
				got, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if string(got) != string(want) {
					t.Errorf("%s was rewritten", name)
				}
			}
			if n, err := s.CursorFor(r); err != nil || n != 17 {
				t.Errorf("cursor %d %v, want 17", n, err)
			}
			cfg, err := s.Config()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DefaultRelay != "relay.example" {
				t.Fatalf("config after finishing: %+v", cfg)
			}
			legacy, err := s.legacyConfig()
			if err != nil {
				t.Fatal(err)
			}
			if legacy.Relay != "" {
				t.Fatalf("config.json still names a relay: %+v", legacy)
			}
		})
	}
}

// A pre-plan home that had registered but never fetched had no cursor file at
// all. It still has a mailbox, and 'auu inbox' must drain it.
func TestAMigratedHomeWithNoCursorIsStillRegistered(t *testing.T) {
	const relayURL = "https://relay.example:9443"
	root := t.TempDir()
	anchor := testAnchor(t, "never fetched")
	oldHome(t, root, relayURL, anchor)
	if err := os.Remove(filepath.Join(root, cursorFile)); err != nil {
		t.Fatal(err)
	}

	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Registered(r) {
		t.Fatal("a home that had a relay configured is not marked registered on it")
	}
	if n, err := s.CursorFor(r); err != nil || n != 0 {
		t.Fatalf("cursor %d %v, want 0", n, err)
	}
}

func TestRelayNamesResolveLikePeerNames(t *testing.T) {
	s := newStore(t)
	work, err := s.AddRelay("work", "https://work.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRelay("workshop", "https://workshop.example:9443"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRelay("personal", "https://personal.example"); err != nil {
		t.Fatal(err)
	}

	if got, err := s.Relay("work"); err != nil || got.Name != "work" {
		t.Errorf("exact name: %v %v", got, err)
	}
	if got, err := s.Relay("p"); err != nil || got.Name != "personal" {
		t.Errorf("unique prefix: %v %v", got, err)
	}
	// "work" is also a prefix of "workshop", and it resolves because an
	// exact name is tried before any prefix. "wor" is not, and names both.
	var amb *ErrAmbiguous
	_, err = s.Relay("wor")
	if !errors.As(err, &amb) {
		t.Fatalf("ambiguous prefix gave %v", err)
	}
	if len(amb.Candidates) != 2 || amb.What != "relays" {
		t.Errorf("ambiguity names %v (%s)", amb.Candidates, amb.What)
	}

	// By URL, with the port and without one the scheme implies.
	if got, err := s.Relay("https://work.example:9443"); err != nil || got.Name != "work" {
		t.Errorf("by URL: %v %v", got, err)
	}
	if got, err := s.Relay("https://personal.example:443"); err != nil || got.Name != "personal" {
		t.Errorf("by URL with the default port: %v %v", got, err)
	}
	if got, err := s.Relay("https://personal.example/"); err != nil || got.Name != "personal" {
		t.Errorf("by URL with a trailing slash: %v %v", got, err)
	}
	// A URL with a port that is not the scheme's is a different address.
	if _, err := s.Relay("https://work.example:9444"); !errors.Is(err, ErrNoSuchRelay) {
		t.Errorf("another port on the same host resolved: %v", err)
	}
	_, err = s.Relay("https://nobody.example")
	if !errors.Is(err, ErrNoSuchRelay) {
		t.Errorf("an unknown URL gave %v", err)
	}
	if err == nil || !contains(err.Error(), "add it first") {
		t.Errorf("an unknown URL does not say to add it: %v", err)
	}
	if _, err := s.Relay("nobody"); !errors.Is(err, ErrNoSuchRelay) {
		t.Errorf("an unknown name gave %v", err)
	}
	_ = work
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

func TestTheFirstRelayIsTheDefaultAndTheSecondIsNot(t *testing.T) {
	s := newStore(t)
	if _, err := s.DefaultRelay(); !errors.Is(err, ErrNoDefaultRelay) {
		t.Fatalf("an empty home has a default: %v", err)
	}
	if _, err := s.AddRelay("work", "https://work.example:9443"); err != nil {
		t.Fatal(err)
	}
	def, err := s.DefaultRelay()
	if err != nil || def.Name != "work" {
		t.Fatalf("the first relay is not the default: %v %v", def, err)
	}
	if _, err := s.AddRelay("personal", "https://personal.example:9443"); err != nil {
		t.Fatal(err)
	}
	if def, _ := s.DefaultRelay(); def.Name != "work" {
		t.Errorf("adding a second relay moved the default to %q", def.Name)
	}
}

func TestRemovingTheDefaultLeavesNoDefault(t *testing.T) {
	s := newStore(t)
	if _, err := s.AddRelay("work", "https://work.example:9443"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRelay("personal", "https://personal.example:9443"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveRelay("work"); err != nil {
		t.Fatal(err)
	}
	// Deliberately not replaced with the one that is left: which relay
	// somebody's mail goes to is theirs to say.
	if _, err := s.DefaultRelay(); !errors.Is(err, ErrNoDefaultRelay) {
		t.Fatalf("removing the default left one: %v", err)
	}
	cfg, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultRelay != "" {
		t.Errorf("config still names %q as the default", cfg.DefaultRelay)
	}
	// Removing one that is not the default leaves it alone.
	if err := s.SetDefaultRelay("personal"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRelay("third", "https://third.example:9443"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveRelay("third"); err != nil {
		t.Fatal(err)
	}
	if def, err := s.DefaultRelay(); err != nil || def.Name != "personal" {
		t.Errorf("removing another relay disturbed the default: %v %v", def, err)
	}
}

func TestPerRelayStateDoesNotLeak(t *testing.T) {
	s := newStore(t)
	work, err := s.AddRelay("work", "https://work.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	personal, err := s.AddRelay("personal", "https://personal.example:9443")
	if err != nil {
		t.Fatal(err)
	}

	// An anchor on one and none on the other.
	anchor := testAnchor(t, "work anchor")
	if err := s.SaveAnchorFor(work, anchor); err != nil {
		t.Fatal(err)
	}
	if rec, err := s.AnchorFor(work); err != nil || rec.SPKI != pki.SPKI(anchor) {
		t.Fatalf("work's anchor: %v %v", rec, err)
	}
	if _, err := s.AnchorFor(personal); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("personal borrowed work's anchor: %v", err)
	}

	// A certificate on the other and none on the first.
	if err := s.SaveCertFor(personal, &CertRecord{Relay: personal.URL, Serial: strings.Repeat("b", 32), Label: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if rec, err := s.CertFor(personal); err != nil || rec.Serial != strings.Repeat("b", 32) {
		t.Fatalf("personal's certificate: %v %v", rec, err)
	}
	if _, err := s.CertFor(work); !errors.Is(err, ErrNoCert) {
		t.Fatalf("work borrowed personal's certificate: %v", err)
	}
	if s.HasCertFor(work) || !s.HasCertFor(personal) {
		t.Error("HasCertFor disagrees with CertFor")
	}

	// A certificate file copied from one relay's directory into another's is
	// refused, exactly as one copied between homes is.
	data, err := os.ReadFile(filepath.Join(s.RelayDir(personal), certFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.RelayDir(work), certFile), data, fileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CertFor(work); !errors.Is(err, ErrCertForAnotherRelay) {
		t.Errorf("a certificate copied between relay directories was used, or was taken for none: %v", err)
	}

	// Cursors are each relay's own counter.
	if err := s.SetCursorFor(work, 7); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCursorFor(personal, 91); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CursorFor(work); n != 7 {
		t.Errorf("work's cursor is %d", n)
	}
	if n, _ := s.CursorFor(personal); n != 91 {
		t.Errorf("personal's cursor is %d", n)
	}

	// And the ratchet: what one relay's authority did says nothing about
	// another's.
	spki := strings.Repeat("deadbeef", 8)
	if err := s.SeenIntermediateFor(work, spki, time.Unix(1000, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	reloaded, err := s.Relay("work")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ServerIntSPKI != spki {
		t.Errorf("work's ratchet is %q", reloaded.ServerIntSPKI)
	}
	if other, _ := s.Relay("personal"); other.ServerIntSPKI != "" {
		t.Errorf("personal's ratchet moved with work's: %q", other.ServerIntSPKI)
	}
}

func TestRelayNamesAreValidatedAndUnique(t *testing.T) {
	s := newStore(t)
	for _, bad := range []string{"self", "..", ".", "a/b", "-leading", ""} {
		if err := ValidRelayName(bad); err == nil {
			t.Errorf("%q was accepted as a relay name", bad)
		}
	}
	if _, err := s.AddRelay("work", "https://work.example:9443"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRelay("work", "https://other.example:9443"); err == nil {
		t.Error("two relays were given one name")
	}
	if _, err := s.AddRelay("second", "https://work.example:9443"); err == nil {
		t.Error("one relay was added twice under two names")
	}
	// Two relays on one host, which is what a person running two on one
	// machine has: the second gets the port rather than failing.
	first, err := s.AddRelay("", "https://host.example:1111")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.AddRelay("", "https://host.example:2222")
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != "host.example" || second.Name != "host.example-2222" {
		t.Errorf("default names are %q and %q", first.Name, second.Name)
	}
}

func TestRenamingARelayMovesItsDirectoryAndTheDefault(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("work", "https://work.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	anchor := testAnchor(t, "work")
	if err := s.SaveAnchorFor(r, anchor); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameRelay("work", "office"); err != nil {
		t.Fatal(err)
	}
	moved, err := s.Relay("office")
	if err != nil {
		t.Fatal(err)
	}
	if rec, err := s.AnchorFor(moved); err != nil || rec.SPKI != pki.SPKI(anchor) {
		t.Errorf("the anchor did not come with the rename: %v", err)
	}
	if def, err := s.DefaultRelay(); err != nil || def.Name != "office" {
		t.Errorf("the default did not follow the rename: %v %v", def, err)
	}
	if _, err := s.Relay("work"); !errors.Is(err, ErrNoSuchRelay) {
		t.Errorf("the old name still resolves: %v", err)
	}
}

func TestForgettingAnIdentityKeepsTheRelayAndItsAnchor(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("work", "https://work.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	anchor := testAnchor(t, "work")
	if err := s.SaveAnchorFor(r, anchor); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCertFor(r, &CertRecord{Relay: r.URL, Serial: strings.Repeat("a", 32)}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCursorFor(r, 12); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetIdentityAt(r); err != nil {
		t.Fatal(err)
	}
	if s.HasCertFor(r) {
		t.Error("the old identity's certificate was kept")
	}
	if s.Registered(r) {
		t.Error("the new identity is recorded as registered")
	}
	if _, err := s.AnchorFor(r); err != nil {
		t.Errorf("the relay's own anchor was discarded with the identity: %v", err)
	}
}
