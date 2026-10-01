package store

import (
	"crypto/mldsa"
	"crypto/rand"
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
// and the cursor loose in the root. It is what Open refuses.
func oldHome(t *testing.T, root, relayURL string, anchor *x509.Certificate) {
	t.Helper()
	anchorPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw})
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
}

// A home from before it could know more than one relay is refused at Open,
// by the file and the key, with the fix, and is not moved to the new
// shape: nothing on this machine is from before. Each of the four old
// config keys alone is enough, and so is each of the three files a home
// kept loose in its root, since a home whose relay came from the
// environment had those with no relay in config.json.
func TestAHomeFromBeforeIsRefusedByNameAndNotMoved(t *testing.T) {
	const relayURL = "https://relay.example:9443"
	anchor := testAnchor(t, "old home")
	wantFix := "this auu reads none of it; delete config.json and any of trust_anchor.pem, cert.json and cursor " +
		"in the home's root, then add the relay again with 'auu relay add', or delete the home and run 'auu init' again"

	t.Run("whole", func(t *testing.T) {
		root := t.TempDir()
		oldHome(t, root, relayURL, anchor)
		before := snapshot(t, root)
		_, err := Open(root)
		want := filepath.Join(root, configFile) + ` has a key "relay", which is how a home from before v0.11.0 kept its one relay: ` + wantFix
		if err == nil || err.Error() != want {
			t.Fatalf("Open of an old home: %v\nwant %s", err, want)
		}
		if !errors.Is(err, ErrDamaged) {
			t.Error("the refusal is not ErrDamaged, so auu would not exit 5")
		}
		if after := snapshot(t, root); len(after) != len(before) {
			t.Errorf("Open moved or wrote files: %d before, %d after", len(before), len(after))
		} else {
			for name, was := range before {
				if string(after[name]) != string(was) {
					t.Errorf("%s was rewritten by a refusal", name)
				}
			}
		}
		// The fix the sentence names, walked through: the four files gone,
		// the home opens and the relay is added again.
		for _, name := range []string{configFile, anchorFile, certFile, cursorFile} {
			if err := os.Remove(filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
		}
		s, err := Open(root)
		if err != nil {
			t.Fatalf("Open after the named fix: %v", err)
		}
		if _, err := s.AddRelay("relay", relayURL); err != nil {
			t.Fatalf("auu relay add after the named fix: %v", err)
		}
	})

	for _, key := range configKeysFromBefore {
		t.Run("config key "+key, func(t *testing.T) {
			root := t.TempDir()
			cfg := `{"name": "ada", "` + key + `": "x"}` + "\n"
			if err := os.WriteFile(filepath.Join(root, configFile), []byte(cfg), fileMode); err != nil {
				t.Fatal(err)
			}
			_, err := Open(root)
			want := filepath.Join(root, configFile) + ` has a key "` + key + `", which is how a home from before v0.11.0 kept its one relay: ` + wantFix
			if err == nil || err.Error() != want {
				t.Fatalf("Open: %v\nwant %s", err, want)
			}
			if !errors.Is(err, ErrDamaged) {
				t.Error("the refusal is not ErrDamaged")
			}
		})
	}

	for _, file := range looseRelayFiles {
		t.Run("loose "+file, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(root, dirMode); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, file), []byte("x\n"), fileMode); err != nil {
				t.Fatal(err)
			}
			_, err := Open(root)
			want := filepath.Join(root, file) + " is a relay's file in the home's root, which is how a home from before v0.11.0 kept its one relay: " + wantFix
			if err == nil || err.Error() != want {
				t.Fatalf("Open: %v\nwant %s", err, want)
			}
			if !errors.Is(err, ErrDamaged) {
				t.Error("the refusal is not ErrDamaged")
			}
		})
	}
}

// config.json is a file this program wrote, read to its shape: a key
// Config does not write is refused by name, and every key it writes
// reads back. The keys are read from Config's tags, so a field added to
// it is accepted without a list to update, and the set is shown here.
func TestConfigRefusesAKeyItDoesNotKnow(t *testing.T) {
	s := newStore(t)
	want := map[string]bool{"name": true, "default_relay": true, "stream_threshold": true, "chunk_size": true, "editor": true, "vouch_answer": true}
	if len(configKeys) != len(want) {
		t.Fatalf("configKeys is %v, want %v", configKeys, want)
	}
	for k := range want {
		if !configKeys[k] {
			t.Errorf("configKeys lacks %q", k)
		}
	}
	full := Config{Name: "ada", DefaultRelay: "work", StreamThreshold: 4096, ChunkSize: 65536, Editor: "vi"}
	if err := s.SaveConfig(full); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Config(); err != nil || got != full {
		t.Fatalf("a full config read back as %+v, %v", got, err)
	}
	cfg := `{"name": "ada", "colour": "blue"}` + "\n"
	if err := os.WriteFile(s.path(configFile), []byte(cfg), fileMode); err != nil {
		t.Fatal(err)
	}
	_, err := s.Config()
	wantErr := s.path(configFile) + ` has a key this auu does not know, "colour": remove it, or delete the file and ` +
		"set the default relay again with 'auu relay default NAME'; it holds only that, the stream settings, your editor and whether vouch questions are answered"
	if err == nil || err.Error() != wantErr {
		t.Fatalf("Config: %v\nwant %s", err, wantErr)
	}
	if !errors.Is(err, ErrDamaged) {
		t.Error("the refusal is not ErrDamaged")
	}
	// And Open refuses it too, since a home with such a file is not one
	// to write into.
	if _, err := Open(s.Root()); err == nil || err.Error() != wantErr {
		t.Fatalf("Open: %v\nwant %s", err, wantErr)
	}
	// The key is echoed in the sentence, so it is quoted: a key with an
	// escape in it, or a line break, reaches the terminal as text.
	cfg = `{"name": "ada", "co\u001bl\nour": "blue"}` + "\n"
	if err := os.WriteFile(s.path(configFile), []byte(cfg), fileMode); err != nil {
		t.Fatal(err)
	}
	_, err = s.Config()
	if err == nil || !strings.Contains(err.Error(), `has a key this auu does not know, "co\x1bl\nour"`) ||
		strings.ContainsAny(err.Error(), "\x1b\n") {
		t.Fatalf("Config with an escape in the key: %q", err)
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
