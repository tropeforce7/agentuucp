package store

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// Every file in the home that a person could damage is refused with a
// sentence that names the file, the plain fact, Go's reason in brackets
// where there is one, and what to do, and every one is ErrDamaged, which is
// what makes it exit 5. The container suite's K02, K04, K05, K08, K11, K12,
// K14, K15 and K20 found the right sentences with exit 1, or Go's wording,
// or no file named.
func TestDamagedFilesAreNamed(t *testing.T) {
	// fixture makes a home with an identity, a relay with an anchor, a
	// certificate and a cursor, and returns the store and the relay.
	fixture := func(t *testing.T) (*Store, *Relay) {
		t.Helper()
		s := newStore(t)
		id, err := identity.Generate("ada")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SaveIdentity(id); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveConfig(Config{Name: "ada", DefaultRelay: "work"}); err != nil {
			t.Fatal(err)
		}
		r, err := s.AddRelay("work", "https://work.example:9443")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SaveAnchorFor(r, testAnchor(t, "work")); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveCertFor(r, &CertRecord{Relay: r.URL, Serial: "aaa"}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetCursorFor(r, 12); err != nil {
			t.Fatal(err)
		}
		return s, r
	}
	write := func(t *testing.T, path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const identityLost = "if you have a backup of this home, restore it; if not, this identity is lost and 'auu init --force' makes a new one"

	for _, tc := range []struct {
		name string
		// damage alters one file and returns the sentence expected, with
		// the paths it needs from the store.
		damage func(t *testing.T, s *Store, r *Relay) string
		// read is the operation that meets the file.
		read func(s *Store, r *Relay) error
		// interrupted says ErrInterrupted must be beneath too.
		interrupted bool
	}{
		{
			name: "identity.json emptied, as an editor crash leaves it",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.path(identityFile), "")
				return s.path(identityFile) + " is not valid JSON (unexpected end of JSON input): " + identityLost
			},
			read: func(s *Store, r *Relay) error { _, err := s.Identity(); return err },
		},
		{
			name: "identity.json with one seed and not the other",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.path(identityFile), `{"name":"ada","sign_seed":"AAAA"}`)
				return s.path(identityFile) + " holds one seed and not the other: " + identityLost
			},
			read: func(s *Store, r *Relay) error { _, err := s.Identity(); return err },
		},
		{
			name: "identity.json with seeds and a bundle both",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.path(identityFile), `{"name":"ada","sign_seed":"AAAA","kem_seed":"AAAA","bundle":"AAAA"}`)
				return s.path(identityFile) + " holds both the seeds and a bundle, which is neither a plain identity nor an encrypted one: " + identityLost
			},
			read: func(s *Store, r *Relay) error { _, err := s.Identity(); return err },
		},
		{
			name: "identity.json with neither seeds nor a bundle",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.path(identityFile), `{"name":"ada"}`)
				return s.path(identityFile) + " holds neither seeds nor a bundle: " + identityLost
			},
			read: func(s *Store, r *Relay) error { _, err := s.Identity(); return err },
		},
		{
			name: "config.json not valid JSON",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.path(configFile), "{")
				return s.path(configFile) + " is not valid JSON (unexpected end of JSON input): delete it and set the " +
					"default relay again with 'auu relay default NAME'; it holds only that, the stream settings and your editor"
			},
			read: func(s *Store, r *Relay) error { _, err := s.Config(); return err },
		},
		{
			name: "relay.json with a trailing comma",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				path := s.relayPath(r, relayFile)
				write(t, path, `{"url": "https://work.example:9443",,}`)
				return path + " is not valid JSON (invalid character ',' looking for beginning of object key string): " +
					"enrol again with a token, or remove the relay with 'auu relay rm work' and add it again"
			},
			read: func(s *Store, r *Relay) error { _, err := s.Relay("work"); return err },
		},
		{
			name: "the cursor holds abc",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.relayPath(r, cursorFile), "abc\n")
				return s.relayPath(r, cursorFile) + ` is not a message id ("abc"): delete it and run 'auu inbox --relay work'; that starts from the beginning and delivers nothing twice`
			},
			read: func(s *Store, r *Relay) error { _, err := s.CursorFor(r); return err },
		},
		{
			name: "the cursor holds a long thing, shown bounded",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.relayPath(r, cursorFile), strings.Repeat("x", 100))
				return s.relayPath(r, cursorFile) + ` is not a message id ("` + strings.Repeat("x", 40) + `…"): delete it and run 'auu inbox --relay work'; that starts from the beginning and delivers nothing twice`
			},
			read: func(s *Store, r *Relay) error { _, err := s.CursorFor(r); return err },
		},
		{
			name: "allow_pushed holds something that is not a time",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.relayPath(r, allowPushedFile), "yesterday\n")
				return s.relayPath(r, allowPushedFile) + ` is not a time ("yesterday"): delete it, or run 'auu allow push', which writes it again; it records only when this machine last pushed its allow list`
			},
			read: func(s *Store, r *Relay) error { _, _, err := s.AllowPushed(r); return err },
		},
		{
			name: "cert.json truncated, met by CertFor",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.relayPath(r, certFile), `{"relay": "https://work.ex`)
				return s.relayPath(r, certFile) + " is not valid JSON (unexpected end of JSON input): run 'auu register --relay work --token TOKEN' to replace it"
			},
			read: func(s *Store, r *Relay) error { _, err := s.CertFor(r); return err },
		},
		{
			name: "cert.json truncated, met by the home's state",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.relayPath(r, certFile), `{"relay": "https://work.ex`)
				return s.relayPath(r, certFile) + " is not valid JSON (unexpected end of JSON input): run 'auu register --relay work --token TOKEN' to replace it"
			},
			read: func(s *Store, r *Relay) error { _, err := s.Identity(); return err },
		},
		{
			name: "trust_anchor.pem deleted",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				if err := os.Remove(s.relayPath(r, anchorFile)); err != nil {
					t.Fatal(err)
				}
				return "relay.json records a trust anchor for work but " + s.relayPath(r, anchorFile) + " is missing; enrol again with a token"
			},
			read: func(s *Store, r *Relay) error { _, err := s.AnchorFor(r); return err },
		},
		{
			name: "trust_anchor.pem replaced by another authority's",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				other := newStore(t)
				o, err := other.AddRelay("other", "https://other.example")
				if err != nil {
					t.Fatal(err)
				}
				if err := other.SaveAnchorFor(o, testAnchor(t, "other")); err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(other.relayPath(o, anchorFile))
				if err != nil {
					t.Fatal(err)
				}
				write(t, s.relayPath(r, anchorFile), string(raw))
				return s.relayPath(r, anchorFile) + " holds a different trust anchor than relay.json records (" +
					o.TrustAnchorSPKI[:16] + ", not " + r.TrustAnchorSPKI[:16] + "); it has been replaced, so nothing here should be trusted until you enrol again"
			},
			read: func(s *Store, r *Relay) error { _, err := s.AnchorFor(r); return err },
		},
		{
			name: "trust_anchor.pem not PEM",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.relayPath(r, anchorFile), "not a certificate\n")
				return s.relayPath(r, anchorFile) + " is not a PEM certificate: enrol again with a token"
			},
			read: func(s *Store, r *Relay) error { _, err := s.AnchorFor(r); return err },
		},
		{
			name: "trust_anchor.pem a PEM block that is not a certificate",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.relayPath(r, anchorFile), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
				return s.relayPath(r, anchorFile) + " does not hold a certificate (x509: malformed certificate): enrol again with a token"
			},
			read: func(s *Store, r *Relay) error { _, err := s.AnchorFor(r); return err },
		},
		{
			name: "a passphrase change interrupted: home.key beside a plain identity",
			damage: func(t *testing.T, s *Store, r *Relay) string {
				write(t, s.path(homeKeyFile), "not a key")
				return "home.key exists but identity.json holds the keys in the clear: a passphrase change was interrupted; " +
					"run 'auu passphrase set' or 'auu passphrase remove' again, whichever was interrupted, to finish it"
			},
			read:        func(s *Store, r *Relay) error { _, err := s.Identity(); return err },
			interrupted: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r := fixture(t)
			want := tc.damage(t, s, r)
			err := tc.read(s, r)
			if err == nil {
				t.Fatal("the damaged file was accepted")
			}
			if err.Error() != want {
				t.Fatalf("sentence\n  %q\nwant\n  %q", err, want)
			}
			if !errors.Is(err, ErrDamaged) {
				t.Fatalf("not ErrDamaged: %v", err)
			}
			if tc.interrupted != errors.Is(err, ErrInterrupted) {
				t.Fatalf("ErrInterrupted beneath: %v, want %v", errors.Is(err, ErrInterrupted), tc.interrupted)
			}
		})
	}
}

// A relay.json with no trust anchor recorded is what a relay under a public
// authority looks like, and pinning is off; with the pinned file still
// beside it, the one line that made the file count has been edited out, and
// carrying on unpinned would be what the edit was for. The container
// suite's K13 found it carried on. A record with its file passes as before.
func TestARemovedAnchorHashIsCaught(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("work", "https://work.example:9443")
	if err != nil {
		t.Fatal(err)
	}

	// Neither file nor record: a public-CA or plain-HTTP relay, unpinned.
	if _, err := s.AnchorFor(r); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("a relay with no anchor and no file gave %v, want ErrNoAnchor", err)
	}

	// Pinned: record and file, and it passes.
	anchor := testAnchor(t, "work")
	if err := s.SaveAnchorFor(r, anchor); err != nil {
		t.Fatal(err)
	}
	if got, err := s.AnchorFor(r); err != nil || got.SPKI != r.TrustAnchorSPKI {
		t.Fatalf("a pinned relay gave %v", err)
	}

	// The record edited out of relay.json, the file left: refused, as a
	// damaged file, by name.
	edited := *r
	edited.TrustAnchorSPKI = ""
	if err := s.SaveRelay(&edited); err != nil {
		t.Fatal(err)
	}
	reread, err := s.Relay("work")
	if err != nil {
		t.Fatal(err)
	}
	if reread.TrustAnchorSPKI != "" {
		t.Fatal("the record still holds the hash; the edit did not take")
	}
	_, err = s.AnchorFor(reread)
	if err == nil {
		t.Fatal("a relay.json with the hash removed beside its pinned file was accepted")
	}
	want := s.relayPath(r, relayFile) + " records no trust anchor but " + s.relayPath(r, anchorFile) +
		" is here; relay.json has been edited. Enrol again with a token, or run 'auu anchor pin HASH' with the hash from the relay's operator"
	if err.Error() != want {
		t.Fatalf("sentence\n  %q\nwant\n  %q", err, want)
	}
	if !errors.Is(err, ErrDamaged) || errors.Is(err, ErrNoAnchor) {
		t.Fatalf("want ErrDamaged and not ErrNoAnchor: %v", err)
	}

	// The file gone too — the relay unpinned by removing both, which a
	// person may do on purpose — is no anchor, not damage.
	if err := os.Remove(s.relayPath(r, anchorFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AnchorFor(reread); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("a relay with neither file nor record gave %v, want ErrNoAnchor", err)
	}
}

// A cert.json whose relay names another URL is a file that is there and
// wrong, which is not a file that is missing: it was copied between relay
// directories, or the relay's URL was changed under it. It is named, with
// the register command for this relay, and it is damaged. The container
// suite's K10 found it treated as absent, so that the relay's refusal of a
// certificate it never saw was the only word said.
func TestACertificateForAnotherRelayIsNamed(t *testing.T) {
	s := newStore(t)
	r, err := s.AddRelay("work", "https://work.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCertFor(r, &CertRecord{Relay: "https://other.example:9443", Serial: "aaa"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.CertFor(r)
	if err == nil {
		t.Fatal("a certificate for another relay was accepted")
	}
	want := "this machine's " + s.relayPath(r, certFile) + " for work was issued by https://other.example:9443: " +
		"run 'auu register --relay work --token TOKEN' to get one for this relay"
	if err.Error() != want {
		t.Fatalf("sentence\n  %q\nwant\n  %q", err, want)
	}
	if !errors.Is(err, ErrCertForAnotherRelay) || !errors.Is(err, ErrDamaged) || errors.Is(err, ErrNoCert) {
		t.Fatalf("want ErrCertForAnotherRelay and ErrDamaged and not ErrNoCert: %v", err)
	}
	// Its own relay's URL, in any of the forms sameRelay accepts, passes.
	if err := s.SaveCertFor(r, &CertRecord{Relay: "https://work.example:9443/", Serial: "aaa"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CertFor(r); err != nil {
		t.Fatalf("the relay's own certificate was refused: %v", err)
	}
	// And none at all is still none.
	if err := s.RemoveCertFor(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CertFor(r); !errors.Is(err, ErrNoCert) {
		t.Fatalf("no certificate gave %v, want ErrNoCert", err)
	}
}
