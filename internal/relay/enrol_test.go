package relay

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// tokenHarness is a relay in token mode with one administrator, which is the
// shape every enrolment test needs.
func tokenHarness(t *testing.T, boss *identity.Identity) *harness {
	t.Helper()
	h := newHarness(t, Config{
		AdminFile:    adminFile(t, boss),
		Registration: relayapi.RegistrationToken,
		TokenMaxAge:  720 * time.Hour,
	})
	return h
}

func TestEnrolmentWithAValidToken(t *testing.T) {
	people := ids(t, "boss", "newcomer")
	boss, newcomer := people[0], people[1]
	h := tokenHarness(t, boss)

	tok := h.addToken(boss, nil)
	if status, body := h.enrol(newcomer, tok); status != http.StatusOK {
		t.Fatalf("enrolment: %d %s", status, body)
	}

	// Single use: the second identity is refused, and the token is spent.
	other := ids(t, "other")[0]
	status, body := h.enrol(other, tok)
	if status != http.StatusForbidden {
		t.Fatalf("second use: %d, want 403: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, "already been used") {
		t.Fatalf("error %q does not say the token is spent", got)
	}

	// Re-registration by an existing mailbox needs no token at all.
	if status, body := h.enrol(newcomer, ""); status != http.StatusOK {
		t.Fatalf("re-registration needed a token: %d %s", status, body)
	}
}

func TestEnrolmentRefusals(t *testing.T) {
	people := ids(t, "boss", "outsider")
	boss, outsider := people[0], people[1]

	cases := []struct {
		name   string
		token  func(h *harness) string
		status int
		want   string
	}{
		{
			name:   "no token at all",
			token:  func(h *harness) string { return "" },
			status: http.StatusForbidden,
			want:   "requires an enrolment token",
		},
		{
			name:   "not a token",
			token:  func(h *harness) string { return "hello" },
			status: http.StatusBadRequest,
			want:   "malformed enrolment token",
		},
		{
			name:   "signed by somebody who is not an administrator",
			token:  func(h *harness) string { return h.issue(outsider, nil) },
			status: http.StatusForbidden,
			want:   "not issued by an administrator",
		},
		{
			name: "signature does not verify",
			token: func(h *harness) string {
				raw := h.addToken(boss, nil)
				parts := strings.Split(raw, ".")
				return parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
			},
			status: http.StatusForbidden,
			want:   "not issued by an administrator",
		},
		{
			name: "expired",
			token: func(h *harness) string {
				raw := h.addToken(boss, nil)
				// Registered while valid, then aged out by rewriting the row,
				// which is what the passage of time would do.
				if _, err := h.store.db.Exec(`UPDATE tokens SET not_before = ?, not_after = ?`,
					time.Now().Add(-48*time.Hour).Unix(), time.Now().Add(-24*time.Hour).Unix()); err != nil {
					t.Fatal(err)
				}
				return expire(t, boss, raw, -48*time.Hour, -24*time.Hour)
			},
			status: http.StatusForbidden,
			want:   "has expired",
		},
		{
			name: "not yet valid",
			token: func(h *harness) string {
				return expire(t, boss, h.issue(boss, nil), 24*time.Hour, 48*time.Hour)
			},
			status: http.StatusForbidden,
			want:   "not yet valid",
		},
		{
			name: "issued to a different identity",
			token: func(h *harness) string {
				return h.addToken(boss, func(c *token.Claims) {
					c.Subject = outsider.Fingerprint()
				})
			},
			status: http.StatusForbidden,
			want:   "issued to a different identity",
		},
		{
			name:   "never registered with this relay",
			token:  func(h *harness) string { return h.issue(boss, nil) },
			status: http.StatusForbidden,
			want:   "unknown to this relay",
		},
		{
			name: "revoked",
			token: func(h *harness) string {
				raw := h.addToken(boss, nil)
				u, err := token.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				if status, _, _ := h.send(boss, "DELETE", "/v1/admin/tokens/"+u.Claims.ID,
					nil, nil); status != http.StatusNoContent {
					t.Fatal("revoke failed")
				}
				return raw
			},
			status: http.StatusForbidden,
			want:   "has been revoked",
		},
		{
			name: "already spent",
			token: func(h *harness) string {
				raw := h.addToken(boss, nil)
				first := ids(t, "first")[0]
				if status, _ := h.enrol(first, raw); status != http.StatusOK {
					t.Fatal("the first use should have worked")
				}
				return raw
			},
			status: http.StatusForbidden,
			want:   "already been used",
		},
		{
			name: "wrong use",
			token: func(h *harness) string {
				return resign(t, boss, h.issue(boss, nil), func(m map[string]any) {
					m["use"] = "administer"
				})
			},
			status: http.StatusForbidden,
			want:   "not for registration",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := tokenHarness(t, boss)
			newcomer := ids(t, "newcomer")[0]
			tok := c.token(h)

			before := h.mailboxCount()
			status, body := h.enrol(newcomer, tok)
			if status != c.status {
				t.Fatalf("status %d, want %d: %s", status, c.status, body)
			}
			if got := errorText(t, body); !strings.Contains(got, c.want) {
				t.Fatalf("error %q does not contain %q", got, c.want)
			}
			if after := h.mailboxCount(); after != before {
				t.Fatalf("a refused enrolment created %d mailbox(es)", after-before)
			}
			h.assertNoTokenSpent()
		})
	}
}

// expire re-signs a token with a different validity window.
func expire(t *testing.T, id *identity.Identity, tok string, from, to time.Duration) string {
	t.Helper()
	now := time.Now()
	return resign(t, id, tok, func(m map[string]any) {
		m["not_before"] = now.Add(from).Unix()
		m["not_after"] = now.Add(to).Unix()
	})
}

func (h *harness) mailboxCount() int {
	h.t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM mailboxes`).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// assertNoTokenSpent checks that every token still has the uses it was
// registered with, except where a test deliberately spent one.
func (h *harness) assertNoTokenSpent() {
	h.t.Helper()
	rows, err := h.store.db.Query(`SELECT id, uses, uses_left, last_redeemed FROM tokens`)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var uses, left int
		var lastRedeemed any
		if err := rows.Scan(&id, &uses, &left, &lastRedeemed); err != nil {
			h.t.Fatal(err)
		}
		// A token a test spent on purpose has a redemption stamp; one that a
		// refused enrolment touched would not.
		if left != uses && lastRedeemed == nil {
			h.t.Fatalf("token %s lost a use without being redeemed", id[:8])
		}
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
}

func TestMultiUseToken(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := tokenHarness(t, boss)
	tok := h.addToken(boss, func(c *token.Claims) { c.Uses = 2 })

	people := ids(t, "one", "two", "three")
	for i, id := range people[:2] {
		if status, body := h.enrol(id, tok); status != http.StatusOK {
			t.Fatalf("use %d: %d %s", i+1, status, body)
		}
	}
	if status, _ := h.enrol(people[2], tok); status != http.StatusForbidden {
		t.Fatalf("a two-use token admitted a third identity: %d", status)
	}
}

func TestSubjectBoundToken(t *testing.T) {
	people := ids(t, "boss", "invited", "gatecrasher")
	boss, invited, gatecrasher := people[0], people[1], people[2]
	h := tokenHarness(t, boss)
	tok := h.addToken(boss, func(c *token.Claims) { c.Subject = invited.Fingerprint() })

	if status, body := h.enrol(gatecrasher, tok); status != http.StatusForbidden {
		t.Fatalf("a bound token admitted somebody else: %d %s", status, body)
	}
	if status, body := h.enrol(invited, tok); status != http.StatusOK {
		t.Fatalf("the identity the token was issued to was refused: %d %s", status, body)
	}
}

func TestRegistrationModes(t *testing.T) {
	boss := ids(t, "boss")[0]

	t.Run("closed refuses a first registration and allows a change of name", func(t *testing.T) {
		h := newHarness(t, Config{Registration: relayapi.RegistrationClosed})
		newcomer, existing := ids(t, "newcomer")[0], ids(t, "existing")[0]
		h.enroll(existing)

		status, body := h.enrol(newcomer, "")
		if status != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", status, body)
		}
		if got := errorText(t, body); got != msgNotAccepting {
			t.Fatalf("error %q, want %q", got, msgNotAccepting)
		}
		if status, body := h.enrol(existing, ""); status != http.StatusOK {
			t.Fatalf("an existing mailbox could not re-register: %d %s", status, body)
		}
	})

	t.Run("open ignores a token and does not spend it", func(t *testing.T) {
		h := newHarness(t, Config{
			AdminFile:    adminFile(t, boss),
			Registration: relayapi.RegistrationOpen,
		})
		tok := h.addToken(boss, nil)
		newcomer := ids(t, "newcomer")[0]
		if status, body := h.enrol(newcomer, tok); status != http.StatusOK {
			t.Fatalf("open registration was refused: %d %s", status, body)
		}
		var left int
		if err := h.store.db.QueryRow(`SELECT uses_left FROM tokens`).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if left != 1 {
			t.Fatalf("an open relay consumed a use: %d left", left)
		}
	})
}

// The mailbox cap and blocks are settled before the token is looked at, so a
// refusal there costs the holder nothing.
func TestCapAndBlockDoNotSpendAToken(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{
		AdminFile:    adminFile(t, boss),
		Registration: relayapi.RegistrationToken,
		Limits:       Limits{MaxMailboxes: 1},
	})
	h.enroll(ids(t, "sitting-tenant")[0])

	tok := h.addToken(boss, nil)
	newcomer := ids(t, "newcomer")[0]
	status, body := h.enrol(newcomer, tok)
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", status, body)
	}
	if got := errorText(t, body); got != msgNotAccepting {
		t.Fatalf("error %q, want %q", got, msgNotAccepting)
	}
	var left int
	if err := h.store.db.QueryRow(`SELECT uses_left FROM tokens`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Fatal("a registration refused by the mailbox cap spent the token")
	}
}

// A relay that gains a public_url after some tokens were registered must not
// honour ones issued for somewhere else, so the audience is checked again at
// redemption and not only when the token is registered.
func TestTokenForAnotherRelayIsRefusedAtRedemption(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{
		AdminFile:    adminFile(t, boss),
		Registration: relayapi.RegistrationToken,
		PublicURL:    "https://relay.example.com",
	})
	// Put it straight in the table, as one registered before this relay knew
	// its own name: the admin endpoint would refuse it now, which is the other
	// half of the same check.
	raw := h.issue(boss, func(c *token.Claims) { c.Relay = "https://somewhere.else.example" })
	u, err := token.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.AddToken(u.Claims, time.Now()); err != nil {
		t.Fatal(err)
	}

	newcomer := ids(t, "newcomer")[0]
	status, body := h.enrol(newcomer, raw)
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, "for a different relay") {
		t.Fatalf("error %q does not say why", got)
	}

	// And registering one now is refused outright.
	status, body, _ = h.send(boss, "POST", "/v1/admin/tokens",
		relayapi.RegisterTokenRequest{Token: h.issue(boss, func(c *token.Claims) {
			c.Relay = "https://somewhere.else.example"
		})}, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("registering a token for another relay: %d, want 400: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, "different relay") {
		t.Fatalf("error %q does not say why", got)
	}
}

// The relay's own name is the audience, so a token issued for one relay cannot
// be spent on another even when both trust the same administrator.
func TestPublicURLIsTheAudience(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{
		AdminFile:    adminFile(t, boss),
		Registration: relayapi.RegistrationToken,
		PublicURL:    "https://relay.example.com",
	})
	newcomer := ids(t, "newcomer")[0]

	// Registered for this relay's public name, which is not its test address.
	tok := h.addToken(boss, func(c *token.Claims) { c.Relay = "https://relay.example.com/" })
	if status, body := h.enrol(newcomer, tok); status != http.StatusOK {
		t.Fatalf("a token naming the public URL was refused: %d %s", status, body)
	}
}

// The schema version is the contract with a database on disk. Version 1 is
// migrated; version 0 with tables in it is refused.
func TestMigrationFromVersionOne(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "v1.db")

	// The version 1 schema, written out as it shipped rather than derived from
	// the current constants, so that changing an existing table without a
	// migration fails here.
	const schemaV1 = `
CREATE TABLE mailboxes (
	fp              TEXT PRIMARY KEY,
	bundle          BLOB NOT NULL,
	name            TEXT NOT NULL,
	created         TEXT NOT NULL,
	queued_messages INTEGER NOT NULL DEFAULT 0,
	queued_bytes    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE allowlist (
	fp        TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	sender_fp TEXT NOT NULL,
	PRIMARY KEY (fp, sender_fp)
);
CREATE TABLE messages (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	to_fp    TEXT NOT NULL REFERENCES mailboxes(fp) ON DELETE CASCADE,
	received TEXT NOT NULL,
	envelope BLOB NOT NULL
);
CREATE INDEX messages_to ON messages(to_fp, id);
CREATE TABLE nonces (
	nonce   TEXT PRIMARY KEY,
	expires INTEGER NOT NULL
);
CREATE INDEX nonces_expires ON nonces(expires);
CREATE TABLE relay_stats (
	id              INTEGER PRIMARY KEY CHECK (id = 1),
	queued_messages INTEGER NOT NULL,
	queued_bytes    INTEGER NOT NULL
);
INSERT INTO relay_stats (id, queued_messages, queued_bytes) VALUES (1, 0, 0);
PRAGMA user_version = 1;
`
	alice := ids(t, "alice")[0]
	rawDB := openRaw(t, old)
	if _, err := rawDB.Exec(schemaV1); err != nil {
		t.Fatal(err)
	}
	if _, err := rawDB.Exec(
		`INSERT INTO mailboxes (fp, bundle, name, created) VALUES (?, ?, ?, ?)`,
		alice.Fingerprint(), alice.Public().Bundle(), "alice", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	rawDB.Close()

	migrated, err := OpenStore(old, filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatalf("a version 1 database would not open: %v", err)
	}
	defer migrated.Close()

	var version int
	if err := migrated.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version %d after migrating, want %d", version, schemaVersion)
	}
	// The old row survived.
	mb, err := migrated.Mailbox(alice.Fingerprint())
	if err != nil || mb.Name != "alice" {
		t.Fatalf("the existing mailbox did not survive the migration: %v", err)
	}
	// And the new tables work.
	if _, err := migrated.Blocks(); err != nil {
		t.Fatalf("blocks table missing after migration: %v", err)
	}
	if _, err := migrated.Tokens(true, time.Now()); err != nil {
		t.Fatalf("tokens table missing after migration: %v", err)
	}

	// A database created from scratch and one migrated forward must be the
	// same shape, or the two paths have drifted apart.
	fresh, err := OpenStore(filepath.Join(dir, "fresh.db"), filepath.Join(dir, "fresh-messages"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if want, got := tableDDL(t, fresh), tableDDL(t, migrated); want != got {
		t.Fatalf("a migrated database differs from a fresh one:\n--- fresh ---\n%s\n--- migrated ---\n%s", want, got)
	}
}

// openRaw opens a database without any of OpenStore's checks, so a test can
// build one that looks like an older release's.
func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(connectionPragmas); err != nil {
		t.Fatal(err)
	}
	return db
}

// tableDDL is the text SQLite stored for every table and index we created.
func tableDDL(t *testing.T, s *Store) string {
	t.Helper()
	rows, err := s.db.Query(`SELECT COALESCE(sql, '') FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sql string
		if err := rows.Scan(&sql); err != nil {
			t.Fatal(err)
		}
		if sql == "" {
			continue
		}
		out = append(out, strings.Join(strings.Fields(sql), " "))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(out, "\n")
}
