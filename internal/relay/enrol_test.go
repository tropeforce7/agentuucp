package relay

import (
	"net/http"
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
