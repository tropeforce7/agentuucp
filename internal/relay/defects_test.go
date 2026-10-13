package relay

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// The lifetime cap used to be computed as a time.Duration, which overflows
// into a negative number for any span over about 292 years. A negative
// duration compares as shorter than token_max_age, so the cap was bypassed
// entirely by a token claiming a far-future expiry.
func TestTokenLifetimeCapDoesNotOverflow(t *testing.T) {
	boss := ids(t, "boss")[0]
	maxAge := 48 * time.Hour
	h := newHarness(t, Config{AdminFile: adminFile(t, boss), TokenMaxAge: maxAge})
	now := time.Now()

	register := func(notBefore, notAfter int64) (int, []byte) {
		raw := resign(t, boss, h.issue(boss, nil), func(m map[string]any) {
			m["not_before"] = notBefore
			m["not_after"] = notAfter
		})
		status, body, _ := h.send(boss, "POST", "/v1/admin/tokens",
			relayapi.RegisterTokenRequest{Token: raw}, nil)
		return status, body
	}

	maxSeconds := int64(maxAge / time.Second)
	t.Run("exactly at the cap is accepted", func(t *testing.T) {
		if status, body := register(now.Unix(), now.Unix()+maxSeconds); status != http.StatusCreated {
			t.Fatalf("status %d, want 201: %s", status, body)
		}
	})
	t.Run("one second over the cap is refused", func(t *testing.T) {
		status, body := register(now.Unix(), now.Unix()+maxSeconds+1)
		if status != http.StatusBadRequest {
			t.Fatalf("status %d, want 400: %s", status, body)
		}
		if got := errorText(t, body); !strings.Contains(got, "token_max_age") {
			t.Fatalf("error %q does not name the cap", got)
		}
	})
	// The overflow cases. Each of these has a lifetime far past the cap and
	// past the 292 years a Duration holds, and each used to produce a
	// negative Duration and be accepted. Since G26 a token's dates end with
	// the year 9999, so the longest span the cap can still be asked about is
	// to the last writable second, some eight thousand years.
	for name, notAfter := range map[string]int64{
		"a thousand years":         now.Unix() + 1000*365*24*3600,
		"the last writable second": 253402300799,
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			status, body := register(now.Unix(), notAfter)
			if status != http.StatusBadRequest {
				t.Fatalf("not_after=%d gave status %d, want 400: %s", notAfter, status, body)
			}
			if got := errorText(t, body); !strings.Contains(got, "token_max_age") {
				t.Fatalf("error %q does not name the cap", got)
			}
		})
	}
	// Past the year 9999 the date itself is refused first (G26), before the
	// cap is reached, still 400 and nothing stored.
	for name, notAfter := range map[string]int64{
		"MaxInt64":         math.MaxInt64,
		"half of MaxInt64": math.MaxInt64 / 2,
		"2^40 seconds":     now.Unix() + 1<<40,
	} {
		t.Run(name+" is refused for its date", func(t *testing.T) {
			status, body := register(now.Unix(), notAfter)
			if status != http.StatusBadRequest {
				t.Fatalf("not_after=%d gave status %d, want 400: %s", notAfter, status, body)
			}
			if got := errorText(t, body); !strings.Contains(got, "past 253402300799, the end of the year 9999") {
				t.Fatalf("error %q does not name the year 9999", got)
			}
		})
	}
}

// A path arrives from the caller and reaches the operator's log.
func TestLoggedPathIsTruncated(t *testing.T) {
	h := newHarness(t, Config{})
	long := "/v1/keys/" + strings.Repeat("a", 4096)
	h.send(nil, "GET", long, nil, nil)

	logged := h.logs.String()
	for _, line := range strings.Split(logged, "\n") {
		if len(line) > 1024 {
			t.Fatalf("a log line is %d bytes; the path was not truncated", len(line))
		}
	}
	if !strings.Contains(logged, "…") {
		t.Fatalf("nothing was truncated:\n%s", logged)
	}
}

// Every Limits field at MaxInt64 must still start a relay that serves.
// MaxInflight in particular becomes a channel capacity.
func TestLimitsAtMaxInt64(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{
		RequestsPerMinute:        math.MaxInt64,
		PostsPerMinute:           math.MaxInt64,
		PostBytesPerHour:         math.MaxInt64,
		UnauthenticatedPerMinute: math.MaxInt64,
		RegistrationsPerHour:     math.MaxInt64,
		MaxMailboxes:             math.MaxInt64,
		MailboxMaxMessages:       math.MaxInt64,
		MailboxMaxBytes:          math.MaxInt64,
		RelayMaxBytes:            math.MaxInt64,
		MaxInflight:              math.MaxInt64,
		MaxWaiting:               math.MaxInt64,
	}})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	if status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "hello"), nil); status != http.StatusOK {
		t.Fatalf("a relay with every limit at MaxInt64 refused a post: %d %s", status, body)
	}
	h.healthy()
}

// intParam feeds two int64s straight from the query string.
func TestListParametersAtTheExtremes(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)
	box := "/v1/mailbox/" + alice.Fingerprint()

	cases := []struct {
		query string
		want  int
	}{
		{"?limit=9223372036854775807", http.StatusOK}, // capped to MaxListLimit
		{"?limit=-9223372036854775808", http.StatusBadRequest},
		{"?limit=0", http.StatusBadRequest},
		{"?limit=1", http.StatusOK},
		{"?limit=200", http.StatusOK},
		{"?limit=201", http.StatusOK}, // capped, not refused
		{"?limit=-1", http.StatusBadRequest},
		{"?after=9223372036854775807", http.StatusOK},
		{"?after=-1", http.StatusBadRequest},
		{"?after=-9223372036854775808", http.StatusBadRequest},
		{"?after=0", http.StatusOK},
		{"?limit=99999999999999999999", http.StatusBadRequest}, // does not fit int64
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			status, body, _ := h.send(alice, "GET", box+c.query, nil, nil)
			if status != c.want {
				t.Fatalf("status %d, want %d: %s", status, c.want, body)
			}
			if status != http.StatusOK {
				return
			}
			var list relayapi.ListResponse
			if err := json.Unmarshal(body, &list); err != nil {
				t.Fatal(err)
			}
			if len(list.Messages) > relayapi.MaxListLimit {
				t.Fatalf("returned %d messages, over the cap", len(list.Messages))
			}
		})
	}
}

// The admin page limit is the same parameter on a different route.
func TestAdminMailboxLimitAtTheExtremes(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	h.enroll(ids(t, "a", "b", "c")...)

	for query, want := range map[string]int{
		"?limit=9223372036854775807":        http.StatusOK,
		"?limit=-1":                         http.StatusBadRequest,
		"?limit=0":                          http.StatusBadRequest,
		"?limit=1":                          http.StatusOK,
		"?after=" + strings.Repeat("z", 64): http.StatusBadRequest,
		"?after=short":                      http.StatusBadRequest,
	} {
		status, body, _ := h.send(boss, "GET", "/v1/admin/mailboxes"+query, nil, nil)
		if status != want {
			t.Errorf("%s gave %d, want %d: %s", query, status, want, body)
		}
	}
}

// An unregistered token whose signature is also bad must be refused for the
// signature, which proves the token table is not consulted first.
func TestUnregisteredTokenWithABadSignature(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := tokenHarness(t, boss)
	newcomer := ids(t, "newcomer")[0]

	raw := h.issue(boss, nil) // never registered
	parts := strings.Split(raw, ".")
	forged := parts[0] + "." + parts[1] + "." + flipEncodedSignature(t, parts[2])

	status, body := h.enrol(newcomer, forged)
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, "not issued by an administrator") {
		t.Fatalf("error %q; the token table was consulted before the signature", got)
	}
}

// The block list must not be readable by an unauthenticated caller.
func TestBlockedMailboxIsNotAnOracle(t *testing.T) {
	people := ids(t, "boss", "blocked")
	boss, blocked := people[0], people[1]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	h.register(blocked)
	if status, _, _ := h.send(boss, "PUT", "/v1/admin/blocks/"+blocked.Fingerprint(),
		relayapi.BlockRequest{Reason: "testing"}, nil); status != http.StatusNoContent {
		t.Fatal("block failed")
	}

	// No auth header at all: the answer must be the same as for any other
	// unauthenticated request, never the block.
	if status, body, _ := h.send(nil, "GET", "/v1/mailbox/"+blocked.Fingerprint(), nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("an unsigned request naming a blocked fingerprint gave %d, want 401: %s", status, body)
	}
	// A stranger's valid signature, likewise.
	stranger := ids(t, "stranger")[0]
	if status, _, _ := h.send(stranger, "GET", "/v1/mailbox/"+blocked.Fingerprint(), nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("a stranger learned about the block: %d", status)
	}
}

// A blocked identity holding a valid token is refused, and keeps the use.
func TestBlockedIdentityCannotSpendAToken(t *testing.T) {
	people := ids(t, "boss", "blocked")
	boss, blocked := people[0], people[1]
	h := newHarness(t, Config{
		AdminFile:    adminFile(t, boss),
		Registration: relayapi.RegistrationToken,
		TokenMaxAge:  720 * time.Hour,
	})
	if err := h.store.SetBlock(blocked.Fingerprint(), "blocked in advance",
		boss.Fingerprint(), time.Now()); err != nil {
		t.Fatal(err)
	}
	tok := h.addToken(boss, nil)

	status, body := h.enrol(blocked, tok)
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", status, body)
	}
	if got := errorText(t, body); got != msgBlocked {
		t.Fatalf("error %q, want %q", got, msgBlocked)
	}
	var left int
	if err := h.store.db.QueryRow(`SELECT uses_left FROM tokens`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Fatal("a blocked identity's refused enrolment spent the token")
	}
}

// flipEncodedSignature decodes a base64url signature, flips one bit, and
// re-encodes it. One flipped bit keeps the length and the encoding valid, so
// the only thing left to reject it is the signature check itself.
func flipEncodedSignature(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(testutil.FlipBit(raw, 0))
}
