package client

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// TestLimitARelaysStampsAreHeldToTheSkew: a time a relay says something
// happened at, the status's started, a queue row's last_try, a listing
// row's received, the lookup's created, a mailbox's, a block's and a
// token's created and a token's last_redeemed, is kept, copied into files
// and printed, so each is held to no further ahead of this machine's clock
// than a request may be (relayapi.MaxSkew) and to what this program can
// write back. Every value goes on the wire as JSON text through a fake
// relay and is checked by the client's own answer check: now and a second
// inside the skew are taken, a minute past it, a day and a year ahead are
// refused by name, a year past is taken, the wire's earliest end, year 0
// at +23:59, which is UTC year -1, is refused by name, the earliest
// writable time is taken, and the zero time is taken where the field may
// be empty. Now is read from the clock, never written as a literal. The
// exact edges are shown on stampAt against a fixed now: now + MaxSkew
// taken and a nanosecond past it refused, a nanosecond outside either end
// of what can be written refused, and the earliest and latest instants
// refused, which json.Marshal refuses too, so on the wire the wire's own
// ends stand in for them.
func TestLimitARelaysStampsAreHeldToTheSkew(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	fp := alice.Fingerprint()
	tokenID := strings.Repeat("7", 32)

	// The bound itself, against a fixed now: the edge is taken and a
	// nanosecond past it refused, and the ends of what can be written are
	// held apart from the skew by a now close to the latest of them.
	latestInstant := time.Unix(math.MaxInt64-62135596800, 999999999)
	t.Run("stampAt", func(t *testing.T) {
		now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
		nearLatest := relayapi.LatestWritable.Add(-relayapi.MaxSkew / 2)
		// The grammar's values around the edge, now + MaxSkew.
		for _, e := range testutil.TimeEdges(now.Add(relayapi.MaxSkew)) {
			var taken bool
			switch e.Name {
			case testutil.AtTheEdge, testutil.ASecondBefore, testutil.AYearPast:
				taken = true
			case testutil.ASecondPast, testutil.ADayAhead, testutil.AYearAhead,
				testutil.TheEarliest, testutil.OnePastYear9999, testutil.TheLatest:
			default:
				t.Fatalf("no answer for %s", e.Name)
			}
			if got := stampAt(e.At, now); got != taken {
				t.Errorf("%s: stampAt(%v, %v) = %v; want %v", e.Name, e.At, now, got, taken)
			}
		}
		for _, tc := range []struct {
			name   string
			t, now time.Time
			taken  bool
		}{
			{"now", now, now, true},
			{"a nanosecond past the edge", now.Add(relayapi.MaxSkew + time.Nanosecond), now, false},
			{"the zero time", time.Time{}, now, true},
			{"EarliestWritable", relayapi.EarliestWritable, now, true},
			{"a nanosecond before EarliestWritable", relayapi.EarliestWritable.Add(-time.Nanosecond), now, false},
			{"LatestWritable, now near it", relayapi.LatestWritable, nearLatest, true},
			{"a nanosecond after LatestWritable, now near it", relayapi.LatestWritable.Add(time.Nanosecond), nearLatest, false},
			{"the latest instant, now near LatestWritable", latestInstant, nearLatest, false},
		} {
			if got := stampAt(tc.t, tc.now); got != tc.taken {
				t.Errorf("%s: stampAt(%v, %v) = %v; want %v", tc.name, tc.t, tc.now, got, tc.taken)
			}
		}
	})

	// The encoder half: the two instants no wire can carry are refused by
	// json.Marshal, so a relay cannot send them; the wire's own ends, year
	// 0 at +23:59 and year 9999 at -12:00, stand in for them through the
	// answer path below.
	t.Run("the encoder refuses the instants past the wire", func(t *testing.T) {
		for _, v := range []time.Time{testutil.EarliestInstant(), testutil.PastYear9999(), latestInstant} {
			if b, err := json.Marshal(v); err == nil {
				t.Errorf("json.Marshal(%v) = %s; want it refused", v, b)
			}
		}
	})

	// tree is a well-formed answer as JSON-decoded maps, with the one
	// time at keys set to raw, so the decoder, not this test, reads it.
	tree := func(t *testing.T, good any, raw string, keys ...any) map[string]any {
		t.Helper()
		b, err := json.Marshal(good)
		if err != nil {
			t.Fatal(err)
		}
		var root map[string]any
		if err := json.Unmarshal(b, &root); err != nil {
			t.Fatal(err)
		}
		var at any = root
		for i, k := range keys {
			last := i == len(keys)-1
			switch k := k.(type) {
			case string:
				m := at.(map[string]any)
				if last {
					m[k] = json.RawMessage(raw)
				} else {
					at = m[k]
				}
			case int:
				s := at.([]any)
				if last {
					s[k] = json.RawMessage(raw)
				} else {
					at = s[k]
				}
			}
		}
		return root
	}

	list := func(c *Client) error { _, err := c.List(context.Background(), 0, 10); return err }
	type field struct {
		name, path, field string
		good              any
		keys              []any
		call              func(*Client) error
		mayBeEmpty        bool
	}
	listing := map[string]any{"messages": []any{map[string]any{"id": 1, "received": "2026-09-20T01:19:29Z", "kind": "envelope", "size": 3,
		"channel": "default", "envelope": map[string]any{"v": 1, "to": "x", "ct": "AAA"}}},
		"queued": 1, "first": 1, "last": 1, "allow": "none", "card": "none", "directory": "none"}
	fields := []field{
		{"the status's started", "/v1/admin/status", "started",
			relayapi.AdminStatusResponse{Registration: relayapi.RegistrationOpen, ClientCerts: relayapi.ClientCertsOff},
			[]any{"started"}, func(c *Client) error { _, err := c.AdminStatus(context.Background()); return err }, false},
		{"a queue row's last_try", "/v1/mailbox/" + fp + "/queue", "last_try",
			relayapi.QueueResponse{Queued: []relayapi.QueuedMessage{{ID: 1, Neighbour: "bar", Path: "baz", State: "waiting"}}},
			[]any{"queued", 0, "last_try"}, func(c *Client) error { _, err := c.Queue(context.Background()); return err }, true},
		{"a listing row's received", "/v1/mailbox/" + fp, "received", listing,
			[]any{"messages", 0, "received"}, list, false},
		{"the lookup's created", "/v1/keys/" + fp, "created",
			map[string]any{"bundle": alice.Public().Bundle(), "name": "alice", "created": "2026-09-20T01:19:29Z"},
			[]any{"created"}, func(c *Client) error { _, err := c.Lookup(context.Background(), fp); return err }, false},
		{"a mailbox's created", "/v1/admin/mailboxes/" + fp, "created",
			relayapi.MailboxAnswer{Mailbox: relayapi.MailboxRecord{FP: fp, Name: "alice", Allow: relayapi.AllowSigned}},
			[]any{"mailbox", "created"}, func(c *Client) error { _, err := c.AdminMailbox(context.Background(), fp); return err }, false},
		{"a mailbox listing row's created", "/v1/admin/mailboxes", "created",
			relayapi.MailboxListResponse{Mailboxes: []relayapi.MailboxRecord{{FP: fp, Name: "alice", Allow: relayapi.AllowSigned}}},
			[]any{"mailboxes", 0, "created"}, func(c *Client) error { _, err := c.AdminMailboxes(context.Background(), "", 0); return err }, false},
		{"a block's created", "/v1/admin/blocks", "created",
			relayapi.BlocksResponse{Blocks: []relayapi.BlockRecord{{FP: fp, ByFP: fp}}},
			[]any{"blocks", 0, "created"}, func(c *Client) error { _, err := c.AdminBlocks(context.Background()); return err }, false},
		{"a token's created", "/v1/admin/tokens", "created",
			relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: tokenID, Issuer: fp, Use: token.UseRegister, State: relayapi.TokenLive}}},
			[]any{"tokens", 0, "created"}, func(c *Client) error { _, err := c.AdminTokens(context.Background(), false); return err }, false},
		{"a token's last_redeemed", "/v1/admin/tokens", "last_redeemed",
			relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: tokenID, Issuer: fp, Use: token.UseRegister, State: relayapi.TokenLive}}},
			[]any{"tokens", 0, "last_redeemed"}, func(c *Client) error { _, err := c.AdminTokens(context.Background(), false); return err }, true},
		{"a registered token's created", "/v1/admin/tokens", "created",
			relayapi.TokenAnswer{Token: relayapi.TokenRecord{ID: tokenID, Issuer: fp, Use: token.UseRegister, State: relayapi.TokenLive}},
			[]any{"token", "created"}, func(c *Client) error { _, err := c.AdminAddToken(context.Background(), "tok"); return err }, false},
		{"a registered token's last_redeemed", "/v1/admin/tokens", "last_redeemed",
			relayapi.TokenAnswer{Token: relayapi.TokenRecord{ID: tokenID, Issuer: fp, Use: token.UseRegister, State: relayapi.TokenLive}},
			[]any{"token", "last_redeemed"}, func(c *Client) error { _, err := c.AdminAddToken(context.Background(), "tok"); return err }, true},
	}

	quote := func(s string) string { return `"` + s + `"` }
	at := func(d time.Duration) string { return quote(time.Now().Add(d).UTC().Format(time.RFC3339Nano)) }
	years := func(n int) string { return quote(time.Now().AddDate(n, 0, 0).UTC().Format(time.RFC3339Nano)) }

	for _, f := range fields {
		values := []struct {
			name, raw string
			taken     bool
		}{
			{"now", at(0), true},
			{"a second inside the skew", at(relayapi.MaxSkew - time.Second), true},
			{"a minute past the skew", at(relayapi.MaxSkew + time.Minute), false},
			{"a day ahead", at(24 * time.Hour), false},
			{"a year ahead", years(1), false},
			{"a year past", years(-1), true},
			{"the wire's earliest end, UTC year -1", quote("0000-01-01T00:00:00+23:59"), false},
			{"the earliest writable", quote(relayapi.EarliestWritable.Format(time.RFC3339Nano)), true},
			{"past the latest writable, year 9999 at -12:00", quote("9999-12-31T23:59:59-12:00"), false},
		}
		if f.mayBeEmpty {
			values = append(values, struct {
				name, raw string
				taken     bool
			}{"the zero time", quote(time.Time{}.Format(time.RFC3339Nano)), true})
		}
		for _, v := range values {
			t.Run(f.name+", "+v.name, func(t *testing.T) {
				srv := fakeRelay(t, map[string]any{f.path: tree(t, f.good, v.raw, f.keys...)})
				c, err := New(srv.URL, alice, nil)
				if err != nil {
					t.Fatal(err)
				}
				err = f.call(c)
				if v.taken {
					if err != nil {
						t.Fatalf("%s = %s: %v; want it taken", f.field, v.raw, err)
					}
					return
				}
				if !errors.Is(err, ErrMalformedAnswer) {
					t.Fatalf("%s = %s: %v; want ErrMalformedAnswer naming %s", f.field, v.raw, err, f.field)
				}
				if !strings.Contains(err.Error(), ", "+f.field+" is not a time no further ahead of this machine's clock than a request may be, and within the years 0000 to 9999") || !strings.Contains(err.Error(), srv.URL) {
					t.Fatalf("%q does not name %s, what it should be and the relay", err, f.field)
				}
			})
		}
	}
}
