package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestAnAnswerWithoutARequiredFieldIsRefusedByName: nothing on the wire is
// from before. Every field the relay always sends is required here, and an
// answer that leaves one out — the field absent from the JSON, not zero
// or empty — is refused as malformed, naming the field and the relay, with
// nothing of the answer used. The listing's queued, allow, and each
// row's kind and channel; a stubs listing carrying an envelope; the
// status answer's registration and client_certs; the lookup's created.
// Each answer is first given whole and taken, so the refusal is the
// absence and nothing else.
func TestAnAnswerWithoutARequiredFieldIsRefusedByName(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	fp := alice.Fingerprint()
	bundle := alice.Public().Bundle()
	row := func(over map[string]any) map[string]any {
		m := map[string]any{"id": 1, "received": "2026-09-20T01:19:29Z", "kind": "envelope", "size": 3,
			"channel": "default", "envelope": map[string]any{"v": 1, "to": "x", "ct": "AAA"}}
		for k, v := range over {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	listing := func(over map[string]any, rows ...map[string]any) map[string]any {
		span := 0
		if len(rows) > 0 {
			span = 1
		}
		m := map[string]any{"messages": rows, "queued": len(rows), "first": span, "last": span,
			"allow": "none", "card": "none", "directory": "none"}
		for k, v := range over {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	status := map[string]any{"ok": true, "registration": "open", "client_certs": "off",
		"limits": map[string]any{}, "max_bytes": relayapi.DefaultMaxBytes, "token_max_age_seconds": 3600}
	without := func(m map[string]any, field string) map[string]any {
		out := map[string]any{}
		for k, v := range m {
			if k != field {
				out[k] = v
			}
		}
		return out
	}
	keys := map[string]any{"bundle": bundle, "name": "alice", "created": "2026-09-20T01:19:29Z"}
	health := map[string]any{"ok": true, "max_bytes": relayapi.DefaultMaxBytes, "knock_max_bytes": relayapi.DefaultMaxBytes, "registration": "open"}
	cardAnswer := map[string]any{"document": nil, "signature": nil, "state": "none"}
	over := func(m map[string]any, field string, v any) map[string]any {
		out := map[string]any{}
		for k, val := range m {
			out[k] = val
		}
		out[field] = v
		return out
	}

	list := func(c *Client) error { _, err := c.List(context.Background(), 0, 10); return err }
	stubs := func(c *Client) error {
		_, err := c.ListWait(context.Background(), ListRequest{Limit: 10, Stubs: true})
		return err
	}
	adminStatus := func(c *Client) error { _, err := c.AdminStatus(context.Background()); return err }
	lookup := func(c *Client) error { _, err := c.Lookup(context.Background(), fp); return err }
	healthCall := func(c *Client) error { return c.Health(context.Background()) }
	cardCall := func(c *Client) error { _, err := c.Card(context.Background()); return err }

	for _, tc := range []struct {
		name, path, field, want string
		answer                  any
		call                    func(*Client) error
		whole                   any
	}{
		{"a listing without queued", "/v1/mailbox/" + fp, "queued", "", listing(map[string]any{"queued": nil}, row(nil)), list, listing(nil, row(nil))},
		{"a listing without first", "/v1/mailbox/" + fp, "first", "the lowest message id held, from 0 to last, and 0 only with last 0", listing(map[string]any{"first": nil}, row(nil)), list, listing(nil, row(nil))},
		{"a listing without last", "/v1/mailbox/" + fp, "last", "the lowest message id held, from 0 to last, and 0 only with last 0", listing(map[string]any{"last": nil}, row(nil)), list, listing(nil, row(nil))},
		{"a listing whose first is after its last", "/v1/mailbox/" + fp, "first", "the lowest message id held, from 0 to last, and 0 only with last 0", listing(map[string]any{"first": 2, "last": 1}, row(nil)), list, listing(nil, row(nil))},
		{"a listing with a last and no first", "/v1/mailbox/" + fp, "first", "the lowest message id held, from 0 to last, and 0 only with last 0", listing(map[string]any{"first": 0, "last": 5}, row(nil)), list, listing(nil, row(nil))},
		{"a listing with a first and no last", "/v1/mailbox/" + fp, "first", "the lowest message id held, from 0 to last, and 0 only with last 0", listing(map[string]any{"first": 3, "last": 0}, row(nil)), list, listing(nil, row(nil))},
		{"a listing with a negative first", "/v1/mailbox/" + fp, "first", "the lowest message id held, from 0 to last, and 0 only with last 0", listing(map[string]any{"first": -1, "last": -1}, row(nil)), list, listing(nil, row(nil))},
		{"a listing without allow", "/v1/mailbox/" + fp, "allow", "one of signed, none, broken", listing(map[string]any{"allow": nil}, row(nil)), list, listing(nil, row(nil))},
		{"a listing without card", "/v1/mailbox/" + fp, "card", "one of signed, none, broken", listing(map[string]any{"card": nil}, row(nil)), list, listing(nil, row(nil))},
		{"a listing with another card word", "/v1/mailbox/" + fp, "card", "one of signed, none, broken", listing(map[string]any{"card": "lost"}, row(nil)), list, listing(nil, row(nil))},
		{"a listing without directory", "/v1/mailbox/" + fp, "directory", "one of signed, none, broken", listing(map[string]any{"directory": nil}, row(nil)), list, listing(nil, row(nil))},
		{"a listing with another directory word", "/v1/mailbox/" + fp, "directory", "one of signed, none, broken", listing(map[string]any{"directory": "lost"}, row(nil)), list, listing(nil, row(nil))},
		{"a health answer without registration", "/v1/health", "registration", "one of open, token, closed", without(health, "registration"), healthCall, health},
		{"a health answer without knock_max_bytes", "/v1/health", "knock_max_bytes", "the relay's knock cap (from 1 to 1073741824; a health answer without it is refused)", without(health, "knock_max_bytes"), healthCall, health},
		{"a health answer with a fourth word", "/v1/health", "registration", "one of open, token, closed", over(health, "registration", "invite"), healthCall, health},
		{"a card answer without state", "/v1/mailbox/" + fp + "/card", "state", "one of signed, none, broken", without(cardAnswer, "state"), cardCall, cardAnswer},
		{"a card answer with another word", "/v1/mailbox/" + fp + "/card", "state", "one of signed, none, broken", over(cardAnswer, "state", "lost"), cardCall, cardAnswer},
		{"a row without kind", "/v1/mailbox/" + fp, "kind", "a message kind (envelope, stream or knock)", listing(nil, row(map[string]any{"kind": nil})), list, listing(nil, row(nil))},
		// The whole here is a row of the third kind, a knock, taken as an
		// envelope's row is; the fourth word is refused.
		{"a row with another kind", "/v1/mailbox/" + fp, "kind", "a message kind (envelope, stream or knock)", listing(nil, row(map[string]any{"kind": "letter"})), list, listing(nil, row(map[string]any{"kind": "knock"}))},
		{"a row without channel", "/v1/mailbox/" + fp, "channel", "a channel name", listing(nil, row(map[string]any{"channel": nil})), list, listing(nil, row(nil))},
		{"a row whose channel is not a name", "/v1/mailbox/" + fp, "channel", "a channel name", listing(nil, row(map[string]any{"channel": "bad\x1bname"})), list, listing(nil, row(nil))},
		{"a stubs listing with an envelope", "/v1/mailbox/" + fp, "envelope", "absent: a stubs listing carries no envelope", listing(nil, row(nil)), stubs, listing(nil, row(map[string]any{"envelope": nil}))},
		{"a status without registration", "/v1/admin/status", "registration", "one of open, token, closed", without(status, "registration"), adminStatus, status},
		{"a status without client_certs", "/v1/admin/status", "client_certs", "one of off, required", without(status, "client_certs"), adminStatus, status},
		{"a lookup without created", "/v1/keys/" + fp, "created", "a time", without(keys, "created"), lookup, keys},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeRelay(t, map[string]any{tc.path: tc.whole})
			c, err := New(srv.URL, alice, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.call(c); err != nil {
				t.Fatalf("the whole answer: %v; want it taken", err)
			}
			srv = fakeRelay(t, map[string]any{tc.path: tc.answer})
			if c, err = New(srv.URL, alice, nil); err != nil {
				t.Fatal(err)
			}
			err = tc.call(c)
			if tc.field == "queued" {
				// Zero is the count of an empty mailbox, and an absent
				// count decodes as zero: a listing without queued is
				// taken as one saying zero, which the relay does say.
				if err != nil {
					t.Fatalf("a listing without queued: %v; want it read as zero, a count the relay sends", err)
				}
				return
			}
			if !errors.Is(err, ErrMalformedAnswer) {
				t.Fatalf("%v; want ErrMalformedAnswer naming %s", err, tc.field)
			}
			if !strings.Contains(err.Error(), ", "+tc.field+" is not "+tc.want) || !strings.Contains(err.Error(), srv.URL) {
				t.Fatalf("%q does not name the field, what it should be and the relay", err)
			}
		})
	}
}
