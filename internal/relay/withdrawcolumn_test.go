package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

// withdrawColumn is a row's withdraw column, read through the store's own
// handle.
func (h *harness) withdrawColumn(fp string, id int64) string {
	h.t.Helper()
	var stored string
	if err := h.store.db.QueryRow(`SELECT withdraw FROM messages WHERE to_fp = ? AND id = ?`, fp, id).Scan(&stored); err != nil {
		h.t.Fatal(err)
	}
	return stored
}

// The column of a message posted here is the stored form of the key its
// sender computes from what it sealed: withdraw.EnvelopeKey over the
// envelope's recipient and ciphertext, whatever the channel on the outer
// field and however the JSON around them is spaced. A post repeated is
// answered from the carried table and writes nothing. Under both access-
// log modes no line the relay wrote carries the key or its stored form.
func TestAPostedMessageKeepsItsWithdrawalKey(t *testing.T) {
	for _, mode := range []string{AccessLogFull, AccessLogMinimal} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, Config{AccessLog: mode})
			alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
			h.enroll(alice, bob)
			body := sealedTo(t, alice, bob.Public(), "to withdraw", "")
			var env relayapi.Carried
			if err := json.Unmarshal(body, &env); err != nil {
				t.Fatal(err)
			}
			key := withdraw.EnvelopeKey(env.To, env.CT)

			// Spaced as no client writes it: the bytes are the hop's, the
			// key is the seal's.
			spaced := bytes.ReplaceAll(body, []byte(`,"`), []byte(`, "`))
			status, id := h.postOnce(alice, bob, spaced)
			if status != http.StatusOK || id == 0 {
				t.Fatalf("the post: %d, id %d", status, id)
			}
			if got := h.withdrawColumn(bob.Fingerprint(), id); got != withdraw.Stored(key) {
				t.Fatalf("the column is %q, want the stored form of the sender's key, %q", got, withdraw.Stored(key))
			}
			if status, again := h.postOnce(alice, bob, spaced); status != http.StatusOK || again != id {
				t.Fatalf("the same post again: %d, id %d; want 200 and %d", status, again, id)
			}
			if rows, _ := h.held(bob.Fingerprint()); rows != 1 {
				t.Fatalf("bob holds %d rows after the repeat, want one", rows)
			}
			for _, secret := range []string{key, withdraw.Stored(key)} {
				if strings.Contains(h.logs.String(), secret) {
					t.Fatalf("a log line carries %s:\n%s", secret, h.logs.String())
				}
			}
		})
	}
}

// A stream's column is the stored form of the stream key over the first
// withdraw.StreamPrefix bytes of what was uploaded, which is what the
// sender's sealed file begins with; one short of the prefix and one past
// it both take their whole bytes or the prefix as StreamKey says.
func TestAPlacedStreamKeepsItsWithdrawalKey(t *testing.T) {
	for _, payload := range []int{withdraw.StreamPrefix - 201, 3000 + withdraw.StreamPrefix} {
		h := newHarness(t, Config{})
		people := ids(t, "alice", "bob")
		alice, bob := people[0], people[1]
		h.register(alice)
		h.register(bob)

		blob := fakeStream(200, payload)
		status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		status, body, _ = h.putStream(alice, opened.Upload, blob, 0)
		if status != http.StatusCreated {
			t.Fatalf("put: %d %s", status, body)
		}
		var done relayapi.PutStreamResponse
		if err := json.Unmarshal(body, &done); err != nil {
			t.Fatal(err)
		}
		key, err := withdraw.StreamKey(bob.Fingerprint(), bytes.NewReader(blob), int64(len(blob)))
		if err != nil {
			t.Fatal(err)
		}
		if got := h.withdrawColumn(bob.Fingerprint(), done.ID); got != withdraw.Stored(key) {
			t.Fatalf("a stream of %d bytes: the column is %q, want %q", len(blob), got, withdraw.Stored(key))
		}
		if strings.Contains(h.logs.String(), key) || strings.Contains(h.logs.String(), withdraw.Stored(key)) {
			t.Fatal("a log line carries the stream's key")
		}
	}
}

// A knock and a courier's delivery keep no key: neither is withdrawable in
// this version, the knock because it is a stranger's one message and the
// delivery because every relay it crossed holds its ciphertext.
func TestAKnockAndADeliveryKeepNoWithdrawalKey(t *testing.T) {
	t.Run("knock", func(t *testing.T) {
		h := newHarness(t, Config{})
		people := ids(t, "alice", "bob")
		alice, bob := people[0], people[1]
		h.register(alice)
		h.register(bob)
		if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
			t.Fatalf("card push: %d %s", status, body)
		}
		if status, body, _ := h.knock(alice, bob, "hello"); status != http.StatusOK {
			t.Fatalf("knock: %d %s", status, body)
		}
		_, id, _ := h.knockerOf(bob.Fingerprint())
		if got := h.withdrawColumn(bob.Fingerprint(), id); got != "" {
			t.Fatalf("a knock's column is %q, want empty", got)
		}
	})
	t.Run("delivery", func(t *testing.T) {
		courier := neighbourID(t, "alpha")
		h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
		h.enroll(courier)
		to := h.user(t, "bob").Fingerprint()
		status, answer, body := h.forward(courier, request(sealedFor(to, "delivered here"), nil, []string{"one"}))
		if status != http.StatusCreated {
			t.Fatalf("the delivery: %d %s", status, body)
		}
		if got := h.withdrawColumn(to, answer.ID); got != "" {
			t.Fatalf("a delivery's column is %q, want empty", got)
		}
	})
}

// Put keeps a stored key on an envelope posted here and on nothing else:
// a knock, a row with a via and a key that is not a key's shape are each
// refused as the programming faults they are, and nothing is stored.
func TestPutKeepsAWithdrawalKeyOnAPostedEnvelopeAlone(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	fp := bob.Fingerprint()
	raw := sealed(t, alice, bob.Public(), "x")
	good := withdraw.Stored(withdraw.EnvelopeKey(fp, []byte("ct")))
	for name, c := range map[string]struct {
		kind, knocker, stored string
		f                     Forwarded
	}{
		"a knock":          {relayapi.KindKnock, alice.Fingerprint(), good, Forwarded{}},
		"a delivery":       {relayapi.KindEnvelope, "", good, Forwarded{Via: "bar"}},
		"uppercase":        {relayapi.KindEnvelope, "", strings.ToUpper(good), Forwarded{}},
		"one short":        {relayapi.KindEnvelope, "", good[:63], Forwarded{}},
		"not hex":          {relayapi.KindEnvelope, "", "z" + good[1:], Forwarded{}},
		"a stream's kind":  {relayapi.KindStream, "", good, Forwarded{}},
		"a report's words": {"report", "", good, Forwarded{}},
	} {
		if _, err := h.store.Put(fp, "default", c.kind, c.knocker, c.stored, raw, Quotas{}, c.f); err == nil {
			t.Errorf("%s with a stored key was stored", name)
		}
	}
	if rows, _ := h.held(fp); rows != 0 {
		t.Fatalf("bob holds %d rows after the refusals, want none", rows)
	}
	id, err := h.store.Put(fp, "default", relayapi.KindEnvelope, "", good, raw, Quotas{}, Forwarded{})
	if err != nil {
		t.Fatal(err)
	}
	if got := h.withdrawColumn(fp, id); got != good {
		t.Fatalf("the column is %q, want %q", got, good)
	}
}

// The relay's two hashes over one envelope are two values: the carried
// hash a relay keeps for every message is never the key, nor its stored
// form.
func TestTheCarriedHashIsNotTheWithdrawalKey(t *testing.T) {
	env := &relayapi.Carried{V: 1, To: strings.Repeat("ab", 32), CT: []byte("the same sealed bytes")}
	k := withdraw.EnvelopeKey(env.To, env.CT)
	if h := CarriedHash(env); h == k || h == withdraw.Stored(k) {
		t.Fatal("the carried hash is the withdrawal key or its stored form")
	}
}
