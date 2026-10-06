package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// sealedKnock is a knock from one identity to another, sealed as the
// client seals one, under the default channel unless ch is given.
func sealedKnock(t *testing.T, from *identity.Identity, to *identity.Public, ch, text string) []byte {
	t.Helper()
	env, _, err := envelope.SealFor(from, to, ch, message.Body{
		Type: message.TypeKnock, Thread: "0123456789abcdef0123456789abcdef", Name: from.Name, Text: text,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The outer field is the client's to set at the post, as it does.
	env.Ch = ch
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// knock posts a knock from one identity to another's mailbox and returns
// the status, the body and the header.
func (h *harness) knock(from *identity.Identity, to *identity.Identity, text string) (int, []byte, http.Header) {
	h.t.Helper()
	return h.send(from, "POST", "/v1/mailbox/"+to.Fingerprint()+"/knock", sealedKnock(h.t, from, to.Public(), "", text), nil)
}

// knockRows is the mailbox's rows of kind knock, from the database.
func (h *harness) knockRows(fp string) int64 {
	h.t.Helper()
	var n int64
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE to_fp = ? AND kind = ?`, fp, relayapi.KindKnock).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// The card is what lets a knock past the allow list, and the relay reads
// the document and never the column: a mailbox with no card, with a card
// that says no, and with a card that no longer verifies each refuse a
// knock 403 with the one sentence, storing nothing; the knocks column
// set by hand on a card that says no changes nothing, since the relay
// verifies the document at every knock; and a card that says knocks
// takes one from a stranger the allow list would refuse, filed under the
// default channel and listed back to the owner as a knock with the
// envelope inline. The line for a broken card names the mailbox alone,
// once a minute, under both access log modes.
func TestAKnockNeedsACardThatSaysKnocks(t *testing.T) {
	for _, mode := range []string{AccessLogFull, AccessLogMinimal} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, Config{AccessLog: mode})
			people := ids(t, "alice", "bob", "carol")
			alice, bob, carol := people[0], people[1], people[2]
			for _, id := range people {
				h.register(id)
			}
			fp := bob.Fingerprint()
			// Bob admits carol alone, so alice is a stranger to the post
			// route throughout.
			if status, body, _ := h.pushAllow(bob, bob, time.Now(), carol.Fingerprint()); status != http.StatusNoContent {
				t.Fatalf("allow push: %d %s", status, body)
			}
			refused := func(what string) {
				t.Helper()
				before := h.messageCount(fp)
				status, body, hdr := h.knock(alice, bob, "hello")
				if status != http.StatusForbidden || errorText(t, body) != relayapi.MsgNoKnocks {
					t.Fatalf("%s: %d %s; want 403 %q", what, status, body, relayapi.MsgNoKnocks)
				}
				if hdr.Get("Retry-After") != "" {
					t.Fatalf("%s: a 403 with Retry-After", what)
				}
				if h.messageCount(fp) != before || h.knockRows(fp) != 0 {
					t.Fatalf("%s: the refused knock was stored", what)
				}
				h.assertCountersAgree()
			}
			refused("no card")
			if status, _ := h.do(alice, "POST", "/v1/mailbox/"+fp, sealed(t, alice, bob.Public(), "x"), nil); status != http.StatusForbidden {
				t.Fatalf("alice is not a stranger to the post route: %d", status)
			}

			// A card that says no.
			if status, body, _ := h.pushCard(bob, bob, time.Now(), true, false); status != http.StatusNoContent {
				t.Fatalf("card push: %d %s", status, body)
			}
			refused("a card that says no")
			// The column set by hand on that card: the document still says
			// no, and the relay reads the document.
			if _, err := h.store.db.Exec(`UPDATE cards SET knocks = 1 WHERE fp = ?`, fp); err != nil {
				t.Fatal(err)
			}
			refused("the knocks column set on a card that says no")
			if got := h.cardListState(bob); got != relayapi.CardSigned {
				t.Fatalf("the card after the column edit: %q, want signed", got)
			}

			// A card that says knocks: the stranger's knock is taken.
			if status, body, _ := h.pushCard(bob, bob, time.Now().Add(time.Second), false, true); status != http.StatusNoContent {
				t.Fatalf("card push: %d %s", status, body)
			}
			status, body, _ := h.knock(alice, bob, "alice would like to exchange keys")
			if status != http.StatusOK {
				t.Fatalf("a knock to a card that says knocks: %d %s", status, body)
			}
			var posted relayapi.PostResponse
			if err := json.Unmarshal(body, &posted); err != nil || posted.ID <= 0 {
				t.Fatalf("the knock's answer: %s", body)
			}
			if h.knockRows(fp) != 1 || h.messageCount(fp) != 1 {
				t.Fatalf("the knock is not one row of kind knock: %d knock rows, %d rows", h.knockRows(fp), h.messageCount(fp))
			}
			h.assertCountersAgree()
			// Listed back to the owner as a knock, under default, with the
			// envelope inline as an envelope's is.
			status, body = h.do(bob, "GET", "/v1/mailbox/"+fp, nil, nil)
			var list relayapi.ListResponse
			if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Messages) != 1 {
				t.Fatalf("the owner's listing: %d %s", status, body)
			}
			row := list.Messages[0]
			if row.Kind != relayapi.KindKnock || row.Channel != "default" || len(row.Envelope) == 0 || row.ID != posted.ID {
				t.Fatalf("the listed knock: kind %q channel %q envelope %d bytes id %d", row.Kind, row.Channel, len(row.Envelope), row.ID)
			}
			// The card says knocks and alice is still a stranger to the
			// post route: the knock route is the only door.
			if status, _ := h.do(alice, "POST", "/v1/mailbox/"+fp, sealed(t, alice, bob.Public(), "x"), nil); status != http.StatusForbidden {
				t.Fatalf("a card that says knocks opened the post route: %d", status)
			}
			// A sender the owner admits knocks the same way; the relay does
			// not care.
			if status, body, _ := h.knock(carol, bob, "hi"); status != http.StatusOK {
				t.Fatalf("an admitted sender's knock: %d %s", status, body)
			}

			// A card that no longer verifies: a bit of the signature flipped
			// in the database. The knock is refused with the same sentence,
			// and the log says so once a minute, naming the mailbox alone.
			var sig []byte
			if err := h.store.db.QueryRow(`SELECT sig FROM cards WHERE fp = ?`, fp).Scan(&sig); err != nil {
				t.Fatal(err)
			}
			sig[0] ^= 1
			if _, err := h.store.db.Exec(`UPDATE cards SET sig = ? WHERE fp = ?`, sig, fp); err != nil {
				t.Fatal(err)
			}
			line := fmt.Sprintf("card for %s does not verify; refusing knocks to it until the owner pushes again", fp)
			logged := func() int { return strings.Count(h.logs.String(), line) }
			before := logged()
			rowsBefore := h.messageCount(fp)
			for range 2 {
				status, body, _ := h.knock(alice, bob, "hello")
				if status != http.StatusForbidden || errorText(t, body) != relayapi.MsgNoKnocks {
					t.Fatalf("a knock under a broken card: %d %s", status, body)
				}
			}
			if h.messageCount(fp) != rowsBefore {
				t.Fatal("a knock under a broken card was stored")
			}
			if got := logged() - before; got != 1 {
				t.Fatalf("%d log lines for two refusals inside a minute, want 1", got)
			}
			h.clock.advance(2 * time.Minute)
			h.knock(alice, bob, "hello")
			if got := logged() - before; got != 2 {
				t.Fatalf("%d log lines after a minute, want 2", got)
			}
			// The line names the mailbox and never the knocker.
			for _, l := range strings.Split(h.logs.String(), "\n") {
				if strings.Contains(l, "card for ") && strings.Contains(l, alice.Fingerprint()[:16]) {
					t.Fatalf("the fault line names the knocker:\n%s", l)
				}
			}
			// Keyed apart from the allow list's line: the two broken at
			// once are two lines inside one minute, not one.
			if _, err := h.store.db.Exec(`UPDATE allowlists SET sig = X'' WHERE fp = ?`, fp); err != nil {
				t.Fatal(err)
			}
			h.clock.advance(2 * time.Minute)
			allowLine := fmt.Sprintf("allow list for %s does not verify", fp)
			allowBefore := strings.Count(h.logs.String(), allowLine)
			cardBefore := logged()
			if status, _ := h.do(alice, "POST", "/v1/mailbox/"+fp, sealed(t, alice, bob.Public(), "x"), nil); status != http.StatusForbidden {
				t.Fatalf("a post under a broken allow list: %d", status)
			}
			h.knock(alice, bob, "hello")
			if strings.Count(h.logs.String(), allowLine)-allowBefore != 1 || logged()-cardBefore != 1 {
				t.Fatalf("the allow list's line and the card's inside one minute: %d and %d, want one each",
					strings.Count(h.logs.String(), allowLine)-allowBefore, logged()-cardBefore)
			}
			if got := h.cardListState(bob); got != relayapi.CardBroken {
				t.Fatalf("the owner's listing says %q, want broken", got)
			}
			// The repair: a fresh push, and the knock goes through again.
			if status, body, _ := h.pushCard(bob, bob, time.Now().Add(2*time.Second), false, true); status != http.StatusNoContent {
				t.Fatalf("the repairing push: %d %s", status, body)
			}
			if status, body, _ := h.knock(alice, bob, "hello again"); status != http.StatusOK {
				t.Fatalf("a knock after the repair: %d %s", status, body)
			}
		})
	}
}

// What is judged before the card, each refused with nothing stored: a
// knock that names a channel, one not addressed to the mailbox, one that
// is not an envelope, one to a mailbox that is not there, one to a
// blocked recipient, and one from a blocked knocker, which the wrapper
// refuses before the handler with the knock bucket untouched.
func TestAKnockIsJudgedBeforeTheCard(t *testing.T) {
	people := ids(t, "alice", "bob", "boss")
	alice, bob, boss := people[0], people[1], people[2]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss), Limits: Limits{KnocksPerHour: 1}})
	h.register(alice)
	h.register(bob)
	h.enroll(boss)
	fp := bob.Fingerprint()
	if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("card push: %d %s", status, body)
	}
	refused := func(what string, status int, body []byte, wantStatus int, want string) {
		t.Helper()
		if status != wantStatus || errorText(t, body) != want {
			t.Fatalf("%s: %d %s; want %d %q", what, status, body, wantStatus, want)
		}
		if h.messageCount(fp) != 0 {
			t.Fatalf("%s: stored", what)
		}
	}
	status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+fp+"/knock", sealedKnock(t, alice, bob.Public(), "bug reports", "hi"), nil)
	refused("a knock naming a channel", status, body, http.StatusBadRequest, "a knock names no channel")
	status, body, _ = h.send(alice, "POST", "/v1/mailbox/"+fp+"/knock", sealedKnock(t, alice, boss.Public(), "", "hi"), nil)
	refused("a knock addressed elsewhere", status, body, http.StatusBadRequest, "envelope is not addressed to this mailbox")
	status, body, _ = h.send(alice, "POST", "/v1/mailbox/"+fp+"/knock", []byte("{not json"), nil)
	refused("a body that is not an envelope", status, body, http.StatusBadRequest,
		"malformed envelope: invalid character 'n' looking for beginning of object key string")
	nobody := ids(t, "nobody")[0]
	status, body, _ = h.send(alice, "POST", "/v1/mailbox/"+nobody.Fingerprint()+"/knock", sealedKnock(t, alice, nobody.Public(), "", "hi"), nil)
	refused("a knock to no mailbox", status, body, http.StatusNotFound, "no such mailbox")
	// The recipient blocked.
	if status, body, _ := h.send(boss, "PUT", "/v1/admin/blocks/"+fp, relayapi.BlockRequest{Reason: "testing"}, nil); status != http.StatusNoContent {
		t.Fatalf("block: %d %s", status, body)
	}
	status, body, _ = h.knock(alice, bob, "hi")
	refused("a knock to a blocked recipient", status, body, http.StatusForbidden, "recipient is blocked on this relay")
	if status, body, _ := h.send(boss, "DELETE", "/v1/admin/blocks/"+fp, nil, nil); status != http.StatusNoContent {
		t.Fatalf("unblock: %d %s", status, body)
	}
	// The knocker blocked: the wrapper's refusal, and the one knock the
	// hour allows is still there after the unblock, so the bucket was not
	// charged for the refused request.
	if status, body, _ := h.send(boss, "PUT", "/v1/admin/blocks/"+alice.Fingerprint(), relayapi.BlockRequest{Reason: "testing"}, nil); status != http.StatusNoContent {
		t.Fatalf("block: %d %s", status, body)
	}
	status, body, _ = h.knock(alice, bob, "hi")
	refused("a knock from a blocked knocker", status, body, http.StatusForbidden, msgBlocked)
	if status, body, _ := h.send(boss, "DELETE", "/v1/admin/blocks/"+alice.Fingerprint(), nil, nil); status != http.StatusNoContent {
		t.Fatalf("unblock: %d %s", status, body)
	}
	if status, body, _ := h.knock(alice, bob, "hi"); status != http.StatusOK {
		t.Fatalf("the knock after the unblock: %d %s; the bucket was charged for the refused one", status, body)
	}
	if status, body, hdr := h.knock(alice, bob, "hi"); status != http.StatusTooManyRequests || hdr.Get("Retry-After") == "" {
		t.Fatalf("the second knock of the hour: %d %s", status, body)
	}
}

// The three settings. max_knocks_waiting: at 2, two knocks are taken and
// the third refused 429 with the sentence naming the setting and no
// Retry-After, the sender's knock token given back so the refusal costs
// the sender nothing, and one acknowledged makes room. The cap counts
// knockers, not knocks: a knocker already waiting is never refused by
// it, since their second knock replaces their first. knocks_per_hour:
// at 1 the second knock is refused 429 with Retry-After, and two senders
// do not share a bucket. Zero is unlimited for both counts. The two 429s
// name their limits in the log.
func TestLimitKnocksWaitingAndKnocksPerHour(t *testing.T) {
	t.Run("max_knocks_waiting", func(t *testing.T) {
		h := newHarness(t, Config{Limits: Limits{MaxKnocksWaiting: 2, KnocksPerHour: 3}})
		people := ids(t, "alice", "bob", "carol", "dave")
		alice, bob, carol, dave := people[0], people[1], people[2], people[3]
		for _, id := range people {
			h.register(id)
		}
		fp := bob.Fingerprint()
		if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
			t.Fatalf("card push: %d %s", status, body)
		}
		// Two knockers fill the two places.
		var first int64
		for i, who := range []*identity.Identity{alice, carol} {
			status, body, _ := h.knock(who, bob, "hi")
			if status != http.StatusOK {
				t.Fatalf("knock %d: %d %s", i+1, status, body)
			}
			if i == 0 {
				var posted relayapi.PostResponse
				json.Unmarshal(body, &posted)
				first = posted.ID
			}
		}
		// A third knocker, twice, at the cap: with three tokens an hour
		// and one spent, the first refusal gives its token back, so the
		// second meets the same refusal and not the bucket's.
		for i := range 2 {
			status, body, hdr := h.knock(dave, bob, "hi")
			if status != http.StatusTooManyRequests || errorText(t, body) != relayapi.MsgKnocksWaiting {
				t.Fatalf("knock %d at the cap: %d %s; want 429 %q", i+3, status, body, relayapi.MsgKnocksWaiting)
			}
			if hdr.Get("Retry-After") != "" {
				t.Fatalf("knock %d at the cap carries Retry-After %q; the relay cannot say when the owner fetches", i+3, hdr.Get("Retry-After"))
			}
		}
		// But a knocker already waiting is not refused at the cap: their
		// second knock replaces their first, so the mailbox still holds
		// two rows and alice's is the new one.
		status, body, _ := h.knock(alice, bob, "hi again")
		if status != http.StatusOK {
			t.Fatalf("a waiting knocker's second knock at the cap: %d %s", status, body)
		}
		var again relayapi.PostResponse
		json.Unmarshal(body, &again)
		if again.ID == first {
			t.Fatal("the replacing knock kept the replaced row's id")
		}
		if h.knockRows(fp) != 2 {
			t.Fatalf("%d knock rows, want 2", h.knockRows(fp))
		}
		h.assertCountersAgree()
		if !strings.Contains(h.logs.String(), "limit=knocks_waiting") {
			t.Fatalf("the log does not name the limit:\n%s", h.logs.String())
		}
		// One acknowledged makes room, and the token given back is the
		// one that pays for it: alice's row goes, and she knocks again
		// into the place it left.
		if status, body := h.do(bob, "DELETE", fmt.Sprintf("/v1/mailbox/%s/%d", fp, again.ID), nil, nil); status != http.StatusNoContent {
			t.Fatalf("ack: %d %s", status, body)
		}
		if status, body, _ := h.knock(alice, bob, "hi"); status != http.StatusOK {
			t.Fatalf("the knock after an ack: %d %s", status, body)
		}
		// Alice's hour is spent now — three knocks taken, the refusals
		// having given their tokens back — so her fourth meets the
		// bucket rather than the cap she is inside, with Retry-After,
		// named apart in the log.
		status, body, hdr := h.knock(alice, bob, "hi")
		if status != http.StatusTooManyRequests || errorText(t, body) != "rate limited: knocks" {
			t.Fatalf("the fourth knock of the hour: %d %s", status, body)
		}
		h.retryAfter(hdr)
		if !strings.Contains(h.logs.String(), "limit=knocks ") && !strings.Contains(h.logs.String(), "limit=knocks\n") {
			t.Fatalf("the log does not name the knock budget:\n%s", h.logs.String())
		}
	})
	t.Run("knocks_per_hour", func(t *testing.T) {
		h := newHarness(t, Config{Limits: Limits{KnocksPerHour: 1}})
		people := ids(t, "alice", "bob", "carol")
		alice, bob, carol := people[0], people[1], people[2]
		for _, id := range people {
			h.register(id)
		}
		for _, id := range []*identity.Identity{bob, carol} {
			if status, body, _ := h.pushCard(id, id, time.Now(), false, true); status != http.StatusNoContent {
				t.Fatalf("card push: %d %s", status, body)
			}
		}
		if status, body, _ := h.knock(alice, bob, "hi"); status != http.StatusOK {
			t.Fatalf("the first knock: %d %s", status, body)
		}
		// Across every mailbox: the second, to another mailbox, is the
		// second of the hour.
		status, body, hdr := h.knock(alice, carol, "hi")
		if status != http.StatusTooManyRequests || errorText(t, body) != "rate limited: knocks" {
			t.Fatalf("the second knock of the hour: %d %s", status, body)
		}
		if secs := h.retryAfter(hdr); secs != 3600 {
			t.Fatalf("Retry-After %d, want the hour", secs)
		}
		if h.knockRows(carol.Fingerprint()) != 0 {
			t.Fatal("the refused knock was stored")
		}
		// Two senders do not share a bucket.
		if status, body, _ := h.knock(carol, bob, "hi"); status != http.StatusOK {
			t.Fatalf("another sender's first knock: %d %s", status, body)
		}
		h.clock.advance(time.Hour)
		if status, body, _ := h.knock(alice, carol, "hi"); status != http.StatusOK {
			t.Fatalf("the knock after the hour: %d %s", status, body)
		}
	})
	t.Run("zero is unlimited", func(t *testing.T) {
		h := newHarness(t, Config{Limits: Limits{MaxKnocksWaiting: 0, KnocksPerHour: 0}})
		bob := ids(t, "bob")[0]
		h.register(bob)
		if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
			t.Fatalf("card push: %d %s", status, body)
		}
		// Twenty-five knockers, since a mailbox holds one row per
		// knocker however many times each knocks: with no cap at all,
		// every one of them is taken.
		for i := range 25 {
			who := ids(t, fmt.Sprintf("knocker%d", i))[0]
			h.register(who)
			if status, body, _ := h.knock(who, bob, "hi"); status != http.StatusOK {
				t.Fatalf("knock %d under no limits: %d %s", i+1, status, body)
			}
		}
		if h.knockRows(bob.Fingerprint()) != 25 {
			t.Fatalf("%d knock rows, want 25", h.knockRows(bob.Fingerprint()))
		}
		h.assertCountersAgree()
	})
}

// A knock is a post for the post budgets: posts_per_minute and
// post_bytes_per_hour are charged before anything else, and a knock
// refused by Put — the mailbox full — keeps the post token it spent,
// exactly as an envelope refused the same way does, which the post route
// is held to here beside it.
func TestAKnockIsAPostForTheBudgets(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	setUp := func(t *testing.T, cfg Config) *harness {
		t.Helper()
		h := newHarness(t, cfg)
		h.register(alice)
		h.register(bob)
		if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
			t.Fatalf("card push: %d %s", status, body)
		}
		return h
	}
	t.Run("posts_per_minute", func(t *testing.T) {
		h := setUp(t, Config{Limits: Limits{PostsPerMinute: 1}})
		if status, body, _ := h.knock(alice, bob, "hi"); status != http.StatusOK {
			t.Fatalf("the first knock: %d %s", status, body)
		}
		status, body, hdr := h.knock(alice, bob, "hi")
		if status != http.StatusTooManyRequests || errorText(t, body) != "rate limited: posts" {
			t.Fatalf("the second knock of the minute: %d %s", status, body)
		}
		h.retryAfter(hdr)
		if h.knockRows(bob.Fingerprint()) != 1 {
			t.Fatal("the refused knock was stored")
		}
	})
	t.Run("post_bytes_per_hour", func(t *testing.T) {
		h := setUp(t, Config{Limits: Limits{PostBytesPerHour: 100}})
		status, body, hdr := h.knock(alice, bob, "hi")
		if status != http.StatusTooManyRequests || !strings.HasPrefix(errorText(t, body), "rate limited: post bytes") {
			t.Fatalf("a knock over the byte budget: %d %s", status, body)
		}
		h.retryAfter(hdr)
		if h.knockRows(bob.Fingerprint()) != 0 {
			t.Fatal("the refused knock was stored")
		}
	})
	t.Run("a refused Put keeps the post token", func(t *testing.T) {
		for _, route := range []string{"knock", "post"} {
			t.Run(route, func(t *testing.T) {
				h := setUp(t, Config{Limits: Limits{MailboxMaxMessages: 1, PostsPerMinute: 2}})
				// A fresh knocker each time on the knock route: one
				// knocker's second knock replaces their first and would
				// never meet the full mailbox, which is the rule the
				// mailbox quota sits behind.
				knockers := ids(t, "kn1", "kn2", "kn3")
				for _, who := range knockers {
					h.register(who)
				}
				n := 0
				post := func() (int, []byte) {
					if route == "knock" {
						who := knockers[n]
						n++
						status, body, _ := h.knock(who, bob, "hi")
						return status, body
					}
					status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), sealed(t, alice, bob.Public(), "x"), nil)
					return status, body
				}
				if status, body := post(); status != http.StatusOK {
					t.Fatalf("the first: %d %s", status, body)
				}
				if status, body := post(); status != http.StatusInsufficientStorage || errorText(t, body) != relayapi.MsgMailboxFull {
					t.Fatalf("the second, the mailbox full: %d %s", status, body)
				}
				// The token the refused one spent is spent. On the post
				// route, where every post is alice's, the third meets the
				// minute's budget rather than the full mailbox; on the
				// knock route each knocker has a budget of their own, so
				// the proof is the recipient's counters, which a refused
				// Put must leave as they were.
				if route == "post" {
					if status, body := post(); status != http.StatusTooManyRequests || errorText(t, body) != "rate limited: posts" {
						t.Fatalf("the third, after a refused Put: %d %s; want the post budget", status, body)
					}
				}
				h.assertCountersAgree()
				if got := h.messageCount(bob.Fingerprint()); got != 1 {
					t.Fatalf("%d messages after a refused Put, want the one that was taken", got)
				}
			})
		}
	})
}

// TestLimitAKnockIsHeldToKnockMaxBytes: a knock envelope of exactly
// knock_max_bytes is taken and one byte over refused 413 naming the
// setting, with nothing stored; a body that declares itself over the
// route's cap, knock_max_bytes plus the framing allowance, is refused 413
// before a byte of it is read, naming the cap, from a raw connection that
// sends the headers and nothing more; and knock_max_bytes at zero makes
// the route's cap the post's, so a knock the post route would take is
// taken and one over max_bytes is refused as the post refuses it.
func TestLimitAKnockIsHeldToKnockMaxBytes(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	// The knock's size is known before the relay is built, so the cap can
	// be set to it exactly: the same text seals to the same size.
	probe := sealedKnock(t, alice, bob.Public(), "", "alice would like to exchange keys")
	cap := int64(len(probe))
	h := newHarness(t, Config{MaxBytes: 1 << 20, Limits: Limits{KnockMaxBytes: cap}})
	h.register(alice)
	h.register(bob)
	fp := bob.Fingerprint()
	if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("card push: %d %s", status, body)
	}
	if status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+fp+"/knock", probe, nil); status != http.StatusOK {
		t.Fatalf("a knock at the cap, %d bytes: %d %s", cap, status, body)
	}
	// One over: the same envelope with one byte of whitespace, which the
	// decoder would take and the cap refuses first.
	over := append(append([]byte{}, probe...), ' ')
	status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+fp+"/knock", over, nil)
	if status != http.StatusRequestEntityTooLarge || errorText(t, body) != fmt.Sprintf("knock too large: at most %d bytes (knock_max_bytes)", cap) {
		t.Fatalf("a knock one over the cap: %d %s", status, body)
	}
	if h.knockRows(fp) != 1 {
		t.Fatalf("%d knock rows, want the one at the cap", h.knockRows(fp))
	}
	// The route's cap, declared and never sent: 413 before a byte, the
	// connection closed behind it.
	routeCap := cap + relayapi.FramingAllowance
	status, body, hdr := h.rawRequest(alice, "POST", "/v1/mailbox/"+fp+"/knock", nil, routeCap+1, nil)
	if status != http.StatusRequestEntityTooLarge || errorText(t, body) != fmt.Sprintf("%s: at most %d bytes", relayapi.MsgBodyTooLarge, routeCap) {
		t.Fatalf("a body declared one over the route's cap: %d %s", status, body)
	}
	if hdr.Get("Connection") != "close" {
		t.Errorf("Connection is %q, want close: the unsent body is not waited for", hdr.Get("Connection"))
	}
	// A body at the route's cap that is a knock over knock_max_bytes: read
	// under the route's cap and refused by the handler's, so the two caps
	// are each held.
	padded := append(append([]byte{}, probe...), strings.Repeat(" ", int(relayapi.FramingAllowance))...)
	status, body, _ = h.send(alice, "POST", "/v1/mailbox/"+fp+"/knock", padded, nil)
	if status != http.StatusRequestEntityTooLarge || !strings.HasPrefix(errorText(t, body), "knock too large") {
		t.Fatalf("a knock padded to the route's cap: %d %s", status, body)
	}

	// Zero: the post's cap. A knock the post route would take at
	// max_bytes is taken, and one over max_bytes refused, by the handler
	// naming knock_max_bytes since that is the setting to turn.
	h2 := newHarness(t, Config{MaxBytes: cap, Limits: Limits{KnockMaxBytes: 0}})
	h2.register(alice)
	h2.register(bob)
	if status, body, _ := h2.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("card push: %d %s", status, body)
	}
	if status, body, _ := h2.send(alice, "POST", "/v1/mailbox/"+fp+"/knock", probe, nil); status != http.StatusOK {
		t.Fatalf("under knock_max_bytes 0, a knock at max_bytes: %d %s", status, body)
	}
	if status, body, _ := h2.send(alice, "POST", "/v1/mailbox/"+fp+"/knock", over, nil); status != http.StatusRequestEntityTooLarge || errorText(t, body) != fmt.Sprintf("knock too large: at most %d bytes (knock_max_bytes)", cap) {
		t.Fatalf("under knock_max_bytes 0, a knock one over max_bytes: %d %s", status, body)
	}
	status, body, _ = h2.rawRequest(alice, "POST", "/v1/mailbox/"+fp+"/knock", nil, cap+relayapi.FramingAllowance+1, nil)
	if status != http.StatusRequestEntityTooLarge || errorText(t, body) != fmt.Sprintf("%s: at most %d bytes", relayapi.MsgBodyTooLarge, cap+relayapi.FramingAllowance) {
		t.Fatalf("under knock_max_bytes 0, a body declared one over the post's cap: %d %s", status, body)
	}
}

// The administrator's status view carries the three knock limits as
// configured, beside the others.
func TestTheAdministratorSeesTheKnockLimits(t *testing.T) {
	boss := ids(t, "boss")[0]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss), Limits: Limits{KnockMaxBytes: 4096, MaxKnocksWaiting: 7, KnocksPerHour: 3}})
	status, body, _ := h.send(boss, "GET", "/v1/admin/status", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	var st relayapi.AdminStatusResponse
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.Limits.KnockMaxBytes != 4096 || st.Limits.MaxKnocksWaiting != 7 || st.Limits.KnocksPerHour != 3 {
		t.Fatalf("the limits view: %+v", st.Limits)
	}
	for _, key := range []string{`"knock_max_bytes":4096`, `"max_knocks_waiting":7`, `"knocks_per_hour":3`} {
		if !strings.Contains(string(body), key) {
			t.Errorf("the status answer lacks %s", key)
		}
	}
}

// knockID posts a knock and returns the relay id it was given.
func (h *harness) knockID(from, to *identity.Identity, text string) int64 {
	h.t.Helper()
	status, body, _ := h.send(from, "POST", "/v1/mailbox/"+to.Fingerprint()+"/knock",
		sealedKnock(h.t, from, to.Public(), "", text), nil)
	if status != http.StatusOK {
		h.t.Fatalf("knock: %d %s", status, body)
	}
	var posted relayapi.PostResponse
	if err := json.Unmarshal(body, &posted); err != nil {
		h.t.Fatal(err)
	}
	return posted.ID
}

// knockerOf is the knocker column of a mailbox's one knock row, and the
// row's id and size beside it.
func (h *harness) knockerOf(fp string) (knocker string, id, size int64) {
	h.t.Helper()
	if err := h.store.db.QueryRow(
		`SELECT knocker, id, size FROM messages WHERE to_fp = ? AND kind = ?`, fp, relayapi.KindKnock).
		Scan(&knocker, &id, &size); err != nil {
		h.t.Fatal(err)
	}
	return knocker, id, size
}

// A second knock from one key replaces the first: one row, the second's
// bytes, the first's file gone and its counters given back, and the new
// id where the old one was. So the waiting cap counts knockers rather
// than knocks, and a knocker who got their line wrong can send it again.
// The row carries the fingerprint the signature proved and no other, and
// every row that is not a knock carries none.
func TestAKnockReplacesTheKnockersEarlierKnock(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	for _, id := range people {
		h.register(id)
	}
	fp := bob.Fingerprint()
	if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("card push: %d %s", status, body)
	}
	first := h.knockID(alice, bob, "alice here, at the standup")
	knocker, id, size := h.knockerOf(fp)
	if knocker != alice.Fingerprint() || id != first {
		t.Fatalf("the knock row: knocker %q id %d, want alice's fingerprint and %d", knocker, id, first)
	}
	firstFile := h.store.messagePath(fp, first)
	if _, err := os.Stat(firstFile); err != nil {
		t.Fatalf("the first knock has no file: %v", err)
	}

	// The second, longer, so the sizes differ and the row's is the new
	// one's.
	second := h.knockID(alice, bob, "alice here, from the Tuesday standup, about the CFP")
	if second == first {
		t.Fatal("the replacing knock kept the replaced id")
	}
	if n := h.knockRows(fp); n != 1 {
		t.Fatalf("%d knock rows after a second knock from one knocker, want 1", n)
	}
	knocker, id, newSize := h.knockerOf(fp)
	if knocker != alice.Fingerprint() || id != second || newSize <= size {
		t.Fatalf("the row after the replacement: knocker %q id %d size %d, want alice, %d and more than %d",
			knocker, id, newSize, second, size)
	}
	if _, err := os.Stat(firstFile); !os.IsNotExist(err) {
		t.Fatalf("the replaced knock's file is still there: %v", err)
	}
	h.assertCountersAgree()
	// The owner sees one message, and it is the second text.
	status, body := h.do(bob, "GET", "/v1/mailbox/"+fp, nil, nil)
	var list relayapi.ListResponse
	if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Messages) != 1 {
		t.Fatalf("the owner's listing: %d %s", status, body)
	}
	if list.Messages[0].ID != second {
		t.Fatalf("the listed id is %d, want the replacement %d", list.Messages[0].ID, second)
	}

	// Another knocker is another row: replacement is by the knocker and
	// not by the mailbox.
	h.knockID(carol, bob, "carol here")
	if n := h.knockRows(fp); n != 2 {
		t.Fatalf("%d knock rows after a second knocker, want 2", n)
	}
	h.assertCountersAgree()

	// A row that is not a knock carries no knocker: an envelope from a
	// peer, and a stream.
	if status, body, _ := h.pushAllow(bob, bob, time.Now(), alice.Fingerprint()); status != http.StatusNoContent {
		t.Fatalf("allow push: %d %s", status, body)
	}
	if status, body := h.do(alice, "POST", "/v1/mailbox/"+fp, sealed(t, alice, bob.Public(), "x"), nil); status != http.StatusOK {
		t.Fatalf("an ordinary post: %d %s", status, body)
	}
	var others int64
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE to_fp = ? AND kind <> ? AND knocker <> ''`,
		fp, relayapi.KindKnock).Scan(&others); err != nil {
		t.Fatal(err)
	}
	if others != 0 {
		t.Fatalf("%d rows that are not knocks carry a knocker", others)
	}
}

// The knocker is the fingerprint the request's signature proved, never
// what the sealed record says: a sender who seals a record claiming
// somebody else's key still owns their own row, and the forged inner is
// the receiver's to refuse when they open it.
func TestTheKnockerIsTheVerifiedCallerAndNotTheSealedClaim(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "mallory")
	alice, bob, mallory := people[0], people[1], people[2]
	for _, id := range people {
		h.register(id)
	}
	fp := bob.Fingerprint()
	if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("card push: %d %s", status, body)
	}
	// Alice knocks first, and then mallory posts a knock alice sealed:
	// the request is mallory's and signed by her, the record inside is
	// alice's.
	h.knockID(alice, bob, "alice here")
	sealedByAlice := sealedKnock(t, alice, bob.Public(), "", "alice here again")
	if status, body, _ := h.send(mallory, "POST", "/v1/mailbox/"+fp+"/knock", sealedByAlice, nil); status != http.StatusOK {
		t.Fatalf("mallory's knock carrying alice's record: %d %s", status, body)
	}
	// Two rows, since the knocker is mallory: alice's is untouched.
	if n := h.knockRows(fp); n != 2 {
		t.Fatalf("%d knock rows, want 2: the sealed claim replaced the row the signature owns", n)
	}
	var byMallory int64
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE to_fp = ? AND knocker = ?`,
		fp, mallory.Fingerprint()).Scan(&byMallory); err != nil {
		t.Fatal(err)
	}
	if byMallory != 1 {
		t.Fatalf("%d rows carry mallory's fingerprint, want the one she posted", byMallory)
	}
	h.assertCountersAgree()
}

// Eight knocks from one knocker at once leave one row. The store keeps
// one connection, so the replacement, the count and the insert of each
// are one transaction against the others' whole transactions; the stall
// harness is no use here, since it parks a request in readBody, before
// any of that. What is proved is the end state: one row, its bytes one
// of the eight, the counters agreeing, and one file in the mailbox.
func TestKnocksFromOneKnockerAtOnceLeaveOneRow(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{MaxKnocksWaiting: 2}})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	fp := bob.Fingerprint()
	if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("card push: %d %s", status, body)
	}
	const n = 8
	texts := make([]string, n)
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := range n {
		texts[i] = fmt.Sprintf("alice here, attempt %d", i)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status, _, _ := h.send(alice, "POST", "/v1/mailbox/"+fp+"/knock",
				sealedKnock(t, alice, bob.Public(), "", texts[i]), nil)
			statuses[i] = status
		}(i)
	}
	wg.Wait()
	for i, status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("knock %d of %d at once: %d; the cap counts knockers and alice is one", i, n, status)
		}
	}
	if got := h.knockRows(fp); got != 1 {
		t.Fatalf("%d knock rows after %d knocks at once from one knocker, want 1", got, n)
	}
	h.assertCountersAgree()
	// The row's bytes are one of the eight, and its file is the only one
	// the mailbox holds.
	_, id, size := h.knockerOf(fp)
	ok := false
	for _, text := range texts {
		if int64(len(sealedKnock(t, alice, bob.Public(), "", text))) == size {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("the surviving row is %d bytes, which is none of the eight knocks", size)
	}
	entries, err := os.ReadDir(filepath.Dir(h.store.messagePath(fp, id)))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != strconv.FormatInt(id, 10) {
		t.Fatalf("the mailbox holds %d files, want the surviving row's alone", len(entries))
	}
}

// A mailbox that goes takes its knock rows with it, and so does a purge:
// the knocker's fingerprint lives exactly as long as the row it is on,
// which is what the security document promises. A knocker whose row was
// purged knocks again into an empty mailbox.
func TestDeregisterAndPurgeTakeTheKnockRows(t *testing.T) {
	for _, what := range []string{"purge", "deregister"} {
		t.Run(what, func(t *testing.T) {
			people := ids(t, "alice", "bob", "boss")
			alice, bob, boss := people[0], people[1], people[2]
			h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
			h.register(alice)
			h.register(bob)
			h.enroll(boss)
			fp := bob.Fingerprint()
			if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
				t.Fatalf("card push: %d %s", status, body)
			}
			h.knockID(alice, bob, "alice here")
			if h.knockRows(fp) != 1 {
				t.Fatal("the knock was not stored")
			}
			path := "/v1/admin/mailboxes/" + fp
			if what == "purge" {
				path += "/messages"
			}
			if status, body, _ := h.send(boss, "DELETE", path, nil, nil); status != http.StatusNoContent {
				t.Fatalf("%s: %d %s", what, status, body)
			}
			var left int64
			if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE knocker <> ''`).Scan(&left); err != nil {
				t.Fatal(err)
			}
			if left != 0 {
				t.Fatalf("%d rows still name a knocker after a %s", left, what)
			}
			if what == "purge" {
				// The mailbox is still there, so a knocker knocks again.
				h.assertCountersAgree()
				if id := h.knockID(alice, bob, "alice again"); id == 0 {
					t.Fatal("a knock after a purge was not stored")
				}
				if h.knockRows(fp) != 1 {
					t.Fatalf("%d knock rows after a purge and a knock, want 1", h.knockRows(fp))
				}
			}
		})
	}
}

// Put holds its own invariant: a knock names its knocker and no other
// kind does. A caller that gets this wrong is a programming fault, not a
// request, so it is refused with a sentence naming the kind and the value
// rather than storing a row nothing can account for: a knock with no
// knocker would never be replaced, and an envelope carrying one would be
// a row naming a sender for no reason at all, which is the thing the
// relay is built not to hold. (The replacement's lookup asks for the
// knock kind as well, so such a row would not in fact be swept away by
// the next knock; it would simply sit there naming somebody.)
func TestPutRefusesAKnockerOnTheWrongKind(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	fp := bob.Fingerprint()
	raw := sealed(t, alice, bob.Public(), "x")
	for _, tc := range []struct{ name, kind, knocker string }{
		{"a knock with no knocker", relayapi.KindKnock, ""},
		{"an envelope with one", relayapi.KindEnvelope, alice.Fingerprint()},
		{"a stream with one", relayapi.KindStream, alice.Fingerprint()},
	} {
		_, err := h.store.Put(fp, "default", tc.kind, tc.knocker, raw, Quotas{}, Forwarded{})
		if err == nil || !strings.Contains(err.Error(), "a knock names its knocker and nothing else does") {
			t.Errorf("%s: %v; want the invariant's refusal", tc.name, err)
		}
	}
	if n := h.messageCount(fp); n != 0 {
		t.Fatalf("%d messages stored by a refused Put", n)
	}
	// And the two right ways round are taken.
	if _, err := h.store.Put(fp, "default", relayapi.KindEnvelope, "", raw, Quotas{}, Forwarded{}); err != nil {
		t.Fatalf("an envelope with no knocker: %v", err)
	}
	if _, err := h.store.Put(fp, "default", relayapi.KindKnock, alice.Fingerprint(), raw, Quotas{}, Forwarded{}); err != nil {
		t.Fatalf("a knock with its knocker: %v", err)
	}
	h.assertCountersAgree()
}

// Two rows name a sender — an upload's from_fp and a knock's knocker —
// and both are promised to live no longer than the row itself. SQLite
// would otherwise leave a deleted row's bytes in free pages until
// something reused them, so a backup taken after a knock was
// acknowledged would still carry who knocked at whom; secure_delete is
// what makes the promise the documents give true of the file and not
// only of the table. It is a connection pragma, so every connection the
// store opens must have it.
//
// What this pins is the setting, not its effect: a knocker has a mailbox
// on the same relay, so their fingerprint is in the file either way, and
// the thing secure_delete protects — the association between that
// fingerprint and a recipient, in a freed page — has no assertion that
// is not also true of a database that never held it.
func TestTheStoreDeletesSecurely(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var on int
	if err := store.db.QueryRow(`PRAGMA secure_delete`).Scan(&on); err != nil {
		t.Fatal(err)
	}
	if on != 1 {
		t.Fatalf("secure_delete is %d on a fresh store; a deleted knocker's bytes stay in the file", on)
	}
}
