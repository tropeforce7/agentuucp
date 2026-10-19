package relay

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// postOnce posts body to the recipient's mailbox as from and answers the
// status and the id the relay gave.
func (h *harness) postOnce(from, to *identity.Identity, body []byte) (int, int64) {
	h.t.Helper()
	status, out := h.do(from, "POST", "/v1/mailbox/"+to.Fingerprint(), body, nil)
	var answer relayapi.PostResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(out, &answer); err != nil {
			h.t.Fatal(err)
		}
	}
	return status, answer.ID
}

// held is how many messages a mailbox holds and the bytes it is charged.
func (h *harness) held(fp string) (rows, bytes int64) {
	h.t.Helper()
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE to_fp = ?`, fp).Scan(&rows); err != nil {
		h.t.Fatal(err)
	}
	if err := h.store.db.QueryRow(`SELECT queued_bytes FROM mailboxes WHERE fp = ?`, fp).Scan(&bytes); err != nil {
		h.t.Fatal(err)
	}
	return rows, bytes
}

// TestADirectPostIsStoredOnceByItsEnvelope: a sender whose answer was lost
// on the way back posts the same envelope again (S50). The relay stores
// it once, charges the mailbox once, and answers the second post as the
// first, with the first row's id. Different bytes are another message.
// The relay here has no couriers configured, and the post is held to its
// window all the same (D133).
func TestADirectPostIsStoredOnceByItsEnvelope(t *testing.T) {
	h := newHarness(t, Config{})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	body := sealedTo(t, alice, bob.Public(), "once", "")

	status, first := h.postOnce(alice, bob, body)
	if status != http.StatusOK || first == 0 {
		t.Fatalf("the first post: %d, id %d", status, first)
	}
	status, again := h.postOnce(alice, bob, body)
	if status != http.StatusOK || again != first {
		t.Fatalf("the same envelope again: %d, id %d; want 200 and %d", status, again, first)
	}
	if rows, charged := h.held(bob.Fingerprint()); rows != 1 || charged != int64(len(body)) {
		t.Fatalf("bob holds %d messages charged %d bytes; want one of %d", rows, charged, len(body))
	}

	other := sealedTo(t, alice, bob.Public(), "another", "")
	status, second := h.postOnce(alice, bob, other)
	if status != http.StatusOK || second == first {
		t.Fatalf("a different envelope: %d, id %d", status, second)
	}
	if rows, _ := h.held(bob.Fingerprint()); rows != 2 {
		t.Fatalf("bob holds %d messages; want two", rows)
	}
}

// The first post's id is the answer after bob has read and removed it: the
// envelope was delivered, whatever bob did with it since, and nothing is
// stored again.
func TestADirectPostsRetryIsAnsweredAfterTheMessageIsGone(t *testing.T) {
	h := newHarness(t, Config{})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	body := sealedTo(t, alice, bob.Public(), "read and removed", "")
	_, first := h.postOnce(alice, bob, body)
	if removed, err := h.store.Delete(bob.Fingerprint(), first); err != nil || !removed {
		t.Fatalf("removing bob's message: %v %v", removed, err)
	}
	status, again := h.postOnce(alice, bob, body)
	if status != http.StatusOK || again != first {
		t.Fatalf("the retry: %d, id %d; want 200 and %d", status, again, first)
	}
	if rows, _ := h.held(bob.Fingerprint()); rows != 0 {
		t.Fatalf("bob holds %d messages after the retry; want none", rows)
	}
}

// TestADirectPostsWindowIsFixed: the window a post's hash stands for is
// directPostWindow, three days, and not the courier's last-hop window,
// which at a day's forward_ttl is a day: the post one second inside three
// days is the first, one second past it a new message (D133).
func TestADirectPostsWindowIsFixed(t *testing.T) {
	h := newHarness(t, Config{CourierLimits: CourierLimits{ForwardTTL: 24 * time.Hour, MaxHops: 8}})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	body := sealedTo(t, alice, bob.Public(), "within the window", "")
	_, first := h.postOnce(alice, bob, body)

	h.clock.advance(directPostWindow - time.Second)
	if status, again := h.postOnce(alice, bob, body); status != http.StatusOK || again != first {
		t.Fatalf("a second inside the window, with forward_ttl a day: %d, id %d; want %d", status, again, first)
	}
	h.clock.advance(2 * time.Second)
	status, later := h.postOnce(alice, bob, body)
	if status != http.StatusOK || later == first {
		t.Fatalf("a second past the window: %d, id %d; want a new message", status, later)
	}
	if rows, _ := h.held(bob.Fingerprint()); rows != 2 {
		t.Fatalf("bob holds %d messages; want two", rows)
	}
	if directPostWindow != 72*time.Hour {
		t.Fatalf("directPostWindow is %v, want the forward_ttl default, 72h", directPostWindow)
	}
}

// At a forward_ttl short enough that three days would cost more than
// max_hops tokens, the window is max_hops forward_ttls, eight hours at an
// hour's, so the cost never passes what the share's bucket is sized for
// and a post still writes its hash (D137): one second inside eight hours
// is the first, one second past it a new message.
func TestADirectPostsWindowIsHeldToMaxHopsForwardTTLs(t *testing.T) {
	h := newHarness(t, Config{CourierLimits: CourierLimits{ForwardTTL: time.Hour, MaxHops: 8}})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	body := sealedTo(t, alice, bob.Public(), "within eight hours", "")
	_, first := h.postOnce(alice, bob, body)
	h.clock.advance(8*time.Hour - time.Second)
	if status, again := h.postOnce(alice, bob, body); status != http.StatusOK || again != first {
		t.Fatalf("a second inside eight hours: %d, id %d; want %d", status, again, first)
	}
	h.clock.advance(2 * time.Second)
	if status, later := h.postOnce(alice, bob, body); status != http.StatusOK || later == first {
		t.Fatalf("a second past eight hours: %d, id %d; want a new message", status, later)
	}
}

// A carried table at its ceiling refuses no post: the post is stored
// without its hash, and a retry of it is stored again (D134).
func TestACarriedCeilingRefusesNoDirectPost(t *testing.T) {
	h := newHarness(t, Config{CourierLimits: CourierLimits{CarriedMaxRows: 1}})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	if status, _ := h.postOnce(alice, bob, sealedTo(t, alice, bob.Public(), "takes the one row", "")); status != http.StatusOK {
		t.Fatalf("the first post: %d", status)
	}
	body := sealedTo(t, alice, bob.Public(), "over the ceiling", "")
	status, first := h.postOnce(alice, bob, body)
	if status != http.StatusOK {
		t.Fatalf("a post with the carried table full: %d", status)
	}
	status, again := h.postOnce(alice, bob, body)
	if status != http.StatusOK || again == first {
		t.Fatalf("its retry: %d, id %d; want stored again, the table being full", status, again)
	}
	if rows, _ := h.held(bob.Fingerprint()); rows != 3 {
		t.Fatalf("bob holds %d messages; want three", rows)
	}
}

// The same envelope posted directly and then delivered by a courier is one
// message: the courier is answered with the row the post made, and nothing
// is stored twice.
func TestAnEnvelopePostedAndThenForwardedIsStoredOnce(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	alice, bob := h.user(t, "alice"), h.user(t, "bob")
	env := sealedFor(bob.Fingerprint(), "both ways")
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	status, first := h.postOnce(alice, bob, body)
	if status != http.StatusOK {
		t.Fatalf("the direct post: %d", status)
	}
	status, answer, out := h.forward(courier, request(env, nil, []string{"one"}))
	if status != http.StatusConflict || answer.ID != first {
		t.Fatalf("the courier's delivery: %d %+v (%s); want 409 with %d", status, answer, out, first)
	}
	if rows, _ := h.held(bob.Fingerprint()); rows != 1 {
		t.Fatalf("bob holds %d messages; want one", rows)
	}
}

// A caller the recipient's allow list refuses is refused before the
// envelope is looked for, so holding the same sealed envelope as an
// admitted sender learns no row id: 403, nothing stored.
func TestARefusedPosterLearnsNoRowFromTheSameEnvelope(t *testing.T) {
	h := newHarness(t, Config{})
	alice, bob, carol := neighbourID(t, "alice"), neighbourID(t, "bob"), neighbourID(t, "carol")
	h.enroll(alice, bob, carol)
	if status, body, _ := h.pushAllow(bob, bob, h.clock.Now(), alice.Fingerprint()); status != http.StatusOK && status != http.StatusNoContent {
		t.Fatalf("bob's allow list: %d %s", status, body)
	}
	body := sealedTo(t, alice, bob.Public(), "for bob from alice", "")
	if status, _ := h.postOnce(alice, bob, body); status != http.StatusOK {
		t.Fatalf("alice's post: %d", status)
	}
	status, out := h.do(carol, "POST", "/v1/mailbox/"+bob.Fingerprint(), body, nil)
	if status != http.StatusForbidden {
		t.Fatalf("carol posting alice's envelope: %d %s; want 403", status, out)
	}
	if rows, _ := h.held(bob.Fingerprint()); rows != 1 {
		t.Fatalf("bob holds %d messages; want one", rows)
	}
}

// A direct post's hash is charged to its poster's carried share, as a
// forward's is, so one poster cannot fill the carried table that couriers
// need; a poster over its share is stored without the hash and never
// refused, and a retry of that post is stored again (D135, amended). A
// retry of a post whose hash was written is still answered as the first,
// spending nothing.
func TestADirectPostSpendsItsPostersCarriedShare(t *testing.T) {
	h := newHarness(t, Config{CourierLimits: CourierLimits{ForwardTTL: directPostWindow, MaxHops: 8, CarriedRowsPerPoster: 1}})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	first := sealedTo(t, alice, bob.Public(), "within the share", "")
	_, firstID := h.postOnce(alice, bob, first)
	over := sealedTo(t, alice, bob.Public(), "over the share", "")
	status, overID := h.postOnce(alice, bob, over)
	if status != http.StatusOK || overID == firstID {
		t.Fatalf("a post over the share: %d, id %d; want stored", status, overID)
	}
	status, again := h.postOnce(alice, bob, over)
	if status != http.StatusOK || again == overID {
		t.Fatalf("its retry: %d, id %d; want stored again, no hash having been written", status, again)
	}
	if status, retry := h.postOnce(alice, bob, first); status != http.StatusOK || retry != firstID {
		t.Fatalf("a retry of the post within the share: %d, id %d; want %d", status, retry, firstID)
	}
	var hashes int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM carried`).Scan(&hashes); err != nil {
		t.Fatal(err)
	}
	if rows, _ := h.held(bob.Fingerprint()); rows != 3 || hashes != 1 {
		t.Fatalf("bob holds %d messages and the relay %d hashes; want three and one", rows, hashes)
	}
}

// A direct post's hash costs one token for each forward_ttl it stands,
// since the share refills once a forward_ttl, and never more than
// max_hops, its window shortening instead (D137): one at the default,
// three at a day, eight at an hour or a minute. With a share whose bucket
// holds three, one post at a day's forward_ttl takes its hash and the next
// is stored without one, so the standing hashes stay within the share
// whatever forward_ttl is (D135).
func TestADirectPostsHashCostsAForwardTTLsToken(t *testing.T) {
	type cost struct {
		window time.Duration
		tokens int64
	}
	day := 24 * time.Hour
	for ttl, want := range map[time.Duration]cost{
		0:                    {directPostWindow, 1},
		directPostWindow:     {directPostWindow, 1},
		2 * directPostWindow: {directPostWindow, 1},
		day:                  {directPostWindow, 3},
		day + time.Hour:      {directPostWindow, 3},
		day - time.Hour:      {directPostWindow, 4},
		9 * time.Hour:        {directPostWindow, 8},
		8 * time.Hour:        {64 * time.Hour, 8},
		time.Hour:            {8 * time.Hour, 8},
		time.Minute:          {8 * time.Minute, 8},
	} {
		window, tokens := CourierLimits{ForwardTTL: ttl, MaxHops: 8}.directPost()
		if window != want.window || tokens != want.tokens {
			t.Errorf("directPost at forward_ttl %v: %v and %d tokens, want %v and %d", ttl, window, tokens, want.window, want.tokens)
		}
	}
	h := newHarness(t, Config{CourierLimits: CourierLimits{ForwardTTL: 24 * time.Hour, MaxHops: 8, CarriedRowsPerPoster: 12}})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	for _, text := range []string{"takes the three tokens", "finds none"} {
		if status, _ := h.postOnce(alice, bob, sealedTo(t, alice, bob.Public(), text, "")); status != http.StatusOK {
			t.Fatalf("%s: %d", text, status)
		}
	}
	var hashes int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM carried`).Scan(&hashes); err != nil {
		t.Fatal(err)
	}
	if hashes != 1 {
		t.Fatalf("the relay holds %d hashes; want one, the second post over the share", hashes)
	}
}

// A post that spent its token and wrote no hash, the carried table being
// at its ceiling, gives the token back, so the share counts only hashes
// that stand.
func TestADirectPostThatWritesNoHashGivesItsTokenBack(t *testing.T) {
	h := newHarness(t, Config{CourierLimits: CourierLimits{ForwardTTL: directPostWindow, MaxHops: 8, CarriedMaxRows: 1, CarriedRowsPerPoster: 8}})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	for _, text := range []string{"takes the one row", "finds the table full"} {
		if status, _ := h.postOnce(alice, bob, sealedTo(t, alice, bob.Public(), text, "")); status != http.StatusOK {
			t.Fatalf("%s: %d", text, status)
		}
	}
	// A bucket of two: the first post spent one, the second spent one and
	// gave it back, so one is left.
	if ok, _ := h.server.lim.carried.AllowN(alice.Fingerprint(), 1); !ok {
		t.Fatal("no token is left: the post that wrote no hash kept its token")
	}
	if ok, _ := h.server.lim.carried.AllowN(alice.Fingerprint(), 1); ok {
		t.Fatal("two tokens were left: the bucket is not the size the test assumes")
	}
}
