package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// patience is how long a test waits for the relay to do something it
// claims to do at once or on a wake. Generous on purpose: the claim is
// that it happens, not how fast this machine schedules it, and every hold
// in these tests is far longer, so a hold mistaken for a wake still fails.
const patience = 15 * time.Second

// longHold is the wait a test asks for when the point is that something
// else ends the hold: well past patience, so a hold that ran out would be
// seen as one that was never woken.
const longHold = "wait=30s"

// listing is one GET of a mailbox with a query, in flight. The test reads
// its answer when it comes, and can cut it off from the client's side.
type listing struct {
	started time.Time
	cancel  context.CancelFunc
	done    chan struct{}
	status  int
	body    []byte
	err     error
	dur     time.Duration
}

// list sends a signed listing for id's own mailbox with the query given,
// without waiting for the answer.
func (h *harness) list(id *identity.Identity, query string) *listing {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	l := &listing{started: time.Now(), cancel: cancel, done: make(chan struct{})}
	req, err := http.NewRequestWithContext(ctx, "GET", h.srv.URL+"/v1/mailbox/"+id.Fingerprint()+"?"+query, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := relayapi.SignRequest(id, req, nil); err != nil {
		h.t.Fatal(err)
	}
	go func() {
		defer close(l.done)
		resp, err := h.srv.Client().Do(req)
		l.dur = time.Since(l.started)
		if err != nil {
			l.err = err
			return
		}
		defer resp.Body.Close()
		l.status = resp.StatusCode
		l.body, l.err = io.ReadAll(resp.Body)
	}()
	return l
}

// answer waits for the listing's answer and decodes it; a listing that is
// not answered within patience fails the test.
func (l *listing) answer(t *testing.T) (int, relayapi.ListResponse, []byte) {
	t.Helper()
	select {
	case <-l.done:
	case <-time.After(patience):
		t.Fatalf("the listing was not answered within %s", patience)
	}
	if l.err != nil {
		t.Fatal(l.err)
	}
	var resp relayapi.ListResponse
	if l.status == http.StatusOK {
		if err := json.Unmarshal(l.body, &resp); err != nil {
			t.Fatalf("the listing is not JSON: %v\n%s", err, l.body)
		}
	}
	return l.status, resp, l.body
}

// answered reports whether the listing has been answered, without waiting.
func (l *listing) answered() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// cut ends the listing from the client's side, as a watcher that was
// killed does, and waits for the relay to let go of it: one hold fewer
// than before.
func (l *listing) cut(t *testing.T, h *harness) {
	t.Helper()
	before := h.server.holds.held()
	l.cancel()
	<-l.done
	h.holding(before - 1)
}

// holding waits until the relay holds exactly n listings, observing the
// relay's own count rather than inferring from the client's side.
func (h *harness) holding(n int64) {
	h.t.Helper()
	deadline := time.Now().Add(patience)
	for time.Now().Before(deadline) {
		if h.server.holds.held() == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("the relay holds %d listings, want %d", h.server.holds.held(), n)
}

// subscribed waits until n subscriptions are registered under key.
func (h *harness) subscribed(key string, n int) {
	h.t.Helper()
	deadline := time.Now().Add(patience)
	for time.Now().Before(deadline) {
		if h.server.notify.waiting(key) == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("%d subscriptions under %s, want %d", h.server.notify.waiting(key), key, n)
}

// atOnce asserts a listing that asked to be held was answered without the
// hold: well inside the wait it asked for, which is longHold everywhere
// it is used.
func atOnce(t *testing.T, l *listing, what string) {
	t.Helper()
	if l.dur >= 20*time.Second {
		t.Fatalf("%s took %s, which is the hold and not an answer at once", what, l.dur)
	}
}

// heldListingLines are the access log lines for the mailbox listing route.
func (h *harness) listingLines() []string {
	var out []string
	for _, line := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(line, "method=GET") && strings.Contains(line, "/v1/mailbox/") &&
			!strings.Contains(line, "/channels") && !strings.Contains(line, "/blob") {
			out = append(out, line)
		}
	}
	return out
}

func TestAHeldListingAnswersWhenAPostLands(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	l := h.list(alice, longHold)
	h.holding(1)
	h.subscribed(mailKey(alice.Fingerprint()), 1)
	if l.answered() {
		t.Fatal("an empty mailbox was answered without the hold")
	}
	posted := time.Now()
	if status, body := h.postTo(bob, alice, ""); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	status, resp, _ := l.answer(t)
	if status != http.StatusOK || len(resp.Messages) != 1 || resp.Messages[0].ID != 1 ||
		resp.Messages[0].Channel != "default" || len(resp.Messages[0].Envelope) == 0 || resp.Queued != 1 {
		t.Fatalf("the answer to a woken hold: %d %+v", status, resp)
	}
	if since := time.Since(posted); since > patience {
		t.Fatalf("the hold answered %s after the post", since)
	}
	h.holding(0)
	if n := h.server.notify.waiting(mailKey(alice.Fingerprint())); n != 0 {
		t.Fatalf("%d subscriptions left after the answer", n)
	}

	// Mail already after the cursor is answered without a hold, and the
	// hold is charged as one request, like any listing.
	l = h.list(alice, longHold)
	if status, resp, _ := l.answer(t); status != http.StatusOK || len(resp.Messages) != 1 {
		t.Fatalf("a listing with mail waiting: %d %+v", status, resp)
	}
	atOnce(t, l, "a listing with mail already waiting")
	// After the row, nothing: held again.
	l = h.list(alice, longHold+"&after=1")
	h.holding(1)
	l.cut(t, h)
	for _, line := range h.listingLines() {
		if strings.Contains(line, "limit=") {
			t.Fatalf("a listing under the caps was logged with a limit:\n%s", line)
		}
	}
}

func TestAHeldListingAnswersEmptyAtTheWait(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)

	l := h.list(alice, "wait=300ms")
	status, resp, body := l.answer(t)
	if status != http.StatusOK || len(resp.Messages) != 0 || resp.Queued != 0 || resp.DirectoriesChanged != nil {
		t.Fatalf("the answer at the wait: %d %s", status, body)
	}
	if l.dur < 300*time.Millisecond {
		t.Fatalf("answered after %s, before the wait of 300ms was up", l.dur)
	}
	h.holding(0)
	if strings.Contains(string(body), "directories_changed") {
		t.Fatalf("an empty answer names the field:\n%s", body)
	}
	// The access log shows the hold as what it is: a 200 that took the
	// wait, under no limit.
	var logged bool
	for _, line := range h.listingLines() {
		if strings.Contains(line, "status=200") && !strings.Contains(line, "limit=") {
			logged = true
		}
	}
	if !logged {
		t.Fatalf("no held listing in the log:\n%s", h.logs.String())
	}
}

func TestACompletedStreamWakesAHeldListing(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	l := h.list(alice, longHold)
	h.holding(1)
	blob := fakeStream(200, 3000)
	status, opened, body := h.openStream(bob, alice.Fingerprint(), int64(len(blob)))
	if status != http.StatusCreated {
		t.Fatalf("open: %d %s", status, body)
	}
	if status, body, _ := h.sendRaw(bob, "PATCH", "/v1/uploads/"+opened.Upload, blob,
		map[string]string{relayapi.UploadOffsetHeader: "0"}); status != http.StatusNoContent {
		t.Fatalf("append: %d %s", status, body)
	}
	// Opened and appended is not arrived.
	if l.answered() {
		t.Fatal("an upload not yet complete answered the hold")
	}
	if status, body, _ := h.send(bob, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil); status != http.StatusOK {
		t.Fatalf("complete: %d %s", status, body)
	}
	status, resp, _ := l.answer(t)
	if status != http.StatusOK || len(resp.Messages) != 1 || resp.Messages[0].Kind != relayapi.KindStream ||
		resp.Messages[0].Size != int64(len(blob)) || len(resp.Messages[0].Envelope) != 0 {
		t.Fatalf("the answer to a completed stream: %d %+v", status, resp)
	}
}

func TestAPostToAnotherMailboxDoesNotWakeAHold(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	l := h.list(alice, longHold)
	h.holding(1)
	if status, body := h.postTo(alice, bob, ""); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	// Bob's mail is not alice's: the post has been answered and stored,
	// and alice's listing is still held, still subscribed.
	if l.answered() {
		t.Fatal("a post to bob answered alice's hold")
	}
	h.holding(1)
	if n := h.server.notify.waiting(mailKey(alice.Fingerprint())); n != 1 {
		t.Fatalf("%d subscriptions for alice after a post to bob", n)
	}
	// A watcher that goes away takes its hold with it: the relay lets go
	// of the slot and the subscription without answering anyone.
	l.cut(t, h)
	if n := h.server.notify.waiting(mailKey(alice.Fingerprint())); n != 0 {
		t.Fatalf("%d subscriptions left after the watcher went away", n)
	}
	// And bob's own hold answers at once, since his mail is there.
	lb := h.list(bob, longHold)
	if status, resp, _ := lb.answer(t); status != http.StatusOK || len(resp.Messages) != 1 {
		t.Fatalf("bob's listing: %d %+v", status, resp)
	}
	atOnce(t, lb, "bob's listing with his mail waiting")
}

// Over max_waiting the relay does not refuse: the next listing that asks to
// be held is answered at once, as a relay without the hold would, and the
// access log says limit=waiting on a status=200 line. Both edges: two held
// under a cap of two, the third at once.
func TestOverMaxWaitingTheListingIsAnsweredAtOnce(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{MaxWaiting: 2}})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	for _, id := range people {
		h.register(id)
	}
	la := h.list(alice, longHold)
	h.holding(1)
	lb := h.list(bob, longHold)
	h.holding(2)
	lc := h.list(carol, longHold)
	status, resp, _ := lc.answer(t)
	if status != http.StatusOK || len(resp.Messages) != 0 {
		t.Fatalf("the listing over the cap: %d %+v", status, resp)
	}
	atOnce(t, lc, "the listing over max_waiting")
	if la.answered() || lb.answered() {
		t.Fatal("a listing over the cap answered one under it")
	}
	h.holding(2)
	var degraded bool
	for _, line := range h.listingLines() {
		if strings.Contains(line, "limit=waiting") {
			degraded = true
			if !strings.Contains(line, "status=200") {
				t.Fatalf("the degraded hold was not a 200:\n%s", line)
			}
		}
	}
	if !degraded {
		t.Fatalf("no listing logged with limit=waiting:\n%s", h.logs.String())
	}
	// A hold given back is a hold somebody else may take.
	la.cut(t, h)
	h.holding(1)
	lc = h.list(carol, longHold)
	h.holding(2)
	if lc.answered() {
		t.Fatal("carol's second listing was not held once a hold was free")
	}
	lb.cut(t, h)
	h.holding(1)
	lc.cut(t, h)
	h.holding(0)
}

// Two machines of one identity may each hold a listing; a third request
// from it is answered at once while the two are held, and nobody else is
// affected.
func TestAThirdHoldFromOneIdentityIsAnsweredAtOnce(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	l1 := h.list(alice, longHold)
	h.holding(1)
	l2 := h.list(alice, longHold)
	h.holding(2)
	l3 := h.list(alice, longHold)
	if status, resp, _ := l3.answer(t); status != http.StatusOK || len(resp.Messages) != 0 {
		t.Fatalf("alice's third listing: %d %+v", status, resp)
	}
	atOnce(t, l3, "alice's third listing")
	if l1.answered() || l2.answered() {
		t.Fatal("the third listing answered one of the two held")
	}
	var degraded int
	for _, line := range h.listingLines() {
		if strings.Contains(line, "limit=waiting") {
			degraded++
		}
	}
	if degraded != 1 {
		t.Fatalf("%d listings logged with limit=waiting, want 1", degraded)
	}
	// Bob is not alice.
	lb := h.list(bob, longHold)
	h.holding(3)
	if lb.answered() {
		t.Fatal("bob's hold was refused for alice's two")
	}
	// One of alice's given back, and her third is held.
	l1.cut(t, h)
	h.holding(2)
	l3 = h.list(alice, longHold)
	h.holding(3)
	if l3.answered() {
		t.Fatal("alice's hold was not held once one of hers was free")
	}
	// Every hold answers when its mail arrives, and the count comes down.
	if status, body := h.postTo(bob, alice, ""); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	for _, l := range []*listing{l2, l3} {
		if status, resp, _ := l.answer(t); status != http.StatusOK || len(resp.Messages) != 1 {
			t.Fatalf("a held listing woken by a post: %d %+v", status, resp)
		}
	}
	h.holding(1)
	lb.cut(t, h)
}

// wait above the ceiling is clamped, not refused, and the ceiling is
// proved with a short one rather than by waiting a minute. Bad forms are
// 400 by the sentence, and zero is no hold.
func TestAWaitAboveTheCeilingIsClamped(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)
	h.server.maxWait = 300 * time.Millisecond

	for _, wait := range []string{"10m", "300ms", "1h", "9223372036854775807ns"} {
		l := h.list(alice, "wait="+wait)
		status, resp, _ := l.answer(t)
		if status != http.StatusOK || len(resp.Messages) != 0 {
			t.Fatalf("wait=%s: %d %+v", wait, status, resp)
		}
		if l.dur < 300*time.Millisecond {
			t.Fatalf("wait=%s answered after %s, before the ceiling", wait, l.dur)
		}
		if l.dur >= 10*time.Second {
			t.Fatalf("wait=%s took %s: the ceiling did not clamp it", wait, l.dur)
		}
	}
	// Under the ceiling is the wait asked for.
	l := h.list(alice, "wait=100ms")
	if status, _, _ := l.answer(t); status != http.StatusOK || l.dur < 100*time.Millisecond {
		t.Fatalf("wait=100ms: %d after %s", status, l.dur)
	}
	for _, bad := range []string{"-1s", "abc", "1", "", "1.5", "9223372036854775808ns"} {
		status, body := h.do(alice, "GET", "/v1/mailbox/"+alice.Fingerprint()+"?wait="+bad, nil, nil)
		if bad == "" {
			// Present and empty is absent.
			if status != http.StatusOK {
				t.Fatalf("wait=: %d %s", status, body)
			}
			continue
		}
		if status != http.StatusBadRequest || errorText(t, body) != "bad wait parameter" {
			t.Fatalf("wait=%s: %d %s", bad, status, body)
		}
	}
	// Zero is today's listing: no hold, no subscription, nothing logged
	// as a limit.
	l = h.list(alice, "wait=0")
	if status, _, _ := l.answer(t); status != http.StatusOK {
		t.Fatalf("wait=0: %d", status)
	}
	atOnce(t, l, "wait=0")
	for _, line := range h.listingLines() {
		if strings.Contains(line, "limit=") {
			t.Fatalf("a listing was logged with a limit:\n%s", line)
		}
	}
	h.holding(0)
}

func TestCloseAnswersEveryHeldListing(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	la := h.list(alice, longHold)
	lb := h.list(bob, longHold)
	h.holding(2)
	closed := time.Now()
	h.server.Close()
	for _, l := range []*listing{la, lb} {
		if status, resp, _ := l.answer(t); status != http.StatusOK || len(resp.Messages) != 0 {
			t.Fatalf("a held listing at Close: %d %+v", status, resp)
		}
		if since := time.Since(closed); since > patience {
			t.Fatalf("Close took %s to answer a held listing", since)
		}
	}
	h.holding(0)
	// After Close nothing is held: a listing that asks answers at once,
	// with what it finds, so the shutdown that follows has nothing to
	// wait on.
	l := h.list(alice, longHold)
	if status, _, _ := l.answer(t); status != http.StatusOK {
		t.Fatalf("a listing after Close: %d", status)
	}
	atOnce(t, l, "a listing after Close")
}

// peersQuery renders a peers parameter.
func peersQuery(entries ...string) string {
	return "peers=" + strings.Join(entries, ",")
}

// at is FP:ISSUED for a peer at an issue time.
func at(fp string, issued time.Time) string {
	return fp + ":" + strconv.FormatInt(issued.UnixNano(), 10)
}

func TestADirectoryPushWakesAWatcherAndNamesThePeer(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	for _, id := range people {
		h.register(id)
	}
	bobFP, carolFP := bob.Fingerprint(), carol.Fingerprint()
	start := h.clock.Now()

	// Nothing pushed yet: bob and carol have no directory, so at issue
	// zero nothing has changed, and the hold holds under three keys.
	l := h.list(alice, longHold+"&"+peersQuery(at(bobFP, time.Time{}), at(carolFP, time.Time{})))
	h.holding(1)
	h.subscribed(dirKey(bobFP), 1)
	h.subscribed(dirKey(carolFP), 1)
	if l.answered() {
		t.Fatal("a watch of two peers without directories answered at once")
	}
	if status, body, _ := h.pushDirectory(bob, bob, start, dflt, bugs); status != http.StatusNoContent {
		t.Fatalf("push: %d %s", status, body)
	}
	status, resp, _ := l.answer(t)
	if status != http.StatusOK || len(resp.Messages) != 0 || len(resp.DirectoriesChanged) != 1 || resp.DirectoriesChanged[0] != bobFP {
		t.Fatalf("the answer to a watched push: %d %+v", status, resp)
	}
	// The subscription under every key is gone with the answer.
	h.subscribed(dirKey(carolFP), 0)
	h.subscribed(dirKey(bobFP), 0)

	// Holding bob's issue as it now is: the same directory pushed again
	// is a 204 that wakes nothing, and the hold goes on; a newer one wakes
	// it and is named.
	l = h.list(alice, longHold+"&"+peersQuery(at(bobFP, start)))
	h.holding(1)
	h.subscribed(dirKey(bobFP), 1)
	if status, body, _ := h.pushDirectory(bob, bob, start, dflt, bugs); status != http.StatusNoContent {
		t.Fatalf("the same push again: %d %s", status, body)
	}
	if l.answered() {
		t.Fatal("pushing the stored directory again answered the watcher")
	}
	h.subscribed(dirKey(bobFP), 1)
	// Nor does an older one, which is refused.
	if status, body, _ := h.pushDirectory(bob, bob, start.Add(-time.Second), dflt); status != http.StatusConflict {
		t.Fatalf("an older push: %d %s", status, body)
	}
	if l.answered() {
		t.Fatal("a refused push answered the watcher")
	}
	newer := start.Add(time.Nanosecond)
	if status, body, _ := h.pushDirectory(bob, bob, newer, dflt, bugs, channels.Channel{Name: "cfp"}); status != http.StatusNoContent {
		t.Fatalf("a newer push: %d %s", status, body)
	}
	if status, resp, _ := l.answer(t); status != http.StatusOK || len(resp.DirectoriesChanged) != 1 || resp.DirectoriesChanged[0] != bobFP {
		t.Fatalf("the answer to a newer push: %d %+v", status, resp)
	}

	// The issue time is the comparison, to the nanosecond: a watcher
	// holding the issue as stored is told nothing and held; one holding
	// an earlier issue is told at once, hold or no hold; one holding a
	// later issue than the relay does (a relay behind another) is told
	// nothing.
	for _, tc := range []struct {
		name    string
		held    time.Time
		changed bool
	}{
		{"as stored", newer, false},
		{"a nanosecond before", newer.Add(-time.Nanosecond), true},
		{"a nanosecond after", newer.Add(time.Nanosecond), false},
		{"zero", time.Time{}, true},
	} {
		l := h.list(alice, "wait=300ms&"+peersQuery(at(bobFP, tc.held)))
		status, resp, _ := l.answer(t)
		if status != http.StatusOK {
			t.Fatalf("%s: %d", tc.name, status)
		}
		if got := len(resp.DirectoriesChanged) == 1; got != tc.changed {
			t.Fatalf("%s: changed %v, want %v: %+v", tc.name, got, tc.changed, resp)
		}
		if tc.changed && l.dur >= 10*time.Second {
			t.Fatalf("%s: a change already there was held for %s", tc.name, l.dur)
		}
		if !tc.changed && l.dur < 300*time.Millisecond {
			t.Fatalf("%s: answered after %s, before the wait, with nothing to say", tc.name, l.dur)
		}
		// Without a hold, the same answer at once.
		status, resp2, _ := h.list(alice, peersQuery(at(bobFP, tc.held))).answer(t)
		if status != http.StatusOK || len(resp2.DirectoriesChanged) != len(resp.DirectoriesChanged) {
			t.Fatalf("%s without a hold: %d %+v", tc.name, status, resp2)
		}
	}

	// Two changed peers are named in a fixed order, and a message beside
	// them is in the same answer.
	if status, body, _ := h.pushDirectory(carol, carol, start, dflt); status != http.StatusNoContent {
		t.Fatalf("carol's push: %d %s", status, body)
	}
	if status, body := h.postTo(bob, alice, ""); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	status, resp, _ = h.list(alice, longHold+"&"+peersQuery(at(carolFP, time.Time{}), at(bobFP, time.Time{}))).answer(t)
	want := []string{bobFP, carolFP}
	if bobFP > carolFP {
		want = []string{carolFP, bobFP}
	}
	if status != http.StatusOK || len(resp.Messages) != 1 || strings.Join(resp.DirectoriesChanged, " ") != strings.Join(want, " ") {
		t.Fatalf("two changed peers and a message: %d %+v", status, resp)
	}
	// The watcher's own directory is watched the same way, for the other
	// machine of the same identity.
	l = h.list(alice, longHold+"&"+peersQuery(at(alice.Fingerprint(), time.Time{}))+"&after=1")
	h.holding(1)
	if status, body, _ := h.pushDirectory(alice, alice, start, dflt); status != http.StatusNoContent {
		t.Fatalf("alice's push: %d %s", status, body)
	}
	if status, resp, _ := l.answer(t); status != http.StatusOK || len(resp.DirectoriesChanged) != 1 || resp.DirectoriesChanged[0] != alice.Fingerprint() {
		t.Fatalf("a watch of the watcher's own directory: %d %+v", status, resp)
	}

	// No log line carries the query: which peers a watcher may post to is
	// not the operator's, under either mode.
	if logs := h.logs.String(); strings.Contains(logs, "peers=") || strings.Contains(logs, "wait=") {
		t.Fatalf("the query reached the log:\n%s", logs)
	}
}

// A peer the watcher may not post to — not on the allow list, blocked, or
// with no mailbox at all — is dropped from the watch without a word: not
// subscribed under, never named, however many times its owner pushes, and
// the rest of the request is unaffected.
func TestAPeerTheWatcherMayNotPostToIsNeitherNamedNorWokenOn(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "carol", "dave")
	alice, bob, carol, dave := people[0], people[1], people[2], people[3]
	for _, id := range people {
		h.register(id)
	}
	start := h.clock.Now()
	// bob admits carol and not alice; dave is blocked; nobody is the fp
	// of a mailbox that is not there.
	if status, body := h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow",
		h.allowReq(bob, carol.Fingerprint()), nil); status != http.StatusNoContent {
		t.Fatalf("allow: %d %s", status, body)
	}
	if err := h.store.SetBlock(dave.Fingerprint(), "test", alice.Fingerprint(), start); err != nil {
		t.Fatal(err)
	}
	nobody := strings.Repeat("0", 64)
	query := peersQuery(at(bob.Fingerprint(), time.Time{}), at(dave.Fingerprint(), time.Time{}), at(nobody, time.Time{}))

	l := h.list(alice, longHold+"&"+query)
	h.holding(1)
	h.subscribed(mailKey(alice.Fingerprint()), 1)
	for _, fp := range []string{bob.Fingerprint(), dave.Fingerprint(), nobody} {
		if n := h.server.notify.waiting(dirKey(fp)); n != 0 {
			t.Fatalf("alice is subscribed under %s, a peer she may not post to", fp[:8])
		}
	}
	for i := range 3 {
		if status, body, _ := h.pushDirectory(bob, bob, start.Add(time.Duration(i)*time.Second), dflt, bugs); status != http.StatusNoContent {
			t.Fatalf("bob's push %d: %d %s", i, status, body)
		}
		if status, body, _ := h.pushDirectory(dave, dave, start.Add(time.Duration(i)*time.Second), dflt); status != http.StatusForbidden {
			t.Fatalf("dave's push %d: %d %s", i, status, body)
		}
	}
	if l.answered() {
		t.Fatal("a push by a peer the watcher may not post to answered the hold")
	}
	h.holding(1)
	l.cut(t, h)
	// And at the wait, nothing is named, though bob's directory is three
	// issues past what alice said.
	status, resp, body := h.list(alice, "wait=300ms&"+query).answer(t)
	if status != http.StatusOK || resp.DirectoriesChanged != nil || strings.Contains(string(body), "directories_changed") {
		t.Fatalf("the answer names a peer the watcher may not post to: %d %s", status, body)
	}
	// Carol, whom bob admits, is told.
	status, resp, _ = h.list(carol, peersQuery(at(bob.Fingerprint(), time.Time{}))).answer(t)
	if status != http.StatusOK || len(resp.DirectoriesChanged) != 1 {
		t.Fatalf("carol's watch of bob: %d %+v", status, resp)
	}
}

// The peers parameter is checked for its count before any entry is read,
// and for every entry's form before any is looked up.
func TestMoreThanMaxWatchPeersIsRefused(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)
	box := "/v1/mailbox/" + alice.Fingerprint()
	// Distinct fingerprints of mailboxes that are not there: dropped, and
	// the answer is the listing.
	entries := func(n int) []string {
		out := make([]string, n)
		for i := range n {
			out[i] = fmt.Sprintf("%064x", i+1) + ":0"
		}
		return out
	}
	status, body := h.do(alice, "GET", box+"?"+peersQuery(entries(relayapi.MaxWatchPeers)...), nil, nil)
	if status != http.StatusOK {
		t.Fatalf("%d peers: %d %s", relayapi.MaxWatchPeers, status, body)
	}
	status, body = h.do(alice, "GET", box+"?"+peersQuery(entries(relayapi.MaxWatchPeers+1)...), nil, nil)
	if status != http.StatusBadRequest || errorText(t, body) != "too many peers to watch; narrow with --peer" {
		t.Fatalf("%d peers: %d %s", relayapi.MaxWatchPeers+1, status, body)
	}
	// The count is refused before the form is read: a hundred and one
	// pieces of garbage are too many, not malformed.
	garbage := make([]string, relayapi.MaxWatchPeers+1)
	for i := range garbage {
		garbage[i] = "x"
	}
	status, body = h.do(alice, "GET", box+"?"+peersQuery(garbage...), nil, nil)
	if status != http.StatusBadRequest || errorText(t, body) != "too many peers to watch; narrow with --peer" {
		t.Fatalf("too many malformed peers: %d %s", status, body)
	}
	// Prove "before any is looked up" by closing the store: a malformed
	// list is refused with the sentence, where a lookup would be a 500.
	// The mailbox lookup for the caller's own authentication comes
	// first, so the store is closed after the request is signed and a
	// well-formed list is checked to fail on the store.
	for _, bad := range []string{
		"x", alice.Fingerprint(), alice.Fingerprint() + ":", alice.Fingerprint() + ":x",
		alice.Fingerprint() + ":1.5", alice.Fingerprint() + ":1,", "," + alice.Fingerprint() + ":1",
		alice.Fingerprint() + ":1,,", "abc:1", strings.ToUpper(alice.Fingerprint()) + ":1",
		alice.Fingerprint() + ":9223372036854775808", alice.Fingerprint() + ":1:2",
	} {
		status, body := h.do(alice, "GET", box+"?peers="+bad, nil, nil)
		if status != http.StatusBadRequest || errorText(t, body) != "bad peers parameter" {
			t.Fatalf("peers=%s: %d %s", bad, status, body)
		}
	}
	// Every edge of ISSUED that parses: the largest and smallest int64,
	// zero, minus one.
	for _, issued := range []string{"9223372036854775807", "-9223372036854775808", "0", "-1"} {
		status, body := h.do(alice, "GET", box+"?peers="+alice.Fingerprint()+":"+issued, nil, nil)
		if status != http.StatusOK {
			t.Fatalf("peers=self:%s: %d %s", issued, status, body)
		}
	}
	// Present and empty is absent.
	if status, body := h.do(alice, "GET", box+"?peers=", nil, nil); status != http.StatusOK {
		t.Fatalf("peers=: %d %s", status, body)
	}
}

// A listing that asks for nothing new is what it was: the same bytes as
// the v5 client reads in TestAnOldClientReadsThisRelaysAnswers, but for
// the one field every listing now carries, the state of the owner's allow
// list, which a client from before it does not read; and a watch that
// finds nothing changed adds nothing to them.
func TestAListingWithoutWaitIsUnchanged(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	if status, body := h.postTo(bob, alice, ""); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	row, err := h.store.Listing(alice.Fingerprint(), 0, 10, false)
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("the row: %v %+v", err, row)
	}
	// The shape as the client from before the hold reads it, written out
	// here rather than taken from relayapi, so a field added to the
	// response type cannot add itself to both sides of the comparison.
	type v6Message struct {
		ID       int64           `json:"id"`
		Received time.Time       `json:"received"`
		Kind     string          `json:"kind,omitempty"`
		Size     int64           `json:"size,omitempty"`
		Channel  string          `json:"channel"`
		Envelope json.RawMessage `json:"envelope,omitempty"`
	}
	want, err := json.Marshal(struct {
		Messages []v6Message `json:"messages"`
		Queued   int64       `json:"queued"`
		Allow    string      `json:"allow"`
	}{
		Messages: []v6Message{{
			ID: row.Rows[0].ID, Received: row.Rows[0].Received, Kind: row.Rows[0].Kind,
			Size: row.Rows[0].Size, Channel: row.Rows[0].Channel, Envelope: json.RawMessage(row.Rows[0].Envelope),
		}},
		Queued: 1,
		Allow:  "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	for _, query := range []string{"", "?wait=0", "?stubs=0", "?" + peersQuery(at(bob.Fingerprint(), time.Time{})),
		"?wait=30s", "?wait=30s&" + peersQuery(at(bob.Fingerprint(), time.Time{}))} {
		status, body := h.do(alice, "GET", "/v1/mailbox/"+alice.Fingerprint()+query, nil, nil)
		if status != http.StatusOK || string(body) != string(want) {
			t.Fatalf("the listing with %q:\n%s\nwant\n%s", query, body, want)
		}
	}
	// The tag: the zero value has no directories_changed.
	if zero, _ := json.Marshal(relayapi.ListResponse{}); strings.Contains(string(zero), "directories_changed") {
		t.Fatalf("the zero value names the field: %s", zero)
	}
}
