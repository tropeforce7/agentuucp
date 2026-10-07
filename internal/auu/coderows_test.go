package auu

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
)

// Each refusal here is the real relay's, written with its code, and each
// test is of what the client does on the code: the relay in front of the
// command is the one in internal/relay, started in-process, so a relay that
// wrote the sentence without its code would fail the test.

// TestAKnockToACouriersMailboxIsAdvised: a knock to a mailbox that belongs to
// a neighbouring relay's courier is refused at internal/relay/knockapi.go:92
// (the s.isCourierMailbox branch) with RefusalNoKnocks, and the client reads
// the code and gives the advice knockHint gives.
//
// The courier's own card says it takes knocks, so that the branch for a card
// that says no (knockapi.go:104) cannot be the one that answered: only the
// couriers file makes this mailbox one that takes none.
func TestAKnockToACouriersMailboxIsAdvised(t *testing.T) {
	relayURL, _ := accepting(t, "zed")
	alice := newUser(t, "alice", relayURL)
	// The courier enrols at this relay as any identity does, and its card
	// says it takes knocks.
	courier := newUser(t, "alpha", relayURL)
	courier.run("card", "push", "--listed", "--knocks")
	_, courierID, _ := courier.opened()
	fp := courier.exportFingerprint()

	// Before the operator's line, the knock is the ordinary kind's to
	// answer, and a card that takes knocks takes it: the setting is sound.
	// The look is answered n, so nothing is sent.
	atTerminal(t)
	if out, err := alice.answer("n", "knock", fp); err != nil || !strings.Contains(out, "nothing sent") {
		t.Fatalf("a knock looked at before the courier line: %v\n%s", err, out)
	}

	// The operator adds the courier's line, and its mailbox is a courier's
	// from the next request on.
	rewriteCouriers(t, relayURL, []*identity.Identity{courierID})

	_, err := alice.answer("y\nAlpha", "knock", fp)
	var e *exitError
	if !errors.As(err, &e) || e.code != exitTransport ||
		!strings.Contains(err.Error(), "the recipient does not take knocks") ||
		!strings.Contains(err.Error(), "card push --knocks") {
		t.Fatalf("a knock to a courier's mailbox: %v", err)
	}
	if names := alice.peerNames(); len(names) != 0 {
		t.Fatalf("a refused knock added %v", names)
	}
}

// rowC6Proxy sits in front of a real relay and passes every request and
// answer through, counting each request by method and path and keeping each
// answer's status. The one thing it changes is Retry-After on a 429, which it
// sets to one second: that does not change what the client decides on, the
// status and the code, and it bounds how long a client that ignored the code
// would sleep through its retries to seconds rather than minutes.
type rowC6Proxy struct {
	mu       sync.Mutex
	asked    map[string]int
	statuses map[string][]int
}

func rowC6Behind(t *testing.T, relayURL string) (string, *rowC6Proxy) {
	t.Helper()
	target, err := url.Parse(relayURL)
	if err != nil {
		t.Fatal(err)
	}
	p := &rowC6Proxy{asked: map[string]int{}, statuses: map[string][]int{}}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = func(resp *http.Response) error {
		key := resp.Request.Method + " " + resp.Request.URL.Path
		p.mu.Lock()
		p.statuses[key] = append(p.statuses[key], resp.StatusCode)
		p.mu.Unlock()
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Header.Set("Retry-After", "1")
		}
		return nil
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.asked[r.Method+" "+r.URL.Path]++
		p.mu.Unlock()
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, p
}

func (p *rowC6Proxy) count(key string) (int, []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.asked[key], append([]int(nil), p.statuses[key]...)
}

// TestAPostOverTheWholeBudgetIsAskedOnce: a message larger than a sender's
// whole post_bytes_per_hour budget is refused at internal/relay/server.go:1215
// (handlePost's rateLimitedCode with CodeOverBudget), and the client, reading
// the code, asks once and stops: without it doWithin retries a 429 three more
// times, four asks in all.
func TestAPostOverTheWholeBudgetIsAskedOnce(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.PostBytesPerHour = 1 << 10 // smaller than the message
	proxyURL, proxy := rowC6Behind(t, startRelayWith(t, limits))
	alice := newUser(t, "alice", proxyURL)
	bob := newUser(t, "bob", proxyURL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	bob.run("allow", "push")

	// Well under the inline limit, so it goes as one post and not a stream,
	// and well over the whole budget.
	text := strings.Repeat("x", 8<<10)
	out, err := alice.tryRun("send", "--to", "bob", text)
	if err == nil {
		t.Fatalf("a message over the whole byte budget was accepted:\n%s", out)
	}
	if !strings.Contains(err.Error(), "post_bytes_per_hour") {
		t.Fatalf("the refusal does not name the setting: %v", err)
	}
	asked, statuses := proxy.count("POST /v1/mailbox/" + bob.exportFingerprint())
	if asked != 1 {
		t.Fatalf("the post route was asked %d times (statuses %v), want once: "+
			"a refusal no wait lets through is not retried", asked, statuses)
	}
	if len(statuses) != 1 || statuses[0] != http.StatusTooManyRequests {
		t.Fatalf("the relay answered %v, want one 429", statuses)
	}
}

// rowC6Planted is the newer document another machine of this identity
// pushed: a time an hour from now, on a whole second as RFC 3339 shows it.
func rowC6Planted() time.Time {
	return time.Now().Add(time.Hour).Truncate(time.Second)
}

// TestAPushOlderThanTheHeldAllowListSaysWhenThatWasIssued: the relay holds an
// allow list issued later than this machine's clock, pushed by another
// machine of the same identity, and refuses the push at
// internal/relay/allowapi.go:92 with a 409, CodeNewerAllowList and the held
// list's issued time in at. The client reads the code and shows the time in
// this zone; nothing is read out of the sentence.
func TestAPushOlderThanTheHeldAllowListSaysWhenThatWasIssued(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)
	bob := newUser(t, "bob", relayURL)
	alice.run("peers", "add", bob.exportLine())

	// The other machine: the same identity, its own client, a clock ahead.
	s, id, relays := alice.opened()
	issued := rowC6Planted()
	doc, sig, err := allowlist.Sign(id, &allowlist.Document{Issued: issued, Senders: []string{bob.exportFingerprint()}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(s, id, relays[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetAllowlist(ctx(), doc, sig); err != nil {
		t.Fatal(err)
	}

	_, err = alice.tryRun("allow", "push")
	var e *exitError
	want := relays[0].Name + ": holds a newer allow list, issued " + stampLocal(issued) +
		", from another machine of yours; 'auu allow show --relay " + relays[0].Name + "' shows it"
	if !errors.As(err, &e) || e.code != exitTransport || err.Error() != want {
		t.Fatalf("a push older than the held list:\n%v\nwant\n%s", err, want)
	}
}

// TestAPushOlderThanTheHeldCardSaysWhenThatWasIssued: the same for a card,
// refused at internal/relay/cardapi.go:77 with CodeNewerCard and at.
func TestAPushOlderThanTheHeldCardSaysWhenThatWasIssued(t *testing.T) {
	relayURL := startRelay(t)
	alice := newUser(t, "alice", relayURL)

	s, id, relays := alice.opened()
	issued := rowC6Planted()
	doc, sig, err := card.Sign(id, &card.Document{Name: id.Name, Listed: true, Issued: issued})
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(s, id, relays[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetCard(ctx(), doc, sig); err != nil {
		t.Fatal(err)
	}

	_, err = alice.tryRun("card", "push", "--knocks")
	var e *exitError
	want := relays[0].Name + ": holds a newer card, issued " + stampLocal(issued) +
		", from another machine of yours; 'auu card show --relay " + relays[0].Name + "' shows it"
	if !errors.As(err, &e) || e.code != exitTransport || err.Error() != want {
		t.Fatalf("a push older than the held card:\n%v\nwant\n%s", err, want)
	}
}
