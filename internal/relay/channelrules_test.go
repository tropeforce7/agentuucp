package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A channel's own rules, max_bytes, no_streams and no_forwards, judged by
// channelForPost where the channel's period is, on the post, the stream's
// open and a courier's delivery (PLAN-CHANNEL-POLICY commit 2).

// issuer hands out directory issue times one second apart, behind the
// real clock CheckIssued judges them by, so each push is newer than the
// last.
type issuer struct{ next time.Time }

func newIssuer() *issuer { return &issuer{next: time.Now().Add(-time.Hour).Truncate(time.Second)} }

func (i *issuer) at() time.Time { i.next = i.next.Add(time.Second); return i.next }

// pushRules pushes owner's directory with default and the channels given,
// and fails the test on anything but 204.
func (h *harness) pushRules(owner *identity.Identity, at time.Time, chs ...channels.Channel) {
	h.t.Helper()
	if status, body, _ := h.pushDirectory(owner, owner, at, append([]channels.Channel{dflt}, chs...)...); status != http.StatusNoContent {
		h.t.Fatalf("directory push: %d %s", status, body)
	}
}

// wantRefusal requires a refusal's status, code and exact sentence.
func wantRefusal(t *testing.T, label string, status int, body []byte, wantStatus int, wantCode, wantSentence string) {
	t.Helper()
	e := refusal(t, body)
	if status != wantStatus || e.Code != wantCode || e.Error != wantSentence {
		t.Fatalf("%s: %d %s; want %d %s %q", label, status, body, wantStatus, wantCode, wantSentence)
	}
}

// A channel's max_bytes is the largest message it takes in wire bytes,
// judged where its period is: an inline post of exactly max_bytes is taken
// and one byte over refused 413 channel-size, the post's tokens spent as a
// refused post's are and nothing stored; a stream's open declaring
// max_bytes is taken and one over refused before the posts token, the
// budget unspent and nothing reserved.
func TestAChannelsSizeIsJudgedWhereItsPeriodIs(t *testing.T) {
	t.Run("post", func(t *testing.T) {
		limits := Limits{RequestsPerMinute: 1000, PostsPerMinute: 1000, PostBytesPerHour: 1 << 20}
		h := newHarness(t, Config{Limits: limits})
		people := ids(t, "alice", "bob")
		alice, bob := people[0], people[1]
		h.register(alice)
		h.register(bob)
		fp := bob.Fingerprint()
		iss := newIssuer()

		first := sealedTo(t, alice, bob.Public(), "x", "bug reports")
		h.pushRules(bob, iss.at(), channels.Channel{Name: "bug reports", MaxBytes: int64(len(first))})
		if status, body := h.do(alice, "POST", "/v1/mailbox/"+fp, first, nil); status != http.StatusOK {
			t.Fatalf("a post of exactly max_bytes: %d %s", status, body)
		}

		over := sealedTo(t, alice, bob.Public(), "x", "bug reports")
		n := int64(len(over))
		h.pushRules(bob, iss.at(), channels.Channel{Name: "bug reports", MaxBytes: n - 1})
		a := alice.Fingerprint()
		before := []int64{left(h.server.lim.requests, a), left(h.server.lim.posts, a), left(h.server.lim.postBytes, a)}
		status, body := h.do(alice, "POST", "/v1/mailbox/"+fp, over, nil)
		wantRefusal(t, "a post one byte over max_bytes", status, body, http.StatusRequestEntityTooLarge, relayapi.CodeChannelSize,
			fmt.Sprintf(`channel "bug reports" takes at most %d bytes on the wire; this message is %d`, n-1, n))
		after := []int64{left(h.server.lim.requests, a), left(h.server.lim.posts, a), left(h.server.lim.postBytes, a)}
		// As a closed channel's refusal: the body was read and charged
		// before the allow list, so the request, the post and its bytes are
		// spent and nothing is given back.
		if spent := []int64{before[0] - after[0], before[1] - after[1], before[2] - after[2]}; spent[0] != 1 || spent[1] != 1 || spent[2] != n {
			t.Errorf("the refused post spent %v; want [1 1 %d], what a refused post spends", spent, n)
		}
		if got, _ := h.queued(fp); got != 1 {
			t.Errorf("%d queued; want the one post taken and nothing more", got)
		}
	})

	t.Run("stream", func(t *testing.T) {
		limits := Limits{RequestsPerMinute: 1000, PostsPerMinute: 1000, PostBytesPerHour: 1 << 20, UploadOpensPerHour: 64}
		h := newHarness(t, Config{Limits: limits, MaxStreamBytes: 1 << 20})
		people := ids(t, "alice", "bob")
		alice, bob := people[0], people[1]
		h.register(alice)
		h.register(bob)
		fp := bob.Fingerprint()
		const size = 5000
		h.pushRules(bob, newIssuer().at(), channels.Channel{Name: "logs", MaxBytes: size})

		a := alice.Fingerprint()
		before := []int64{left(h.server.lim.posts, a), left(h.server.lim.postBytes, a), left(h.server.lim.uploadOpens, a)}
		status, _, body := h.openStreamTo(alice, fp, size+1, "logs")
		wantRefusal(t, "an open declaring one byte over max_bytes", status, body, http.StatusRequestEntityTooLarge, relayapi.CodeChannelSize,
			fmt.Sprintf(`channel "logs" takes at most %d bytes on the wire; this message is %d`, size, size+1))
		after := []int64{left(h.server.lim.posts, a), left(h.server.lim.postBytes, a), left(h.server.lim.uploadOpens, a)}
		if before[0] != after[0] || before[1] != after[1] || before[2] != after[2] {
			t.Errorf("the refused open spent posts, bytes, opens %v → %v; want nothing", before, after)
		}
		if n := h.reserved(fp); n != 0 {
			t.Errorf("%d uploads reserved after the refusal; want none", n)
		}
		if status, _, body := h.openStreamTo(alice, fp, size, "logs"); status != http.StatusCreated {
			t.Fatalf("an open declaring exactly max_bytes: %d %s", status, body)
		}
		if n := h.reserved(fp); n != 1 {
			t.Errorf("%d uploads reserved; want the one taken", n)
		}
	})

	t.Run("courier's delivery", func(t *testing.T) {
		c := newChain(t)
		alice := c.a.user(t, "alice")
		bob := c.c.user(t, "bob")
		iss := newIssuer()

		env := sealedFor(bob.Fingerprint(), "two hops")
		env.Ch = "bug reports"
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		n := int64(len(raw))
		// Exactly max_bytes is taken at the last hop.
		c.c.pushRules(bob, iss.at(), channels.Channel{Name: "bug reports", MaxBytes: n})
		if status, _, body := c.a.forward(alice, request(env, []string{"bar", "baz"}, nil)); status != http.StatusCreated {
			t.Fatalf("alice posting: %d %s", status, body)
		}
		c.handOn(t, c.a, "bar")
		c.handOn(t, c.b, "baz")
		if got, _ := c.c.queued(bob.Fingerprint()); got != 1 {
			t.Fatalf("%d delivered at exactly max_bytes; want 1", got)
		}

		// One byte over is refused at the delivery, and the refusal travels
		// back to the sender as a report with the channel's sentence.
		env2 := sealedFor(bob.Fingerprint(), "two hop2")
		env2.Ch = "bug reports"
		c.c.pushRules(bob, iss.at(), channels.Channel{Name: "bug reports", MaxBytes: n - 1})
		status, answer, body := c.a.forward(alice, request(env2, []string{"bar", "baz"}, nil))
		if status != http.StatusCreated {
			t.Fatalf("alice posting: %d %s", status, body)
		}
		c.handOn(t, c.a, "bar")
		c.handOn(t, c.b, "baz")
		c.handOn(t, c.b, "alpha")
		want := fmt.Sprintf(`channel "bug reports" takes at most %d bytes on the wire; this message is %d`, n-1, n)
		aFinal := c.a.outbound(t, answer.ID)
		if aFinal.State != OutFinal || aFinal.Code != relayapi.CodeRefused || aFinal.Said != "bar: baz: "+want {
			t.Fatalf("A's row: %s/%s %q; want final/refused %q", aFinal.State, aFinal.Code, aFinal.Said, "bar: baz: "+want)
		}
		if got, _ := c.c.queued(bob.Fingerprint()); got != 1 {
			t.Errorf("%d delivered; want only the first", got)
		}
	})
}

// A channel that takes no streams refuses the open 403 channel-streams
// before any charge, and takes an inline post and a courier's delivery,
// neither of which is a stream.
func TestAChannelThatTakesNoStreamsRefusesTheOpenAndTakesThePost(t *testing.T) {
	limits := Limits{RequestsPerMinute: 1000, PostsPerMinute: 1000, PostBytesPerHour: 1 << 20, UploadOpensPerHour: 64}
	h := newHarness(t, Config{Limits: limits})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	fp := bob.Fingerprint()
	h.pushRules(bob, newIssuer().at(), channels.Channel{Name: "notes", NoStreams: true}, channels.Channel{Name: "logs"})

	a := alice.Fingerprint()
	before := []int64{left(h.server.lim.posts, a), left(h.server.lim.postBytes, a), left(h.server.lim.uploadOpens, a)}
	status, _, body := h.openStreamTo(alice, fp, 5000, "notes")
	wantRefusal(t, "an open to a channel that takes no streams", status, body, http.StatusForbidden, relayapi.CodeChannelStreams,
		`channel "notes" takes no streams`)
	after := []int64{left(h.server.lim.posts, a), left(h.server.lim.postBytes, a), left(h.server.lim.uploadOpens, a)}
	if before[0] != after[0] || before[1] != after[1] || before[2] != after[2] {
		t.Errorf("the refused open spent posts, bytes, opens %v → %v; want nothing", before, after)
	}
	if n := h.reserved(fp); n != 0 {
		t.Errorf("%d uploads reserved; want none", n)
	}
	if status, body := h.postTo(alice, bob, "notes"); status != http.StatusOK {
		t.Fatalf("an inline post to the channel: %d %s", status, body)
	}
	if status, _, body := h.openStreamTo(alice, fp, 5000, "logs"); status != http.StatusCreated {
		t.Fatalf("an open to a channel without the rule: %d %s", status, body)
	}

	// A courier's delivery is an envelope, not a stream.
	c := newChain(t)
	carol := c.a.user(t, "carol")
	dave := c.c.user(t, "dave")
	c.c.pushRules(dave, newIssuer().at(), channels.Channel{Name: "notes", NoStreams: true})
	env := sealedFor(dave.Fingerprint(), "by courier")
	env.Ch = "notes"
	if status, _, body := c.a.forward(carol, request(env, []string{"bar", "baz"}, nil)); status != http.StatusCreated {
		t.Fatalf("carol posting: %d %s", status, body)
	}
	c.handOn(t, c.a, "bar")
	c.handOn(t, c.b, "baz")
	if got, _ := c.c.queued(dave.Fingerprint()); got != 1 {
		t.Fatalf("%d delivered to a channel that takes no streams; want the envelope", got)
	}
}

// A channel that takes no forwards refuses a courier's delivery 403
// channel-forwards before the carried share is charged, the report carried
// back to the sender with the sentence; a direct post and a direct open to
// the same channel are taken, and a delivery to a channel without the rule
// is taken.
func TestAChannelThatTakesNoForwardsRefusesTheDeliveryAndTakesThePost(t *testing.T) {
	c := newChain(t)
	alice := c.a.user(t, "alice")
	bob := c.c.user(t, "bob")
	local := c.c.user(t, "local")
	c.c.pushRules(bob, newIssuer().at(), channels.Channel{Name: "inbox", NoForwards: true}, channels.Channel{Name: "open"})

	// The delivery, refused at C. The courier B posted with is charged
	// nothing at C for the hash it did not write.
	bc := c.bCourier.Public().Fingerprint()
	beforeCarried := left(c.c.server.lim.courierCarried, bc)
	env := sealedFor(bob.Fingerprint(), "by courier")
	env.Ch = "inbox"
	status, answer, body := c.a.forward(alice, request(env, []string{"bar", "baz"}, nil))
	if status != http.StatusCreated {
		t.Fatalf("alice posting: %d %s", status, body)
	}
	c.handOn(t, c.a, "bar")
	bRow := c.b.onlyOutbound(t, OutWaiting)
	c.handOn(t, c.b, "baz")
	want := `channel "inbox" takes no mail by way of another relay`
	if bFinal := c.b.outbound(t, bRow.ID); bFinal.State != OutFinal || bFinal.Said != "baz: "+want {
		t.Fatalf("B's row: %s %q; want final %q", bFinal.State, bFinal.Said, "baz: "+want)
	}
	if got := left(c.c.server.lim.courierCarried, bc); got != beforeCarried {
		t.Errorf("the refused delivery charged the courier's carried share: %d → %d", beforeCarried, got)
	}
	c.handOn(t, c.b, "alpha")
	aFinal := c.a.outbound(t, answer.ID)
	if aFinal.State != OutFinal || aFinal.Code != relayapi.CodeRefused || aFinal.Said != "bar: baz: "+want {
		t.Fatalf("A's row: %s/%s %q; want final/refused %q", aFinal.State, aFinal.Code, aFinal.Said, "bar: baz: "+want)
	}
	if queued := c.a.queueOf(t, alice); len(queued) != 1 || queued[0].Said != aFinal.Said {
		t.Fatalf("alice's queue: %+v", queued)
	}
	if got, _ := c.c.queued(bob.Fingerprint()); got != 0 {
		t.Fatalf("%d delivered to a channel that takes no forwards; want none", got)
	}

	// What the route writes when C is asked directly, by the courier: the
	// status and the code.
	direct := sealedFor(bob.Fingerprint(), "direct")
	direct.Ch = "inbox"
	status, _, body = c.c.forward(c.bCourier, request(direct, []string{}, []string{"alpha"}))
	wantRefusal(t, "a courier's delivery to a channel that takes no forwards", status, body,
		http.StatusForbidden, relayapi.CodeChannelForwards, want)

	// A post and an open by a user of C's own, to the same channel.
	if status, body := c.c.postTo(local, bob, "inbox"); status != http.StatusOK {
		t.Fatalf("a direct post: %d %s", status, body)
	}
	if status, _, body := c.c.openStreamTo(local, bob.Fingerprint(), 5000, "inbox"); status != http.StatusCreated {
		t.Fatalf("a direct open: %d %s", status, body)
	}
	// And a delivery to a channel without the rule.
	other := sealedFor(bob.Fingerprint(), "other")
	other.Ch = "open"
	if status, _, body := c.a.forward(alice, request(other, []string{"bar", "baz"}, nil)); status != http.StatusCreated {
		t.Fatalf("alice posting: %d %s", status, body)
	}
	c.handOn(t, c.a, "bar")
	c.handOn(t, c.b, "baz")
	if got, _ := c.c.queued(bob.Fingerprint()); got != 2 {
		t.Fatalf("%d queued for bob; want the direct post and the delivery to the open channel", got)
	}
}

// A channel's max_bytes is held at the push to the most this relay takes
// of any kind, the larger of max_bytes and max_stream_bytes, with
// max_stream_bytes 0 meaning the protocol's MaxStreamSize: at the ceiling
// taken, one over refused 400 naming the channel, the value and the
// relay's number, and nothing stored. And a stored directory naming more
// than the relay now takes, as one pushed before the operator lowered the
// caps, loosens nothing: each route's own cap is judged first.
func TestLimitAChannelsMaxBytesIsHeldToTheRelays(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cfg           Config
		ceiling       int64
		oneOverSigned bool
	}{
		{"max_stream_bytes the larger", Config{MaxBytes: 2048, MaxStreamBytes: 100000}, 100000, true},
		{"max_bytes the larger", Config{MaxBytes: 60000, MaxStreamBytes: 10000}, 60000, true},
		{"max_stream_bytes unlimited", Config{MaxBytes: 2048}, relayapi.MaxStreamSize, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.cfg)
			bob := ids(t, "bob")[0]
			h.register(bob)
			fp := bob.Fingerprint()
			iss := newIssuer()
			h.pushRules(bob, iss.at(), channels.Channel{Name: "logs", MaxBytes: tc.ceiling})
			kept, _, _, _ := h.store.Directory(fp)
			if !tc.oneOverSigned {
				// One over MaxStreamSize is refused by Validate before any
				// relay sees it (TestLimitChannelMaxBytes).
				return
			}
			status, body, _ := h.pushDirectory(bob, bob, iss.at(), dflt, channels.Channel{Name: "logs", MaxBytes: tc.ceiling + 1})
			if status != http.StatusBadRequest {
				t.Fatalf("a push one over the ceiling: %d %s", status, body)
			}
			if got, want := errorText(t, body), fmt.Sprintf(`channel "logs": max_bytes %d is over the %d this relay takes`, tc.ceiling+1, tc.ceiling); got != want {
				t.Fatalf("the refusal is %q; want %q", got, want)
			}
			if doc, _, _, _ := h.store.Directory(fp); string(doc) != string(kept) {
				t.Fatal("a refused directory replaced the stored one")
			}
		})
	}

	t.Run("a stored directory over the caps loosens nothing", func(t *testing.T) {
		h := newHarness(t, Config{MaxBytes: 8192, MaxStreamBytes: 20000})
		people := ids(t, "alice", "bob")
		alice, bob := people[0], people[1]
		h.register(alice)
		h.register(bob)
		fp := bob.Fingerprint()
		// Signed and stored as a relay with higher caps took it, through
		// the store, as the same database under a restarted relay holds it.
		d := &channels.Directory{Issued: newIssuer().at(), Channels: []channels.Channel{dflt, {Name: "logs", MaxBytes: 1 << 30}}}
		doc, sig, err := channels.Sign(bob, d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.store.SetDirectory(fp, d, doc, sig); err != nil {
			t.Fatal(err)
		}
		// The post at the relay's own cap taken, one over refused by the
		// relay's cap and not the channel's.
		inline := h.server.inlineMax()
		for _, tc := range []struct {
			size int64
			ok   bool
		}{{inline, true}, {inline + 1, false}} {
			env := paddedTo(t, alice, bob, "logs", int(tc.size))
			status, body := h.do(alice, "POST", "/v1/mailbox/"+fp, env, nil)
			switch {
			case tc.ok && status != http.StatusOK:
				t.Fatalf("a post at the relay's max_bytes: %d %s", status, body)
			case !tc.ok && (status != http.StatusRequestEntityTooLarge || refusal(t, body).Code == relayapi.CodeChannelSize):
				t.Fatalf("a post one over the relay's max_bytes: %d %s; want the relay's own refusal", status, body)
			}
		}
		if status, _, body := h.openStreamTo(alice, fp, 20000, "logs"); status != http.StatusCreated {
			t.Fatalf("an open at the relay's max_stream_bytes: %d %s", status, body)
		}
		status, _, body := h.openStreamTo(alice, fp, 20001, "logs")
		if status != http.StatusForbidden || errorText(t, body) != "stream is 20001 bytes; this relay's max_stream_bytes is 20000" {
			t.Fatalf("an open one over the relay's max_stream_bytes: %d %s; want the relay's own refusal", status, body)
		}
	})
}

// paddedTo is an envelope for a channel whose encoding is exactly size
// bytes, padded at the front of its ciphertext, which the relay does not
// read beyond its encoding.
func paddedTo(t *testing.T, from, to *identity.Identity, ch string, size int) []byte {
	t.Helper()
	base := string(sealedTo(t, from, to.Public(), "", ch))
	grow := size - len(base)
	if grow < 0 || !strings.Contains(base, `"ct":"`) {
		t.Fatalf("an envelope of %d bytes cannot be padded to %d", len(base), size)
	}
	// Whole base64 groups on the ciphertext, the rest as JSON whitespace
	// after the opening brace.
	padded := strings.Replace(base, `"ct":"`, `"ct":"`+strings.Repeat("A", grow-grow%4), 1)
	out := []byte("{" + strings.Repeat(" ", grow%4) + padded[1:])
	if len(out) != size {
		t.Fatalf("padded to %d bytes, want %d", len(out), size)
	}
	return out
}

// A stored directory edited to loosen a channel, its max_bytes raised and
// its no_streams cleared through the store's own handle, does not verify:
// the mailbox closes, every post refused with the closed mailbox's
// sentence, and the owner's push is the whole repair.
func TestADirectoryEditedToLoosenAChannelClosesTheMailbox(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	fp := bob.Fingerprint()
	iss := newIssuer()
	h.pushRules(bob, iss.at(), channels.Channel{Name: "notes", MaxBytes: 1, NoStreams: true})

	var doc string
	if err := h.store.db.QueryRow(`SELECT doc FROM directories WHERE fp = ?`, fp).Scan(&doc); err != nil {
		t.Fatal(err)
	}
	loose := strings.Replace(doc, `"max_bytes":1,`, `"max_bytes":1000000,`, 1)
	loose = strings.Replace(loose, `"no_streams":true`, `"no_streams":false`, 1)
	if loose == doc || !strings.Contains(loose, `"max_bytes":1000000,`) || !strings.Contains(loose, `"no_streams":false`) {
		t.Fatalf("the edit did not take: %s", doc)
	}
	if _, err := h.store.db.Exec(`UPDATE directories SET doc = ? WHERE fp = ?`, loose, fp); err != nil {
		t.Fatal(err)
	}
	for _, ch := range []string{"notes", channels.Default} {
		status, body := h.postTo(alice, bob, ch)
		if status != http.StatusNotFound || errorText(t, body) != fmt.Sprintf("no such channel %q", ch) {
			t.Fatalf("a post to %q under the edited directory: %d %s; want the closed mailbox's refusal", ch, status, body)
		}
	}
	if status, _, body := h.openStreamTo(alice, fp, 5000, "notes"); status != http.StatusNotFound {
		t.Fatalf("an open under the edited directory: %d %s; want the closed mailbox's refusal", status, body)
	}
	// The owner's push repairs it, with the rules as signed.
	h.pushRules(bob, iss.at(), channels.Channel{Name: "notes", MaxBytes: 1, NoStreams: true})
	status, body := h.postTo(alice, bob, "notes")
	if status != http.StatusRequestEntityTooLarge || refusal(t, body).Code != relayapi.CodeChannelSize {
		t.Fatalf("a post after the repair: %d %s; want the signed max_bytes", status, body)
	}
	if status, body := h.postTo(alice, bob, channels.Default); status != http.StatusOK {
		t.Fatalf("a post to default after the repair: %d %s", status, body)
	}
}

// A rule the owner sets under an open upload refuses it (R22, R12), at the
// start of an attempt, a first or a resume, and at the placement of an
// attempt already copying, with the code and the sentence the open would
// now get, and the upload is gone. Two rules: max_bytes lowered below the
// stream's size, and no_streams set.
func TestAChannelRuleSetUnderAnUploadRefusesIt(t *testing.T) {
	type rule struct {
		name   string
		ch     func(size int64) channels.Channel
		status int
		code   string
		want   func(size int64) string
	}
	rules := []rule{
		{"max_bytes lowered", func(size int64) channels.Channel { return channels.Channel{Name: "logs", MaxBytes: size - 1} },
			http.StatusRequestEntityTooLarge, relayapi.CodeChannelSize,
			func(size int64) string {
				return fmt.Sprintf(`channel "logs" takes at most %d bytes on the wire; this message is %d`, size-1, size)
			}},
		{"no_streams set", func(int64) channels.Channel { return channels.Channel{Name: "logs", NoStreams: true} },
			http.StatusForbidden, relayapi.CodeChannelStreams,
			func(int64) string { return `channel "logs" takes no streams` }},
	}
	setup := func(t *testing.T) (*revocationCase, *issuer, string) {
		c := newRevocationCase(t, Config{MaxBytes: 2048, StallTimeout: time.Minute})
		iss := newIssuer()
		c.h.pushRules(c.owner, iss.at(), channels.Channel{Name: "logs", MaxBytes: int64(len(c.blob))})
		return c, iss, c.open("logs")
	}
	check := func(t *testing.T, c *revocationCase, r rule, status int, body []byte) {
		t.Helper()
		size := int64(len(c.blob))
		wantRefusal(t, "an attempt under the new rule", status, body, r.status, r.code, r.want(size))
		if n := len(c.listed()); n != 0 {
			t.Errorf("the channel took %d messages under its new rule; want none", n)
		}
	}
	for _, r := range rules {
		for _, kept := range []int{0, 2500} {
			t.Run(fmt.Sprintf("%s, at the start, offset %d", r.name, kept), func(t *testing.T) {
				c, iss, id := setup(t)
				if kept > 0 {
					c.keep(id, kept)
				}
				c.h.pushRules(c.owner, iss.at(), r.ch(int64(len(c.blob))))
				status, body, _, _ := c.h.putHeadOnly(c.sender, id, len(c.blob), kept, 5*time.Second)
				check(t, c, r, status, body)
				c.gone(id, "after the refusal")
			})
		}
		t.Run(r.name+", during an attempt", func(t *testing.T) {
			c, iss, id := setup(t)
			status, body := c.h.putBetween(c.sender, id, c.blob, 0, between(0), func() {
				c.h.pushRules(c.owner, iss.at(), r.ch(int64(len(c.blob))))
			})
			check(t, c, r, status, body)
			c.gone(id, "after the placement was refused")
		})
	}
}

// The access log says nothing of a channel's rule: no limit= for these
// refusals, which are not rate limits, and no channel's name, under either
// mode.
func TestARulesRefusalIsNotLoggedAsALimit(t *testing.T) {
	for _, mode := range []string{AccessLogFull, AccessLogMinimal} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, Config{AccessLog: mode})
			people := ids(t, "alice", "bob")
			alice, bob := people[0], people[1]
			h.register(alice)
			h.register(bob)
			h.pushRules(bob, newIssuer().at(), channels.Channel{Name: "secret-name", MaxBytes: 1, NoStreams: true})
			if status, body := h.postTo(alice, bob, "secret-name"); status != http.StatusRequestEntityTooLarge {
				t.Fatalf("the post: %d %s", status, body)
			}
			if status, _, body := h.openStreamTo(alice, bob.Fingerprint(), 5000, "secret-name"); status != http.StatusForbidden {
				t.Fatalf("the open: %d %s", status, body)
			}
			logs := h.logs.String()
			if strings.Contains(logs, "secret-name") {
				t.Errorf("the log names the channel:\n%s", logs)
			}
			if strings.Contains(logs, "limit=") {
				t.Errorf("the log calls a channel's rule a limit:\n%s", logs)
			}
		})
	}
}
