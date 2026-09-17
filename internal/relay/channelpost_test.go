package relay

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// sealedTo is sealed with the outer ch set, which is what a client sending
// with --channel puts on the wire. The outer field is outside the seal, so
// setting it after sealing is exactly what the relay sees.
func sealedTo(t *testing.T, from *identity.Identity, to *identity.Public, text, ch string) []byte {
	t.Helper()
	var env envelope.Envelope
	if err := json.Unmarshal(sealed(t, from, to, text), &env); err != nil {
		t.Fatal(err)
	}
	env.Ch = ch
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// postTo posts an envelope for a channel; ch empty means none named.
func (h *harness) postTo(from *identity.Identity, to *identity.Identity, ch string) (int, []byte) {
	h.t.Helper()
	return h.do(from, "POST", "/v1/mailbox/"+to.Fingerprint(), sealedTo(h.t, from, to.Public(), "x", ch), nil)
}

// openStreamTo opens a stream for a channel; ch empty means none named.
func (h *harness) openStreamTo(from *identity.Identity, toFP string, size int64, ch string) (int, relayapi.OpenStreamResponse, []byte) {
	h.t.Helper()
	status, body, _ := h.send(from, "POST", "/v1/mailbox/"+toFP+"/streams",
		relayapi.OpenStreamRequest{Size: size, Channel: ch}, nil)
	var out relayapi.OpenStreamResponse
	if status == http.StatusCreated {
		if err := json.Unmarshal(body, &out); err != nil {
			h.t.Fatal(err)
		}
	}
	return status, out, body
}

// reserved is how many uploads are open for a mailbox.
func (h *harness) reserved(fp string) int {
	h.t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads WHERE to_fp = ?`, fp).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// The channel check, for a post and for a stream open, at every edge of a
// period and with each bound absent, against the relay's own clock. Each
// refusal queues and reserves nothing; each acceptance files the message
// under its name.
func TestAPostIsCheckedAgainstTheChannel(t *testing.T) {
	for _, kind := range []string{"post", "stream"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, Config{})
			people := ids(t, "alice", "bob")
			alice, bob := people[0], people[1]
			for _, id := range people {
				h.register(id)
			}
			fp := bob.Fingerprint()
			start := h.clock.Now() // 2026-09-06T12:00:00Z
			opens, closes := start.Add(time.Second), start.Add(3*time.Second)
			if status, body, _ := h.pushDirectory(bob, bob, start, dflt,
				channels.Channel{Name: "cfp", NotBefore: &opens, NotAfter: &closes},
				channels.Channel{Name: "early", NotAfter: &closes},
				channels.Channel{Name: "late", NotBefore: &opens}); status != http.StatusNoContent {
				t.Fatalf("push: %d %s", status, body)
			}

			// try posts or opens for a channel and returns the status and
			// the error text.
			try := func(ch string) (int, string) {
				t.Helper()
				var status int
				var body []byte
				if kind == "post" {
					status, body = h.postTo(alice, bob, ch)
				} else {
					status, _, body = h.openStreamTo(alice, fp, 5000, ch)
				}
				if status == http.StatusOK || status == http.StatusCreated {
					return status, ""
				}
				return status, errorText(t, body)
			}
			accepted := http.StatusOK
			if kind == "stream" {
				accepted = http.StatusCreated
			}
			var okCount, reservedCount int
			expect := func(label, ch string, status int, want string) {
				t.Helper()
				got, text := try(ch)
				if got != status || text != want {
					t.Fatalf("%s: %d %q, want %d %q", label, got, text, status, want)
				}
				if status == accepted {
					if kind == "post" {
						okCount++
					} else {
						reservedCount++
					}
				}
				if n, _ := h.queued(fp); n != int64(okCount) {
					t.Fatalf("%s: %d queued, want %d", label, n, okCount)
				}
				if n := h.reserved(fp); n != reservedCount {
					t.Fatalf("%s: %d uploads reserved, want %d", label, n, reservedCount)
				}
			}

			expect("a channel that is not there", "bugs", http.StatusNotFound, `no such channel "bugs"`)
			expect("one second before not_before", "cfp", http.StatusForbidden,
				`channel "cfp" is not open: opens 2026-09-06T12:00:01Z`)
			expect("no not_before, before the other bound", "early", accepted, "")
			expect("no not_after, before not_before", "late", http.StatusForbidden,
				`channel "late" is not open: opens 2026-09-06T12:00:01Z`)
			h.clock.advance(time.Second)
			expect("at not_before", "cfp", accepted, "")
			expect("no not_after, at not_before", "late", accepted, "")
			h.clock.advance(2 * time.Second)
			expect("at not_after", "cfp", accepted, "")
			expect("no not_before, at not_after", "early", accepted, "")
			h.clock.advance(time.Second)
			expect("one second after not_after", "cfp", http.StatusForbidden,
				`channel "cfp" is not open: closed 2026-09-06T12:00:03Z`)
			expect("no not_before, after not_after", "early", http.StatusForbidden,
				`channel "early" is not open: closed 2026-09-06T12:00:03Z`)
			expect("no not_after, long after not_before", "late", accepted, "")
			expect("no channel named, with default listed", "", accepted, "")
			expect("default by name", channels.Default, accepted, "")
			expect("a name too long for any directory", strings.Repeat("c", 65), http.StatusBadRequest,
				"channel name is 65 bytes; at most 64")
			expect("a name no directory could hold", "cfp\x1b[2J", http.StatusBadRequest,
				"channel name contains U+001B, a control character")
			expect("case is not folded", "CFP", http.StatusNotFound, `no such channel "CFP"`)

			if kind == "post" {
				// The rows carry the names they were accepted under.
				l, err := h.store.Listing(fp, 0, 100, false)
				if err != nil {
					t.Fatal(err)
				}
				want := []string{"early", "cfp", "late", "cfp", "early", "late", "default", "default"}
				if len(l.Rows) != len(want) {
					t.Fatalf("%d rows, want %d", len(l.Rows), len(want))
				}
				for i, row := range l.Rows {
					if row.Channel != want[i] {
						t.Errorf("row %d is under %q, want %q", i, row.Channel, want[i])
					}
				}
			}
		})
	}
}

// A mailbox with no directory has default and nothing else; one whose
// directory leaves default out refuses a post that names nothing.
func TestAPostThatNamesNoChannelGoesToDefault(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	fp := bob.Fingerprint()

	// No directory: nothing named is default, and a name is not there.
	if status, body := h.postTo(alice, bob, ""); status != http.StatusOK {
		t.Fatalf("a post naming nothing, no directory: %d %s", status, body)
	}
	if status, body := h.postTo(alice, bob, "bugs"); status != http.StatusNotFound ||
		errorText(t, body) != `no such channel "bugs"` {
		t.Fatalf("a post to a name, no directory: %d %s", status, body)
	}
	if status, _, body := h.openStreamTo(alice, fp, 5000, ""); status != http.StatusCreated {
		t.Fatalf("a stream naming nothing, no directory: %d %s", status, body)
	}
	if status, _, body := h.openStreamTo(alice, fp, 5000, "bugs"); status != http.StatusNotFound ||
		errorText(t, body) != `no such channel "bugs"` {
		t.Fatalf("a stream to a name, no directory: %d %s", status, body)
	}

	// A directory without default.
	if status, body, _ := h.pushDirectory(bob, bob, h.clock.Now(), bugs); status != http.StatusNoContent {
		t.Fatalf("push: %d %s", status, body)
	}
	if status, body := h.postTo(alice, bob, ""); status != http.StatusNotFound ||
		errorText(t, body) != `no such channel "default"` {
		t.Fatalf("a post naming nothing, default removed: %d %s", status, body)
	}
	if status, _, body := h.openStreamTo(alice, fp, 5000, ""); status != http.StatusNotFound ||
		errorText(t, body) != `no such channel "default"` {
		t.Fatalf("a stream naming nothing, default removed: %d %s", status, body)
	}
	if status, body := h.postTo(alice, bob, "bug reports"); status != http.StatusOK {
		t.Fatalf("a post to the listed channel: %d %s", status, body)
	}
	if n, _ := h.queued(fp); n != 2 {
		t.Fatalf("%d queued, want 2", n)
	}
}

// The allow list and the block decide before anything about channels is
// said: a sender the owner has not admitted is refused with the allow
// list's sentence for a channel that does not exist, and so is anyone for a
// blocked mailbox.
func TestTheAllowListDecidesBeforeTheChannel(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	for _, id := range people {
		h.register(id)
	}
	fp := bob.Fingerprint()
	if status, body := h.do(bob, "PUT", "/v1/mailbox/"+fp+"/allow",
		h.allowReq(bob, alice.Fingerprint()), nil); status != http.StatusNoContent {
		t.Fatalf("allow push: %d %s", status, body)
	}
	const allow = "sender is not on the recipient's allow list"
	if status, body := h.postTo(carol, bob, "nothing here"); status != http.StatusForbidden || errorText(t, body) != allow {
		t.Fatalf("a refused sender's post to a missing channel: %d %s", status, body)
	}
	if status, _, body := h.openStreamTo(carol, fp, 5000, "nothing here"); status != http.StatusForbidden || errorText(t, body) != allow {
		t.Fatalf("a refused sender's stream to a missing channel: %d %s", status, body)
	}
	// And the admitted sender gets the channel's answer for the same name.
	if status, body := h.postTo(alice, bob, "nothing here"); status != http.StatusNotFound ||
		errorText(t, body) != `no such channel "nothing here"` {
		t.Fatalf("an admitted sender's post to a missing channel: %d %s", status, body)
	}

	if err := h.store.SetBlock(fp, "spam", carol.Fingerprint(), time.Now()); err != nil {
		t.Fatal(err)
	}
	const blocked = "recipient is blocked on this relay"
	if status, body := h.postTo(alice, bob, "nothing here"); status != http.StatusForbidden || errorText(t, body) != blocked {
		t.Fatalf("a post to a blocked mailbox's missing channel: %d %s", status, body)
	}
	if status, _, body := h.openStreamTo(alice, fp, 5000, "nothing here"); status != http.StatusForbidden || errorText(t, body) != blocked {
		t.Fatalf("a stream to a blocked mailbox's missing channel: %d %s", status, body)
	}
	if n, _ := h.queued(fp); n != 0 {
		t.Fatalf("%d queued, want 0", n)
	}
	if n := h.reserved(fp); n != 0 {
		t.Fatalf("%d uploads reserved, want 0", n)
	}
}

// A stream opened for a channel becomes a message under that channel, and
// a refused open spends none of the sender's budget.
func TestAStreamIsFiledUnderTheChannelItWasOpenedFor(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{PostBytesPerHour: 10000}})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	fp := bob.Fingerprint()
	if status, body, _ := h.pushDirectory(bob, bob, h.clock.Now(), dflt, bugs); status != http.StatusNoContent {
		t.Fatalf("push: %d %s", status, body)
	}
	blob := fakeStream(200, 3000)

	// Refused opens, each of the whole budget's size, then an accepted one
	// that fits only if none of them was charged.
	for range 3 {
		if status, _, body := h.openStreamTo(alice, fp, 9000, "nothing here"); status != http.StatusNotFound {
			t.Fatalf("a refused open: %d %s", status, body)
		}
	}
	status, opened, body := h.openStreamTo(alice, fp, int64(len(blob)), "bug reports")
	if status != http.StatusCreated {
		t.Fatalf("open after refusals: %d %s (a refused channel was charged)", status, body)
	}
	status, body, _ = h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob,
		map[string]string{relayapi.UploadOffsetHeader: "0"})
	if status != http.StatusNoContent {
		t.Fatalf("append: %d %s", status, body)
	}
	status, body, _ = h.send(alice, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("complete: %d %s", status, body)
	}
	var done relayapi.CompleteStreamResponse
	if err := json.Unmarshal(body, &done); err != nil {
		t.Fatal(err)
	}
	l, err := h.store.Listing(fp, 0, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Rows) != 1 || l.Rows[0].ID != done.ID || l.Rows[0].Kind != relayapi.KindStream || l.Rows[0].Channel != "bug reports" {
		t.Fatalf("the completed stream: %+v", l.Rows)
	}
	if counts, _ := h.store.ChannelCounts(fp); counts["bug reports"] != 1 {
		t.Fatalf("counts: %v", counts)
	}
}

// The listing says which channel each message is under, for an envelope and
// for a stream, and says it for default too: the field is always present
// from this relay, so a listing without it is from a relay from before
// channels.
func TestTheListingSaysWhichChannel(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	fp := bob.Fingerprint()
	if status, body, _ := h.pushDirectory(bob, bob, h.clock.Now(), dflt, bugs); status != http.StatusNoContent {
		t.Fatalf("push: %d %s", status, body)
	}
	if status, body := h.postTo(alice, bob, "bug reports"); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	if status, body := h.postTo(alice, bob, ""); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	blob := fakeStream(200, 3000)
	status, opened, body := h.openStreamTo(alice, fp, int64(len(blob)), "bug reports")
	if status != http.StatusCreated {
		t.Fatalf("open: %d %s", status, body)
	}
	if status, body, _ := h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob,
		map[string]string{relayapi.UploadOffsetHeader: "0"}); status != http.StatusNoContent {
		t.Fatalf("append: %d %s", status, body)
	}
	if status, body, _ := h.send(alice, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil); status != http.StatusOK {
		t.Fatalf("complete: %d %s", status, body)
	}

	status, raw := h.do(bob, "GET", "/v1/mailbox/"+fp, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, raw)
	}
	var list relayapi.ListResponse
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Messages) != 3 {
		t.Fatalf("listed %d messages, want 3", len(list.Messages))
	}
	want := []struct{ kind, channel string }{{relayapi.KindEnvelope, "bug reports"}, {relayapi.KindEnvelope, "default"}, {relayapi.KindStream, "bug reports"}}
	for i, m := range list.Messages {
		if m.Kind != want[i].kind || m.Channel != want[i].channel {
			t.Errorf("message %d is kind %q under %q, want %q under %q", i, m.Kind, m.Channel, want[i].kind, want[i].channel)
		}
	}
	// On the wire, named channel, and present for default rather than
	// omitted: absent is what an old relay says.
	if strings.Count(string(raw), `"channel":"`) != 3 || !strings.Contains(string(raw), `"channel":"default"`) {
		t.Fatalf("the listing does not carry channel on every message:\n%s", raw)
	}
	// A relay never lists an empty name, so the rule that the field has no
	// omitempty is checked on the type itself: the zero message still says
	// channel, as it still says queued on the response.
	if zero, _ := json.Marshal(relayapi.StoredMessage{}); !strings.Contains(string(zero), `"channel":""`) {
		t.Fatalf("StoredMessage omits an empty channel; absent must mean an old relay: %s", zero)
	}
}

// The administrator's record counts a mailbox's channels and never names
// them: zero for a mailbox with no directory, which has default by that
// fact and not by a row.
func TestTheAdministratorCountsChannelsAndNeverNamesThem(t *testing.T) {
	people := ids(t, "boss", "alice", "bob")
	boss, alice, bob := people[0], people[1], people[2]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	h.register(alice)
	h.register(bob)
	secret := channels.Channel{Name: "xylophone lessons", Description: "quiet ones only"}
	if status, body, _ := h.pushDirectory(bob, bob, h.clock.Now(), dflt, secret); status != http.StatusNoContent {
		t.Fatalf("push: %d %s", status, body)
	}

	status, body, _ := h.send(boss, "GET", "/v1/admin/mailboxes/"+bob.Fingerprint(), nil, nil)
	if status != http.StatusOK {
		t.Fatalf("mailbox: %d %s", status, body)
	}
	var rec relayapi.MailboxRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Channels != 2 {
		t.Fatalf("bob's record counts %d channels, want 2: %s", rec.Channels, body)
	}
	if !strings.Contains(string(body), `"channels":2`) {
		t.Fatalf("the field is not named channels: %s", body)
	}
	for _, word := range []string{"xylophone", "quiet ones", "default"} {
		if strings.Contains(string(body), word) {
			t.Fatalf("the administrator's record names a channel (%q): %s", word, body)
		}
	}
	status, body, _ = h.send(boss, "GET", "/v1/admin/mailboxes/"+alice.Fingerprint(), nil, nil)
	if status != http.StatusOK {
		t.Fatalf("mailbox: %d %s", status, body)
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Channels != 0 || !strings.Contains(string(body), `"channels":0`) {
		t.Fatalf("alice's record, with no directory: %s", body)
	}
	// And the page.
	status, body, _ = h.send(boss, "GET", "/v1/admin/mailboxes", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("mailboxes: %d %s", status, body)
	}
	var list relayapi.MailboxListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, m := range list.Mailboxes {
		counts[m.FP] = m.Channels
	}
	if counts[bob.Fingerprint()] != 2 || counts[alice.Fingerprint()] != 0 {
		t.Fatalf("the page's counts: %v", counts)
	}
	if strings.Contains(string(body), "xylophone") {
		t.Fatalf("the page names a channel: %s", body)
	}
}

// A client from before channels reads this relay's listing and its
// open-stream answer with plain json.Unmarshal, which ignores a field it
// has never heard of: the shapes it knew decode from what this relay says,
// and a relay reads an old client's open-stream request, which names no
// channel, as default. The old shapes are written out here rather than
// derived from the current types, so a change that would break an old
// client fails here.
func TestAnOldClientReadsThisRelaysAnswers(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	fp := bob.Fingerprint()
	if status, body, _ := h.pushDirectory(bob, bob, h.clock.Now(), dflt, bugs); status != http.StatusNoContent {
		t.Fatalf("push: %d %s", status, body)
	}
	if status, body := h.postTo(alice, bob, "bug reports"); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	status, raw := h.do(bob, "GET", "/v1/mailbox/"+fp, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, raw)
	}
	// The v5 client's ListResponse and StoredMessage.
	var old struct {
		Messages []struct {
			ID       int64           `json:"id"`
			Received time.Time       `json:"received"`
			Kind     string          `json:"kind,omitempty"`
			Size     int64           `json:"size,omitempty"`
			Envelope json.RawMessage `json:"envelope,omitempty"`
		} `json:"messages"`
		Queued int64 `json:"queued"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatalf("an old client cannot read the listing: %v\n%s", err, raw)
	}
	if len(old.Messages) != 1 || old.Messages[0].ID == 0 || len(old.Messages[0].Envelope) == 0 || old.Queued != 1 {
		t.Fatalf("an old client read %+v", old)
	}
	// The v5 client's outer envelope, from the bytes served: ch is ignored,
	// and what it reads is what it would have sealed itself.
	var env struct {
		V  int    `json:"v"`
		To string `json:"to"`
		CT []byte `json:"ct"`
	}
	if err := json.Unmarshal(old.Messages[0].Envelope, &env); err != nil || env.To != fp || len(env.CT) == 0 {
		t.Fatalf("an old client cannot read the envelope: %v", err)
	}
	// An old client's open-stream request has no channel: this relay reads
	// that as default, and answers in the shape the old client knew.
	status, body, _ := h.send(alice, "POST", "/v1/mailbox/"+fp+"/streams", []byte(`{"size":5000}`), nil)
	if status != http.StatusCreated {
		t.Fatalf("an old client's open: %d %s", status, body)
	}
	var opened struct {
		Upload     string    `json:"upload"`
		Expires    time.Time `json:"expires"`
		MaxRequest int64     `json:"max_request"`
	}
	if err := json.Unmarshal(body, &opened); err != nil || opened.Upload == "" {
		t.Fatalf("an old client cannot read the open answer: %v %s", err, body)
	}
	up, err := h.store.Upload(opened.Upload)
	if err != nil || up.Channel != "default" {
		t.Fatalf("an old client's upload is for %q, want default (%v)", up.Channel, err)
	}
}
