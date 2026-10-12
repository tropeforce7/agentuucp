package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/ratelimit"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// The third adversarial trace, at v0.17.0 (reviews/trace/trace-3-v0.17.0/):
// what a sender's reservation of a recipient's room costs the sender. Its
// tests are here as the regression tests, each renamed for what it proves.

// unfedLine is the message the relay logs when an upload goes unplaced with
// no byte held.
const unfedLine = `msg="upload abandoned unfed"`

// unfedLines is every line of the harness's log that carries unfedLine.
func unfedLines(h *harness) []string {
	var out []string
	for _, l := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(l, unfedLine) {
			out = append(out, l)
		}
	}
	return out
}

// TestAnUnfedReservationIsNotRefunded: a sender opened a stream for nearly
// the recipient's whole quota and sent no byte, and the recipient's mailbox
// was full to every sender while the recipient's listing said queued 0.
// When the upload went unplaced, by an abort, by its expiry met at a route,
// by the purge or by a first attempt that left nothing, the relay gave the
// sender back the whole declared size, so the sender opened again at once
// and held the mailbox for as long as it liked at no cost to its post bytes
// budget. Now an upload the relay never fed gives nothing back: the open's
// charge stands for the hour, so on every one of those paths the sender's
// next open of the same size is refused for its budget, the refusal leaves
// no reservation behind it, and the recipient is reachable the moment the
// first reservation is gone.
func TestAnUnfedReservationIsNotRefunded(t *testing.T) {
	const quota = int64(1 << 20)
	const reserve = quota - 64
	// The first attempt that leaves nothing stops short of the resume
	// threshold, which is max_bytes, on a stream shaped to the declared
	// size.
	blob := fakeStream(200, int(reserve)-stream.HeaderSize-200)
	if int64(len(blob)) != reserve {
		t.Fatalf("the test stream is %d bytes, want %d", len(blob), reserve)
	}
	paths := []struct {
		name string
		end  func(t *testing.T, h *harness, attacker *identity.Identity, upload string)
	}{
		{"an abort", func(t *testing.T, h *harness, attacker *identity.Identity, upload string) {
			if status, body, _ := h.sendRaw(attacker, "DELETE", "/v1/uploads/"+upload, nil, nil); status != http.StatusNoContent {
				t.Fatalf("abort: %d %s", status, body)
			}
		}},
		{"an expiry met at the route by a PUT", func(t *testing.T, h *harness, attacker *identity.Identity, upload string) {
			h.clock.advance(relayapi.ResumeWindow + time.Second)
			if status, body, _ := h.putStream(attacker, upload, blob, 0); status != http.StatusGone {
				t.Fatalf("an attempt on the expired upload: %d %s; want 410", status, body)
			}
		}},
		{"an expiry met at the route by a DELETE", func(t *testing.T, h *harness, attacker *identity.Identity, upload string) {
			h.clock.advance(relayapi.ResumeWindow + time.Second)
			if status, body, _ := h.sendRaw(attacker, "DELETE", "/v1/uploads/"+upload, nil, nil); status != http.StatusGone {
				t.Fatalf("an abort of the expired upload: %d %s; want 410", status, body)
			}
		}},
		{"the purge", func(t *testing.T, h *harness, attacker *identity.Identity, upload string) {
			h.clock.advance(relayapi.ResumeWindow + time.Second)
			h.server.purgeUploads(h.clock.Now())
		}},
		{"a first attempt that leaves nothing", func(t *testing.T, h *harness, attacker *identity.Identity, upload string) {
			status, body, _ := h.putPartial(attacker, upload, blob, 0, 1000)
			if status != http.StatusBadRequest || !strings.Contains(string(body), "nothing is kept") {
				t.Fatalf("the short attempt: %d %s; want 400 nothing kept", status, body)
			}
			// The clock has not moved, so the budget is exactly what the
			// open left: the declared size is still charged.
			if got := left(h.server.lim.postBytes, attacker.Fingerprint()); got != quota-reserve {
				t.Fatalf("after the short attempt the sender's budget holds %d, want %d: the declared size of %d was given back",
					got, quota-reserve, reserve)
			}
		}},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			h := newHarness(t, Config{Limits: Limits{MailboxMaxBytes: quota, PostBytesPerHour: quota, MaxOpenUploads: 4}})
			attacker, victim, sender := h.user(t, "attacker"), h.user(t, "victim"), h.user(t, "sender")
			to := victim.Fingerprint()

			status, opened, body := h.openStream(attacker, to, reserve)
			if status != http.StatusCreated {
				t.Fatalf("open: %d %s", status, body)
			}
			// While the reservation stands, the mailbox is full to an
			// honest sender and the recipient sees nothing queued.
			if status, body := h.do(sender, "POST", "/v1/mailbox/"+to, sealed(t, sender, victim.Public(), "hello"), nil); status != http.StatusInsufficientStorage {
				t.Fatalf("an honest post while the reservation stands: %d %s; want 507", status, body)
			}
			status, body = h.do(victim, "GET", "/v1/mailbox/"+to, nil, nil)
			var l relayapi.ListResponse
			if status != http.StatusOK {
				t.Fatalf("the victim's listing: %d %s", status, body)
			}
			if err := json.Unmarshal(body, &l); err != nil {
				t.Fatalf("the victim's listing: %v %s", err, body)
			}
			if l.Queued != 0 {
				t.Fatalf("the victim sees %d queued, want 0", l.Queued)
			}

			p.end(t, h, attacker, opened.Upload)

			// The sender cannot hold the room again: the open is refused
			// for its post bytes budget, which the first open spent.
			status, _, body = h.openStream(attacker, to, reserve)
			if status != http.StatusTooManyRequests || errorText(t, body) != "rate limited: "+limitPostBytes {
				t.Fatalf("a second open of %d bytes after %s of an upload never fed: %d %s; want 429 rate limited: %s, "+
					"since a reservation the relay never fed is not given back",
					reserve, p.name, status, body, limitPostBytes)
			}
			// The refusal spent no reservation.
			var rows int
			if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads`).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows != 0 {
				t.Fatalf("%d upload rows after the refused open, want none", rows)
			}
			if n := h.openCount(attacker.Fingerprint()); n != 0 {
				t.Fatalf("the sender has %d uploads open after the refused open, want none", n)
			}
			// And the recipient is reachable again.
			if status, body := h.do(sender, "POST", "/v1/mailbox/"+to, sealed(t, sender, victim.Public(), "hello"), nil); status != http.StatusOK {
				t.Fatalf("an honest post after the reservation went: %d %s; want 200", status, body)
			}
		})
	}
}

// TestAnUnfedUploadIsLoggedOnceAMinutePerSender: with a reservation never
// fed given nothing back, an operator wants to see who is holding
// mailboxes full with them, and the relay said nothing of it. Now an
// upload that goes unplaced with no byte held is logged as a warning, at
// most once a minute for each sender: under the full access log, which
// names every caller anyway, the line names the sender and the declared
// size, and a second sender inside the same minute has a line of its own;
// under the minimal access log it names nobody, sender or recipient, and
// is one line a minute for every sender together. An upload that received
// bytes is not unfed and is logged under neither.
func TestAnUnfedUploadIsLoggedOnceAMinutePerSender(t *testing.T) {
	blob := fakeStream(200, 3000)
	size := int64(len(blob))
	fresh := func(t *testing.T, mode string) (*harness, *identity.Identity, *identity.Identity, string) {
		t.Helper()
		h := newHarness(t, Config{AccessLog: mode, MaxBytes: 2048, Limits: Limits{PostBytesPerHour: 20 * size}})
		return h, h.user(t, "alice"), h.user(t, "carol"), h.user(t, "bob").Fingerprint()
	}
	abort := func(t *testing.T, h *harness, from *identity.Identity, upload string) {
		t.Helper()
		if status, body, _ := h.sendRaw(from, "DELETE", "/v1/uploads/"+upload, nil, nil); status != http.StatusNoContent {
			t.Fatalf("abort: %d %s", status, body)
		}
	}
	unfedAbort := func(t *testing.T, h *harness, from *identity.Identity, to string) {
		t.Helper()
		abort(t, h, from, h.openOrFail(from, to, size))
	}
	keptAbort := func(t *testing.T, h *harness, from *identity.Identity, to string) {
		t.Helper()
		id := h.openOrFail(from, to, size)
		status, body, _ := h.putPartial(from, id, blob, 0, 2500)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "kept for one resume") {
			t.Fatalf("the first attempt stopping at 2500: %d %s; want 400 kept", status, body)
		}
		abort(t, h, from, id)
	}
	sizeAttr := "size=" + strconv.FormatInt(size, 10)

	t.Run("full: one line a minute for each sender, naming it", func(t *testing.T) {
		h, alice, carol, bob := fresh(t, AccessLogFull)
		unfedAbort(t, h, alice, bob)
		unfedAbort(t, h, alice, bob)
		lines := unfedLines(h)
		if len(lines) != 1 {
			t.Fatalf("two unfed aborts by one sender inside a minute logged %d lines, want 1:\n%s", len(lines), h.logs.String())
		}
		if !strings.Contains(lines[0], "level=WARN") || !strings.Contains(lines[0], "fp="+alice.Fingerprint()) || !strings.Contains(lines[0], sizeAttr) {
			t.Fatalf("the line does not warn with fp=%s and %s:\n%s", alice.Fingerprint(), sizeAttr, lines[0])
		}
		// Another sender inside the same minute is not hidden by the first.
		unfedAbort(t, h, carol, bob)
		lines = unfedLines(h)
		if len(lines) != 2 || !strings.Contains(lines[1], "fp="+carol.Fingerprint()) {
			t.Fatalf("an unfed abort by a second sender inside the minute: %d lines, want a second naming it:\n%s", len(lines), h.logs.String())
		}
		// A minute on, the first sender's next one is logged again.
		h.clock.advance(time.Minute)
		unfedAbort(t, h, alice, bob)
		lines = unfedLines(h)
		if len(lines) != 3 || !strings.Contains(lines[2], "fp="+alice.Fingerprint()) {
			t.Fatalf("an unfed abort a minute on: %d lines, want a third naming the first sender:\n%s", len(lines), h.logs.String())
		}
	})
	t.Run("minimal: one line a minute for all, naming nobody", func(t *testing.T) {
		h, alice, carol, bob := fresh(t, AccessLogMinimal)
		unfedAbort(t, h, alice, bob)
		unfedAbort(t, h, carol, bob)
		lines := unfedLines(h)
		if len(lines) != 1 {
			t.Fatalf("two unfed aborts by two senders inside a minute logged %d lines under minimal, want 1:\n%s", len(lines), h.logs.String())
		}
		h.clock.advance(time.Minute)
		unfedAbort(t, h, carol, bob)
		lines = unfedLines(h)
		if len(lines) != 2 {
			t.Fatalf("an unfed abort a minute on logged %d lines under minimal, want 2:\n%s", len(lines), h.logs.String())
		}
		for _, l := range lines {
			if !strings.Contains(l, "level=WARN") || !strings.Contains(l, sizeAttr) {
				t.Errorf("the line does not warn with %s:\n%s", sizeAttr, l)
			}
			if strings.Contains(l, "fp=") {
				t.Errorf("the minimal line carries a fingerprint attribute:\n%s", l)
			}
			for _, fp := range []string{alice.Fingerprint(), carol.Fingerprint(), bob} {
				if strings.Contains(l, fp[:16]) {
					t.Errorf("the minimal line names %s:\n%s", fp[:16], l)
				}
			}
		}
	})
	for _, mode := range []string{AccessLogFull, AccessLogMinimal} {
		t.Run(mode+": an abort that received bytes is not logged", func(t *testing.T) {
			h, alice, _, bob := fresh(t, mode)
			keptAbort(t, h, alice, bob)
			if lines := unfedLines(h); len(lines) != 0 {
				t.Fatalf("the abort of a kept partial logged %d unfed lines, want none:\n%s", len(lines), h.logs.String())
			}
			// The same sender's unfed abort inside the minute is still
			// logged, so the kept partial took no slot of its own.
			unfedAbort(t, h, alice, bob)
			if lines := unfedLines(h); len(lines) != 1 {
				t.Fatalf("an unfed abort after the kept partial's logged %d lines, want 1:\n%s", len(lines), h.logs.String())
			}
		})
	}
}

// TestAnExpiredReservationIsLetGoWhenTheRoomIsAskedFor: roomFor counts
// every upload's reservation whatever its expiry, so a reservation nobody
// fed held the recipient's room past the sixty seconds the open gave it,
// until its sender's next request on it, its sender's open at the
// max_open_uploads cap or the purge every hundredth request, which on a
// quiet relay is a long time: an honest post, open, knock or courier's
// delivery into the mailbox was refused for a full mailbox by a
// reservation that had already expired. Now each of those routes, refused
// for a full mailbox or relay, lets go of the expired uploads and asks the
// store once more when that let anything go, so the same request a second
// past the expiry is taken at once, the expired row is gone, and its
// sender is given nothing back for it. A refusal while the reservation is
// live is still a 507, and a purge that let nothing go leaves it so with
// no second ask. The post is made once more with the relay's total full
// rather than the mailbox, to another recipient, so the room let go is the
// relay's.
func TestAnExpiredReservationIsLetGoWhenTheRoomIsAskedFor(t *testing.T) {
	const quota = int64(1 << 20)
	const reserve = quota - 64
	limits := Limits{MailboxMaxBytes: quota, PostBytesPerHour: quota}
	// Each route builds its own relay and answers the honest request into
	// the victim's mailbox, which it makes once refused and once taken.
	routes := []struct {
		name  string
		taken int
		setup func(t *testing.T) (h *harness, victim *identity.Identity, ask func() (int, []byte))
	}{
		{"the post", http.StatusOK, func(t *testing.T) (*harness, *identity.Identity, func() (int, []byte)) {
			h := newHarness(t, Config{Limits: limits})
			victim, sender := h.user(t, "victim"), h.user(t, "sender")
			return h, victim, func() (int, []byte) {
				return h.do(sender, "POST", "/v1/mailbox/"+victim.Fingerprint(), sealed(t, sender, victim.Public(), "hello"), nil)
			}
		}},
		{"the post, with the relay full", http.StatusOK, func(t *testing.T) (*harness, *identity.Identity, func() (int, []byte)) {
			// No mailbox quota: the reservation fills the relay's total, so
			// a post to anybody else is refused for the relay, not a mailbox.
			h := newHarness(t, Config{Limits: Limits{RelayMaxBytes: quota, PostBytesPerHour: quota}})
			victim, other, sender := h.user(t, "victim"), h.user(t, "other"), h.user(t, "sender")
			return h, victim, func() (int, []byte) {
				status, body := h.do(sender, "POST", "/v1/mailbox/"+other.Fingerprint(), sealed(t, sender, other.Public(), "hello"), nil)
				if status == http.StatusInsufficientStorage && errorText(t, body) != relayapi.MsgRelayFull {
					t.Fatalf("the post to another recipient was refused, but not for the relay: %s", body)
				}
				return status, body
			}
		}},
		{"the stream open", http.StatusCreated, func(t *testing.T) (*harness, *identity.Identity, func() (int, []byte)) {
			h := newHarness(t, Config{Limits: limits})
			victim, sender := h.user(t, "victim"), h.user(t, "sender")
			return h, victim, func() (int, []byte) {
				status, _, body := h.openStream(sender, victim.Fingerprint(), 128<<10)
				return status, body
			}
		}},
		{"the knock", http.StatusOK, func(t *testing.T) (*harness, *identity.Identity, func() (int, []byte)) {
			h := newHarness(t, Config{Limits: limits})
			victim, sender := h.user(t, "victim"), h.user(t, "sender")
			if status, body, _ := h.pushCard(victim, victim, time.Now(), false, true); status != http.StatusNoContent {
				t.Fatalf("the victim's card: %d %s", status, body)
			}
			return h, victim, func() (int, []byte) {
				status, body, _ := h.knock(sender, victim, "may I write?")
				return status, body
			}
		}},
		{"a courier's delivery", http.StatusCreated, func(t *testing.T) (*harness, *identity.Identity, func() (int, []byte)) {
			courier := neighbourID(t, "alpha")
			c, err := NewCourier(CourierConfig{
				Home:           courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"}),
				AuthorizedFile: couriersFile(t, courier), PublicURL: "https://mine.example",
			}, slogDiscard())
			if err != nil {
				t.Fatal(err)
			}
			h := newHarness(t, Config{Courier: c, CourierLimits: DefaultCourierLimits(), Limits: limits})
			quiet(t, h)
			h.enroll(courier)
			victim := h.user(t, "victim")
			n := 0
			return h, victim, func() (int, []byte) {
				// A fresh envelope each time, since a courier's second
				// copy of one is a duplicate and not a delivery.
				n++
				status, _, body := h.forward(courier, request(sealedFor(victim.Fingerprint(), fmt.Sprintf("carried %d", n)), nil, nil))
				return status, body
			}
		}},
	}
	for _, r := range routes {
		t.Run(r.name, func(t *testing.T) {
			h, victim, ask := r.setup(t)
			attacker := h.user(t, "attacker")
			upload := h.openOrFail(attacker, victim.Fingerprint(), reserve)

			// While the reservation is live the room is taken.
			if status, body := ask(); status != http.StatusInsufficientStorage {
				t.Fatalf("%s while the reservation is live: %d %s; want 507", r.name, status, body)
			}
			if strings.Contains(h.logs.String(), "abandoned uploads removed") {
				t.Fatalf("the refusal while the reservation is live removed uploads:\n%s", h.logs.String())
			}

			// Past its expiry, with no request from its sender and no
			// hundredth request's purge, the same request is taken.
			h.clock.advance(relayapi.ResumeWindow + time.Second)
			if status, body := ask(); status != r.taken {
				t.Fatalf("%s past the reservation's expiry: %d %s; want %d, the expired reservation let go",
					r.name, status, body, r.taken)
			}
			var rows int
			if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads WHERE id = ?`, upload).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows != 0 || h.openCount(attacker.Fingerprint()) != 0 {
				t.Fatalf("the expired reservation's row is still held after %s was taken", r.name)
			}
			// Settled as an unfed upload is: nothing given back. A refund
			// of the declared size would leave the attacker its whole
			// budget; without one it has the 64 bytes the open left and
			// what refilled in the minute since, far short of reserve.
			if got := left(h.server.lim.postBytes, attacker.Fingerprint()); got >= reserve {
				t.Fatalf("the attacker's budget holds %d after its unfed reservation was let go; "+
					"the declared size of %d was given back", got, reserve)
			}
		})
	}

	// A purge that lets nothing go leaves the refusal as it was: the
	// reservation live, a second inside the start window an unfed open is
	// held for (D82), the post is 507 and nothing was removed.
	t.Run("a purge that lets nothing go", func(t *testing.T) {
		h := newHarness(t, Config{Limits: limits})
		attacker, victim, sender := h.user(t, "attacker"), h.user(t, "victim"), h.user(t, "sender")
		upload := h.openOrFail(attacker, victim.Fingerprint(), reserve)
		h.clock.advance(relayapi.StartWindow - time.Second)
		status, body := h.do(sender, "POST", "/v1/mailbox/"+victim.Fingerprint(), sealed(t, sender, victim.Public(), "hello"), nil)
		if status != http.StatusInsufficientStorage || errorText(t, body) != relayapi.MsgMailboxFull {
			t.Fatalf("a post into the mailbox a live reservation fills: %d %s; want 507 %s", status, body, relayapi.MsgMailboxFull)
		}
		if strings.Contains(h.logs.String(), "abandoned uploads removed") {
			t.Fatalf("a purge with nothing expired removed uploads:\n%s", h.logs.String())
		}
		var rows int
		if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads WHERE id = ?`, upload).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != 1 {
			t.Fatalf("the live reservation's row count is %d, want 1", rows)
		}
	})
}

// TestRoomFreedPurgesOnlyForAFullRefusalAndSaysWhetherItLetGo: every route
// above asks the store a second time on roomFreed's word alone, so its
// contract is what keeps a second ask to the refusals it can change. A
// refusal for a full mailbox or relay, wrapped or not, purges, and says
// yes only when that let an expired upload go: with the reservation live
// it says no and the row stays, so a 507 is not asked twice for nothing.
// Any other answer, an error of another kind or none, says no and purges
// nothing, so roomFreed runs no purge for a refusal room cannot change.
func TestRoomFreedPurgesOnlyForAFullRefusalAndSaysWhetherItLetGo(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		expired bool
		want    bool
	}{
		{"a full mailbox with the reservation live", ErrMailboxFull, false, false},
		{"a wrapped full mailbox with the reservation live", fmt.Errorf("put: %w", ErrMailboxFull), false, false},
		{"a full mailbox with the reservation expired", ErrMailboxFull, true, true},
		{"a wrapped full mailbox with the reservation expired", fmt.Errorf("put: %w", ErrMailboxFull), true, true},
		{"a full relay with the reservation expired", ErrRelayFull, true, true},
		{"a wrapped full relay with the reservation expired", fmt.Errorf("put: %w", ErrRelayFull), true, true},
		{"no mailbox with the reservation expired", ErrNoMailbox, true, false},
		{"another error with the reservation expired", errors.New("x"), true, false},
		{"no error with the reservation expired", nil, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, Config{Limits: Limits{MailboxMaxBytes: 1 << 20, PostBytesPerHour: 1 << 20}})
			attacker, victim := h.user(t, "attacker"), h.user(t, "victim")
			upload := h.openOrFail(attacker, victim.Fingerprint(), 1<<19)
			if c.expired {
				h.clock.advance(relayapi.ResumeWindow + time.Second)
			}
			if got := h.server.roomFreed(c.err); got != c.want {
				t.Fatalf("roomFreed(%v): %v, want %v", c.err, got, c.want)
			}
			var rows int
			if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads WHERE id = ?`, upload).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			// The row goes exactly when roomFreed says the room was freed.
			if wantRows := map[bool]int{true: 0, false: 1}[c.want]; rows != wantRows {
				t.Fatalf("after roomFreed(%v) the reservation's rows are %d, want %d", c.err, rows, wantRows)
			}
		})
	}
}

// tableCounts is how many rows each table a forward or a delivery writes holds,
// so a refusal can be shown to have written none of them.
type tableCounts struct{ carried, outbound, messages, uploads int }

func (h *harness) tableCounts(t *testing.T) tableCounts {
	t.Helper()
	var s tableCounts
	for _, c := range []struct {
		table string
		n     *int
	}{{"carried", &s.carried}, {"outbound", &s.outbound}, {"messages", &s.messages}, {"uploads", &s.uploads}} {
		if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM ` + c.table).Scan(c.n); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// refusedCarried asserts a forward was refused for the caller's carried
// share, in the words the setting is named by, with a Retry-After to wait
// by and the limit named in the access log line this request wrote, and
// that it stored nothing.
func refusedCarried(t *testing.T, h *harness, id *identity.Identity, req *relayapi.ForwardRequest, setting string) {
	t.Helper()
	before, mark := h.tableCounts(t), len(h.logs.String())
	status, body, header := h.send(id, "POST", "/v1/forward", req, nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("a forward past the carried share: %d %s; want 429", status, body)
	}
	if msg := errorText(t, body); !strings.HasPrefix(msg, "rate limited: carried") || !strings.Contains(msg, setting) {
		t.Fatalf("the refusal says %q; want it to start \"rate limited: carried\" and name %s", msg, setting)
	}
	if retry, err := strconv.Atoi(header.Get("Retry-After")); err != nil || retry < 1 {
		t.Fatalf("the refusal's Retry-After is %q; want a whole number of seconds", header.Get("Retry-After"))
	}
	if since := h.logs.String()[mark:]; !strings.Contains(since, "limit=carried") {
		t.Fatalf("the refusal was not logged by its limit:\n%s", since)
	}
	if after := h.tableCounts(t); after != before {
		t.Fatalf("the refusal stored something: before %+v, after %+v", before, after)
	}
}

// TestACarriedHashIsChargedToItsPoster: every per-poster queue bound
// counted waiting rows alone, while the carried hash a forward writes lives
// for CarriedWindow (72h at the defaults) whatever became of the row, and
// the only bound on the hashes was the relay-wide carried_max_rows. So a
// user whose rows were handed at once spent that ceiling alone at
// posts_per_minute, and from then every forward and every neighbour's
// delivery, to anybody, was refused 507 until the hashes expired. Now a hash
// is charged to its poster when it is written, from a share of its own: a
// user's next fresh forward past the share is refused 429 and stores
// nothing, the ceiling is left for everybody else, and a neighbour's
// delivery to a mailbox here is taken.
func TestACarriedHashIsChargedToItsPoster(t *testing.T) {
	limits := DefaultCourierLimits()
	limits.CarriedMaxRows = 2
	limits.QueueMaxMessagesPerPoster = 1
	limits.CarriedRowsPerPoster = 1
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	user := h.user(t, "alice")
	bob := h.user(t, "bob")
	far := h.fpOf(t, "far")

	status, answer, body := h.forward(user, request(sealedFor(far, "ct0"), []string{"bar"}, nil))
	if status != http.StatusCreated {
		t.Fatalf("the first forward: %d %s", status, body)
	}
	// The neighbour takes it, as the worker records: the row leaves the
	// waiting state and the poster's share of the queue is free again,
	// while the hash stays.
	if err := h.store.Handed(answer.ID, 100, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	refusedCarried(t, h, user, request(sealedFor(far, "ct1"), []string{"bar"}, nil), "courier.carried_rows_per_poster")

	// A neighbour delivering unrelated mail to bob, who is on this relay.
	status, _, body = h.forward(courier, request(sealedFor(bob.Fingerprint(), "from-afar"), nil, nil))
	if status != http.StatusCreated {
		t.Fatalf("one user with a carried share of %d has the neighbour's delivery to another user refused: %d %s",
			limits.CarriedRowsPerPoster, status, body)
	}
}

// TestACourierIsChargedFromItsOwnCarriedShare: a neighbour's delivery
// writes a hash as a user's forward does, and is charged to the courier's
// share, carried_rows_per_courier, which is its own and not a user's: a
// courier past it is refused 429 and stores nothing, and a user's forward
// is taken after it.
func TestACourierIsChargedFromItsOwnCarriedShare(t *testing.T) {
	limits := DefaultCourierLimits()
	limits.CarriedRowsPerCourier = 1
	limits.CarriedRowsPerPoster = 100
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	user := h.user(t, "alice")
	bob := h.user(t, "bob")

	if status, _, body := h.forward(courier, request(sealedFor(bob.Fingerprint(), "one"), nil, nil)); status != http.StatusCreated {
		t.Fatalf("the courier's first delivery: %d %s", status, body)
	}
	refusedCarried(t, h, courier, request(sealedFor(bob.Fingerprint(), "two"), nil, nil), "courier.carried_rows_per_courier")
	if got, want := left(h.server.lim.carried, user.Fingerprint()), h.server.cfg.CourierLimits.carriedBurst(limits.CarriedRowsPerPoster); got != want {
		t.Fatalf("the courier's deliveries left the user %d of a bucket of %d", got, want)
	}
	if status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "far"), "mine"), []string{"bar"}, nil)); status != http.StatusCreated {
		t.Fatalf("a user's forward after the courier's share was spent: %d %s", status, body)
	}
}

// TestARetryOfACarriedEnvelopeCostsNoShare: a retry after a lost answer is
// one of the two callers the forward route expects, and the envelope's hash
// was charged when it was written. The retry is answered with the row it
// already has and spends nothing of the share.
func TestARetryOfACarriedEnvelopeCostsNoShare(t *testing.T) {
	limits := DefaultCourierLimits()
	limits.CarriedRowsPerPoster = CarriedShareFloor(limits.MaxHops)
	h := peered(t, []string{"bar"}, nil, &limits)
	if b := h.server.cfg.CourierLimits.carriedBurst(limits.CarriedRowsPerPoster); b < 2 {
		t.Fatalf("a share of %d is a bucket of %d; the retry needs one left after the forward", limits.CarriedRowsPerPoster, b)
	}
	user := h.user(t, "alice")
	req := request(sealedFor(h.fpOf(t, "far"), "once"), []string{"bar"}, nil)

	status, first, body := h.forward(user, req)
	if status != http.StatusCreated {
		t.Fatalf("the forward: %d %s", status, body)
	}
	before := left(h.server.lim.carried, user.Fingerprint())
	status, again, body := h.forward(user, req)
	if status != http.StatusConflict || again.ID != first.ID {
		t.Fatalf("the retry: %d %s; want 409 naming row %d", status, body, first.ID)
	}
	if after := left(h.server.lim.carried, user.Fingerprint()); after != before {
		t.Fatalf("the retry of a carried envelope spent %d of the share", before-after)
	}
}

// TestACarriedHashCostsAShareForEachWindowItIsKept: a hash is kept one
// ForwardTTL for each hop left and this one, so a long path costs as many
// tokens as windows: a path of three relays spends three of the share and
// a path of one spends one.
func TestACarriedHashCostsAShareForEachWindowItIsKept(t *testing.T) {
	limits := DefaultCourierLimits()
	limits.MaxHops = 8
	limits.CarriedRowsPerPoster = CarriedShareFloor(limits.MaxHops)
	h := peered(t, []string{"bar"}, nil, &limits)
	if b := h.server.cfg.CourierLimits.carriedBurst(limits.CarriedRowsPerPoster); b < 3 {
		t.Fatalf("a share of %d is a bucket of %d; a path of three needs three", limits.CarriedRowsPerPoster, b)
	}
	far := h.fpOf(t, "far")
	for _, c := range []struct {
		path []string
		want int64
	}{
		{[]string{"bar", "next", "last"}, 3},
		{[]string{"bar"}, 1},
	} {
		user := h.user(t, "poster-"+strconv.Itoa(len(c.path)))
		before := left(h.server.lim.carried, user.Fingerprint())
		if status, _, body := h.forward(user, request(sealedFor(far, strings.Join(c.path, "!")), c.path, nil)); status != http.StatusCreated {
			t.Fatalf("a forward by %v: %d %s", c.path, status, body)
		}
		if spent := before - left(h.server.lim.carried, user.Fingerprint()); spent != c.want {
			t.Fatalf("a forward by %v spent %d of the share; want %d", c.path, spent, c.want)
		}
	}
}

// TestAStoreRefusalGivesTheCarriedShareBack: the share is spent before the
// write, and a write the store refuses writes no hash, so every refusal of
// it gives the tokens back: the poster's own queue share full and the
// relay's carried ceiling reached each leave the bucket as it was, and a
// courier's delivery refused at the ceiling leaves the courier's as it was.
func TestAStoreRefusalGivesTheCarriedShareBack(t *testing.T) {
	cases := []struct {
		name   string
		set    func(*CourierLimits)
		filler bool
	}{
		{"the poster's queue share", func(c *CourierLimits) { c.QueueMaxMessagesPerPoster = 1 }, false},
		{"the carried ceiling", func(c *CourierLimits) { c.CarriedMaxRows = 1 }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			limits := DefaultCourierLimits()
			limits.CarriedRowsPerPoster = CarriedShareFloor(limits.MaxHops)
			c.set(&limits)
			h := peered(t, []string{"bar"}, nil, &limits)
			if b := h.server.cfg.CourierLimits.carriedBurst(limits.CarriedRowsPerPoster); b < 2 {
				t.Fatalf("a share of %d is a bucket of %d; the refused forward needs one left", limits.CarriedRowsPerPoster, b)
			}
			far := h.fpOf(t, "far")
			user := h.user(t, "alice")
			first := user
			if c.filler {
				first = h.user(t, "filler")
			}
			if status, _, body := h.forward(first, request(sealedFor(far, "first"), []string{"bar"}, nil)); status != http.StatusCreated {
				t.Fatalf("the first forward: %d %s", status, body)
			}
			before, rows := left(h.server.lim.carried, user.Fingerprint()), h.tableCounts(t)
			status, _, body := h.forward(user, request(sealedFor(far, "second"), []string{"bar"}, nil))
			if status != http.StatusInsufficientStorage {
				t.Fatalf("the forward past %s: %d %s; want 507", c.name, status, body)
			}
			if after := left(h.server.lim.carried, user.Fingerprint()); after != before {
				t.Fatalf("the refused forward kept %d of the share", before-after)
			}
			if after := h.tableCounts(t); after != rows {
				t.Fatalf("the refused forward stored something: before %+v, after %+v", rows, after)
			}
		})
	}
	t.Run("a courier's delivery against the carried ceiling", func(t *testing.T) {
		limits := DefaultCourierLimits()
		limits.CarriedMaxRows = 1
		limits.CarriedRowsPerCourier = CarriedShareFloor(limits.MaxHops)
		courier := neighbourID(t, "alpha")
		h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
		h.enroll(courier)
		bob := h.user(t, "bob")
		filler := h.user(t, "filler")
		if status, _, body := h.forward(filler, request(sealedFor(h.fpOf(t, "far"), "first"), []string{"bar"}, nil)); status != http.StatusCreated {
			t.Fatalf("the filler's forward: %d %s", status, body)
		}
		before, rows := left(h.server.lim.courierCarried, courier.Fingerprint()), h.tableCounts(t)
		status, _, body := h.forward(courier, request(sealedFor(bob.Fingerprint(), "delivery"), nil, nil))
		if status != http.StatusInsufficientStorage {
			t.Fatalf("a delivery past the carried ceiling: %d %s; want 507", status, body)
		}
		if after := left(h.server.lim.courierCarried, courier.Fingerprint()); after != before {
			t.Fatalf("the refused delivery kept %d of the courier's share", before-after)
		}
		if after := h.tableCounts(t); after != rows {
			t.Fatalf("the refused delivery stored something: before %+v, after %+v", rows, after)
		}
	})
}

// TestTheCarriedShareRefillsOverTheWindow: a share's bucket is refilled its
// own size per ForwardTTL, the time a hash at its last hop is kept, and no
// faster: a poster refused for its share is still refused a minute short of
// that, and taken again once it has passed. A user's share and a courier's
// alike.
func TestTheCarriedShareRefillsOverTheWindow(t *testing.T) {
	cases := []struct {
		name    string
		courier bool
		setting string
	}{
		{"a user's", false, "courier.carried_rows_per_poster"},
		{"a courier's", true, "courier.carried_rows_per_courier"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			limits := DefaultCourierLimits()
			limits.CarriedRowsPerPoster = 1
			limits.CarriedRowsPerCourier = 1
			courier := neighbourID(t, "alpha")
			h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
			h.enroll(courier)
			poster := h.user(t, "alice")
			bob := h.user(t, "bob")
			far := h.fpOf(t, "far")
			req := func(ct string) *relayapi.ForwardRequest {
				return request(sealedFor(far, ct), []string{"bar"}, nil)
			}
			if c.courier {
				poster = courier
				req = func(ct string) *relayapi.ForwardRequest {
					return request(sealedFor(bob.Fingerprint(), ct), nil, nil)
				}
			}
			if status, _, body := h.forward(poster, req("one")); status != http.StatusCreated {
				t.Fatalf("the first: %d %s", status, body)
			}
			refusedCarried(t, h, poster, req("two"), c.setting)
			h.clock.advance(limits.CarriedWindow(0) - time.Minute)
			refusedCarried(t, h, poster, req("three"), c.setting)
			h.clock.advance(time.Minute)
			if status, _, body := h.forward(poster, req("four")); status != http.StatusCreated {
				t.Fatalf("a window after the share was spent: %d %s", status, body)
			}
		})
	}
}

// TestACourierForwardingOnwardIsChargedToItsOwnShare: a neighbour's courier
// that forwards an envelope onward, a path still ahead of it, reaches the
// queue as a courier, and the hash that row writes is charged to the
// courier's share by the path's cost, never to a user's bucket under the
// courier's fingerprint.
func TestACourierForwardingOnwardIsChargedToItsOwnShare(t *testing.T) {
	limits := DefaultCourierLimits()
	limits.CarriedRowsPerCourier = CarriedShareFloor(limits.MaxHops)
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	path := []string{"bar", "next"}
	cost := h.server.cfg.CourierLimits.carriedHops(len(path) - 1)
	if b := h.server.cfg.CourierLimits.carriedBurst(limits.CarriedRowsPerCourier); b < cost {
		t.Fatalf("a share of %d is a bucket of %d; the path costs %d", limits.CarriedRowsPerCourier, b, cost)
	}
	fp := courier.Fingerprint()
	courierBefore, userBefore := left(h.server.lim.courierCarried, fp), left(h.server.lim.carried, fp)
	if status, _, body := h.forward(courier, request(sealedFor(h.fpOf(t, "far"), "onward"), path, nil)); status != http.StatusCreated {
		t.Fatalf("the courier's onward forward: %d %s", status, body)
	}
	if spent := courierBefore - left(h.server.lim.courierCarried, fp); spent != cost {
		t.Fatalf("the onward forward spent %d of the courier's share; want the path's %d", spent, cost)
	}
	if after := left(h.server.lim.carried, fp); after != userBefore {
		t.Fatalf("the onward forward spent %d of a user's bucket under the courier's fingerprint", userBefore-after)
	}
}

// carriedSpender is one poster's carried share as the adversary sees it:
// buy one hash of a cost, say how many of its hashes stand now, and move
// the clock. With a bound, the count is held to it after every hash bought
// and the test stops at the first that passes it, so a share that never
// refuses fails at once rather than spending forever.
type carriedSpender struct {
	spend    func(cost int64) bool
	standing func() int
	advance  func(time.Duration)
	t        *testing.T
	bound    int
}

// spendAll buys hashes of one cost until the share refuses one, calling
// after with the standing count after every hash bought, and answers how
// many it bought.
func (c carriedSpender) spendAll(cost int64, after func(int)) int {
	n := 0
	for c.spend(cost) {
		n++
		standing := c.standing()
		if c.bound > 0 && standing > c.bound {
			c.t.Fatalf("%d hashes stood at once on a share of %d, the last of cost %d", standing, c.bound, cost)
		}
		after(standing)
	}
	return n
}

// harmonicAdversary is the spending R4 found: the bucket full at the
// start, the window m back from the end spent whole on hashes costing m,
// each window after on hashes costing its own distance from the end, and a
// minute short of the end the last window's refill on one-hop hashes. Every
// hash bought is still standing at that last moment. It answers the most
// that stood at once, checked after every hash.
func harmonicAdversary(c carriedSpender, m int64, window time.Duration) int {
	most := 0
	note := func(n int) { most = max(most, n) }
	for k := m; k >= 1; k-- {
		c.spendAll(k, note)
		if k > 1 {
			c.advance(window)
		}
	}
	c.advance(window - time.Minute)
	c.spendAll(1, note)
	return most
}

// steadySpender is the plain spending: the bucket whole on hashes of one
// cost, then a minute short of a window later its refill on the same.
func steadySpender(c carriedSpender, cost int64, window time.Duration) int {
	most := 0
	note := func(n int) { most = max(most, n) }
	c.spendAll(cost, note)
	c.advance(window - time.Minute)
	c.spendAll(cost, note)
	return most
}

// limiterSpender is a share at the limiter alone, with each hash's expiry
// kept by the test as the route would keep it, for a max_hops whose paths
// the route's harness does not lay out. A burst of 0 is the relay's own
// bucket, as newLimiters builds it; any other is a bucket of that size
// refilled as much per window, the sizing R4 replaced.
func limiterSpender(cl CourierLimits, burst int64) carriedSpender {
	clock := newTestClock()
	lim := newLimiters(Limits{}, cl, clock.Now).carried
	if burst != 0 {
		lim = ratelimit.New(burst, cl.CarriedWindow(0), cl.CarriedWindow(0), clock.Now)
	}
	var expiries []time.Time
	return carriedSpender{
		spend: func(cost int64) bool {
			if ok, _ := lim.AllowN("poster", cost); !ok {
				return false
			}
			expiries = append(expiries, clock.Now().Add(time.Duration(cost)*cl.ForwardTTL))
			return true
		},
		standing: func() int {
			n := 0
			for _, e := range expiries {
				if e.After(clock.Now()) {
					n++
				}
			}
			return n
		},
		advance: clock.advance,
	}
}

// routeSpender is a user's share through the forward route, each hash of
// cost k a fresh envelope by a path naming k relays, and the standing count
// the carried table's rows not yet expired.
func routeSpender(t *testing.T, h *harness) carriedSpender {
	user := h.user(t, "adversary")
	far := h.fpOf(t, "far")
	n := 0
	return carriedSpender{
		spend: func(cost int64) bool {
			t.Helper()
			path := []string{"bar"}
			for i := int64(2); i <= cost; i++ {
				path = append(path, fmt.Sprintf("r%d", i))
			}
			n++
			status, _, body := h.forward(user, request(sealedFor(far, fmt.Sprintf("hash-%d", n)), path, nil))
			switch status {
			case http.StatusCreated:
				return true
			case http.StatusTooManyRequests:
				if !strings.HasPrefix(errorText(t, body), "rate limited: carried") {
					t.Fatalf("a forward refused for something other than its carried share: %s", body)
				}
				return false
			}
			t.Fatalf("a forward of cost %d: %d %s", cost, status, body)
			return false
		},
		standing: func() int {
			var rows int
			if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM carried WHERE expires > ?`, h.clock.Now().Unix()).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			return rows
		},
		advance: h.clock.advance,
	}
}

// unmetered is a peered relay whose only bound on a user's forwards is the
// carried share: the posting rates, the request rate and the queue's
// per-poster shares are off, so a thousand forwards in one instant are
// refused for nothing but the share being measured.
func unmetered(t *testing.T, cl CourierLimits) *harness {
	t.Helper()
	h := peered(t, []string{"bar"}, nil, &cl)
	l := DefaultLimits()
	l.PostsPerMinute, l.PostBytesPerHour, l.RequestsPerMinute = 0, 0, 0
	h.server.lim = newLimiters(l, cl, h.clock.Now)
	return h
}

// TestACarriedShareBoundsTheStandingHashesAtEveryMoment: ruling R4. A
// carried share is the most a poster may have standing at once, and a hash
// costs one token for each window it is kept, so a hash bought j windows
// ago still stands only if it cost at least j. harmonicAdversary spends
// the full bucket first on hashes costing M, each later window's refill on
// hashes costing that window's distance from the end, and the last refill
// on one-hop hashes. Every hash is still standing at the end, b(1 + H(M))
// of them, b the bucket and H the harmonic number at max_hops M. The
// bucket sized at the share itself, as it first was, let that reach
// (1 + H(M)) × S: 3.72 S at max_hops 8 and 5.06 S at 32. Sized by
// carriedBurst, the share over 1 + H(M), the count never passes S, checked
// after every hash bought: through the forward route at max_hops 8, at the
// limiter at max_hops 32, whose 32-relay paths the harness does not lay
// out, and at both for the old sizing, to show the adversary is real. The
// plain spendings, all one-hop and all max_hops, each spent at once and
// again a minute short of a window later, stay under it too.
func TestACarriedShareBoundsTheStandingHashesAtEveryMoment(t *testing.T) {
	const share = 1000
	limitsAt := func(m int64) CourierLimits {
		cl := DefaultCourierLimits()
		cl.MaxHops = m
		cl.CarriedRowsPerPoster = share
		cl.CarriedMaxRows = 0
		cl.QueueMaxMessagesPerPoster = 1 << 30
		cl.QueueMaxBytesPerPoster = 1 << 40
		cl.QueueMaxBytes = 1 << 40
		return cl
	}
	window := DefaultCourierLimits().CarriedWindow(0)
	type spending struct {
		name string
		run  func(c carriedSpender, m int64) int
		// least is what the spending must reach for the bound to have
		// been pressed, as a fraction of the share in tenths.
		least int
	}
	spendings := []spending{
		{"the harmonic adversary", func(c carriedSpender, m int64) int { return harmonicAdversary(c, m, window) }, 9},
		{"one-hop hashes", func(c carriedSpender, m int64) int { return steadySpender(c, 1, window) }, 0},
		{"max_hops hashes", func(c carriedSpender, m int64) int { return steadySpender(c, m, window) }, 0},
	}
	for _, sp := range spendings {
		t.Run("the route at max_hops 8, "+sp.name, func(t *testing.T) {
			h := unmetered(t, limitsAt(8))
			c := routeSpender(t, h)
			c.t, c.bound = t, share
			most := sp.run(c, 8)
			if most > share || most < share*sp.least/10 {
				t.Fatalf("%d hashes stood at once on a share of %d; want at most the share and at least %d tenths of it",
					most, share, sp.least)
			}
			t.Logf("%d stood at once", most)
		})
		for _, m := range []int64{8, 32} {
			t.Run(fmt.Sprintf("the limiter at max_hops %d, %s", m, sp.name), func(t *testing.T) {
				c := limiterSpender(limitsAt(m), 0)
				c.t, c.bound = t, share
				most := sp.run(c, m)
				if most > share || most < share*sp.least/10 {
					t.Fatalf("%d hashes stood at once on a share of %d; want at most the share and at least %d tenths of it",
						most, share, sp.least)
				}
				t.Logf("%d stood at once", most)
			})
		}
	}
	for _, m := range []int64{8, 32} {
		t.Run(fmt.Sprintf("a bucket of the share itself at max_hops %d", m), func(t *testing.T) {
			most := harmonicAdversary(limiterSpender(limitsAt(m), share), m, window)
			if reach := (1 + harmonic(m)) * share; float64(most) < 0.95*reach {
				t.Fatalf("the adversary stood %d against a bucket of the share; the sizing it replaced reached about %.0f", most, reach)
			}
			t.Logf("a bucket of %d stood %d at once at max_hops %d", share, most, m)
		})
	}
}
