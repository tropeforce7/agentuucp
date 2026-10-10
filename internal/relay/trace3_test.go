package relay

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
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
