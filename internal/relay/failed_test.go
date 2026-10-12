package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// An undeliverable coming back. A relay cannot seal a bounce and should not be
// able to, so what a sender learns about mail that could not be delivered
// comes back as a control message between couriers, hop by hop along the rows
// each relay is holding, until it reaches the row whose poster is the sender.
//
// The route is the one place a relay tells another relay something rather than
// handing it something, so what it is held to is what it can prove: a row it
// really handed to that caller, once.

// failedReq is a report as a courier sends one.
func failedReq(id int64, code, said string) relayapi.ForwardFailedRequest {
	return relayapi.ForwardFailedRequest{ID: id, Code: code, Said: said}
}

// handedRow queues one envelope from poster and marks it handed under the id
// the neighbour is pretending to have given it, which is what a report names.
func (h *harness) handedRow(t *testing.T, poster *identity.Identity, to string, ct string, theirID int64) int64 {
	t.Helper()
	status, answer, body := h.forward(poster, request(sealedFor(to, ct), []string{"bar"}, nil))
	if status != 201 {
		t.Fatalf("queueing: %d %s", status, body)
	}
	if err := h.store.Handed(answer.ID, theirID, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	return answer.ID
}

// TestAnUndeliverableFinalsTheRowAndNamesTheHop: the whole of what a report
// does to the relay that receives it.
func TestAnUndeliverableFinalsTheRowAndNamesTheHop(t *testing.T) {
	courier := neighbourID(t, "bar")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	alice := h.user(t, "alice")
	row := h.handedRow(t, alice, h.fpOf(t, "bob"), "ct", 4711)

	status, body := h.do(courier, "POST", "/v1/forward/failed",
		failedReq(4711, relayapi.CodeRefused, "baz: no such mailbox"), nil)
	if status != 204 {
		t.Fatalf("a report: %d %s", status, body)
	}
	got := h.outbound(t, row)
	if got.State != OutFinal {
		t.Errorf("the row is %q, want %q", got.State, OutFinal)
	}
	if got.Code != relayapi.CodeRefused {
		t.Errorf("code %q", got.Code)
	}
	// This relay's own name for the hop that reported, in front of the
	// sentence that hop gave, so a sender reads each relay by a name their
	// own relay chose.
	if got.Said != "bar: baz: no such mailbox" {
		t.Errorf("said %q; want this relay's name for the reporter in front", got.Said)
	}
	// Taken once: the same report again finds a row that is not handed.
	status, body = h.do(courier, "POST", "/v1/forward/failed",
		failedReq(4711, relayapi.CodeRefused, "baz: no such mailbox"), nil)
	if status != 409 || errorText(t, body) != relayapi.MsgRowNotHanded {
		t.Fatalf("the same report twice: %d %s", status, body)
	}
}

// TestWhoMayReportAndAboutWhat: a report is between couriers, about a row
// this relay really handed to that courier.
func TestWhoMayReportAndAboutWhat(t *testing.T) {
	courier := neighbourID(t, "bar")
	other := neighbourID(t, "baz")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier, other)
	alice := h.user(t, "alice")

	t.Run("a user is not a courier", func(t *testing.T) {
		status, body := h.do(alice, "POST", "/v1/forward/failed",
			failedReq(1, relayapi.CodeRefused, "x"), nil)
		if status != 403 || errorText(t, body) != relayapi.MsgNotACourier {
			t.Fatalf("%d %s", status, body)
		}
	})
	t.Run("a registered identity this relay does not accept from", func(t *testing.T) {
		status, body := h.do(other, "POST", "/v1/forward/failed",
			failedReq(1, relayapi.CodeRefused, "x"), nil)
		if status != 403 || errorText(t, body) != relayapi.MsgNotACourier {
			t.Fatalf("%d %s", status, body)
		}
	})
	t.Run("a row this relay never handed to anybody", func(t *testing.T) {
		status, body := h.do(courier, "POST", "/v1/forward/failed",
			failedReq(9999, relayapi.CodeRefused, "x"), nil)
		if status != 404 || errorText(t, body) != relayapi.MsgNoSuchRow {
			t.Fatalf("%d %s", status, body)
		}
	})
	t.Run("a row still waiting", func(t *testing.T) {
		status, answer, body := h.forward(alice, request(sealedFor(h.fpOf(t, "bob"), "waiting"), []string{"bar"}, nil))
		if status != 201 {
			t.Fatalf("queueing: %d %s", status, body)
		}
		// A row nobody has been handed cannot be reported on, and the reason
		// is that their_id is only ever written by Handed: it is zero here,
		// and the lookup is by their_id, so a report naming this row's own id
		// finds nothing. Asserted on that id rather than on zero, since the
		// claim is about the waiting row and not about the shape check —
		// which the shape test covers, and which would make this subtest pass
		// with the lookup deleted.
		if row := h.outbound(t, answer.ID); row.TheirID != 0 {
			t.Fatalf("a waiting row's their_id is %d, want 0", row.TheirID)
		}
		status, body2 := h.do(courier, "POST", "/v1/forward/failed",
			failedReq(answer.ID, relayapi.CodeRefused, "x"), nil)
		if status != 404 || errorText(t, body2) != relayapi.MsgNoSuchRow {
			t.Fatalf("a report naming a waiting row's own id: %d %s", status, body2)
		}
		// And zero is refused earlier still, for not being an id at all.
		if status, body3 := h.do(courier, "POST", "/v1/forward/failed",
			failedReq(0, relayapi.CodeRefused, "x"), nil); status != 400 {
			t.Fatalf("id 0: %d %s", status, body3)
		}
	})
	t.Run("a row handed to a different neighbour", func(t *testing.T) {
		// The pair is (this relay's name for the caller, their_id), so a
		// report from bar about an id only baz was given finds nothing.
		h2 := peered(t, []string{"bar", "baz"}, []*identity.Identity{courier, other}, nil)
		h2.enroll(courier, other)
		a := h2.user(t, "alice")
		status, answer, body := h2.forward(a, request(sealedFor(h2.fpOf(t, "bob"), "ct"), []string{"baz"}, nil))
		if status != 201 {
			t.Fatalf("queueing: %d %s", status, body)
		}
		if err := h2.store.Handed(answer.ID, 77, h2.clock.Now()); err != nil {
			t.Fatal(err)
		}
		status, body = h2.do(courier, "POST", "/v1/forward/failed",
			failedReq(77, relayapi.CodeRefused, "x"), nil)
		if status != 404 {
			t.Fatalf("bar reporting on baz's row: %d %s", status, body)
		}
	})
}

// TestLimitAReportIsHeldToItsShape: every field, before anything is looked up.
//
// The id is a positive integer this relay itself issued; the code is one of
// two words a relay can prove about its own attempt; the sentence is one line
// under the subject's rule and at most MaxSaid bytes. A body that is not a
// report is refused before a row is read, so nothing is spent on it.
func TestLimitAReportIsHeldToItsShape(t *testing.T) {
	courier := neighbourID(t, "bar")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	alice := h.user(t, "alice")
	h.handedRow(t, alice, h.fpOf(t, "bob"), "ct", 4711)

	for _, tc := range []struct {
		name string
		req  relayapi.ForwardFailedRequest
		want string
	}{
		{"id zero", failedReq(0, relayapi.CodeRefused, "x"), "id"},
		{"id negative", failedReq(-1, relayapi.CodeRefused, "x"), "id"},
		{"id MinInt64", failedReq(math.MinInt64, relayapi.CodeRefused, "x"), "id"},
		{"a code outside the set", failedReq(4711, "no-mailbox", "x"), "code"},
		{"no code at all", failedReq(4711, "", "x"), "code"},
		{"said over its bound", failedReq(4711, relayapi.CodeRefused,
			strings.Repeat("s", relayapi.MaxSaid+1)), "said"},
		{"said with a newline", failedReq(4711, relayapi.CodeRefused, "one\ntwo"), "said"},
		{"said with an escape", failedReq(4711, relayapi.CodeRefused, "one\x1b[2Jtwo"), "said"},
		{"said with a tab", failedReq(4711, relayapi.CodeRefused, "one\ttwo"), "said"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := h.do(courier, "POST", "/v1/forward/failed", tc.req, nil)
			if status != 400 {
				t.Fatalf("%d %s", status, body)
			}
			if got := errorText(t, body); !strings.Contains(got, tc.want) {
				t.Errorf("%q; want the field named", got)
			}
		})
	}
	// MaxInt64 is a number, so it passes the shape and meets the lookup: a
	// row nobody was handed.
	status, body := h.do(courier, "POST", "/v1/forward/failed",
		failedReq(math.MaxInt64, relayapi.CodeRefused, "x"), nil)
	if status != 404 {
		t.Errorf("id MaxInt64: %d %s; want the lookup's answer, the shape being fine", status, body)
	}
	// And a report at every bound is taken.
	if status, body := h.do(courier, "POST", "/v1/forward/failed",
		failedReq(4711, relayapi.CodeGaveUp, strings.Repeat("s", relayapi.MaxSaid)), nil); status != 204 {
		t.Errorf("a report at its bounds: %d %s", status, body)
	}
}

// TestAReportIsBoundToTheNewestHandedRowSharingItsPair: the pair a report is
// looked up by is not unique and cannot be.
//
// A neighbour whose database was recreated numbers its rows from one again,
// and this relay may still hold a handed row from before with the same pair
// inside the window a report could arrive in. So among the rows carrying the
// pair, the newest handed one is the one the report is about, since a report
// comes from the neighbour's present numbering.
func TestAReportIsBoundToTheNewestHandedRowSharingItsPair(t *testing.T) {
	courier := neighbourID(t, "bar")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	alice := h.user(t, "alice")

	t.Run("two handed rows sharing the pair", func(t *testing.T) {
		older := h.handedRow(t, alice, h.fpOf(t, "bob"), "older", 5)
		newer := h.handedRow(t, alice, h.fpOf(t, "bob"), "newer", 5)
		if status, body := h.do(courier, "POST", "/v1/forward/failed",
			failedReq(5, relayapi.CodeRefused, "gone"), nil); status != 204 {
			t.Fatalf("%d %s", status, body)
		}
		if got := h.outbound(t, newer); got.State != OutFinal {
			t.Errorf("the newer row is %q, want final", got.State)
		}
		if got := h.outbound(t, older); got.State != OutHanded {
			t.Errorf("the older row is %q, want still handed: a report is about the neighbour's "+
				"present numbering", got.State)
		}
	})
	t.Run("one final and one handed sharing the pair", func(t *testing.T) {
		done := h.handedRow(t, alice, h.fpOf(t, "carol"), "done", 6)
		if err := h.store.Failed(done, relayapi.CodeRefused, "bar: told already", h.clock.Now()); err != nil {
			t.Fatal(err)
		}
		live := h.handedRow(t, alice, h.fpOf(t, "carol"), "live", 6)
		if status, body := h.do(courier, "POST", "/v1/forward/failed",
			failedReq(6, relayapi.CodeRefused, "gone"), nil); status != 204 {
			t.Fatalf("%d %s", status, body)
		}
		if got := h.outbound(t, live); got.State != OutFinal {
			t.Errorf("the handed row is %q, want final", got.State)
		}
		if got := h.outbound(t, done); got.Said != "bar: told already" {
			t.Errorf("the row already told about was written again: %q", got.Said)
		}
	})
	t.Run("rows sharing the pair with none handed", func(t *testing.T) {
		id := h.handedRow(t, alice, h.fpOf(t, "dave"), "d", 7)
		if err := h.store.Failed(id, relayapi.CodeRefused, "bar: no", h.clock.Now()); err != nil {
			t.Fatal(err)
		}
		status, body := h.do(courier, "POST", "/v1/forward/failed",
			failedReq(7, relayapi.CodeRefused, "again"), nil)
		if status != 409 || errorText(t, body) != relayapi.MsgRowNotHanded {
			t.Fatalf("%d %s", status, body)
		}
	})
}

// TestAReportForACouriersRowIsQueuedOnward: an undeliverable unwinds one hop
// at a time, and the hop it unwinds to is the one that posted the row.
func TestAReportForACouriersRowIsQueuedOnward(t *testing.T) {
	// This relay accepts from bar and from alpha, and dials both: alpha
	// posted the mail, bar was handed it, and bar is now reporting.
	bar := neighbourID(t, "bar")
	alpha := neighbourID(t, "alpha")
	h := peered(t, []string{"bar", "alpha"}, []*identity.Identity{bar, alpha}, nil)
	h.enroll(bar, alpha)
	row := h.handedRow(t, alpha, h.fpOf(t, "bob"), "ct", 4711)

	if status, body := h.do(bar, "POST", "/v1/forward/failed",
		failedReq(4711, relayapi.CodeRefused, "baz: no such mailbox"), nil); status != 204 {
		t.Fatalf("%d %s", status, body)
	}
	// The row is finished, and a report is waiting for the courier that
	// posted it, naming this relay's own row id — the number alpha holds.
	if got := h.outbound(t, row); got.State != OutFinal {
		t.Fatalf("the row is %q", got.State)
	}
	queued := h.reportRows(t)
	if len(queued) != 1 {
		t.Fatalf("%d report rows queued, want 1", len(queued))
	}
	r := queued[0]
	if r.Neighbour != "alpha" {
		t.Errorf("the report is for %q, want alpha, the courier that posted", r.Neighbour)
	}
	if r.TheirID != row {
		t.Errorf("the report names %d, want this relay's own row %d, which is the number alpha holds",
			r.TheirID, row)
	}
	if r.Kind != KindReport {
		t.Errorf("kind %q", r.Kind)
	}
	if r.Said != "bar: baz: no such mailbox" {
		t.Errorf("said %q; want this relay's name for the failing hop in front", r.Said)
	}
	if r.ToFP != "" || r.Hash != "" || r.Size != 0 {
		t.Errorf("a report row carries a recipient, a hash or bytes: %+v", r)
	}
}

// TestNoReportForAReport: the chain ends where it started.
func TestNoReportForAReport(t *testing.T) {
	bar := neighbourID(t, "bar")
	alpha := neighbourID(t, "alpha")
	h := peered(t, []string{"bar", "alpha"}, []*identity.Identity{bar, alpha}, nil)
	h.enroll(bar, alpha)
	// A report row this relay is holding for bar, handed over and then
	// reported on by bar — which cannot happen honestly, and must not make
	// a second report if it does.
	row := h.handedRow(t, alpha, h.fpOf(t, "bob"), "ct", 100)
	if status, body := h.do(bar, "POST", "/v1/forward/failed",
		failedReq(100, relayapi.CodeRefused, "no"), nil); status != 204 {
		t.Fatalf("%d %s", status, body)
	}
	_ = row
	before := len(h.reportRows(t))
	// Hand the report row over and let bar report on it.
	reports := h.reportRows(t)
	if len(reports) != 1 {
		t.Fatalf("%d reports", len(reports))
	}
	if err := h.store.Handed(reports[0].ID, 200, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	// alpha is the neighbour that row is for, so alpha is who could report.
	if status, body := h.do(alpha, "POST", "/v1/forward/failed",
		failedReq(200, relayapi.CodeRefused, "nor this"), nil); status != 204 {
		t.Fatalf("reporting on a report: %d %s", status, body)
	}
	if after := len(h.reportRows(t)); after != before {
		t.Errorf("%d report rows after reporting on a report, was %d: a report begets a report",
			after, before)
	}
}

// TestACouriersReportRateIsItsOwn: reports_per_minute bounds reporting beside
// the request budget and apart from posting.
func TestACouriersReportRateIsItsOwn(t *testing.T) {
	courier := neighbourID(t, "bar")
	limits := DefaultCourierLimits()
	limits.ReportsPerMinute = 2
	// Two neighbours, since a courier named bar cannot post an address that
	// names bar: this relay writes its own name for the caller onto the hops
	// so far, and an address names each relay once.
	h := peered(t, []string{"bar", "baz"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	alice := h.user(t, "alice")
	for i := range 3 {
		h.handedRow(t, alice, h.fpOf(t, "bob"), fmt.Sprintf("ct%d", i), int64(i+1))
	}

	for i := range 2 {
		if status, body := h.do(courier, "POST", "/v1/forward/failed",
			failedReq(int64(i+1), relayapi.CodeRefused, "no"), nil); status != 204 {
			t.Fatalf("report %d: %d %s", i, status, body)
		}
	}
	status, body := h.do(courier, "POST", "/v1/forward/failed",
		failedReq(3, relayapi.CodeRefused, "no"), nil)
	if status != 429 {
		t.Fatalf("at reports_per_minute 2: %d %s", status, body)
	}
	// Posting is untouched: the two rates are separate budgets.
	if status, _, body := h.forward(courier,
		request(sealedFor(h.fpOf(t, "bob"), "still posting"), []string{"baz"}, nil)); status != 201 {
		t.Errorf("posting after the report rate ran out: %d %s", status, body)
	}
}

// TestNoCourierLineAboutAReportNamesAFingerprint: a line this relay writes
// about forwarding names a neighbour by the name its operator gave and never
// an identity, as every other such line does.
//
// The access log is a different thing and is not in scope: it carries the
// caller's fingerprint on purpose, being the relay's own record of who asked
// for what, and an operator turns it down with the minimal mode. What must
// carry no fingerprint is the courier's own remarks, which are about
// neighbours.
func TestNoCourierLineAboutAReportNamesAFingerprint(t *testing.T) {
	bar := neighbourID(t, "bar")
	alpha := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{bar, alpha}, nil)
	h.enroll(bar, alpha)
	// alpha is accepted from and not dialled, so a report for its row is one
	// this relay cannot pass back: the one-way peering line.
	row := h.handedRow(t, alpha, h.fpOf(t, "bob"), "ct", 4711)
	_ = row
	h.do(bar, "POST", "/v1/forward/failed", failedReq(4711, relayapi.CodeRefused, "no"), nil)
	h.do(bar, "POST", "/v1/forward/failed", failedReq(9999, relayapi.CodeRefused, "no"), nil)

	var courierLines []string
	for _, line := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(line, "courier:") {
			courierLines = append(courierLines, line)
		}
	}
	if len(courierLines) == 0 {
		t.Fatal("no courier line was written, so this test proves nothing")
	}
	joined := strings.Join(courierLines, "\n")
	for _, fp := range []string{bar.Fingerprint(), alpha.Fingerprint()} {
		if strings.Contains(joined, fp) || strings.Contains(joined, fp[:16]) {
			t.Errorf("a fingerprint is in a courier line:\n%s", joined)
		}
	}
	// And the neighbour is named, so the operator can act on it.
	if !strings.Contains(joined, "alpha") {
		t.Errorf("no courier line names the neighbour:\n%s", joined)
	}
}

// reportRows is every report row in the queue, oldest first.
func (h *harness) reportRows(t *testing.T) []*Outbound {
	t.Helper()
	rows, err := h.store.db.Query(`SELECT id, poster_fp, neighbour, path, via, to_fp, hash, size, kind,
		received, state, tries, last_try, next_try, gives_up, their_id, code, said
		FROM outbound WHERE kind = ? ORDER BY id`, KindReport)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []*Outbound
	for rows.Next() {
		o, err := scanOutboundRows(rows)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, o)
	}
	return out
}

// TestAReportTakenIsASuccessEvenWhenTheNewsCannotTravel: the request that
// brought a report succeeds whatever becomes of the report this relay owes
// the hop behind.
//
// The reporting relay needs one thing: that this relay has taken it and will
// not be asked again. Answering it a failure would invite a retry of a report
// already acted on, which a final row refuses, so the retry could not be
// answered usefully by anybody. The news failing to travel is this relay's
// own trouble and goes in its log, and the hop behind finds out when its own
// forward_ttl runs out.
//
// The case here is the queue having no room: a report row is counted against
// the row bounds, because it is a row, so a courier at its share can be
// refused one.
func TestAReportTakenIsASuccessEvenWhenTheNewsCannotTravel(t *testing.T) {
	bar := neighbourID(t, "bar")
	alpha := neighbourID(t, "alpha")
	limits := DefaultCourierLimits()
	// One row per courier: alpha's own queued envelope fills its share, so
	// there is no room for the report this relay owes it.
	limits.QueueMaxMessagesPerCourier = 1
	h := peered(t, []string{"bar", "alpha"}, []*identity.Identity{bar, alpha}, &limits)
	h.enroll(bar, alpha)
	row := h.handedRow(t, alpha, h.fpOf(t, "bob"), "ct", 4711)
	// A second row for alpha, still waiting, which is its whole share.
	if status, _, body := h.forward(alpha,
		request(sealedFor(h.fpOf(t, "bob"), "filling the share"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("filling alpha's share: %d %s", status, body)
	}

	status, body := h.do(bar, "POST", "/v1/forward/failed",
		failedReq(4711, relayapi.CodeRefused, "baz: no such mailbox"), nil)
	if status != 204 {
		t.Fatalf("a report this relay cannot pass on: %d %s; the reporter is owed a success", status, body)
	}
	// The row is final, which is what the report was for.
	if got := h.outbound(t, row); got.State != OutFinal {
		t.Errorf("the row is %q, want final", got.State)
	}
	// No report row was written, and the operator has a line saying so.
	if rows := h.reportRows(t); len(rows) != 0 {
		t.Errorf("%d report rows queued past the bound", len(rows))
	}
	if !strings.Contains(h.logs.String(), "could not be queued") {
		t.Errorf("nothing in the log about news that could not travel:\n%s", h.logs.String())
	}
}

// TestAnUndeliverableUnwindsAChainOfThreeRelays: the whole of what the route
// is for, with three relays in the room and nothing between them faked.
//
// Alice on A addresses bob by bar!baz!bob. A carries it to B, B to C, and C
// cannot deliver. C tells B, B finals its row and tells A, A finals the row
// whose poster is alice — and what alice's row says names each hop by the name
// her own relay's operator chose, outermost first, with the sentence C wrote
// innermost: `bar: baz: <C's refusal>`.
//
// C's refusal here is bob's allow list, which is the refusal a courier meets
// first. Delivery asks MayPost about the courier that handed the message over,
// because a relay cannot open an envelope and the only sender it can prove is
// its neighbour, so a recipient who has pushed a list at all refuses everything
// forwarded until they name that courier. No such mailbox needs bob absent from
// C altogether, which is the rarer arrangement and is covered on its own by
// TestWhatDeliveryRefusesAndInWhatOrder.
//
// Two relays cannot find what this finds: with two, the sender's own relay is
// the one that meets the refusal, so its row ends correctly and nothing has to
// travel. The third relay is what makes the onward report necessary.
//
// The relays are real: each has its own store, its own courier home naming the
// next by its own name for it, and its own couriers file admitting the one
// behind. What the test drives by hand is the workers, so there is no timer to
// wait out and each hop happens where the test can see it.
func TestAnUndeliverableUnwindsAChainOfThreeRelays(t *testing.T) {
	c := newChain(t)
	alice := c.a.user(t, "alice")
	bob := c.c.user(t, "bob")

	// Alice addresses bob two relays away. A queues it.
	status, answer, body := c.a.forward(alice,
		request(sealedFor(bob.Fingerprint(), "two hops"), []string{"bar", "baz"}, nil))
	if status != 201 {
		t.Fatalf("alice posting: %d %s", status, body)
	}

	// A's worker hands it to B, whose route queues it for C.
	c.handOn(t, c.a, "bar")
	bRow := c.b.onlyOutbound(t, OutWaiting)
	if bRow.Neighbour != "baz" {
		t.Fatalf("B queued it for %q, want baz", bRow.Neighbour)
	}
	// B's worker hands it to C, whose route tries to deliver and cannot:
	// bob's allow list names somebody else, so the delivery is refused
	// synchronously and B's row fails on the spot.
	if status, body, _ := c.c.pushAllow(bob, bob, time.Now(), c.c.fpOf(t, "nobody")); status != 204 {
		t.Fatalf("bob's allow list: %d %s", status, body)
	}
	c.handOn(t, c.b, "baz")

	// B's row is final with C's refusal, under B's own name for C.
	bFinal := c.b.outbound(t, bRow.ID)
	if bFinal.State != OutFinal {
		t.Fatalf("B's row is %q, want final", bFinal.State)
	}
	if !strings.HasPrefix(bFinal.Said, "baz: ") {
		t.Errorf("B's row says %q; want B's own name for C in front", bFinal.Said)
	}
	// And B has queued a report for A, since B's row was posted by A's
	// courier and not by one of B's own users.
	c.handOn(t, c.b, "alpha")

	// A's row is final, naming both hops by A's own names for them, with the
	// sentence C wrote innermost.
	aFinal := c.a.outbound(t, answer.ID)
	if aFinal.State != OutFinal {
		t.Fatalf("A's row is %q, want final", aFinal.State)
	}
	if !strings.HasPrefix(aFinal.Said, "bar: baz: ") {
		t.Errorf("A's row says %q; want each hop named by A's and B's own names, outermost first",
			aFinal.Said)
	}
	if !strings.Contains(aFinal.Said, "not on the recipient's allow list") {
		t.Errorf("A's row says %q; want the sentence C gave", aFinal.Said)
	}
	if aFinal.Code != relayapi.CodeRefused {
		t.Errorf("A's row's code is %q", aFinal.Code)
	}
	// Alice reads it in her own queue, which is what the route is for.
	queued := c.a.queueOf(t, alice)
	if len(queued) != 1 || queued[0].State != OutFinal {
		t.Fatalf("alice's queue: %+v", queued)
	}
	if queued[0].Said != aFinal.Said {
		t.Errorf("the queue says %q and the row %q", queued[0].Said, aFinal.Said)
	}
}

// TestAChainAtTheSaidCapKeepsTheInnermostSentence: ruling 6, at the cap.
//
// A sentence grows at the front as a report travels back, so at the cap it is
// the front that goes: the last bytes that fit are kept on a rune boundary,
// with a marker in front saying hops were dropped, and the sentence the relay
// that actually failed wrote survives. The head is what a reader can spare —
// the leftmost name is their own relay's name for its neighbour, which the
// row's own neighbour column prints on the line above.
func TestAChainAtTheSaidCapKeepsTheInnermostSentence(t *testing.T) {
	c := newChain(t)
	alice := c.a.user(t, "alice")
	bob := c.c.user(t, "bob")

	status, answer, body := c.a.forward(alice,
		request(sealedFor(bob.Fingerprint(), "long"), []string{"bar", "baz"}, nil))
	if status != 201 {
		t.Fatalf("%d %s", status, body)
	}
	c.handOn(t, c.a, "bar")
	bRow := c.b.onlyOutbound(t, OutWaiting)
	// Handed on, so B's row carries the id C answered with — which is the id
	// a report names. What C did with it is not the point here: this test is
	// the cap's arithmetic over two hops, and the chain above is where a
	// refusal is earned.
	c.handOn(t, c.b, "baz")
	if got := c.b.outbound(t, bRow.ID); got.State != OutHanded {
		t.Fatalf("B's row is %q, want handed", got.State)
	}
	bRow = c.b.outbound(t, bRow.ID)

	// C reports a sentence already at the cap, which is what a long chain
	// eventually produces. B must keep its end and drop its front.
	innermost := "the innermost sentence"
	long := strings.Repeat("x", relayapi.MaxSaid-len(innermost)) + innermost
	if status, body := c.b.do(c.cCourier, "POST", "/v1/forward/failed",
		failedReq(bRow.TheirID, relayapi.CodeRefused, long), nil); status != 204 {
		t.Fatalf("C's report to B: %d %s", status, body)
	}
	bFinal := c.b.outbound(t, bRow.ID)
	if len(bFinal.Said) > relayapi.MaxSaid {
		t.Errorf("B kept %d bytes, want at most %d", len(bFinal.Said), relayapi.MaxSaid)
	}
	if !strings.HasPrefix(bFinal.Said, "…") {
		t.Errorf("B's row says %q; want the marker in front", bFinal.Said[:40])
	}
	if !strings.HasSuffix(bFinal.Said, innermost) {
		t.Errorf("B's row ends %q; want the innermost sentence intact",
			bFinal.Said[len(bFinal.Said)-40:])
	}

	// And one hop further: A's row keeps the same end, still under the cap,
	// still marked.
	c.handOn(t, c.b, "alpha")
	aFinal := c.a.outbound(t, answer.ID)
	if len(aFinal.Said) > relayapi.MaxSaid {
		t.Errorf("A kept %d bytes, want at most %d", len(aFinal.Said), relayapi.MaxSaid)
	}
	if !strings.HasSuffix(aFinal.Said, innermost) {
		t.Errorf("A's row ends %q; want the innermost sentence intact after two hops",
			aFinal.Said[len(aFinal.Said)-40:])
	}
	if !strings.HasPrefix(aFinal.Said, "…") {
		t.Errorf("A's row says %q; want the marker in front", aFinal.Said[:40])
	}
	if !utf8.ValidString(aFinal.Said) {
		t.Error("the sentence was cut through a character")
	}
}

// chain is three relays in a row, A → B → C, each peered with its neighbour
// the way an operator would peer them: a courier identity of its own, enrolled
// at the next relay and admitted there by an export line, with a courier home
// naming that relay by this relay's own name for it.
//
// The names differ in every direction on purpose. A calls B "bar", B calls C
// "baz", B calls A "alpha", C calls B "beta". A name is relative to the relay
// reading it, and a chain where every relay used one name would pass whichever
// name the code happened to read.
type chain struct {
	a, b, c                      *harness
	aCourier, bCourier, cCourier *identity.Identity
}

// newChain builds it. The relays are made back to front, since a courier home
// names a URL that has to be listening: C first, then B naming C, then A
// naming B. B also names A, which does not exist yet — so B's home gets that
// entry once A is up, through the same store B is already reading.
func newChain(t *testing.T) *chain {
	t.Helper()
	// Each courier is named for what its neighbour calls the relay it belongs
	// to, since the name in an export line is the neighbour's name for that
	// relay and is what the neighbour writes into a report.
	aCourier := neighbourID(t, "alpha")
	bCourier := neighbourID(t, "bar")
	cCourier := neighbourID(t, "baz")

	// C accepts from B and dials nobody: the end of the chain.
	cFile := couriersFile(t, bCourier)
	cc, err := NewCourier(CourierConfig{
		Home: courierHomeAs(t, cCourier, map[string]string{}), AuthorizedFile: cFile,
		PublicURL: "https://c.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	c := newHarness(t, Config{Courier: cc, CourierLimits: DefaultCourierLimits(), Limits: DefaultLimits()})
	quiet(t, c)
	c.enroll(bCourier)

	// B accepts from A and C, dials C as "baz"; A is added below.
	bFile := couriersFile(t, aCourier, cCourier)
	bHome := courierHomeAs(t, bCourier, map[string]string{"baz": c.srv.URL})
	bc, err := NewCourier(CourierConfig{Home: bHome, AuthorizedFile: bFile,
		PublicURL: "https://b.example"}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	b := newHarness(t, Config{Courier: bc, CourierLimits: DefaultCourierLimits(), Limits: DefaultLimits()})
	quiet(t, b)
	b.enroll(aCourier, cCourier)

	// A accepts from B and dials B as "bar".
	aFile := couriersFile(t, bCourier)
	ac, err := NewCourier(CourierConfig{
		Home: courierHomeAs(t, aCourier, map[string]string{"bar": b.srv.URL}), AuthorizedFile: aFile,
		PublicURL: "https://a.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	a := newHarness(t, Config{Courier: ac, CourierLimits: DefaultCourierLimits(), Limits: DefaultLimits()})
	quiet(t, a)
	a.enroll(bCourier)

	// And B learns to dial A, now that A is listening.
	//
	// A mutual peering is a knot: a relay reads its neighbours' addresses
	// when its courier is built, and neither address exists until a listener
	// does. The operator's answer is to add the relay and restart; the test's
	// is to do to B's courier what a restart would — write the relay into the
	// home it came out of, and put it in the map that was read from there —
	// because starting a fourth harness to get a listener first would be a
	// fourth relay in a test about three.
	addNeighbour(t, bc, "alpha", a.srv.URL)
	return &chain{a: a, b: b, c: c, aCourier: aCourier, bCourier: bCourier, cCourier: cCourier}
}

// addNeighbour gives a courier a neighbour after it was built, which is what a
// restart would give it: the relay is written into the home the courier came
// out of, so anything reading the home finds it, and into the map that was
// read from there.
func addNeighbour(t *testing.T, c *Courier, name, url string) {
	t.Helper()
	r, err := c.home.AddRelay(name, url)
	if err != nil {
		t.Fatal(err)
	}
	c.neighbours[strings.ToLower(name)] = r
}

// handOn runs one turn of one relay's worker for one neighbour, with the real
// dialling and the real posting, so what crosses between two relays is what
// crosses in earnest.
func (ch *chain) handOn(t *testing.T, h *harness, neighbour string) {
	t.Helper()
	w := worker(t, h)
	r, ok := w.courier.Neighbour(neighbour)
	if !ok {
		t.Fatalf("%s has no neighbour %q", h.srv.URL, neighbour)
	}
	w.drain(r)
}

// onlyOutbound is the one row in that state, or a failure naming what was
// there instead.
func (h *harness) onlyOutbound(t *testing.T, state string) *Outbound {
	t.Helper()
	rows, err := h.store.db.Query(`SELECT id, poster_fp, neighbour, path, via, to_fp, hash, size, kind,
		received, state, tries, last_try, next_try, gives_up, their_id, code, said
		FROM outbound WHERE state = ? ORDER BY id`, state)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var found []*Outbound
	for rows.Next() {
		o, err := scanOutboundRows(rows)
		if err != nil {
			t.Fatal(err)
		}
		found = append(found, o)
	}
	if len(found) != 1 {
		t.Fatalf("%d rows in state %q, want 1", len(found), state)
	}
	return found[0]
}

// TestAReportARelayWillNotTakeEndsTheChain: what becomes of an undeliverable
// the next hop back refuses.
//
// A report is taken once, so a neighbour answering 409 has been told already,
// and one answering 400 will not take what this relay sent: both are final,
// no retry helps and there is nobody left to tell. The row ends, the operator
// gets a line, and — the part that matters now that failing a row carries
// reportBack — no second report is made for it. This is exactly where a
// report for a report would come from if the chain did not stop here.
//
// A 404 was in that list and is not any more inside the row's lifetime
// (G18, R23): the neighbour may not yet have written down the id this relay
// answered it with, so the report waits on its own backoff and the operator
// is told nothing about the chain ending. At the row's gives_up it is final
// as before, and that case carries every assertion the other two do. The
// drain's sweep runs before the attempt and ends a row already at its
// gives_up, so the 404 that is final is the one whose answer takes the clock
// across it: the turn starts a second inside, and the neighbour answers a
// second later.
func TestAReportARelayWillNotTakeEndsTheChain(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		// inside is how far inside the row's lifetime the turn starts, and
		// late how long the neighbour takes to answer.
		inside, late time.Duration
		final        bool
	}{
		{"Conflict", http.StatusConflict, 0, 0, true},
		{"Bad Request", http.StatusBadRequest, 0, 0, true},
		{"Not Found inside the lifetime", http.StatusNotFound, 0, 0, false},
		{"Not Found a second before the lifetime ends", http.StatusNotFound, time.Second, 0, false},
		{"Not Found at the lifetime's end", http.StatusNotFound, time.Second, time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bar := neighbourID(t, "bar")
			alpha := neighbourID(t, "alpha")
			h := peered(t, []string{"bar", "alpha"}, []*identity.Identity{bar, alpha}, nil)
			h.enroll(bar, alpha)
			// alpha posted it, bar was handed it, bar reports: so this relay
			// owes alpha a report, which is the row under test.
			h.handedRow(t, alpha, h.fpOf(t, "bob"), "ct", 4711)
			if got, body := h.do(bar, "POST", "/v1/forward/failed",
				failedReq(4711, relayapi.CodeRefused, "baz: no such mailbox"), nil); got != 204 {
				t.Fatalf("bar's report: %d %s", got, body)
			}
			queued := h.reportRows(t)
			if len(queued) != 1 || queued[0].State != OutWaiting {
				t.Fatalf("report rows: %+v", queued)
			}
			if tc.inside > 0 {
				h.clock.advance(queued[0].GivesUp.Sub(h.clock.Now()) - tc.inside)
			}

			// alpha will not take it.
			w := worker(t, h)
			w.dial = func(*store.Relay) (*client.Client, error) { return nil, nil }
			w.reportTo = func(context.Context, *client.Client, int64, string, string) error {
				h.clock.advance(tc.late)
				return &client.HTTPError{Status: tc.status, Message: "no"}
			}
			r, ok := w.courier.Neighbour("alpha")
			if !ok {
				t.Fatal("no neighbour alpha")
			}
			w.drain(r)

			rows := h.reportRows(t)
			if len(rows) != 1 {
				t.Fatalf("%d report rows, want the one: a report begets no report", len(rows))
			}
			// The operator's lines, in a courier line naming the neighbour
			// and not a fingerprint. The access log is a different thing and
			// carries the caller's fingerprint on purpose, so the claim is
			// about this relay's own remarks, as every other such claim here
			// is.
			var courierLines []string
			for _, line := range strings.Split(h.logs.String(), "\n") {
				if strings.Contains(line, "courier:") {
					courierLines = append(courierLines, line)
				}
			}
			joined := strings.Join(courierLines, "\n")
			if strings.Contains(joined, alpha.Fingerprint()[:16]) ||
				strings.Contains(joined, bar.Fingerprint()[:16]) {
				t.Errorf("a fingerprint is in a courier line:\n%s", joined)
			}
			if !strings.Contains(joined, "alpha") {
				t.Errorf("no courier line names the neighbour:\n%s", joined)
			}

			if !tc.final {
				// The row waits on its own backoff, and nothing says the
				// chain ended.
				if rows[0].State != OutWaiting || rows[0].Tries != 1 || !rows[0].NextTry.After(h.clock.Now()) {
					t.Errorf("the report row is %q after %d tries, next %s; want waiting, put off on its own backoff",
						rows[0].State, rows[0].Tries, rows[0].NextTry)
				}
				if strings.Contains(joined, "the chain ends here") {
					t.Errorf("the operator was told the chain ended inside the row's lifetime:\n%s", joined)
				}
				return
			}

			// The row ends.
			if rows[0].State != OutFinal {
				t.Errorf("the report row is %q, want final: no retry helps and nobody is left to tell",
					rows[0].State)
			}
			// The operator is told.
			if !strings.Contains(joined, "the chain ends here") {
				t.Errorf("nothing in the log about the chain ending:\n%s", joined)
			}
			// And nothing was queued for anybody on its account.
			for _, o := range rows {
				if o.Kind == KindReport && o.State == OutWaiting {
					t.Errorf("row %d is waiting: a report was made for a report", o.ID)
				}
			}
		})
	}
}

// TestLimitAReportAtItsBoundFitsItsBodyCap: the two bounds on a report are
// about the same sentence in two encodings, and one has to allow for the
// other.
//
// MaxSaid bounds the raw sentence; MaxReportBytes bounds the JSON the relay
// being told reads. encoding/json escapes '<', '>' and '&' to six bytes each,
// and those are characters ValidOneLine permits and a refusal really carries,
// so a sentence legal at MaxSaid is up to six times longer on the wire. A cap
// of a kibibyte — what this was — refused a legal report at the cap made of
// '&' with 413 before its shape was read, the relay passing it back read that
// as a refusal and ended the chain, and the sender waited out forward_ttl to
// be told the neighbour was unreachable, which was false.
//
// So every sentence this relay would itself produce at the cap is taken by a
// relay at the cap, whatever it is made of, and a body past the cap is still
// refused.
func TestLimitAReportAtItsBoundFitsItsBodyCap(t *testing.T) {
	courier := neighbourID(t, "bar")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	alice := h.user(t, "alice")

	for _, ch := range []string{"l", "&", "<", ">", `"`, `\`, "é", "☃", "🙂"} {
		t.Run(fmt.Sprintf("a sentence of %q at the cap", ch), func(t *testing.T) {
			// A sentence at exactly MaxSaid bytes, which is what said()
			// produces for a chain that has reached the cap.
			s := strings.Repeat(ch, relayapi.MaxSaid/len(ch))
			if len(s) > relayapi.MaxSaid {
				t.Fatalf("the fixture is %d bytes, over MaxSaid", len(s))
			}
			// The body this relay's own client would send must fit the cap the
			// route reads under. Asserted on the encoding and not only through
			// the request, so that the arithmetic is the claim.
			body, err := json.Marshal(relayapi.ForwardFailedRequest{
				ID: math.MaxInt64, Code: relayapi.CodeGaveUp, Said: s,
			})
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(body)) > relayapi.MaxReportBytes {
				t.Fatalf("a legal sentence of %q at MaxSaid encodes to %d bytes, over the %d "+
					"the route reads: the relay being told would refuse it 413 before its shape "+
					"was read, and the chain would end", ch, len(body), relayapi.MaxReportBytes)
			}
			// And the route really takes it.
			id := int64(4711 + len(ch))
			h.handedRow(t, alice, h.fpOf(t, "bob"), "ct", id)
			if status, got := h.do(courier, "POST", "/v1/forward/failed",
				failedReq(id, relayapi.CodeGaveUp, s), nil); status != 204 {
				t.Fatalf("a report at its bounds: %d %s", status, got)
			}
		})
	}

	// The arithmetic the constant's comment gives, held to the encoder rather
	// than left as prose: the object at its widest, with an empty sentence, is
	// 54 bytes, which is an int64 at 20 characters, the longer code word at 7,
	// and 27 for the keys, the punctuation and the quotes around the two
	// string values. Twenty and not nineteen because the body is read before
	// the shape is, so the cap must cover an id the route will then refuse.
	t.Run("the object's own overhead", func(t *testing.T) {
		empty, err := json.Marshal(relayapi.ForwardFailedRequest{
			ID: math.MinInt64, Code: relayapi.CodeGaveUp, Said: "",
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(empty) != 54 {
			t.Errorf("the widest object with an empty sentence is %d bytes, and the constant's "+
				"comment says 54; one of the two is wrong", len(empty))
		}
		if got := len(empty) - 20 - len(relayapi.CodeGaveUp); got != 27 {
			t.Errorf("the keys, punctuation and quotes are %d bytes, and the comment says 27", got)
		}
		// And the widest body the route can be asked to read, with the spare
		// the comment claims.
		amp := strings.Repeat("&", relayapi.MaxSaid)
		widest, err := json.Marshal(relayapi.ForwardFailedRequest{
			ID: math.MinInt64, Code: relayapi.CodeGaveUp, Said: amp,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(widest) != 6*relayapi.MaxSaid+len(empty) {
			t.Errorf("the widest body is %d bytes, want six times the sentence plus the object's "+
				"%d", len(widest), len(empty))
		}
		if spare := relayapi.MaxReportBytes - len(widest); spare != 74 {
			t.Errorf("%d bytes spare over the widest body; the comment says 74", spare)
		}
	})

	// A body past the cap is still refused, so the raised cap is a cap.
	t.Run("a body past the cap", func(t *testing.T) {
		h.handedRow(t, alice, h.fpOf(t, "bob"), "ct", 9001)
		over := strings.Repeat("l", relayapi.MaxReportBytes+1)
		status, _ := h.do(courier, "POST", "/v1/forward/failed",
			relayapi.ForwardFailedRequest{ID: 9001, Code: relayapi.CodeGaveUp, Said: over}, nil)
		if status != 413 {
			t.Errorf("a body of %d bytes: %d, want 413", len(over), status)
		}
	})
}

// TestGivingUpOnARowTellsTheHopBehind: forward_ttl running out is the third
// way a row ends, and the news has to travel from it too.
//
// The two the route and the worker's refusal path cover are a hop refusing.
// The third is this relay giving up on a neighbour that never answered, which
// is what CodeGaveUp is for and is the only thing that produces it. A row
// given up on whose poster is one of this relay's own users needs nothing
// further — their row says it, and they read it in their own queue, which
// TestForwardTTLEndsARowAndTellsThePoster covers. A row whose poster is a
// neighbour is owed the news exactly as a refused one is.
//
// Without this, alice two relays away is not told the wrong thing: she is told
// nothing at all. Her own relay handed the envelope over successfully, so her
// row is handed rather than waiting, and GiveUp only ever looks at waiting
// rows — so her row is never given up on either. It sits handed until the
// purge takes it at the carried window and she never learns anything.
func TestGivingUpOnARowTellsTheHopBehind(t *testing.T) {
	alpha := neighbourID(t, "alpha")
	limits := DefaultCourierLimits()
	limits.ForwardTTL = time.Hour
	h := peered(t, []string{"bar", "alpha"}, []*identity.Identity{alpha}, &limits)
	h.enroll(alpha)

	// A row alpha's courier posted, bound onward for bar.
	status, answer, body := h.forward(alpha,
		request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))
	if status != 201 {
		t.Fatalf("alpha posting: %d %s", status, body)
	}

	// bar never answers, and forward_ttl runs out.
	w := fakeNeighbour(t, h, func() (int64, error) { return 0, errors.New("connection refused") })
	r, _ := w.courier.Neighbour("bar")
	h.clock.advance(61 * time.Minute)
	w.drain(r)

	row := h.outbound(t, answer.ID)
	if row.State != OutFinal || row.Code != relayapi.CodeGaveUp {
		t.Fatalf("the row is %q with code %q, want final and %q", row.State, row.Code, relayapi.CodeGaveUp)
	}

	// And a report is waiting for alpha, carrying the id alpha holds.
	reports := h.reportRows(t)
	if len(reports) != 1 {
		t.Fatalf("%d report rows, want one: giving up on a neighbour's row told the hop behind nothing, "+
			"so its sender is never told at all — its own row is handed, not waiting, and GiveUp only "+
			"looks at waiting rows", len(reports))
	}
	got := reports[0]
	if got.Neighbour != "alpha" {
		t.Errorf("the report is for %q, want alpha", got.Neighbour)
	}
	if got.TheirID != answer.ID {
		t.Errorf("the report names id %d, want %d, which is the id alpha holds", got.TheirID, answer.ID)
	}
	if got.Code != relayapi.CodeGaveUp {
		t.Errorf("the report's code is %q, want %q", got.Code, relayapi.CodeGaveUp)
	}
	for _, want := range []string{"gave up after", "bar", "unreachable since"} {
		if !strings.Contains(got.Said, want) {
			t.Errorf("the report says %q, which does not carry %q", got.Said, want)
		}
	}
	// The sentence must fit what the hop behind will hold it to, or the news
	// stops at its route.
	if len(got.Said) > relayapi.MaxSaid {
		t.Errorf("the sentence is %d bytes, over MaxSaid %d", len(got.Said), relayapi.MaxSaid)
	}

	// And a report row of this relay's own that gives up makes no report:
	// giving up now runs through fail, so this path reaches reportBack as the
	// other two do and the rule against a report for a report has to hold
	// here too. The report queued above is for alpha and waiting, so it is
	// itself a row that will give up when its own gives_up passes.
	if got.State != OutWaiting {
		t.Fatalf("the report is %q, want waiting", got.State)
	}
	before := len(h.reportRows(t))
	h.clock.advance(2 * time.Hour)
	alphaRelay, ok := w.courier.Neighbour("alpha")
	if !ok {
		t.Fatal("no neighbour alpha")
	}
	if n, err := h.store.GiveUp(w.ctx, alphaRelay.Name, h.clock.Now(), limits.ForwardTTL, w.fail); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Fatalf("gave up on %d rows for alpha, want the one report", n)
	}
	if r := h.outbound(t, got.ID); r.State != OutFinal {
		t.Errorf("the report row is %q, want final", r.State)
	}
	if after := len(h.reportRows(t)); after != before {
		t.Errorf("%d report rows, was %d: a report was made for a report", after, before)
	}
}

// TestASentenceThisRelayWritesIsOneItsOwnRouteAccepts: a name has one rule and
// both ends run it, and a sentence is no different.
//
// What this relay produces from a neighbour's refusal travels to the hop behind
// and is read by that hop's report route, which holds it to
// message.ValidOneLine. So every sentence said can produce has to satisfy that
// rule, or the news stops at a hop that refuses this relay's own words.
//
// The two rules were not the same. identity.PrintableText keeps a tab, a tab
// reaching a terminal being no hazard; ValidOneLine refuses one, a said being
// one line and a tab a control character. Exactly one rune differs, and this is
// the sweep that says so rather than a test of the one character, because the
// claim worth keeping is that the sets agree and not that today's offender is
// handled: a rune added to either rule breaks this test and nothing else.
//
// The failure it prevents: relay C answers with one tab in its refusal, B's
// said carries it, A's route answers 400, and the worker reads a 400 as
// something no retry fixes — so the report row ends, the chain stops, and
// alice is never told, for one byte of C's choosing.
func TestASentenceThisRelayWritesIsOneItsOwnRouteAccepts(t *testing.T) {
	for r := rune(0); r < 0x110000; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // not a character
		}
		if err := message.ValidOneLine("said", said("bar", string(r))); err != nil {
			t.Fatalf("said(bar, U+%04X %q) is %v; this relay produced a sentence its own "+
				"report route refuses, so the news stops at the hop behind", r, r, err)
		}
	}
	// And the sentence still says what it was: a tab is escaped and not
	// dropped, so a reader sees that something was there.
	if got := said("bar", "no\tsuch mailbox"); got != `bar: no\tsuch mailbox` {
		t.Errorf("said = %q, want the tab escaped and the rest whole", got)
	}
	// The sweep is over the whole of what a neighbour can send, not over
	// single runes alone: a sentence at the cap of the worst rune is still
	// one line after both cuts.
	for _, r := range []string{"\t", "\x1b", " ", "é", "🙂"} {
		long := strings.Repeat(r, relayapi.MaxSaid)
		got := said("bar", long)
		if err := message.ValidOneLine("said", got); err != nil {
			t.Errorf("a sentence of %q at the cap gives %v", r, err)
		}
		if len(got) > relayapi.MaxSaid {
			t.Errorf("a sentence of %q is %d bytes, over %d", r, len(got), relayapi.MaxSaid)
		}
	}
}

// TestAReportIsFoundWhicheverHalfOfThePeeringSpelledTheName: a name has one
// rule, and here it had two spellings.
//
// The couriers file's spelling is what Accepts answers; the courier home's is
// what handleForward and reportBack write into a row's neighbour column. Both
// halves of a peering fold internally, and this relay says in as many words
// that a file saying Bar against a home saying bar is one neighbour and not a
// pair of one-way ones — so a lookup by the file's spelling against a column
// with no COLLATE found nothing, and every report from such a peering was
// refused 404 for ever. The reporting relay reads a 404 as final and drops the
// news; nothing is logged at the end that could have fixed it; so the
// misconfiguration is invisible at both ends and no sender is ever told
// anything.
func TestAReportIsFoundWhicheverHalfOfThePeeringSpelledTheName(t *testing.T) {
	// The file says Bar. The home says bar.
	courier := neighbourID(t, "Bar")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	alice := h.user(t, "alice")
	name, ok := h.server.courier.Accepts(courier.Fingerprint())
	if !ok || name != "Bar" {
		t.Fatalf("Accepts says %q, %v; the fixture wants the file's spelling", name, ok)
	}
	id := h.handedRow(t, alice, h.fpOf(t, "bob"), "ct", 4711)
	if row := h.outbound(t, id); row.Neighbour != "bar" {
		t.Fatalf("the row's neighbour is %q; the fixture wants the home's spelling", row.Neighbour)
	}

	status, body := h.do(courier, "POST", "/v1/forward/failed",
		failedReq(4711, relayapi.CodeRefused, "baz: no such mailbox"), nil)
	if status != 204 {
		t.Fatalf("a report from a peering spelled Bar in the file and bar in the home: %d %s; "+
			"want it taken, the two being one neighbour", status, body)
	}
	if row := h.outbound(t, id); row.State != OutFinal {
		t.Errorf("the row is %q, want final", row.State)
	}
	// And the name in front of the sentence is one spelling, the home's,
	// which is the one the row already carries.
	if row := h.outbound(t, id); !strings.HasPrefix(row.Said, "bar: ") {
		t.Errorf("said %q; want the home's spelling in front, as the row's own column has it", row.Said)
	}
}

// TestAReportIsTakenOnceUnderConcurrentReports: "and once" is a claim both
// documents make, and it was two statements.
//
// HandedTo reads the row, to tell a row never handed to that courier from one
// this relay is not waiting to hear about, and then the row is ended. The one
// connection the store has serialises statements and not pairs, so two reports
// naming one id both read handed and both took it. The cost was a duplicate
// report row charged to the hop behind's share of this relay's queue — which a
// neighbour reporting concurrently could spend to have that hop's honest
// forwards refused 507 — and a second report arriving at the hop behind, which
// answers 409 as it should and which this relay then writes up as a neighbour
// refusing an undeliverable: a false line in the operator's log about news that
// did travel.
func TestAReportIsTakenOnceUnderConcurrentReports(t *testing.T) {
	bar := neighbourID(t, "bar")
	alpha := neighbourID(t, "alpha")
	h := peered(t, []string{"bar", "alpha"}, []*identity.Identity{bar, alpha}, nil)
	h.enroll(bar, alpha)
	// The row's poster is alpha's courier, so taking it twice queues two
	// reports and charges two rows to alpha's share.
	h.handedRow(t, alpha, h.fpOf(t, "bob"), "ct", 4711)

	const callers = 8
	statuses := make([]int, callers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			statuses[i], _ = h.do(bar, "POST", "/v1/forward/failed",
				failedReq(4711, relayapi.CodeRefused, "baz: no such mailbox"), nil)
		}()
	}
	close(start)
	wg.Wait()

	var took int
	for _, s := range statuses {
		switch s {
		case 204:
			took++
		case 409:
		default:
			t.Errorf("a concurrent report answered %d; want 204 once and 409 otherwise", s)
		}
	}
	if took != 1 {
		t.Errorf("%d of %d reports were taken (%v); a report is taken once",
			took, callers, statuses)
	}
	if rows := h.reportRows(t); len(rows) != 1 {
		t.Errorf("%d report rows queued for alpha, want one: a duplicate is charged to the hop "+
			"behind's share and comes back 409, which this relay writes up as a neighbour "+
			"refusing news that did in fact travel", len(rows))
	}
}
