package relay

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// G18 and R23: a failure report can come back to the relay behind before
// that relay has written down the id it was answered with, and a 404 for it
// is then not the end of the report. These tests are Codex's reproduction
// under its own name and the cases the plan lists beside it.

// TestAnEarlyFailureReportSurvivesTheHandOver forces a valid scheduling
// interleaving: B accepts A's forward; before A records their_id, B gets a
// final refusal from C and sends the report to A. All network requests and
// state transitions are the real harness paths.
//
// Two changes from Codex's TestReviewEarlyFailureReportSurvivesHandover,
// both the plan's. The early report's answer may be 404 or taken: the race
// this forces may or may not be won under the fix, and what is claimed is the
// end. And B's clock is moved an hour before the recovery turn, since a 404
// now puts the report row off on its own backoff (R23) and a turn at the
// same instant finds nothing due. The final assertion is Codex's, unchanged.
func TestAnEarlyFailureReportSurvivesTheHandOver(t *testing.T) {
	c := newChain(t)
	alice := c.a.user(t, "alice")
	bob := c.c.user(t, "bob")
	if status, body, _ := c.c.pushAllow(bob, bob, c.c.clock.Now(), c.c.fpOf(t, "nobody")); status != 204 {
		t.Fatalf("allow: %d %s", status, body)
	}
	status, answer, body := c.a.forward(alice, request(sealedFor(bob.Fingerprint(), "early failure"), []string{"bar", "baz"}, nil))
	if status != 201 {
		t.Fatalf("queue: %d %s", status, body)
	}
	w := worker(t, c.a)
	post := w.post
	w.post = func(ctx context.Context, cl *client.Client, req *relayapi.ForwardRequest) (int64, error) {
		id, err := post(ctx, cl, req)
		if err != nil {
			return id, err
		}
		c.handOn(t, c.b, "baz")
		back := worker(t, c.b)
		reportTo := back.reportTo
		back.reportTo = func(ctx context.Context, cl *client.Client, id int64, code, said string) error {
			err := reportTo(ctx, cl, id, code, said)
			if err == nil {
				t.Logf("upstream took the early report")
				return nil
			}
			var he *client.HTTPError
			if !errors.As(err, &he) || he.Status != http.StatusNotFound {
				t.Fatalf("early report: %v; want 404 or taken", err)
			}
			t.Logf("upstream rejected early report: %d %s", he.Status, he.Message)
			return err
		}
		back.drainOnce(t, "alpha")
		for _, report := range c.b.reportRows(t) {
			t.Logf("early report state=%s code=%s said=%q", report.State, report.Code, report.Said)
		}
		return id, nil
	}
	w.drainOnce(t, "bar")
	// Further turns should recover news, without manual resending or edits.
	// The report row's retry is on its own schedule now, so B's clock is
	// moved past it.
	c.b.clock.advance(time.Hour)
	c.handOn(t, c.b, "alpha")
	w.drainOnce(t, "bar")
	row := c.a.outbound(t, answer.ID)
	if row.State != OutFinal || row.Code != relayapi.CodeRefused {
		t.Fatalf("A ends %s/%s with their_id=%d; want final/refused despite early report", row.State, row.Code, row.TheirID)
	}
}

// fullOutbound is one row with every column, the times among them, which
// h.outbound leaves out.
func fullOutbound(t *testing.T, st *Store, id int64) *Outbound {
	t.Helper()
	o, err := scanOutbound(st.db.QueryRow(`SELECT id, poster_fp, neighbour, path, via, to_fp, hash, size, kind,
		received, state, tries, last_try, next_try, gives_up, their_id, code, said
		FROM outbound WHERE id = ?`, id))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// earlyReport runs alice's message from A to B and on to C, which refuses
// it, under the interleaving above: B's report reaches A between B's 201 and
// A's writing the id down, and A answers it 404. With lose, A's worker is
// also told the post failed, as a crash after B's 201 leaves it: A's row stays
// waiting with no their_id. It answers A's row id and B's report row.
func earlyReport(t *testing.T, c *chain, lose bool) (aRow int64, report *Outbound) {
	t.Helper()
	alice := c.a.user(t, "alice")
	bob := c.c.user(t, "bob")
	if status, body, _ := c.c.pushAllow(bob, bob, c.c.clock.Now(), c.c.fpOf(t, "nobody")); status != 204 {
		t.Fatalf("allow: %d %s", status, body)
	}
	status, answer, body := c.a.forward(alice, request(sealedFor(bob.Fingerprint(), "early failure"), []string{"bar", "baz"}, nil))
	if status != 201 {
		t.Fatalf("queue: %d %s", status, body)
	}
	w := worker(t, c.a)
	post := w.post
	w.post = func(ctx context.Context, cl *client.Client, req *relayapi.ForwardRequest) (int64, error) {
		id, err := post(ctx, cl, req)
		if err != nil {
			t.Fatalf("A's forward: %v", err)
		}
		c.handOn(t, c.b, "baz")
		back := worker(t, c.b)
		reportTo := back.reportTo
		back.reportTo = func(ctx context.Context, cl *client.Client, id int64, code, said string) error {
			err := reportTo(ctx, cl, id, code, said)
			var he *client.HTTPError
			if !errors.As(err, &he) || he.Status != http.StatusNotFound {
				t.Fatalf("early report: %v; want 404, A not having written the id down", err)
			}
			return err
		}
		back.drainOnce(t, "alpha")
		if lose {
			return 0, errors.New("connection reset by peer")
		}
		return id, nil
	}
	w.drainOnce(t, "bar")
	reports := c.b.reportRows(t)
	if len(reports) != 1 || reports[0].State != OutWaiting || reports[0].Tries != 1 {
		t.Fatalf("B's report rows after the early 404: %+v; want one waiting, tried once", reports)
	}
	return answer.ID, reports[0]
}

// TestAnEarlyReportOutlivesARestartOfTheReporter: the report row is in B's
// database with its next try written down, so a B restarted between the
// early 404 and the retry — its server gone, its store closed and opened
// again from the file, a new set of workers over it — asks again and A's row
// ends as C's refusal says.
func TestAnEarlyReportOutlivesARestartOfTheReporter(t *testing.T) {
	c := newChain(t)
	aRow, report := earlyReport(t, c, false)
	if got := c.a.outbound(t, aRow); got.State != OutHanded {
		t.Fatalf("A's row is %q before the retry, want handed with B's id", got.State)
	}

	path := c.b.dbPath()
	c.b.srv.Close()
	if err := c.b.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path, filepath.Join(filepath.Dir(path), "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	reopened.SetFaultLog(slogDiscard(), c.b.clock.Now)
	if got := fullOutbound(t, reopened, report.ID); got.State != OutWaiting || got.Tries != 1 || got.TheirID != report.TheirID {
		t.Fatalf("after the restart B's report row is %+v; want it waiting as it was left", got)
	}
	fresh := newWorkers(reopened, c.b.server.courier, DefaultCourierLimits(), slogDiscard(), c.b.clock.Now)
	if fresh == nil {
		t.Fatal("B dials nobody after the restart")
	}
	defer fresh.Stop()

	// Not before its time: the restart remembers nothing but the row.
	fresh.drainOnce(t, "alpha")
	if got := c.a.outbound(t, aRow); got.State != OutHanded {
		t.Fatalf("A's row is %q after a turn before the report was due", got.State)
	}
	c.b.clock.advance(time.Hour)
	fresh.drainOnce(t, "alpha")
	got := c.a.outbound(t, aRow)
	if got.State != OutFinal || got.Code != relayapi.CodeRefused {
		t.Fatalf("A ends %s/%s; want final/refused after the restarted reporter asked again", got.State, got.Code)
	}
	if !strings.Contains(got.Said, "not on the recipient's allow list") {
		t.Errorf("A's row says %q; want C's sentence", got.Said)
	}
	if r := fullOutbound(t, reopened, report.ID); r.State != OutHanded {
		t.Errorf("B's report row is %q, want handed: A took it", r.State)
	}
}

// TestAnEarlyReportAndARestartOfTheUpstream: A crashes after B's 201 and
// before writing the id down, and B's report meets a 404 meanwhile.
//
// The plan's shape for this case was that A's retry is answered
// already-carried, A writes the id down, and B's retried report is then
// taken. In the tree it cannot go that way: B has a report only because its
// own row ended, so B answers A's retry 409 with that ending (rulings 44 and
// 45), and A's row ends from the 409 without an id written down. What is
// shown instead is the claim R23 protects: alice is told her message was
// refused and never that it was handed; A keeps nothing it could not match,
// so B's report goes on meeting 404 and ends at its own gives_up without a
// report for a report.
func TestAnEarlyReportAndARestartOfTheUpstream(t *testing.T) {
	c := newChain(t)
	aRow, report := earlyReport(t, c, true)
	if got := c.a.outbound(t, aRow); got.State != OutWaiting || got.TheirID != 0 {
		t.Fatalf("A's row is %q with their_id %d, want waiting with none: the crash came before it was written",
			got.State, got.TheirID)
	}

	// A restarts: a second set of workers over the same store remembers no
	// neighbour, and the row says when it is next due.
	c.a.clock.advance(time.Hour)
	fresh := worker(t, c.a)
	defer fresh.Stop()
	fresh.drainOnce(t, "bar")
	got := c.a.outbound(t, aRow)
	if got.State != OutFinal || got.Code != relayapi.CodeRefused {
		t.Fatalf("A ends %s/%s; want final/refused from B's already-carried answer", got.State, got.Code)
	}
	if !strings.Contains(got.Said, "not on the recipient's allow list") {
		t.Errorf("A's row says %q; want C's sentence", got.Said)
	}

	// B's report is asked again, and A answers it 404 as before: nothing of
	// A's carries B's id.
	before := c.a.outboundRows(t)
	c.b.clock.advance(time.Hour)
	c.handOn(t, c.b, "alpha")
	r := fullOutbound(t, c.b.store, report.ID)
	if r.State != OutWaiting || r.Tries != 2 {
		t.Fatalf("B's report row is %q after %d tries; want still waiting, asked twice", r.State, r.Tries)
	}
	// And at its gives_up it ends, telling nobody.
	reports := len(c.b.reportRows(t))
	c.b.clock.advance(r.GivesUp.Sub(c.b.clock.Now()))
	c.handOn(t, c.b, "alpha")
	if r := fullOutbound(t, c.b.store, report.ID); r.State != OutFinal {
		t.Errorf("B's report row is %q at its gives_up, want final", r.State)
	}
	if n := len(c.b.reportRows(t)); n != reports {
		t.Errorf("%d report rows at B, was %d: a report was made for a report", n, reports)
	}
	if after := c.a.outboundRows(t); after != before {
		t.Errorf("A holds %d rows after the unmatched reports, was %d", after, before)
	}
	if got := c.a.outbound(t, aRow); got.State != OutFinal || got.Code != relayapi.CodeRefused {
		t.Errorf("A's row became %s/%s", got.State, got.Code)
	}
}

// reportOwed builds a relay that owes alpha a report: alpha posted a row,
// bar was handed it, and bar reported. It answers the harness, the worker
// with its dialling and reporting the test's, and the report row.
func reportOwed(t *testing.T, answer func() error) (*harness, *workers, *Outbound, *identity.Identity) {
	t.Helper()
	bar := neighbourID(t, "bar")
	alpha := neighbourID(t, "alpha")
	h := peered(t, []string{"bar", "alpha"}, []*identity.Identity{bar, alpha}, nil)
	h.enroll(bar, alpha)
	h.handedRow(t, alpha, h.fpOf(t, "bob"), "ct", 4711)
	if got, body := h.do(bar, "POST", "/v1/forward/failed",
		failedReq(4711, relayapi.CodeRefused, "baz: no such mailbox"), nil); got != 204 {
		t.Fatalf("bar's report: %d %s", got, body)
	}
	queued := h.reportRows(t)
	if len(queued) != 1 || queued[0].State != OutWaiting {
		t.Fatalf("report rows: %+v", queued)
	}
	w := worker(t, h)
	t.Cleanup(w.Stop)
	w.rnd = func() float64 { return 0 }
	w.dial = func(*store.Relay) (*client.Client, error) { return nil, nil }
	w.reportTo = func(context.Context, *client.Client, int64, string, string) error { return answer() }
	return h, w, queued[0], alpha
}

func courierLines(h *harness) string {
	var lines []string
	for _, line := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(line, "courier:") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

const chainEnds = "the chain ends here"
const notYetKnown = "a neighbour does not yet know the message a report names"

// TestAReportsLifetimeEndsAtItsGivesUp: the edge of R23's lifetime, the
// row's own gives_up, one second apart.
func TestAReportsLifetimeEndsAtItsGivesUp(t *testing.T) {
	notFound := func() error { return &client.HTTPError{Status: http.StatusNotFound, Message: "no such message"} }

	t.Run("a second inside it a 404 waits", func(t *testing.T) {
		h, w, report, _ := reportOwed(t, notFound)
		h.clock.advance(report.GivesUp.Sub(h.clock.Now()) - time.Second)
		w.drainOnce(t, "alpha")
		got := fullOutbound(t, h.store, report.ID)
		if got.State != OutWaiting || got.Tries != 1 {
			t.Fatalf("the report row is %q after %d tries one second inside its lifetime; want waiting, tried once",
				got.State, got.Tries)
		}
		if want := h.clock.Now().Add(firstRetry); !got.NextTry.Equal(want) {
			t.Errorf("next try %s, want %s: the ordinary backoff", got.NextTry, want)
		}
		lines := courierLines(h)
		if strings.Contains(lines, chainEnds) {
			t.Errorf("the operator was told the chain ended inside its lifetime:\n%s", lines)
		}
		if !strings.Contains(lines, notYetKnown) {
			t.Errorf("no line saying the report will be asked again:\n%s", lines)
		}
	})

	t.Run("at it exactly a 404 is final", func(t *testing.T) {
		// The drain's sweep runs before the attempt, so the 404 at gives_up
		// is the one whose answer took the clock across it: the turn starts
		// a second inside, and the neighbour answers a second later.
		var h *harness
		h, w, report, alpha := reportOwed(t, func() error {
			h.clock.advance(time.Second)
			return &client.HTTPError{Status: http.StatusNotFound, Message: "no such message"}
		})
		h.clock.advance(report.GivesUp.Sub(h.clock.Now()) - time.Second)
		before := len(h.reportRows(t))
		w.drainOnce(t, "alpha")
		if !h.clock.Now().Equal(report.GivesUp) {
			t.Fatalf("the 404 came at %s, want the gives_up %s", h.clock.Now(), report.GivesUp)
		}
		got := fullOutbound(t, h.store, report.ID)
		if got.State != OutFinal {
			t.Fatalf("the report row is %q, want final at its gives_up", got.State)
		}
		if got.Code != relayapi.CodeRefused {
			t.Errorf("code %q, want the report's own %q: the 404 ended it, not the sweep", got.Code, relayapi.CodeRefused)
		}
		lines := courierLines(h)
		if !strings.Contains(lines, chainEnds) {
			t.Errorf("nothing in the log about the chain ending:\n%s", lines)
		}
		if !strings.Contains(lines, "alpha") || strings.Contains(lines, alpha.Fingerprint()[:16]) {
			t.Errorf("the line does not name alpha, or names a fingerprint:\n%s", lines)
		}
		if after := len(h.reportRows(t)); after != before {
			t.Errorf("%d report rows, was %d: a report was made for a report", after, before)
		}
	})

	t.Run("a row still waiting at it is ended by GiveUp", func(t *testing.T) {
		h, w, report, _ := reportOwed(t, func() error {
			t.Error("a report past its gives_up was offered")
			return nil
		})
		h.clock.advance(report.GivesUp.Sub(h.clock.Now()))
		before := len(h.reportRows(t))
		w.drainOnce(t, "alpha")
		got := fullOutbound(t, h.store, report.ID)
		if got.State != OutFinal || got.Code != relayapi.CodeGaveUp {
			t.Fatalf("the report row is %s/%s at its gives_up, want final/%s", got.State, got.Code, relayapi.CodeGaveUp)
		}
		if after := len(h.reportRows(t)); after != before {
			t.Errorf("%d report rows, was %d: a report was made for a report", after, before)
		}
	})
}

// TestAReportForAnIdNeverHandedCostsTheReporter: an invented or stale id is
// answered 404 every time, the reporter asks on its own schedule until the
// row's gives_up and then lets it go, every ask is charged to its report
// budget at the relay it asks, and that relay keeps nothing.
func TestAReportForAnIdNeverHandedCostsTheReporter(t *testing.T) {
	t.Run("the reporter asks until gives_up and stops", func(t *testing.T) {
		c := newChain(t)
		now := c.b.clock.Now()
		invented := &Outbound{PosterFP: c.aCourier.Fingerprint(), Neighbour: "alpha", Kind: KindReport,
			Received: now, GivesUp: now.Add(3 * time.Hour), TheirID: 987654,
			Code: relayapi.CodeRefused, Said: "baz: no"}
		if err := c.b.store.EnqueueReport(invented, DefaultCourierLimits().CourierQuotasFor()); err != nil {
			t.Fatal(err)
		}
		rows := c.b.reportRows(t)
		if len(rows) != 1 {
			t.Fatalf("%d report rows", len(rows))
		}
		id := rows[0].ID
		before := c.a.outboundRows(t)

		w := worker(t, c.b)
		defer w.Stop()
		reportTo := w.reportTo
		var answers []int
		w.reportTo = func(ctx context.Context, cl *client.Client, theirID int64, code, said string) error {
			err := reportTo(ctx, cl, theirID, code, said)
			var he *client.HTTPError
			if !errors.As(err, &he) {
				t.Fatalf("the invented report: %v; want an answer", err)
			}
			answers = append(answers, he.Status)
			return err
		}
		for i := 0; ; i++ {
			if i > 100 {
				t.Fatal("the report row never ended")
			}
			w.drainOnce(t, "alpha")
			row := fullOutbound(t, c.b.store, id)
			if row.State == OutFinal {
				if c.b.clock.Now().Before(row.GivesUp) {
					t.Fatalf("the row ended at %s, before its gives_up %s", c.b.clock.Now(), row.GivesUp)
				}
				break
			}
			c.b.clock.advance(row.NextTry.Sub(c.b.clock.Now()))
		}
		if len(answers) < 3 {
			t.Fatalf("asked %d times in three hours", len(answers))
		}
		for i, s := range answers {
			if s != http.StatusNotFound {
				t.Errorf("ask %d answered %d, want 404", i, s)
			}
		}
		if n := len(c.b.reportRows(t)); n != 1 {
			t.Errorf("%d report rows at B: a report was made for a report", n)
		}
		if after := c.a.outboundRows(t); after != before {
			t.Errorf("A holds %d rows after %d unmatched reports, was %d", after, len(answers), before)
		}
	})

	t.Run("each ask is charged to the report budget", func(t *testing.T) {
		courier := neighbourID(t, "bar")
		h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
		h.enroll(courier)
		perMinute := DefaultCourierLimits().ReportsPerMinute
		outbound, carried := h.outboundRows(t), h.carriedRows(t)
		lines := courierLines(h)
		for i := range perMinute {
			if status, body := h.do(courier, "POST", "/v1/forward/failed",
				failedReq(987654, relayapi.CodeRefused, "no"), nil); status != 404 {
				t.Fatalf("ask %d: %d %s, want 404", i+1, status, body)
			}
		}
		status, _, header := h.send(courier, "POST", "/v1/forward/failed",
			failedReq(987654, relayapi.CodeRefused, "no"), nil)
		if status != 429 {
			t.Fatalf("ask %d in a minute: %d, want 429", perMinute+1, status)
		}
		h.retryAfter(header)
		if o, c := h.outboundRows(t), h.carriedRows(t); o != outbound || c != carried {
			t.Errorf("rows %d/%d after the asks, were %d/%d: the relay asked kept something", o, c, outbound, carried)
		}
		if got := courierLines(h); got != lines {
			t.Errorf("the relay asked wrote courier lines:\n%s", strings.TrimPrefix(got, lines))
		}
	})
}

// TestAnOrdinaryReportIsTakenFirstTime: the case nothing races. A has written
// the id down before C refuses, B's report is taken on its first offer, and
// B's row is handed on that one try with no retry scheduled.
func TestAnOrdinaryReportIsTakenFirstTime(t *testing.T) {
	c := newChain(t)
	alice := c.a.user(t, "alice")
	bob := c.c.user(t, "bob")
	if status, body, _ := c.c.pushAllow(bob, bob, c.c.clock.Now(), c.c.fpOf(t, "nobody")); status != 204 {
		t.Fatalf("allow: %d %s", status, body)
	}
	status, answer, body := c.a.forward(alice, request(sealedFor(bob.Fingerprint(), "ordinary"), []string{"bar", "baz"}, nil))
	if status != 201 {
		t.Fatalf("queue: %d %s", status, body)
	}
	c.handOn(t, c.a, "bar")
	c.handOn(t, c.b, "baz")
	w := worker(t, c.b)
	defer w.Stop()
	reportTo := w.reportTo
	offers := 0
	w.reportTo = func(ctx context.Context, cl *client.Client, id int64, code, said string) error {
		offers++
		err := reportTo(ctx, cl, id, code, said)
		if err != nil {
			t.Errorf("the ordinary report: %v, want taken", err)
		}
		return err
	}
	w.drainOnce(t, "alpha")
	if offers != 1 {
		t.Errorf("offered %d times, want once", offers)
	}
	reports := c.b.reportRows(t)
	// Handed counts the attempt that handed it, so one try and a next try
	// never pushed past the turn is a report taken first time.
	if len(reports) != 1 || reports[0].State != OutHanded || reports[0].Tries != 1 ||
		!reports[0].NextTry.Equal(reports[0].Received) {
		t.Fatalf("B's report rows: %d, first %+v; want one handed on its one try, no retry scheduled",
			len(reports), *reports[0])
	}
	if got := c.a.outbound(t, answer.ID); got.State != OutFinal || got.Code != relayapi.CodeRefused {
		t.Errorf("A ends %s/%s, want final/refused", got.State, got.Code)
	}
	if lines := courierLines(c.b); strings.Contains(lines, notYetKnown) {
		t.Errorf("an ordinary report was put off:\n%s", lines)
	}
}

// TestAReportPutOffWaitsAlone: a 404 is the report row's own wait. A row for
// the same neighbour behind it in the queue is offered in the same turn, the
// neighbour is not backed off, and the turn's wait is the report's backoff
// and not the hour an empty queue sleeps.
func TestAReportPutOffWaitsAlone(t *testing.T) {
	h, w, report, _ := reportOwed(t, func() error {
		return &client.HTTPError{Status: http.StatusNotFound, Message: "no such message"}
	})
	// A second report, ahead of the envelope too, so the turn meets two
	// 404s for the once-a-minute line below.
	now := h.clock.Now()
	if err := h.store.EnqueueReport(&Outbound{PosterFP: report.PosterFP, Neighbour: "alpha", Kind: KindReport,
		Received: now, GivesUp: now.Add(time.Hour), TheirID: 987654, Code: relayapi.CodeRefused, Said: "bar: no"},
		DefaultCourierLimits().CourierQuotasFor()); err != nil {
		t.Fatal(err)
	}
	poster := h.user(t, "carol")
	behind := h.queue(poster, sealedFor(h.fpOf(t, "dave"), "behind"), "alpha")
	if behind < report.ID {
		t.Fatalf("the envelope row %d is not behind the report %d", behind, report.ID)
	}
	posts := 0
	w.post = func(context.Context, *client.Client, *relayapi.ForwardRequest) (int64, error) {
		posts++
		return 77, nil
	}
	r, ok := w.courier.Neighbour("alpha")
	if !ok {
		t.Fatal("no neighbour alpha")
	}
	wait := w.drain(r)
	if posts != 1 {
		t.Fatalf("the row behind the report was offered %d times in the turn, want once", posts)
	}
	if got := h.outbound(t, behind); got.State != OutHanded {
		t.Errorf("the row behind is %q, want handed", got.State)
	}
	for _, o := range h.reportRows(t) {
		if o.State != OutWaiting || o.Tries != 1 {
			t.Errorf("report %d is %q after %d tries, want waiting, tried once", o.ID, o.State, o.Tries)
		}
	}
	if wait != firstRetry {
		t.Errorf("the turn waits %s, want the report's own backoff %s (maxRetry is %s)", wait, firstRetry, maxRetry)
	}
	if left := w.waitFor("alpha"); left != 0 {
		t.Errorf("alpha is left alone for %s: a 404 on a report is the row's wait, not the neighbour's", left)
	}

	// And the line is once a minute: two reports put off in one turn are
	// one line, and the next turn a minute on is the second.
	if n := strings.Count(courierLines(h), notYetKnown); n != 1 {
		t.Errorf("%d lines for two reports put off in one turn, want 1", n)
	}
	h.clock.advance(firstRetry)
	w.drainOnce(t, "alpha")
	if n := strings.Count(courierLines(h), notYetKnown); n != 2 {
		t.Errorf("%d lines a minute on, want 2", n)
	}
}
