package relay

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/dial"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// One worker per neighbour empties the queue for that neighbour.
//
// It is woken by a row arriving and by its own timer, takes the rows for its
// neighbour oldest first, and posts each to that neighbour's forward route as
// a courier. Backing off is per neighbour and not per row: a neighbour that
// is down is down for every row it holds, and trying the next one would be
// the same failure again at the same cost.
//
// The worker never holds a request and no request waits on the worker. A
// request writes its row inside its own transaction and wakes the worker,
// which is a channel send that cannot block; everything after is the
// worker's.

// The backoff. These are constants and not settings: a setting is a policy
// an operator has an opinion about, and how soon to try a neighbour again
// after a failure is arithmetic. forward_ttl is the policy, and it is what
// ends the retrying.
const (
	// firstRetry is how long after a failure the next attempt is.
	firstRetry = time.Minute
	// maxRetry is where the doubling stops.
	maxRetry = time.Hour
	// jitterPart is the fraction of the delay that is random, so that two
	// relays which lost the same cable do not knock on the same second
	// every hour for a week.
	jitterPart = 4
)

// backoffFor is how long to wait after a given number of failed attempts:
// a minute doubling to an hour, less a random quarter.
//
// The jitter is subtracted rather than added so that the wait is never
// longer than maxRetry, and the result is never under a second, since a
// worker that woke immediately would spin.
func backoffFor(tries int64, rnd func() float64) time.Duration {
	d := firstRetry
	for range tries - 1 {
		d *= 2
		if d >= maxRetry {
			d = maxRetry
			break
		}
	}
	jitter := time.Duration(rnd() * float64(d) / jitterPart)
	if d -= jitter; d < time.Second {
		d = time.Second
	}
	return d
}

// workers is the set of them, one per neighbour, and the way a request wakes
// one.
type workers struct {
	mu     sync.Mutex
	wakeup map[string]chan struct{}
	// notBefore is when each neighbour may be dialled again. The backing
	// off is the neighbour's and not one row's — a neighbour that is down
	// is down for every row waiting for it — so it is held here rather
	// than only on the rows: a row arriving wakes the worker, and without
	// this every new message would be another dial at a relay that is not
	// answering, which is the shape a busy relay turns into a flood.
	notBefore map[string]time.Time

	stop context.CancelFunc
	ctx  context.Context
	done sync.WaitGroup
	log  *slog.Logger
	now  func() time.Time
	// sleep waits for the next turn: until the duration is up, until a row
	// wakes this neighbour's worker, or until the relay stops. It is a
	// field so a test can hand the worker its own.
	sleep  func(ctx context.Context, d time.Duration, wakeup <-chan struct{})
	rnd    func() float64
	store  *Store
	limits CourierLimits
	// dialer builds a client for a neighbour and renews this courier's
	// certificate there before it dials. Its remarks go to the relay's log,
	// since a relay has no terminal.
	dialer  dial.Dialer
	courier *Courier
	// dial and post are how an attempt reaches a neighbour: the client
	// built for it, and the request sent on that client. They are fields so
	// that a test can make a neighbour answer the ways a real one is
	// awkward to make answer — a rate limit with a Retry-After, a
	// certificate no longer accepted, a cable pulled out — without a second
	// relay in the process. The real ones are dialNeighbour and
	// postToNeighbour, and the peered harness exercises those.
	dial func(r *store.Relay) (*client.Client, error)
	post func(ctx context.Context, c *client.Client, req *relayapi.ForwardRequest) (int64, error)
	// reportTo is how an undeliverable reaches a neighbour, a field for the
	// same reason post is: a test makes the answers a real relay is awkward
	// to make.
	reportTo func(ctx context.Context, c *client.Client, id int64, code, said string) error
}

// startWorkers builds the set and starts one worker per neighbour. A relay
// with no courier, or one that dials nobody, gets none.
func startWorkers(st *Store, c *Courier, limits CourierLimits, log *slog.Logger, now func() time.Time) *workers {
	w := newWorkers(st, c, limits, log, now)
	w.start()
	return w
}

// newWorkers builds the set without starting anything.
//
// The two halves are apart so that a test can hand a worker its own dialling
// before any goroutine is reading it: setting those fields on a running set
// would be a data race, and the race detector is part of the definition of
// done here. A test that wants the goroutines calls start after.
func newWorkers(st *Store, c *Courier, limits CourierLimits, log *slog.Logger, now func() time.Time) *workers {
	if c == nil || len(c.neighbours) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &workers{
		wakeup:    map[string]chan struct{}{},
		notBefore: map[string]time.Time{},
		stop:      cancel,
		ctx:       ctx,
		log:       log,
		now:       now,
		sleep:     sleepFor,
		rnd:       rand.Float64,
		store:     st,
		limits:    limits,
		courier:   c,
		dialer: dial.Dialer{
			Prog: "auu",
			Note: func(s string) { log.Warn("courier: " + s) },
		},
	}
	w.dial, w.post, w.reportTo = w.dialNeighbour, w.postToNeighbour, w.reportToNeighbour
	for _, r := range sortedNeighbours(c.neighbours) {
		w.wakeup[r.Name] = make(chan struct{}, 1)
	}
	return w
}

// start sets the workers going, one goroutine per neighbour.
//
// Each gets its own copy of its neighbour, which is the whole reason
// Courier.Neighbour hands out copies: the dialling writes into the struct —
// the trust anchor's ratchet records the intermediate it last saw, inside
// the handshake — and the shared one is read by every request that names
// that neighbour on the forward route. One pointer in both places is an
// unsynchronised write against an unsynchronised read of the same fields,
// which no test here sees because the harness pins no anchor and so never
// fires the write. A worker is the only thing that dials its neighbour, so
// its copy is where that ratchet lives for as long as the relay runs, and
// the shared one, written by nobody, is what the request path copies from.
func (w *workers) start() {
	if w == nil {
		return
	}
	for _, shared := range sortedNeighbours(w.courier.neighbours) {
		r := *shared
		w.done.Add(1)
		go w.run(&r, w.wakeup[r.Name])
	}
}

// sleepFor waits for whichever comes first: the time being up, a row
// arriving for this neighbour, or the relay stopping.
func sleepFor(ctx context.Context, d time.Duration, wakeup <-chan struct{}) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-wakeup:
	case <-ctx.Done():
	}
}

// wake nudges one neighbour's worker. The send cannot block: the channel
// holds one, and a wake that finds it full is a worker that has not yet
// looked, which will see the new row when it does.
func (w *workers) wake(neighbour string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	ch := w.wakeup[neighbour]
	w.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// Stop ends every worker and waits for them. An attempt in flight is
// abandoned rather than waited out: the neighbour may have taken the
// envelope, and the row stays waiting, which the carried table makes safe —
// the retry after the restart is answered 409 with the id and read as handed.
func (w *workers) Stop() {
	if w == nil {
		return
	}
	w.stop()
	w.done.Wait()
}

// run is one neighbour's worker.
func (w *workers) run(r *store.Relay, wakeup chan struct{}) {
	defer w.done.Done()
	for {
		// Everything due for this neighbour, oldest first, until it is empty
		// or the neighbour is not answering.
		wait := w.drain(r)
		// The wait is the injected one, so a test can drive a worker
		// without the clock: a bare timer here would mean every test of a
		// backoff had to sleep through it, and a test that sleeps is a test
		// that is slow when it passes and flaky when it does not.
		w.sleep(w.ctx, wait, wakeup)
		// And the loop ends where the waiting ends, not inside it: a sleep
		// that returns because the relay is stopping is the only thing that
		// says so, and without this the worker takes the next turn, finds
		// the context done, and comes straight back here for ever.
		if w.ctx.Err() != nil {
			return
		}
	}
}

// drain takes rows for one neighbour until there are none due or one of them
// says to back off, and answers how long to wait before looking again.
func (w *workers) drain(r *store.Relay) time.Duration {
	// A neighbour being left alone is left alone: a wake is a row arriving,
	// which says nothing new about whether the neighbour is answering.
	if wait := w.waitFor(r.Name); wait > 0 {
		return wait
	}
	// A row whose forward_ttl has run out is failed before anything is
	// dialled: the poster is told, and a neighbour that has been down for
	// three days is not asked again on this row's account.
	if n, err := w.store.GiveUp(w.ctx, r.Name, w.now(), w.limits.ForwardTTL, w.fail); err != nil {
		w.log.Error("courier: giving up on mail for a neighbour failed", "neighbour", r.Name, "err", err)
	} else if n > 0 {
		w.log.Warn("courier: gave up on mail for a neighbour", "neighbour", r.Name, "messages", n,
			"after", w.limits.ForwardTTL.String())
	}
	var handed, failed int
	// The row the last turn dealt with. attempt records what it decided in
	// the database, and a write that will not commit — a full disk, a
	// read-only filesystem, a row somebody is holding — leaves the row
	// waiting and hands it back on the next turn, which would be an
	// envelope posted to the neighbour again and again for as long as the
	// relay ran. A row that comes round twice is a fault of this relay's,
	// not the neighbour's, so the neighbour is left alone until the next
	// turn and the operator is told.
	var last int64
	// soonest is when the earliest row this turn put off on its own comes
	// due, an empty queue's hour when none was. A turn that finds nothing
	// due asks the queue as well (untilDue), since a row put off before
	// this process started is written down and not remembered.
	soonest := maxRetry
	// One client for the turn, not one for each row: a dial reads the
	// certificate store and builds the client's transport. Each request
	// still makes a connection of its own, a post-quantum handshake with
	// this courier's client certificate, since the client keeps none for a
	// second request (G28): a signed request the transport sent again on a
	// reused connection would be a replay the neighbour refuses. So an
	// outage's backlog costs one handshake a row. It is dialled on the
	// first row rather than before the loop, so a turn that finds nothing
	// waiting — which is most turns — dials nothing.
	var c *client.Client
	var dialled bool
	defer func() {
		if c != nil {
			c.CloseIdle()
		}
	}()
	for {
		if w.ctx.Err() != nil {
			return maxRetry
		}
		row, err := w.store.NextOutbound(r.Name, w.now())
		if err != nil {
			w.log.Error("courier: reading the queue for a neighbour failed", "neighbour", r.Name, "err", err)
			return firstRetry
		}
		if row == nil {
			w.report(r.Name, handed, failed)
			return w.untilDue(r.Name, soonest)
		}
		if row.ID == last {
			w.log.Error("courier: the queue is not moving; a message was attempted twice in one turn, "+
				"which means what happened to it could not be written down",
				"neighbour", r.Name, "id", row.ID)
			w.report(r.Name, handed, failed)
			return firstRetry
		}
		last = row.ID
		if !dialled {
			dialled = true
			if c, err = w.dial(r); err != nil {
				// The neighbour is not reachable at all, which is every
				// row's answer and not this one's. The row is put back and
				// the wait is its own, as a failed attempt's is.
				w.noteUnreachable(r.Name, err)
				wait := w.retry(row)
				w.backOff(r.Name, wait)
				w.report(r.Name, handed, failed)
				return wait
			}
		}
		switch out, wait := w.attempt(r, c, row); out {
		case attemptHanded:
			handed++
		case attemptFailed:
			failed++
		case attemptLater:
			// The row's own next try is written down; the turn ends no
			// later than it is due, so its wait is its own backoff and not
			// the hour an empty queue sleeps.
			soonest = min(soonest, wait)
		default:
			// The neighbour is not taking anything just now, so every row
			// waiting for it waits: the next would meet the same answer at
			// the same cost. Written down as well as returned, since the
			// return only governs this worker's own sleep and a row
			// arriving would otherwise bring it straight back.
			w.backOff(r.Name, wait)
			w.report(r.Name, handed, failed)
			return wait
		}
	}
}

// untilDue is how long a turn that found nothing due sleeps: until the
// earliest waiting row comes due, no sooner than a second and no later
// than soonest. A worker started after a row was put off knows of it only
// from the queue, and slept the empty queue's hour past a row due in a
// minute unless a new arrival woke it (G40, R56). A row past its gives_up
// is not counted: GiveUp ends it at the next turn, and the hour's turn
// reaches it then as it always has.
func (w *workers) untilDue(neighbour string, soonest time.Duration) time.Duration {
	next, ok, err := w.store.NextDue(neighbour, w.now())
	if err != nil {
		w.log.Error("courier: reading when the queue for a neighbour is next due failed", "neighbour", neighbour, "err", err)
		return min(soonest, firstRetry)
	}
	if !ok {
		return soonest
	}
	return min(soonest, max(next.Sub(w.now()), time.Second))
}

// What one attempt came to. A row is handed over, or it is this row's own
// failure, or it is the neighbour's and every row for it waits.
type attemptOutcome int

const (
	attemptBackOff attemptOutcome = iota
	attemptHanded
	attemptFailed
	// attemptLater is this row's wait alone: the neighbour answered, and
	// the rows behind it go on.
	attemptLater
)

// waitFor is how long this neighbour is still being left alone, or zero.
func (w *workers) waitFor(neighbour string) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	if until, ok := w.notBefore[neighbour]; ok {
		if wait := until.Sub(w.now()); wait > 0 {
			return wait
		}
		delete(w.notBefore, neighbour)
	}
	return 0
}

// backOff leaves a neighbour alone for a while.
func (w *workers) backOff(neighbour string, wait time.Duration) {
	if wait <= 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.notBefore[neighbour] = w.now().Add(wait)
}

// report says what a run of attempts did, once a minute per neighbour, and
// says nothing when it did nothing.
func (w *workers) report(neighbour string, handed, failed int) {
	if handed == 0 && failed == 0 {
		return
	}
	if !w.store.faults.due("forwarded:" + neighbour) {
		return
	}
	w.log.Info("courier: forwarded to a neighbour", "neighbour", neighbour,
		"handed", handed, "failed", failed)
}

// attempt hands one row to its neighbour on the turn's connection and
// records what came back. It reports whether the neighbour should be left
// alone for a while, and for how long.
//
// The connection is the caller's because it is the turn's: every row of a
// drain goes over the one the drain dialled, and a dial that failed is the
// neighbour's answer to every row rather than to this one, so it is decided
// there and never here.
func (w *workers) attempt(r *store.Relay, c *client.Client, row *Outbound) (attemptOutcome, time.Duration) {
	if row.Kind == KindReport {
		return w.attemptReport(r, c, row)
	}
	raw, err := w.store.OutboundBody(row.ID)
	if err != nil {
		// The bytes are gone from under a committed row, which is the
		// relay's own fault and not the neighbour's. The row is failed so
		// the poster is told rather than left waiting for ever.
		w.log.Error("courier: the envelope of a queued message cannot be read", "id", row.ID,
			"neighbour", r.Name, "err", err)
		w.fail(row, relayapi.CodeRefused, "this relay lost the message before it could be carried")
		return attemptFailed, 0
	}
	if w.ctx.Err() != nil {
		return attemptBackOff, firstRetry
	}
	req := &relayapi.ForwardRequest{
		Envelope: raw,
		Path:     SplitPath(row.Path),
		Via:      SplitPath(row.Via),
	}
	// Every field is always sent, so an empty list is [] and not absent.
	if req.Path == nil {
		req.Path = []string{}
	}
	if req.Via == nil {
		req.Via = []string{}
	}
	theirID, err := w.post(w.ctx, c, req)
	switch {
	case err == nil:
		if err := w.store.Handed(row.ID, theirID, w.now()); err != nil {
			w.log.Error("courier: recording a handed message failed", "id", row.ID, "err", err)
		}
		return attemptHanded, 0
	case errors.Is(err, w.ctx.Err()) && w.ctx.Err() != nil:
		// The relay is stopping. The row stays waiting: the neighbour may
		// have taken it, and the retry after the restart is answered
		// already-carried and read as handed.
		return attemptBackOff, firstRetry
	}
	return w.classify(r, row, err)
}

// attemptReport hands an undeliverable back one hop: the worker's second job,
// on the same connection, with the same backoff and the same forward_ttl as
// an envelope, because a neighbour that is not answering is not answering to
// either kind.
//
// What differs is what a refusal means. An envelope refused finally is news
// its sender is owed, so the row is failed and carries a sentence. A report
// refused finally is news nobody is owed: a report is never generated for a
// report, so there is nothing to pass back and nothing to write down but a
// line for the operator. The row ends either way — this relay has said what
// it had to say, or found that it cannot — and when it cannot, nobody further
// back is told at all: the row that would have to notice is one that relay has
// already handed over, and a handed row that hears nothing is the ordinary
// shape of success, so there is no timer that could end it without telling
// every sender their delivered mail had failed. forward_ttl ends a row that is
// still waiting, which is a different thing.
func (w *workers) attemptReport(r *store.Relay, c *client.Client, row *Outbound) (attemptOutcome, time.Duration) {
	if w.ctx.Err() != nil {
		return attemptBackOff, firstRetry
	}
	err := w.reportTo(w.ctx, c, row.TheirID, row.Code, row.Said)
	if err == nil {
		// Handed over and done with. The state is the envelope's word for
		// the same thing: this row is no longer this relay's to act on.
		if err := w.store.Handed(row.ID, 0, w.now()); err != nil {
			w.log.Error("courier: recording a handed report failed", "id", row.ID, "err", err)
		}
		return attemptHanded, 0
	}
	if errors.Is(err, w.ctx.Err()) && w.ctx.Err() != nil {
		return attemptBackOff, firstRetry
	}
	var he *client.HTTPError
	if errors.As(err, &he) {
		switch he.Status {
		case http.StatusNotFound:
			// The neighbour holds no row it handed here under this id.
			// That is not final (G18, R23): the neighbour wakes its worker
			// before it has written down the id this relay answered with,
			// or crashes after its 201 and learns the id only when its own
			// retry is answered already-carried, so a report that comes back
			// fast enough is ahead of the row it is about. So the row waits
			// on the ordinary schedule, its own wait and not the
			// neighbour's, until its gives_up — the forward lifetime it was
			// queued with, written in the row and so kept across a restart —
			// when GiveUp ends it as it ends any row still waiting. Each try
			// is charged to this relay's report budget at the neighbour, so
			// an id that is stale or invented costs the one asking.
			if !w.now().Before(row.GivesUp) {
				w.store.faults.noteReportRefused(r.Name, said(r.Name, he.Message))
				w.fail(row, row.Code, row.Said)
				return attemptFailed, 0
			}
			if w.store.faults.due("report-unmatched:" + r.Name) {
				w.log.Info("courier: a neighbour does not yet know the message a report names; it will be asked again",
					"neighbour", r.Name, "id", row.ID, "their_id", row.TheirID, "until", row.GivesUp.Format(time.RFC3339))
			}
			return attemptLater, w.retry(row)
		case http.StatusConflict:
			// The neighbour is not waiting to hear about the row: a report
			// is taken once, so this is final. There is nobody to tell, so
			// the row ends and the operator gets a line.
			w.store.faults.noteReportRefused(r.Name, said(r.Name, he.Message))
			w.fail(row, row.Code, row.Said)
			return attemptFailed, 0
		case http.StatusBadRequest, http.StatusForbidden, http.StatusRequestEntityTooLarge:
			// This relay sent something that neighbour will not take, which
			// no retry fixes and which is this relay's own fault.
			w.store.faults.noteReportRefused(r.Name, said(r.Name, he.Message))
			w.fail(row, row.Code, row.Said)
			return attemptFailed, 0
		}
	}
	// Anything else is the neighbour not answering, which is every row's
	// answer and not this one's.
	return w.classify(r, row, err)
}

// classify decides what a neighbour's refusal means for the row and for the
// neighbour.
//
// A final answer is the row's: the neighbour will not take this envelope
// however often it is offered, and the sentence it gave is kept so the
// poster reads which hop refused and why. A transient answer is the
// neighbour's: every row waiting for it waits, since the next would meet the
// same thing.
func (w *workers) classify(r *store.Relay, row *Outbound, err error) (attemptOutcome, time.Duration) {
	var he *client.HTTPError
	if !errors.As(err, &he) {
		// Not an answer at all: a dial that failed, a connection that
		// dropped, a body that would not parse. The neighbour is not
		// answering, which is what an outage looks like.
		w.noteUnreachable(r.Name, err)
		return attemptBackOff, w.retry(row)
	}
	switch he.Status {
	case http.StatusConflict:
		// Already carried, which has three causes and three answers
		// (rulings 44 and 45), and reading all three as a hand-over is the
		// defect this used to be: a loop dying at the neighbour was
		// recorded as handed, and its sender told so for good.
		switch {
		case he.ForwardID != 0 && he.ForwardCode != "":
			// A retry after a lost answer, to a row that has since ended
			// there. Its report came back and was refused here, this relay
			// never having heard the id to match it to, so this answer is
			// the only way the news arrives: the row ends as that one did,
			// and the news goes on back.
			w.fail(row, he.ForwardCode, said(r.Name, he.ForwardSaid))
			return attemptFailed, 0
		case he.ForwardID != 0:
			// A retry after a lost answer, to a row still going there or
			// to a message delivered there: taken, and the id is what a
			// report coming back will name.
			if err := w.store.Handed(row.ID, he.ForwardID, w.now()); err != nil {
				w.log.Error("courier: recording a handed message failed", "id", row.ID, "err", err)
			}
			return attemptHanded, 0
		default:
			// Bare: nothing of this relay's there and nothing delivered,
			// which is a loop coming back. The message is not going to
			// arrive, and the sender is told so.
			w.fail(row, relayapi.CodeRefused, said(r.Name, he.Message))
			return attemptFailed, 0
		}
	case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusRequestEntityTooLarge:
		w.fail(row, relayapi.CodeRefused, said(r.Name, he.Message))
		return attemptFailed, 0
	case http.StatusUnauthorized:
		// This relay's courier is no longer accepted there, or its
		// certificate is refused. Every row for that neighbour waits, and
		// the operator is told once a minute, since it is theirs to fix and
		// no retry will.
		if w.store.faults.due("courier:" + r.Name) {
			w.log.Warn("courier: a neighbour will not accept this relay's courier; "+
				"mail for it is waiting until that is fixed",
				"neighbour", r.Name, "said", said(r.Name, he.Message))
		}
		return attemptBackOff, w.wait(row, maxRetry)
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		if he.Code == relayapi.CodeCourierClock && w.store.faults.due("courier-clock-at:"+r.Name) {
			// The neighbour holds this relay's clock to the minute and
			// finds it further out: the row waits the Retry-After as any
			// busy answer's does, and the operator is told it is a clock.
			w.log.Warn("courier: a neighbour says this relay's clock and its own differ by more than a minute; "+
				"relays keep to the minute, so check NTP",
				"neighbour", r.Name)
		}
		if he.RetryAfter > 0 {
			// The neighbour's own answer to when it wants to be asked
			// again, which it knows better than this relay's arithmetic
			// does; the client has already held it to a day.
			return attemptBackOff, w.wait(row, he.RetryAfter)
		}
		return attemptBackOff, w.retry(row)
	default:
		// A 507 at the neighbour, a storage fault there, anything else:
		// mailboxes empty and disks are made bigger, so it waits.
		//
		w.noteRefusal(r.Name, he.Message)
		return attemptBackOff, w.retry(row)
	}
}

// said is what a neighbour told this relay about a message it would not
// take, with the hop's name in front, for the person who sent it to read.
//
// It is cut to relayapi.MaxSaid bytes on a rune boundary. What arrives is a
// neighbour's free text, bounded only by what a client will read from a
// relay — sixteen megabytes twice over — and it goes into a row this relay
// keeps for a day and into a line in its log. A sentence is a sentence: one
// of those per message handed to a neighbour would be that neighbour's
// choice of how large this relay's database grows, which is not a choice a
// neighbour has anywhere else here.
//
// The cut runs before the escaping as well as after, and that is the part
// that matters at an unattended relay. Escaping only ever grows a string —
// an unprintable byte becomes four characters — so escaping first and
// cutting after would leave a neighbour choosing an allocation four times
// the size of an answer this client will read, once for every attempt,
// which is the same choice this cut exists to take away. The client has
// already escaped the sentence where it built the error, and escaping is
// idempotent, so the pass here is the last line under the rule rather than
// the rule: it costs a few hundred bytes now that what reaches it is
// bounded, and it means this function is right whatever a caller hands it.
func said(neighbour, message string) string {
	// Bounded before the escaping, since escaping only grows a string; the
	// generous cut here is from the front too, for the reason below.
	if len(message) > relayapi.MaxSaid {
		message = message[runeStart(message, len(message)-relayapi.MaxSaid):]
	}
	s := neighbour + ": " + oneLine(message)
	if len(s) <= relayapi.MaxSaid {
		return s
	}
	// Over the cap, and it is the front that goes. A sentence grows at the
	// front as a report travels back — each hop writes its own name for the
	// hop that told it — so the tail is the sentence the relay that actually
	// failed wrote, and the head is a list of names. The tail is what the
	// reader needs: it is the only thing that says what went wrong. And the
	// first name they lose is the one they can spare, being this relay's own
	// name for its neighbour, which the row's own neighbour column prints on
	// the line above it.
	//
	// Cutting the other way is what this did first, and it would drop the
	// one thing a report is for. Cutting out the middle — dropping the
	// oldest names and keeping both ends — cannot be done at all: the oldest
	// name is in the middle, and no relay can find where the names end and
	// another relay's free text begins, since that text may hold ": " of its
	// own.
	keep := relayapi.MaxSaid - len(reportEllipsis)
	return reportEllipsis + s[runeStart(s, len(s)-keep):]
}

// oneLine escapes a sentence for a terminal and for the rule the report route
// holds an incoming one to, which are not quite the same rule.
//
// identity.PrintableText keeps a tab, because a tab reaching a terminal is not
// a hazard. message.ValidOneLine refuses one, because a said is one line and a
// tab is a control character. Over every rune there is exactly one that the
// first keeps and the second refuses, and it is U+0009 --
// TestASentenceThisRelayWritesIsOneItsOwnRouteAccepts sweeps them to say so
// rather than taking this comment's word for it.
//
// So without this a relay that failed could put one tab in its refusal, and the
// sentence this relay produced from it would be refused 400 by the hop behind.
// The worker reads a 400 as something this relay sent that no retry fixes: the
// report row ends, the chain stops there, and the person who sent the message is
// never told. One byte, to suppress a bounce for every message.
//
// It runs inside the escaping step and before the cut that follows it, so the
// two characters a tab becomes are bounded by that cut like any other growth.
func oneLine(s string) string {
	return strings.ReplaceAll(identity.PrintableText(s), "\t", `\t`)
}

// reportEllipsis says in front of a sentence that hops were dropped from it.
const reportEllipsis = "…"

// runeStart is the smallest index at or above n that begins a rune, so that a
// string cut there is still a string of characters. It is runeBoundary's
// other direction: that one walks down for a cut that keeps the head, this
// one walks up for a cut that keeps the tail.
func runeStart(s string, n int) int {
	for n < len(s) && !utf8.RuneStart(s[n]) {
		n++
	}
	return n
}

// runeBoundary is the largest index at or below n that begins a rune, so
// that a string cut there is still a string of characters. n must be an
// index into s.
func runeBoundary(s string, n int) int {
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return n
}

// retry records the attempt against the row and answers how long the
// neighbour is left alone, the wait doubling with the tries.
func (w *workers) retry(row *Outbound) time.Duration {
	return w.wait(row, backoffFor(row.Tries+1, w.rnd))
}

// wait records an attempt against the row and pushes its next one out by the
// given time, so that the waiting survives a restart and a wake alike: the
// row itself says when it is next due, and NextOutbound reads it.
func (w *workers) wait(row *Outbound, d time.Duration) time.Duration {
	now := w.now()
	if err := w.store.Retry(row.ID, now, now.Add(d)); err != nil {
		w.log.Error("courier: recording a retry failed", "id", row.ID, "err", err)
	}
	return d
}

// fail ends a row with a code and the sentence a person reads, and passes the
// news back a hop when the row was a neighbour's rather than one of this
// relay's own users'.
//
// That second part is what makes an undeliverable travel at all in the
// commonest case. The last hop refuses a delivery synchronously, so the relay
// before it learns here and not on the report route; if only the route
// reported onward, the news would unwind exactly one hop and stop.
func (w *workers) fail(row *Outbound, code, said string) {
	if err := w.store.Failed(row.ID, code, said, w.now()); err != nil {
		w.log.Error("courier: recording a failed message failed", "id", row.ID, "err", err)
		return
	}
	if name := reportBack(w.store, w.courier, w.limits, w.now(), row, code, said); name != "" {
		w.wake(name)
	}
}

// noteUnreachable says a neighbour is not answering, once a minute, naming
// it and never a mailbox or a fingerprint.
//
// The error here is this relay's own — a dial that failed, a connection
// dropped, an answer that would not parse — and so is bounded by this
// tree's own words. A neighbour's sentence is not, and goes through
// noteRefusal instead.
func (w *workers) noteUnreachable(neighbour string, err error) {
	if !w.store.faults.due("forward:" + neighbour) {
		return
	}
	w.log.Warn("courier: a neighbour is not answering; mail for it is waiting",
		"neighbour", neighbour, "err", err)
}

// noteRefusal says a neighbour answered with something this relay cannot
// act on and cannot blame the row for, once a minute.
//
// It exists so that this line cannot carry an error object. An *HTTPError
// prints the neighbour's whole message, which is held by what a client
// will read from a relay and by nothing smaller, so a line a minute of it
// is a neighbour choosing how large this relay's log grows — the choice
// said takes away, and which a branch logging the error takes back.
func (w *workers) noteRefusal(neighbour, message string) {
	if !w.store.faults.due("forward:" + neighbour) {
		return
	}
	w.log.Warn("courier: a neighbour refused with something this relay cannot act on; "+
		"mail for it is waiting", "neighbour", neighbour, "said", said(neighbour, message))
}

// dialNeighbour is the real dial: this courier's client for that neighbour,
// with its certificate renewed first when it is close to expiry, by the same
// code the command line renews with.
func (w *workers) dialNeighbour(r *store.Relay) (*client.Client, error) {
	// The relay's own context, so a stop cancels a renewal in flight: the
	// dial is the other half of an attempt, and a shutdown that waits on it
	// is a shutdown that waits on a neighbour.
	return w.dialer.Dial(w.ctx, w.courier.home, w.courier.id, r)
}

// reportToNeighbour is the real report: one control message to the
// neighbour's own failed route.
func (w *workers) reportToNeighbour(ctx context.Context, c *client.Client, id int64, code, said string) error {
	return c.ReportFailed(ctx, id, code, said)
}

// postToNeighbour is the real attempt: one forward request, signed fresh, to
// the neighbour's forward route.
func (w *workers) postToNeighbour(ctx context.Context, c *client.Client, req *relayapi.ForwardRequest) (int64, error) {
	return c.Forward(ctx, req)
}
