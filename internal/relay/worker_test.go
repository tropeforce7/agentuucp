package relay

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// TestAnEnvelopeCrossesToTheNeighbour: the whole of what this commit adds,
// end to end, with two relays in the room and nothing faked between them.
//
// A user posts to A with a path naming B and then another relay; A queues it;
// A's worker dials B as its courier, over TLS it verifies against the anchor
// in its courier home, and B takes it and queues it for the next hop. A's row
// is handed, its file is gone, its recipient is blanked, and B holds a row
// whose via names A by B's own name for it.
func TestAnEnvelopeCrossesToTheNeighbour(t *testing.T) {
	b := peered(t, []string{"onward"}, nil, nil)
	// B accepts from A: peer writes the line into the file B is watching.
	// A calls B "bar"; B calls A "alpha". A name is relative to the relay
	// reading it, and nothing anywhere makes the two agree.
	a := peer(t, b, "bar", "alpha", DefaultCourierLimits())

	sender := a.h.user(t, "alice")
	to := a.h.fpOf(t, "bob")
	status, answer, body := a.h.forward(sender, request(sealedFor(to, "ciphertext"), []string{"bar", "onward"}, nil))
	if status != 201 {
		t.Fatalf("the post to A: status %d: %s", status, body)
	}

	// A's worker, driven once rather than waited for.
	worker(t, a.h).drainOnce(t, "bar")

	row := a.h.outbound(t, answer.ID)
	switch {
	case row.State != OutHanded:
		t.Fatalf("A's row is %q, want %q: %s", row.State, OutHanded, row.Said)
	case row.ToFP != "":
		t.Errorf("A's handed row still names the recipient: %s", row.ToFP)
	case row.TheirID == 0:
		t.Error("A's handed row does not carry the id B answered with")
	}
	if _, err := a.h.store.OutboundBody(answer.ID); err == nil {
		t.Error("A's handed row still has its envelope on disk")
	}
	if msgs, _ := a.h.queueCounters(t); msgs != 0 {
		t.Errorf("A's queue still counts %d messages", msgs)
	}

	// B has it, for the hop after, with A named as B calls A.
	theirs := b.outbound(t, row.TheirID)
	switch {
	case theirs.Neighbour != "onward":
		t.Errorf("B queued it for %q, want onward", theirs.Neighbour)
	case theirs.Via != "alpha":
		t.Errorf("B's via is %q, want alpha: the name B knows A by, which is not the name A knows B by", theirs.Via)
	case theirs.Path != "":
		t.Errorf("B's path is %q, want empty: onward is the last name", theirs.Path)
	}
	// And the bytes are the sender's own, byte for byte, through two
	// relays: what the sender sealed is what the last hop will hand over.
	sent, err := a.h.store.OutboundBody(answer.ID)
	if !errors.Is(err, os.ErrNotExist) && err == nil {
		t.Fatal("A still holds the envelope it handed over")
	}
	mine, err := b.store.OutboundBody(theirs.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(mine) != string(request(sealedFor(to, "ciphertext"), nil, nil).Envelope) {
		t.Errorf("B holds %s; the envelope did not cross verbatim", mine)
	}
	_ = sent
}

// TestARetryAfterALostAnswerIsHandedOver: the neighbour answers 409 for an
// envelope it already has, which is what a retry whose answer was lost looks
// like from here, and the row is handed rather than tried for ever.
func TestARetryAfterALostAnswerIsHandedOver(t *testing.T) {
	b := peered(t, []string{"onward"}, nil, nil)
	// A calls B "bar"; B calls A "alpha". A name is relative to the relay
	// reading it, and nothing anywhere makes the two agree.
	a := peer(t, b, "bar", "alpha", DefaultCourierLimits())
	sender := a.h.user(t, "alice")
	env := sealedFor(a.h.fpOf(t, "bob"), "ct")

	status, answer, body := a.h.forward(sender, request(env, []string{"bar", "onward"}, nil))
	if status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	// B is given the same envelope by somebody else first, so A's attempt
	// meets the 409 a lost answer would have left behind.
	other := neighbourID(t, "beta")
	b.enroll(other)
	writeCouriers(t, b.server.courier.couriers.path, a.courier, other)
	if status, _, body := b.forward(other, request(env, []string{"onward"}, nil)); status != 201 {
		t.Fatalf("the other courier: status %d: %s", status, body)
	}

	worker(t, a.h).drainOnce(t, "bar")
	if row := a.h.outbound(t, answer.ID); row.State != OutHanded {
		t.Errorf("A's row is %q after a 409, want %q: a neighbour that already has it has it", row.State, OutHanded)
	}
}

// worker builds this relay's workers without starting them, so a test drives
// one from its own goroutine: no timer to wait out, no goroutine to race, and
// the same drain and attempt the real one runs.
func worker(t *testing.T, h *harness) *workers {
	t.Helper()
	w := newWorkers(h.store, h.server.courier, h.server.cfg.CourierLimits, h.server.log, h.clock.Now)
	if w == nil {
		t.Fatal("this relay dials nobody")
	}
	return w
}

// drainOnce runs one neighbour's worker for one pass.
func (w *workers) drainOnce(t *testing.T, neighbour string) {
	t.Helper()
	r, ok := w.courier.Neighbour(neighbour)
	if !ok {
		t.Fatalf("no neighbour %q", neighbour)
	}
	w.drain(r)
}

// fakeNeighbour is a worker whose dialling and posting are the test's, for
// the answers a real neighbour is awkward to make: a refusal, a rate limit, a
// certificate no longer accepted, a cable pulled out. The fields are set
// before anything is started, so nothing reads them while they are written.
func fakeNeighbour(t *testing.T, h *harness, answer func() (int64, error)) *workers {
	t.Helper()
	w := worker(t, h)
	w.dial = func(*store.Relay) (*client.Client, error) { return nil, nil }
	w.post = func(context.Context, *client.Client, *relayapi.ForwardRequest) (int64, error) { return answer() }
	return w
}

// TestWhatEachAnswerDoesToARow: a neighbour's answer decides whether this row
// is finished, whether it waits, and whether every other row for that
// neighbour waits with it.
//
// A final answer is this row's: the neighbour will not take this envelope
// however often it is offered, and its sentence is kept so the poster reads
// which hop refused and why. A transient one is the neighbour's, and every
// row waiting for it waits, because the next would meet the same thing at the
// same cost.
func TestWhatEachAnswerDoesToARow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answer  func() (int64, error)
		state   string
		code    string
		backOff bool
		said    string
	}{
		{"taken", func() (int64, error) { return 77, nil }, OutHanded, "", false, ""},
		{"already carried", func() (int64, error) {
			return 0, &client.HTTPError{Status: http.StatusConflict, Message: relayapi.MsgAlreadyCarried}
		}, OutHanded, "", false, ""},
		{"a request it will not take", func() (int64, error) {
			return 0, &client.HTTPError{Status: http.StatusBadRequest, Message: "address repeats \"bar\""}
		}, OutFinal, relayapi.CodeRefused, false, "address repeats"},
		{"an address it cannot route", func() (int64, error) {
			return 0, &client.HTTPError{Status: http.StatusNotFound, Message: "no neighbour named \"onward\""}
		}, OutFinal, relayapi.CodeRefused, false, "no neighbour named"},
		{"it forwards nothing", func() (int64, error) {
			return 0, &client.HTTPError{Status: http.StatusForbidden, Message: relayapi.MsgForwardsNothing}
		}, OutFinal, relayapi.CodeRefused, false, "forwards nothing"},
		{"too large for it", func() (int64, error) {
			return 0, &client.HTTPError{Status: http.StatusRequestEntityTooLarge, Message: "body too large"}
		}, OutFinal, relayapi.CodeRefused, false, "too large"},
		{"asked to come back later", func() (int64, error) {
			return 0, &client.HTTPError{Status: http.StatusTooManyRequests, RetryAfter: 30 * time.Second}
		}, OutWaiting, "", true, ""},
		{"its storage is full", func() (int64, error) {
			return 0, &client.HTTPError{Status: http.StatusInsufficientStorage, Message: relayapi.MsgRelayFull}
		}, OutWaiting, "", true, ""},
		{"it no longer accepts this courier", func() (int64, error) {
			return 0, &client.HTTPError{Status: http.StatusUnauthorized, Message: "unauthorized"}
		}, OutWaiting, "", true, ""},
		{"the cable is out", func() (int64, error) {
			return 0, errors.New("dial tcp: connection refused")
		}, OutWaiting, "", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := peered(t, []string{"bar"}, nil, nil)
			user := h.user(t, "alice")
			status, answer, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))
			if status != 201 {
				t.Fatalf("status %d: %s", status, body)
			}
			w := fakeNeighbour(t, h, tc.answer)
			r, _ := w.courier.Neighbour("bar")
			row := h.outbound(t, answer.ID)
			out, wait := w.attempt(r, nil, row)

			got := h.outbound(t, answer.ID)
			if got.State != tc.state {
				t.Errorf("the row is %q, want %q (said %q)", got.State, tc.state, got.Said)
			}
			if got.Code != tc.code {
				t.Errorf("code %q, want %q", got.Code, tc.code)
			}
			if tc.said != "" && !strings.Contains(got.Said, tc.said) {
				t.Errorf("said %q, want it to carry %q", got.Said, tc.said)
			}
			if tc.said != "" && !strings.HasPrefix(got.Said, "bar: ") {
				t.Errorf("said %q; want the hop that refused named first", got.Said)
			}
			if backedOff := out == attemptBackOff; backedOff != tc.backOff {
				t.Errorf("backed off %v, want %v", backedOff, tc.backOff)
			}
			if tc.backOff && wait <= 0 {
				t.Errorf("backed off for %s; want a wait", wait)
			}
			// A row that is finished either way is charged off the queue;
			// one that waits is still on it.
			msgs, _ := h.queueCounters(t)
			if tc.state == OutWaiting && msgs != 1 {
				t.Errorf("a waiting row counts %d, want 1", msgs)
			}
			if tc.state != OutWaiting && msgs != 0 {
				t.Errorf("a finished row still counts %d, want 0", msgs)
			}
		})
	}
}

// TestARetryAfterIsHonoured: a neighbour that says when to come back is
// believed, since it knows its own budgets better than this relay's
// arithmetic does.
func TestARetryAfterIsHonoured(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	_, answer, _ := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))
	w := fakeNeighbour(t, h, func() (int64, error) {
		return 0, &client.HTTPError{Status: http.StatusTooManyRequests, RetryAfter: 45 * time.Second}
	})
	r, _ := w.courier.Neighbour("bar")
	_, wait := w.attempt(r, nil, h.outbound(t, answer.ID))
	if wait != 45*time.Second {
		t.Errorf("waiting %s, want the 45s the neighbour asked for", wait)
	}
}

// TestTheBackoffDoublesAndIsJittered: a minute doubling to an hour, less a
// random part, so that two relays which lost the same cable do not knock on
// the same second every hour for a week.
func TestTheBackoffDoublesAndIsJittered(t *testing.T) {
	// With no jitter, the shape is plain.
	none := func() float64 { return 0 }
	for _, tc := range []struct {
		tries int64
		want  time.Duration
	}{
		{1, time.Minute}, {2, 2 * time.Minute}, {3, 4 * time.Minute},
		{6, 32 * time.Minute},
		// The doubling stops at the hour rather than passing it, which is
		// what maxRetry is: the seventh try would be sixty-four minutes.
		{7, time.Hour}, {8, time.Hour}, {100, time.Hour},
	} {
		if got := backoffFor(tc.tries, none); got != tc.want {
			t.Errorf("%d tries: %s, want %s", tc.tries, got, tc.want)
		}
	}
	// With it, the wait is inside the quarter below and never past the
	// hour, and never so small that a worker spins.
	full := func() float64 { return 1 }
	for _, tries := range []int64{1, 2, 5, 8, 50} {
		plain := backoffFor(tries, none)
		got := backoffFor(tries, full)
		if got > plain || got < plain*3/4 || got < time.Second {
			t.Errorf("%d tries: %s, want between %s and %s", tries, got, plain*3/4, plain)
		}
	}
}

// TestForwardTTLEndsARowAndTellsThePoster: a neighbour that has been
// unreachable for the whole of forward_ttl is given up on, and the row says
// how long the relay tried and since when, so the poster reads what happened
// rather than finding their mail gone.
func TestForwardTTLEndsARowAndTellsThePoster(t *testing.T) {
	limits := DefaultCourierLimits()
	limits.ForwardTTL = time.Hour
	h := peered(t, []string{"bar"}, nil, &limits)
	user := h.user(t, "alice")
	_, answer, _ := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))

	// Inside the window nothing is given up.
	w := fakeNeighbour(t, h, func() (int64, error) { return 0, errors.New("connection refused") })
	r, _ := w.courier.Neighbour("bar")
	h.clock.advance(30 * time.Minute)
	w.drain(r)
	if row := h.outbound(t, answer.ID); row.State != OutWaiting {
		t.Fatalf("inside forward_ttl the row is %q, want waiting", row.State)
	}
	// Past it, the poster is told.
	h.clock.advance(31 * time.Minute)
	w.drain(r)
	row := h.outbound(t, answer.ID)
	if row.State != OutFinal {
		t.Fatalf("past forward_ttl the row is %q, want final", row.State)
	}
	if row.Code != relayapi.CodeGaveUp {
		t.Errorf("code %q, want %q", row.Code, relayapi.CodeGaveUp)
	}
	for _, want := range []string{"gave up after", "bar", "unreachable since"} {
		if !strings.Contains(row.Said, want) {
			t.Errorf("said %q does not carry %q", row.Said, want)
		}
	}
	if msgs, _ := h.queueCounters(t); msgs != 0 {
		t.Errorf("a given-up row still counts %d against the queue", msgs)
	}
}

// TestTheWorkerNamesNeighboursAndNeverFingerprints: every line the queue
// writes is about a neighbour, which is this relay's own name for it, and
// never about a person.
func TestTheWorkerNamesNeighboursAndNeverFingerprints(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	to := h.fpOf(t, "bob")
	_, answer, _ := h.forward(user, request(sealedFor(to, "ct"), []string{"bar"}, nil))
	w := fakeNeighbour(t, h, func() (int64, error) {
		return 0, &client.HTTPError{Status: http.StatusUnauthorized, Message: "unauthorized"}
	})
	r, _ := w.courier.Neighbour("bar")
	w.attempt(r, nil, h.outbound(t, answer.ID))
	w.drain(r)

	// The queue's own lines, which are the ones this test is about: the
	// access log's are the relay's and carry a caller's fingerprint under
	// full logging by design, which is a different rule with its own tests.
	var courierLines []string
	for _, line := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(line, "courier:") {
			courierLines = append(courierLines, line)
		}
	}
	if len(courierLines) == 0 {
		t.Fatal("the queue logged nothing, so this test proves nothing")
	}
	lines := strings.Join(courierLines, "\n")
	if !strings.Contains(lines, "bar") {
		t.Errorf("the queue's lines do not name the neighbour: %s", lines)
	}
	for _, fp := range []string{user.Fingerprint(), to} {
		if strings.Contains(lines, fp) || strings.Contains(lines, fp[:16]) {
			t.Errorf("a fingerprint is in the queue's lines: %s", lines)
		}
	}
}

// TestStoppingDoesNotWaitOnANeighbour: a relay stops when it is asked to, not
// when the far end answers. An attempt in flight is abandoned and its row
// stays waiting, which is safe because the neighbour may have taken the
// envelope: the retry after the restart is answered already-carried and read
// as handed.
func TestStoppingDoesNotWaitOnANeighbour(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	_, answer, _ := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))

	held := make(chan struct{})
	w := worker(t, h)
	w.dial = func(*store.Relay) (*client.Client, error) { return nil, nil }
	w.post = func(ctx context.Context, _ *client.Client, _ *relayapi.ForwardRequest) (int64, error) {
		select {
		case <-held:
		default:
			close(held)
		}
		<-ctx.Done() // a neighbour that has accepted the connection and gone quiet
		return 0, ctx.Err()
	}
	// Started only now, with its dialling already in place.
	w.start()
	<-held

	done := make(chan struct{})
	go func() { w.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("stopping waited on a neighbour that was not answering")
	}
	if row := h.outbound(t, answer.ID); row.State != OutWaiting {
		t.Errorf("an abandoned attempt left the row %q, want waiting", row.State)
	}
}

// TestARelayDrainsItsOwnQueue: the whole of this commit, asserted through a
// running relay rather than a worker a test is driving.
//
// Every other test here calls drain or attempt from its own goroutine, which
// is what makes them deterministic — but it means none of them would notice
// if the relay never started a worker, never woke one when a message
// arrived, or never listened for that wake. This one posts a forward and
// waits for the row to be handed, so all three have to work.
func TestARelayDrainsItsOwnQueue(t *testing.T) {
	// Built by hand rather than through peered, since what is under test is
	// the workers the relay starts for itself.
	c := mustCourier(t, []string{"bar"}, nil)
	h := newHarness(t, Config{Courier: c, CourierLimits: DefaultCourierLimits(), Limits: DefaultLimits()})
	// The started workers answer as a neighbour that takes everything. They
	// are replaced before anything is posted, and a worker only dials once
	// there is a row, so nothing reads these while they are written.
	h.server.workers.Stop()
	w := worker(t, h)
	var posted atomic.Int64
	w.dial = func(*store.Relay) (*client.Client, error) { return nil, nil }
	w.post = func(context.Context, *client.Client, *relayapi.ForwardRequest) (int64, error) {
		return posted.Add(1), nil
	}
	h.server.workers = w
	w.start()
	t.Cleanup(w.Stop)

	user := h.user(t, "alice")
	status, answer, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))
	if status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}

	// The wake is what makes this prompt; the deadline is long because a
	// loaded machine is slow and the claim is "it happens", not "it happens
	// within a millisecond".
	deadline := time.Now().Add(15 * time.Second)
	for {
		if row := h.outbound(t, answer.ID); row.State == OutHanded {
			if row.TheirID == 0 {
				t.Error("the row was handed without the id the neighbour answered with")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the relay did not drain its own queue: nothing started a worker, woke one, or listened")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if posted.Load() != 1 {
		t.Errorf("the neighbour was posted to %d times, want once", posted.Load())
	}
}

// TestABackedOffNeighbourIsNotDialledByEveryNewMessage: the backing off is
// the neighbour's and not one row's, so a message arriving does not buy
// another dial at a relay that is not answering.
//
// Without this a busy relay turns an outage into a flood: every post wakes
// the worker, and a newly queued row is due at once, so the neighbour would
// be dialled once per message however long it had been down.
func TestABackedOffNeighbourIsNotDialledByEveryNewMessage(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	to := h.fpOf(t, "bob")
	var dials atomic.Int64
	w := worker(t, h)
	w.dial = func(*store.Relay) (*client.Client, error) {
		dials.Add(1)
		return nil, errors.New("connection refused")
	}
	r, _ := w.courier.Neighbour("bar")

	for i := range 8 {
		if status, _, body := h.forward(user, request(sealedFor(to, fmt.Sprintf("ct%d", i)), []string{"bar"}, nil)); status != 201 {
			t.Fatalf("%d: status %d: %s", i, status, body)
		}
		// What a wake does: the worker takes a turn.
		w.drain(r)
	}
	if n := dials.Load(); n != 1 {
		t.Errorf("%d dials at a neighbour that is not answering, want 1: the backing off is per neighbour", n)
	}
	// And when the wait is over it is dialled again.
	h.clock.advance(2 * time.Hour)
	w.drain(r)
	if n := dials.Load(); n != 2 {
		t.Errorf("%d dials after the wait, want 2: the backing off must also lift", n)
	}
}

// TestAQueueThatCannotWriteDoesNotSpin: a relay whose disk is full, or whose
// database will not take a write, must not post one envelope to its
// neighbour for ever.
//
// attempt records what it decided in the database; when that write does not
// land the row stays waiting and comes back on the next turn. Without the
// guard the loop posts the same envelope as fast as the neighbour will take
// it, for as long as the relay runs, and the operator is told nothing.
func TestAQueueThatCannotWriteDoesNotSpin(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	if status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	// Whatever the worker decides cannot be written down.
	if _, err := h.store.db.Exec(
		`CREATE TRIGGER no_state BEFORE UPDATE OF state ON outbound BEGIN SELECT RAISE(ABORT, 'no'); END`); err != nil {
		t.Fatal(err)
	}
	var posted atomic.Int64
	w := worker(t, h)
	w.dial = func(*store.Relay) (*client.Client, error) { return nil, nil }
	w.post = func(context.Context, *client.Client, *relayapi.ForwardRequest) (int64, error) {
		return posted.Add(1), nil
	}
	r, _ := w.courier.Neighbour("bar")

	done := make(chan time.Duration, 1)
	go func() { done <- w.drain(r) }()
	select {
	case wait := <-done:
		if wait <= 0 {
			t.Errorf("the turn ended with a wait of %s; want the neighbour left alone", wait)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the turn did not end: it posted the same message %d times", posted.Load())
	}
	if n := posted.Load(); n > 2 {
		t.Errorf("the same message was posted %d times in one turn, want at most twice", n)
	}
	if !strings.Contains(h.logs.String(), "the queue is not moving") {
		t.Errorf("the operator was not told: %s", h.logs.String())
	}
}

// TestANeighboursSentenceIsASentence: what a neighbour says about a message
// it would not take is kept for the person who sent it, and a neighbour does
// not get to choose how large this relay's database grows.
func TestANeighboursSentenceIsASentence(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	_, answer, _ := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))
	huge := strings.Repeat("l", 4<<20)
	w := fakeNeighbour(t, h, func() (int64, error) {
		return 0, &client.HTTPError{Status: http.StatusBadRequest, Message: huge}
	})
	r, _ := w.courier.Neighbour("bar")
	w.attempt(r, nil, h.outbound(t, answer.ID))

	row := h.outbound(t, answer.ID)
	if len(row.Said) > relayapi.MaxSaid {
		t.Errorf("the row kept %d bytes of a neighbour's sentence, want at most %d",
			len(row.Said), relayapi.MaxSaid)
	}
	// Over the cap it is the front that goes, so what survives is the end of
	// what the neighbour said and the marker says hops were dropped. The tail
	// is the part a report is for: it is what the relay that actually failed
	// wrote, where the head is a list of names.
	if !strings.HasPrefix(row.Said, "…") {
		t.Errorf("said %q; want the marker in front, saying the front was cut", row.Said[:40])
	}
	if !strings.HasSuffix(row.Said, huge[len(huge)-20:]) {
		t.Errorf("said %q; want the end of what the neighbour said", row.Said[len(row.Said)-30:])
	}
	// What is kept is still a sentence: cut on a rune boundary, whatever
	// the neighbour sent.
	if !utf8.ValidString(row.Said) {
		t.Error("the sentence was cut through a character")
	}

	// And a sentence that fits is untouched, with the hop that refused named
	// first: the cut is what happens at the cap and not what happens.
	if got := said("bar", "no such mailbox"); got != "bar: no such mailbox" {
		t.Errorf("said %q; want the name in front and the sentence whole", got)
	}
}

// TestASentenceIsCutOnARuneBoundary: the cut is on a character and not on a
// byte, for a neighbour whose sentence is not ASCII.
func TestASentenceIsCutOnARuneBoundary(t *testing.T) {
	for _, r := range []string{"é", "☃", "🙂"} {
		got := said("bar", strings.Repeat(r, relayapi.MaxSaid))
		if !utf8.ValidString(got) {
			t.Errorf("%q: the sentence was cut through a character", r)
		}
		if len(got) > relayapi.MaxSaid {
			t.Errorf("%q: %d bytes, want at most %d", r, len(got), relayapi.MaxSaid)
		}
	}
}

// TestAStoppingRelayLeavesItsRowAlone: an attempt cancelled by a shutdown is
// not a failed attempt. The row keeps its tries and its next_try, so the
// relay that comes back up tries it at once rather than in an hour.
func TestAStoppingRelayLeavesItsRowAlone(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	_, answer, _ := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))
	before := h.outbound(t, answer.ID)

	w := worker(t, h)
	w.dial = func(*store.Relay) (*client.Client, error) { return nil, nil }
	w.post = func(ctx context.Context, _ *client.Client, _ *relayapi.ForwardRequest) (int64, error) {
		w.stop() // the relay is asked to stop while this attempt is in flight
		return 0, ctx.Err()
	}
	r, _ := w.courier.Neighbour("bar")
	w.attempt(r, nil, h.outbound(t, answer.ID))

	after := h.outbound(t, answer.ID)
	switch {
	case after.State != OutWaiting:
		t.Errorf("the row is %q, want waiting", after.State)
	case after.Tries != before.Tries:
		t.Errorf("a cancelled attempt was counted: tries %d, want %d", after.Tries, before.Tries)
	case !after.NextTry.Equal(before.NextTry):
		t.Errorf("a cancelled attempt pushed the row out to %s, want %s; a relay coming back "+
			"up should try it at once", after.NextTry, before.NextTry)
	}
}

// queue posts an envelope down the given address and answers the id of the
// row it made, failing the test if the relay did not take it: what the tests
// below are about is what becomes of a row, so a forward that was refused is
// never the thing under test and always a mistake in the setup.
func (h *harness) queue(from *identity.Identity, env *envelope.Envelope, path ...string) int64 {
	h.t.Helper()
	status, answer, body := h.forward(from, request(env, path, nil))
	if status != 201 {
		h.t.Fatalf("queueing for %v: status %d: %s", path, status, body)
	}
	return answer.ID
}

// TestWhatThePurgeTakesAndWhatItLeaves: a failed row is kept a day so the
// person who sent it can read what happened; a handed one is kept as long as
// its own envelope could still be alive ahead of it, since that is how long
// something coming back about it could take; and a waiting row is never
// taken here at all, because its own gives_up ends it and that is what tells
// the sender.
func TestWhatThePurgeTakesAndWhatItLeaves(t *testing.T) {
	limits := DefaultCourierLimits()
	h := peered(t, []string{"bar"}, nil, &limits)
	user := h.user(t, "alice")
	to := h.fpOf(t, "bob")

	// Three rows: one handed with two hops left, one failed, one waiting.
	handed := h.queue(user, sealedFor(to, "handed"), "bar", "two", "three")
	failed := h.queue(user, sealedFor(to, "failed"), "bar")
	waiting := h.queue(user, sealedFor(to, "waiting"), "bar")
	if err := h.store.Handed(handed, 5, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Failed(failed, relayapi.CodeRefused, "bar: no", h.clock.Now()); err != nil {
		t.Fatal(err)
	}

	// A day and a bit: the failed row goes, the handed one stays, since its
	// own window is three hops of forward_ttl.
	n, err := h.store.PurgeOutbound(h.clock.Now().Add(25*time.Hour), finalRowRetention, limits.CarriedWindow)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d rows purged after a day, want 1", n)
	}
	if rows := h.outboundRows(t); rows != 2 {
		t.Errorf("%d rows left, want the handed one and the waiting one", rows)
	}
	// Past the shortest window but inside this row's own: still there.
	past := h.clock.Now().Add(limits.CarriedWindow(0) + time.Hour)
	if _, err := h.store.PurgeOutbound(past, finalRowRetention, limits.CarriedWindow); err != nil {
		t.Fatal(err)
	}
	if rows := h.outboundRows(t); rows != 2 {
		t.Errorf("a handed row with two hops left went at the one-hop window; %d rows left", rows)
	}
	// Past its own: it goes, and the waiting row is still untouched.
	past = h.clock.Now().Add(limits.CarriedWindow(2) + time.Hour)
	if _, err := h.store.PurgeOutbound(past, finalRowRetention, limits.CarriedWindow); err != nil {
		t.Fatal(err)
	}
	if rows := h.outboundRows(t); rows != 1 {
		t.Errorf("%d rows left, want only the waiting one", rows)
	}
	if row := h.outbound(t, waiting); row.State != OutWaiting {
		t.Errorf("the waiting row is %q; a purge must never take mail nobody has been told about", row.State)
	}
	// And it is still charged to the queue, since it is still queued.
	if msgs, _ := h.queueCounters(t); msgs != 1 {
		t.Errorf("the queue counts %d, want the one row still waiting", msgs)
	}
}

// TestTheQueuePurgeRuns: the purge is wired into the housekeeping every relay
// does, not merely written — the same claim, and the same distinction, as the
// carried table's.
func TestTheQueuePurgeRuns(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	id := h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")
	if err := h.store.Failed(id, relayapi.CodeRefused, "bar: no", h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(25 * time.Hour)
	for range 101 {
		h.do(user, "GET", "/v1/mailbox/"+user.Fingerprint(), nil, nil)
	}
	if rows := h.outboundRows(t); rows != 0 {
		t.Errorf("%d rows after a day and a hundred requests; the purge is written and not run", rows)
	}
}

// TestARowIsChargedOffExactlyOnce: the queue's counters are moved inside the
// transaction that moves the row, so a row that is handed and then failed —
// which is what an undeliverable coming back will do — is charged off once
// and not twice. A counter that has gone below zero is room that is not
// there.
func TestARowIsChargedOffExactlyOnce(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	id := h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")
	msgs, bytes := h.queueCounters(t)
	if msgs != 1 {
		t.Fatalf("the queue counts %d, want 1", msgs)
	}
	if err := h.store.Handed(id, 5, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if msgs, bytes := h.queueCounters(t); msgs != 0 || bytes != 0 {
		t.Fatalf("after handing, the queue counts %d/%d, want 0/0", msgs, bytes)
	}
	// And again, as a report about that row will.
	if err := h.store.Failed(id, relayapi.CodeRefused, "bar: no such mailbox", h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if got, gotBytes := h.queueCounters(t); got != 0 || gotBytes != 0 {
		t.Errorf("after failing a handed row the queue counts %d/%d, want 0/0; it was charged off twice "+
			"(it was %d/%d when queued)", got, gotBytes, msgs, bytes)
	}
}

// TestARowIsHandedOnlyFromWaiting: handing is what takes the file and blanks
// the recipient, and doing it twice would take a file a second time and
// charge the queue off twice. The guard says which state it may be done
// from.
func TestARowIsHandedOnlyFromWaiting(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	id := h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")
	if err := h.store.Handed(id, 5, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Handed(id, 6, h.clock.Now()); err == nil {
		t.Error("a row was handed twice")
	}
	if row := h.outbound(t, id); row.TheirID != 5 {
		t.Errorf("their_id is %d; the second handing overwrote the first", row.TheirID)
	}
	if msgs, _ := h.queueCounters(t); msgs != 0 {
		t.Errorf("the queue counts %d after two handings, want 0", msgs)
	}
}

// TestTheCourierRefusalComesAfterTheMailboxIsKnown: the order the three
// routes take is what keeps this from telling a stranger anything new.
//
// After the mailbox-exists check, so it is not an oracle for which
// fingerprints have mailboxes here; after the block, so a blocked identity
// is told what a blocked identity is told; and before the allow list, so
// nothing about the list is learned and nothing is stored or charged.
func TestTheCourierRefusalComesAfterTheMailboxIsKnown(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	sender := h.user(t, "alice")

	// The courier is in this relay's couriers file but has no mailbox here:
	// the answer is the one any fingerprint with no mailbox gets.
	//
	// The sentences are one sentence now, so what says the order is right
	// is the status: 404 for a mailbox that is not there, and 403 only once
	// it is. A check that ran first would answer 403 for a fingerprint with
	// no mailbox at all, and that difference is a stranger asking which
	// relays this one peers with.
	status, body := h.do(sender, "POST", "/v1/mailbox/"+courier.Fingerprint(),
		sealed(t, sender, courier.Public(), "hello"), nil)
	if status != 404 {
		t.Fatalf("a courier with no mailbox here: status %d, want 404: %s", status, body)
	}
	// With a mailbox, the refusal — and it is the refusal every unadmitted
	// sender gets, byte for byte.
	h.enroll(courier)
	status, body = h.do(sender, "POST", "/v1/mailbox/"+courier.Fingerprint(),
		sealed(t, sender, courier.Public(), "hello"), nil)
	if status != 403 || errorText(t, body) != msgNotAllowed {
		t.Fatalf("a courier with a mailbox: status %d: %s", status, body)
	}
}

// TestARowPutBackWaitsForItsTime: the backoff is written into the row as
// well as held in the set, and the queue honours it.
//
// The two are not the same thing. The set's is this process's memory of a
// neighbour and goes when the relay stops; the row's is what survives a
// restart, so a relay bounced in the middle of an hour's backoff does not
// come up and dial a dead neighbour at once — which is the shape a whole
// queue for one neighbour would take, every row asking again the moment the
// process came back.
func TestARowPutBackWaitsForItsTime(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	id := h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")

	now := h.clock.Now()
	if err := h.store.Retry(id, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if row := h.outbound(t, id); row.Tries != 1 {
		t.Errorf("tries is %d after one attempt, want 1", row.Tries)
	}
	// Nothing due, though the row is waiting and the neighbour is the one
	// asked for: this is the queue reading the row and not the set.
	for _, d := range []time.Duration{0, time.Minute, 59 * time.Minute} {
		row, err := h.store.NextOutbound("bar", now.Add(d))
		if err != nil {
			t.Fatal(err)
		}
		if row != nil {
			t.Fatalf("the queue answered a row put back for an hour after %s", d)
		}
	}
	// And at its time it is due again, unchanged but for the attempt.
	row, err := h.store.NextOutbound("bar", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if row == nil {
		t.Fatal("the queue did not answer the row at its time")
	}
	if row.ID != id || row.State != OutWaiting {
		t.Errorf("the queue answered %d in state %q, want %d waiting", row.ID, row.State, id)
	}
}

// TestABackoffSurvivesARestart: the same claim as the test above, through
// the door an operator uses — the worker is what wrote the row, and a second
// set of workers over the same database is what a restart is.
func TestABackoffSurvivesARestart(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")

	// One worker, and a neighbour nothing answers for: the dial itself
	// fails, which is the cable out of the wall and the commonest reason a
	// queue sits.
	w := worker(t, h)
	w.dial = func(*store.Relay) (*client.Client, error) { return nil, errors.New("connection refused") }
	r, ok := w.courier.Neighbour("bar")
	if !ok {
		t.Fatal("no neighbour bar")
	}
	if wait := w.drain(r); wait <= 0 {
		t.Fatalf("the worker waits %s after a refused dial", wait)
	}

	// A second set over the same store is what a restart is: it remembers
	// no neighbour, so the only thing left saying to wait is the row.
	fresh := worker(t, h)
	fresh.dial = func(*store.Relay) (*client.Client, error) {
		t.Error("a restarted relay dialled a neighbour whose row was not due")
		return nil, errors.New("connection refused")
	}
	if wait := fresh.drain(r); wait <= 0 {
		t.Errorf("a restarted relay waits %s, want the row's own time", wait)
	}
}

// TestAWorkerWithNothingToDoSaysNothing: a worker turns on its own timer and
// on every row that arrives, so a line per turn would be a log that says a
// relay is idle, once a minute, for ever — and the lines an operator needs
// to see would be in among them.
//
// It says something when it handed or failed something, and the fault
// keeper holds even that to once a minute per neighbour, as every repeated
// remark in this relay is held.
func TestAWorkerWithNothingToDoSaysNothing(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	w := worker(t, h)
	w.dial = func(*store.Relay) (*client.Client, error) {
		t.Error("a worker with an empty queue dialled its neighbour")
		return nil, errors.New("connection refused")
	}
	r, ok := w.courier.Neighbour("bar")
	if !ok {
		t.Fatal("no neighbour bar")
	}
	for range 5 {
		w.drain(r)
	}
	if got := h.logs.String(); strings.Contains(got, "courier:") {
		t.Errorf("a worker with nothing to do said something:\n%s", got)
	}

	// And with something done, it says so — once, though it is two turns.
	user := h.user(t, "alice")
	h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")
	h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct2"), "bar")
	w.dial = func(*store.Relay) (*client.Client, error) { return nil, nil }
	var id int64
	w.post = func(context.Context, *client.Client, *relayapi.ForwardRequest) (int64, error) {
		id++
		return id, nil
	}
	w.drain(r)
	w.drain(r)
	if n := strings.Count(h.logs.String(), "courier: forwarded to a neighbour"); n != 1 {
		t.Errorf("%d lines about forwarding, want one for two turns:\n%s", n, h.logs.String())
	}
}

// TestNoLineCarriesANeighboursWholeAnswer: every branch that writes a
// neighbour's words — into a row or into the log — puts them through the
// cut, and the one that logged the error object instead did not.
//
// An *HTTPError prints its whole message, and a message is the neighbour's
// free text held only by what a client will read from a relay. Once a
// minute of that, per neighbour, is a neighbour deciding how large this
// relay's log grows; a fault keeper that holds a line to once a minute
// bounds how often, not how much.
func TestNoLineCarriesANeighboursWholeAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"a fault at the neighbour", http.StatusInsufficientStorage},
		{"something this relay does not know", http.StatusInternalServerError},
		{"a refusal of the request", http.StatusBadRequest},
		{"the courier no longer accepted", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := peered(t, []string{"bar"}, nil, nil)
			user := h.user(t, "alice")
			id := h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")
			huge := strings.Repeat("l", 4<<20)
			w := fakeNeighbour(t, h, func() (int64, error) {
				return 0, &client.HTTPError{Status: tc.status, Message: huge}
			})
			r, _ := w.courier.Neighbour("bar")
			w.attempt(r, nil, h.outbound(t, id))

			if got := len(h.logs.String()); got > 4096 {
				t.Errorf("%d bytes of log for one refusal; a neighbour's answer reached it whole", got)
			}
		})
	}
}

// TestANeighboursSentenceCostsWhatItIsKept: the cut runs before the escaping
// and not only after it.
//
// Escaping only grows a string: an unprintable byte becomes four characters.
// Escaping a whole answer and then keeping half a kilobyte of it would leave
// a neighbour choosing an allocation four times the size of the largest
// answer this relay will read from one — for every attempt, at a process
// nobody is watching. The bound is generous against the fault, which is
// sixteen megabytes of work to keep five hundred bytes.
func TestANeighboursSentenceCostsWhatItIsKept(t *testing.T) {
	huge := strings.Repeat("\xff", 4<<20)
	least := ^uint64(0)
	for range 3 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		got := said("bar", huge)
		runtime.ReadMemStats(&after)
		if len(got) > relayapi.MaxSaid+4 {
			t.Fatalf("%d bytes kept, want at most %d", len(got), relayapi.MaxSaid)
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew < least {
			least = grew
		}
	}
	if least > 1<<20 {
		t.Errorf("%d bytes allocated to keep at most %d: the sentence is escaped before it is cut, "+
			"so how much work a refusal costs is the neighbour's choice", least, relayapi.MaxSaid)
	}
}

// TestASentenceOverTheCapKeepsItsEndAndSaysSo: a sentence shortened at all
// says so, and what it keeps is its end.
func TestASentenceOverTheCapKeepsItsEndAndSaysSo(t *testing.T) {
	long := strings.Repeat("l", relayapi.MaxSaid) + "the innermost sentence"
	got := said("bar", long)
	if !strings.HasPrefix(got, "…") {
		t.Errorf("no marker in front of %q", got[:40])
	}
	if !strings.HasSuffix(got, "the innermost sentence") {
		t.Errorf("said %q; want the innermost sentence intact at the end", got[len(got)-40:])
	}
	if len(got) > relayapi.MaxSaid {
		t.Errorf("%d bytes, want at most %d", len(got), relayapi.MaxSaid)
	}
	// And a sentence that fits says nothing of the kind.
	if got := said("bar", "no such mailbox"); got != "bar: no such mailbox" {
		t.Errorf("said %q, want the sentence whole", got)
	}
}

// TestAHandedRowsFileGoesAtOnceAndThePurgeAsksAgain: the bytes of an
// envelope are what a relay holds that it should stop holding the moment it
// no longer needs them, so the handing takes the file and does not wait for
// the purge; and the purge asks for it again, because an unlink that failed
// is a disk fault and this directory has no sweep to find what it left.
func TestAHandedRowsFileGoesAtOnceAndThePurgeAsksAgain(t *testing.T) {
	limits := DefaultCourierLimits()
	h := peered(t, []string{"bar"}, nil, &limits)
	user := h.user(t, "alice")
	id := h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")

	path := h.store.outboundPath(id)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a waiting row has no file: %v", err)
	}
	if err := h.store.Handed(id, 5, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the envelope is still on disk after the neighbour took it: %v", err)
	}

	// A file back where the unlink failed to take one. The purge asks
	// again, so a disk that was mended between the two is not an orphan
	// nothing looks for.
	if err := os.WriteFile(path, []byte("the unlink that failed"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := h.clock.Now().Add(limits.CarriedWindow(0) + time.Hour)
	if n, err := h.store.PurgeOutbound(past, finalRowRetention, limits.CarriedWindow); err != nil || n != 1 {
		t.Fatalf("purged %d rows: %v", n, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the purge took the row and left the file: %v", err)
	}
}

// TestAWorkerDoesNotShareItsNeighbourWithTheRequestPath: the struct a worker
// dials with is its own, because the dialling writes into it.
//
// The trust anchor's ratchet records the intermediate it last saw by setting
// two fields on the caller's own store.Relay, from inside the TLS handshake;
// the forward route reads the same struct for every request that names that
// neighbour. Courier.Neighbour hands out copies for exactly this reason and
// says so, and the workers are the caller that could have walked past it.
// Nothing here can see the race — the harness pins no anchor, so the write
// never fires — so the test is of the thing that makes the race impossible:
// that the pointer a worker holds is not the pointer the map holds.
func TestAWorkerDoesNotShareItsNeighbourWithTheRequestPath(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	w := newWorkers(h.store, h.server.courier, h.server.cfg.CourierLimits, h.server.log, h.clock.Now)
	if w == nil {
		t.Fatal("this relay dials nobody")
	}
	shared := sortedNeighbours(w.courier.neighbours)
	if len(shared) != 1 {
		t.Fatalf("%d neighbours, want 1", len(shared))
	}
	var held *store.Relay
	w.sleep = func(context.Context, time.Duration, <-chan struct{}) { w.stop() }
	w.dial = func(r *store.Relay) (*client.Client, error) {
		held = r
		return nil, errors.New("connection refused")
	}
	// A row, so the worker has something to dial about, and one turn.
	user := h.user(t, "alice")
	h.queue(user, sealedFor(h.fpOf(t, "bob"), "ct"), "bar")
	w.start()
	w.done.Wait()

	if held == nil {
		t.Fatal("the worker never dialled")
	}
	if held == shared[0] {
		t.Error("the worker dials with the courier's own struct; the ratchet's write inside the " +
			"handshake races every forward request that names this neighbour")
	}
	if held.Name != shared[0].Name || held.URL != shared[0].URL {
		t.Errorf("the worker's copy is %+v, want the same neighbour as %+v", held, shared[0])
	}
	// And the copy the request path takes is a third struct, not the
	// worker's and not the map's.
	cp, ok := w.courier.Neighbour("bar")
	if !ok {
		t.Fatal("no neighbour bar")
	}
	if cp == shared[0] || cp == held {
		t.Error("the request path and the worker share a struct")
	}
}

// TestThePurgeReadsOnlyRowsThatCouldBeDue: the purge runs inside somebody
// else's request, on the one connection the store has, over a table whose
// size is a neighbour's traffic — so it must not read the table to decide
// that none of it is due.
//
// The claim is about the query and is made where the query is: the plan
// SQLite chooses for it, against the schema this relay creates. A plan that
// says SCAN is the fault, whatever the row count on the day somebody runs
// the test.
func TestThePurgeReadsOnlyRowsThatCouldBeDue(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	rows, err := h.store.db.Query(`EXPLAIN QUERY PLAN SELECT id, state, path, last_try FROM outbound
		WHERE state IN (?, ?) AND last_try <= ?`, OutFinal, OutHanded, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "outbound_purge") {
		t.Errorf("the purge does not use its index:\n%s", plan.String())
	}
	if strings.Contains(plan.String(), "SCAN outbound") {
		t.Errorf("the purge scans the table, inside a sender's request and on the store's one "+
			"connection:\n%s", plan.String())
	}
}

// TestThePurgeWritesOnce: the rows go together or not at all, rather than a
// transaction and an fsync for each.
func TestThePurgeWritesOnce(t *testing.T) {
	limits := DefaultCourierLimits()
	h := peered(t, []string{"bar"}, nil, &limits)
	user := h.user(t, "alice")
	for i := range 5 {
		id := h.queue(user, sealedFor(h.fpOf(t, "bob"), fmt.Sprintf("ct%d", i)), "bar")
		if err := h.store.Failed(id, relayapi.CodeRefused, "bar: no", h.clock.Now()); err != nil {
			t.Fatal(err)
		}
	}
	// A trigger that refuses the third delete: with one transaction none of
	// the five goes, and with five transactions two already have.
	if _, err := h.store.db.Exec(`CREATE TRIGGER no_third BEFORE DELETE ON outbound
		WHEN (SELECT COUNT(*) FROM outbound) = 3
		BEGIN SELECT RAISE(ABORT, 'no'); END`); err != nil {
		t.Fatal(err)
	}
	if n, err := h.store.PurgeOutbound(h.clock.Now().Add(25*time.Hour), finalRowRetention,
		limits.CarriedWindow); err == nil {
		t.Fatalf("the purge reported %d rows and no error, with a delete refused", n)
	}
	if rows := h.outboundRows(t); rows != 5 {
		t.Errorf("%d rows left of 5: a purge that could not finish took some of them", rows)
	}
}

// TestAStopDoesNotWaitOutAGiveUp: a relay that is stopping stops.
//
// Giving up is one transaction and one file per row, and a worker only
// reaches it when its neighbour's backoff lifts, so one pass can carry an
// hour of arrivals. The stop runs in front of the listener's own grace
// period, so a wait here is not covered by it: a relay that takes longer
// than the unit's TimeoutStopSec is killed rather than stopped, with
// whatever it was in the middle of. A row left behind is a row still
// waiting, which is what it already was.
func TestAStopDoesNotWaitOutAGiveUp(t *testing.T) {
	limits := DefaultCourierLimits()
	limits.ForwardTTL = time.Hour
	h := peered(t, []string{"bar"}, nil, &limits)
	user := h.user(t, "alice")
	for i := range 20 {
		h.queue(user, sealedFor(h.fpOf(t, "bob"), fmt.Sprintf("ct%d", i)), "bar")
	}
	h.clock.advance(2 * time.Hour)

	w := worker(t, h)
	w.stop()
	n, err := h.store.GiveUp(w.ctx, "bar", h.clock.Now(), limits.ForwardTTL, w.fail)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("a stopping relay ended %d rows; it should have left them waiting", n)
	}
	if rows := h.outboundRows(t); rows != 20 {
		t.Errorf("%d rows left, want all 20 still there", rows)
	}
	// And with the relay running, the same call ends every one of them.
	live := worker(t, h)
	if n, err := h.store.GiveUp(live.ctx, "bar", h.clock.Now(), limits.ForwardTTL, live.fail); err != nil || n != 20 {
		t.Fatalf("a running relay gave up on %d rows: %v", n, err)
	}
}

// TestATurnDialsItsNeighbourOnce: the backlog of an outage goes over one
// connection, not one for each row.
//
// A dial is a post-quantum handshake carrying this courier's ML-DSA client
// certificate, plus a read of the certificate store, plus a renewal check.
// How many rows are waiting when a neighbour comes back is the neighbour's
// to decide — the queue's relay-wide bound is a hundred thousand — so a dial
// per row makes the cost of somebody else's outage this relay's CPU.
func TestATurnDialsItsNeighbourOnce(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	for i := range 6 {
		h.queue(user, sealedFor(h.fpOf(t, "bob"), fmt.Sprintf("ct%d", i)), "bar")
	}
	var dials, posts int
	w := worker(t, h)
	w.dial = func(*store.Relay) (*client.Client, error) { dials++; return nil, nil }
	w.post = func(context.Context, *client.Client, *relayapi.ForwardRequest) (int64, error) {
		posts++
		return int64(posts), nil
	}
	r, ok := w.courier.Neighbour("bar")
	if !ok {
		t.Fatal("no neighbour bar")
	}
	w.drain(r)
	if posts != 6 {
		t.Fatalf("%d rows handed over, want 6", posts)
	}
	if dials != 1 {
		t.Errorf("%d dials for one turn of six rows, want 1", dials)
	}
	// And a turn with nothing waiting dials nothing at all: most turns are
	// a timer going off at a relay whose queue is empty.
	dials = 0
	w.drain(r)
	if dials != 0 {
		t.Errorf("%d dials for a turn with an empty queue, want none", dials)
	}
}
