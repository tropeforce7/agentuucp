package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// A hand-over between relays carries sections as every other request body
// does, and a relay reads it the one way, through decodeRequest: a critical
// section it does not know is refused by name before anything is written.
// These two tests are ruling 66: the refusal itself, at a real relay, and the
// news of it travelling back to the person who sent the message, in the words
// of the relay that refused.

// fwdSectionsMustKnow is the sentence a relay of this build gives for a body
// with a critical section named must-know, which no build knows.
func fwdSectionsMustKnow() string {
	return fmt.Sprintf(relayapi.MsgNeedsNewer, relayapi.WireLevel, "must-know")
}

// TestANeighbourRefusesAHandOverWithASectionItMustNotReadWithout: the refusal
// itself, at a real relay, from the courier it accepts.
//
// The request is signed by B's courier and posted straight at C, which admits
// that courier, so the only thing wrong with it is the section. C answers 400
// with its sentence and the needs-newer code, and writes nothing: no message
// in bob's mailbox, no row in its queue, and no carried hash, which would
// otherwise answer the same envelope's retry, from a newer B, with a 409
// naming a delivery that never happened.
//
// The same request with the section marked not critical is then taken, so
// the refusal is the section's doing and not the envelope's or the courier's.
func TestANeighbourRefusesAHandOverWithASectionItMustNotReadWithout(t *testing.T) {
	c := newChain(t)
	bob := c.c.user(t, "bob")
	to := bob.Fingerprint()

	req := request(sealedFor(to, "for bob"), nil, []string{"alpha"})
	req.Sections = relayapi.Sections{Sections: []wire.Section{
		{Name: "must-know", Critical: true, Data: json.RawMessage("1")},
	}}
	status, body := c.c.do(c.bCourier, "POST", "/v1/forward", req, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("a hand-over with a critical section C does not know: %d %s, want 400", status, body)
	}
	var refusal relayapi.ErrorResponse
	if err := json.Unmarshal(body, &refusal); err != nil {
		t.Fatalf("the refusal is not an error body: %v: %s", err, body)
	}
	if refusal.Error != fwdSectionsMustKnow() {
		t.Errorf("the refusal says %q, want %q", refusal.Error, fwdSectionsMustKnow())
	}
	if refusal.Code != relayapi.CodeNeedsNewer {
		t.Errorf("the refusal's code is %q, want %q", refusal.Code, relayapi.CodeNeedsNewer)
	}
	// Nothing written: the refusal comes before delivery, the queue or the
	// carried table is reached at all.
	if msgs := c.c.stored(t, to); len(msgs) != 0 {
		t.Errorf("%d messages in bob's mailbox after a refused hand-over", len(msgs))
	}
	if n := c.c.outboundRows(t); n != 0 {
		t.Errorf("%d rows queued after a refused hand-over", n)
	}
	if n := c.c.carriedRows(t); n != 0 {
		t.Errorf("%d carried hashes after a refused hand-over; a retry would be answered 409", n)
	}

	// The same envelope, the same courier, the section not critical: taken
	// and delivered, which it could not be had the refusal written a hash.
	req.Sections.Sections[0].Critical = false
	status, answer, body := c.c.forward(c.bCourier, req)
	if status != http.StatusCreated {
		t.Fatalf("the same hand-over with the section not critical: %d %s, want 201", status, body)
	}
	if msgs := c.c.stored(t, to); len(msgs) != 1 || msgs[0].ID != answer.ID {
		t.Errorf("bob's mailbox after the hand-over is taken: %+v, want the one message %d", msgs, answer.ID)
	}
	if n := c.c.carriedRows(t); n != 1 {
		t.Errorf("%d carried hashes after a delivery, want 1", n)
	}
}

// fwdSectionsPair is two real relays, A dialling B as "bar" and B dialling
// A back as "alpha", with B's other neighbour, "baz", at whatever URL the
// test gives it. It is newChain with the third relay left out, for a test
// whose third relay has to answer in a way no relay of this build does.
type fwdSectionsPair struct {
	a, b               *harness
	aCourier, bCourier *identity.Identity
}

func fwdSectionsNewPair(t *testing.T, bazURL string) *fwdSectionsPair {
	t.Helper()
	aCourier := neighbourID(t, "alpha")
	bCourier := neighbourID(t, "bar")

	// B accepts from A and dials baz; A is added once it is listening.
	bc, err := NewCourier(CourierConfig{
		Home:           courierHomeAs(t, bCourier, map[string]string{"baz": bazURL}),
		AuthorizedFile: couriersFile(t, aCourier), PublicURL: "https://b.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	b := newHarness(t, Config{Courier: bc, CourierLimits: DefaultCourierLimits(), Limits: DefaultLimits()})
	quiet(t, b)
	b.enroll(aCourier)

	// A accepts from B and dials B as bar.
	ac, err := NewCourier(CourierConfig{
		Home:           courierHomeAs(t, aCourier, map[string]string{"bar": b.srv.URL}),
		AuthorizedFile: couriersFile(t, bCourier), PublicURL: "https://a.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	a := newHarness(t, Config{Courier: ac, CourierLimits: DefaultCourierLimits(), Limits: DefaultLimits()})
	quiet(t, a)
	a.enroll(bCourier)

	// The knot newChain explains: B learns to dial A once A exists.
	addNeighbour(t, bc, "alpha", a.srv.URL)
	return &fwdSectionsPair{a: a, b: b, aCourier: aCourier, bCourier: bCourier}
}

// TestARefusedHandOverIsReportedBackInTheRefusingRelaysWords: the report
// back, over a chain whose last relay is newer than the one before it.
//
// C is a handler and not a relay, because the answer it gives — a critical
// section this build does not know — is one no relay of this build can be
// made to give for a hand-over this build sends: B sends no sections, so a
// real C would take it. What the test asks of A and B is what they do with a
// newer relay's refusal, and the handler gives exactly that refusal, in the
// body a relay of this build would write for it.
//
// B asks C once. A 400 is final, since a request a neighbour must not read
// is one no retry changes until somebody updates a relay, and asking again
// every hour for three days would be three days of the same answer; so B's
// row ends refused, and asking again after the longest backoff finds nothing
// to ask about. B reports to A, and alice reads, in her own queue, C's
// sentence behind each hop's name for the next.
func TestARefusedHandOverIsReportedBackInTheRefusingRelaysWords(t *testing.T) {
	var asked atomic.Int64
	stand := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/forward" {
			t.Errorf("C was asked %s %s, which this test does not expect of B", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		asked.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(relayapi.ErrorResponse{
			Error: fwdSectionsMustKnow(), Code: relayapi.CodeNeedsNewer,
		})
	}))
	t.Cleanup(stand.Close)

	p := fwdSectionsNewPair(t, stand.URL)
	ch := &chain{a: p.a, b: p.b, aCourier: p.aCourier, bCourier: p.bCourier}
	alice := p.a.user(t, "alice")
	bob := p.a.fpOf(t, "bob")

	status, answer, body := p.a.forward(alice,
		request(sealedFor(bob, "for a newer relay"), []string{"bar", "baz"}, nil))
	if status != http.StatusCreated {
		t.Fatalf("alice posting: %d %s", status, body)
	}
	ch.handOn(t, p.a, "bar")
	bRow := p.b.onlyOutbound(t, OutWaiting)
	if bRow.Neighbour != "baz" {
		t.Fatalf("B queued it for %q, want baz", bRow.Neighbour)
	}

	// B hands it to C, and C refuses it.
	ch.handOn(t, p.b, "baz")
	if n := asked.Load(); n != 1 {
		t.Fatalf("C was asked %d times on B's first turn, want 1", n)
	}
	bFinal := p.b.outbound(t, bRow.ID)
	if bFinal.State != OutFinal {
		t.Errorf("B's row is %q after C's refusal, want final", bFinal.State)
	}
	if bFinal.Code != relayapi.CodeRefused {
		t.Errorf("B's row's code is %q, want %q", bFinal.Code, relayapi.CodeRefused)
	}
	if want := "baz: " + fwdSectionsMustKnow(); bFinal.Said != want {
		t.Errorf("B's row says %q, want %q", bFinal.Said, want)
	}

	// Past the longest backoff there is, B's worker has nothing for C: the
	// one answer was the last, which is what makes it a refusal and not an
	// outage.
	p.b.clock.advance(2 * maxRetry)
	ch.handOn(t, p.b, "baz")
	ch.handOn(t, p.b, "baz")
	if n := asked.Load(); n != 1 {
		t.Errorf("C was asked %d times, want 1: a needs-newer refusal is retried", n)
	}

	// B owes A a report, and gives it.
	if rows := p.b.reportRows(t); len(rows) != 1 || rows[0].Neighbour != "alpha" {
		t.Fatalf("B's report rows: %+v, want one for alpha", rows)
	}
	ch.handOn(t, p.b, "alpha")

	// A's row ends refused, with C's sentence innermost behind A's name for
	// B and B's name for C. The sentence is printable ASCII, which every
	// escaping step on the way leaves as it is, so the escaped form a relay
	// keeps is the sentence itself; the composition is checked against
	// said's own so that a change to the escaping is a change here too.
	want := "bar: baz: " + fwdSectionsMustKnow()
	if escaped := said("bar", said("baz", identity.PrintableText(fwdSectionsMustKnow()))); escaped != want {
		t.Fatalf("the relay escapes the sentence to %q; this test expects %q", escaped, want)
	}
	aFinal := p.a.outbound(t, answer.ID)
	if aFinal.State != OutFinal || aFinal.Code != relayapi.CodeRefused {
		t.Errorf("A's row is %q with code %q, want final and %q", aFinal.State, aFinal.Code, relayapi.CodeRefused)
	}
	queued := p.a.queueOf(t, alice)
	if len(queued) != 1 {
		t.Fatalf("alice's queue: %+v, want her one message", queued)
	}
	if queued[0].State != OutFinal || queued[0].Said != want {
		t.Errorf("alice reads %q (%s), want %q", queued[0].Said, queued[0].State, want)
	}
}
