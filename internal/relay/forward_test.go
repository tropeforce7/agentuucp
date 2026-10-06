package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// peered is a relay that dials the named neighbours and accepts forwarded
// mail from the given identities, with the bounds a relay starts from unless
// the test says otherwise.
func peered(t *testing.T, neighbours []string, accept []*identity.Identity, limits *CourierLimits) *harness {
	t.Helper()
	urls := map[string]string{}
	for i, n := range neighbours {
		// A port nothing listens on, so a worker that gets a turn before a
		// test quiets it is refused at once rather than asking the world's
		// resolvers about a name in the example domain. One port each,
		// since a home refuses to know two relays at one URL.
		urls[n] = fmt.Sprintf("http://127.0.0.1:%d", i+1)
	}
	root := courierHome(t, urls)
	// Always a file, even with nobody in it: a relay that accepts from
	// nobody yet is a relay with an empty couriers file, and a test that
	// wants to add a neighbour later needs the file the set is watching to
	// exist from the start.
	file := couriersFile(t, accept...)
	c, err := NewCourier(CourierConfig{
		Home: root, AuthorizedFile: file, PublicURL: "https://mine.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	cl := DefaultCourierLimits()
	if limits != nil {
		cl = *limits
	}
	h := newHarness(t, Config{Courier: c, CourierLimits: cl, Limits: DefaultLimits()})
	quiet(t, h)
	return h
}

// quiet stops the workers a relay with neighbours starts for itself.
//
// Every test here is about what the relay accepts, stores or decides, and
// drives a worker — where it wants one at all — from its own goroutine
// through drain or attempt, which is deterministic and needs no clock. Left
// running, the workers would be dialling names like bar.example throughout,
// which is slow, noisy in the log a test then reads, and a race against any
// test that hands the set its own dialling.
func quiet(t *testing.T, h *harness) {
	t.Helper()
	h.server.workers.Stop()
	h.server.workers = nil
}

// sealedFor is an envelope addressed to a fingerprint, with ciphertext that
// is not a real seal: this relay never opens one, and what these tests are
// about is what it does with the bytes.
// carried is an envelope as the relay reads it, for a test that built the
// recipient's view and wants the relay's hash of it.
func carried(env *envelope.Envelope) *relayapi.Carried {
	return &relayapi.Carried{V: env.V, To: env.To, CT: env.CT, Ch: env.Ch}
}

func sealedFor(to string, ct string) *envelope.Envelope {
	return &envelope.Envelope{V: envelope.Version, To: to, CT: []byte(ct)}
}

// forward posts a forward request as the given identity and answers the
// status, the parsed answer and the raw body.
func (h *harness) forward(id *identity.Identity, req *relayapi.ForwardRequest) (int, relayapi.ForwardResponse, []byte) {
	h.t.Helper()
	status, body := h.do(id, "POST", "/v1/forward", req, nil)
	var answer relayapi.ForwardResponse
	_ = json.Unmarshal(body, &answer)
	return status, answer, body
}

// request is a forward request with the lists as given, always both present.
func request(env *envelope.Envelope, path, via []string) *relayapi.ForwardRequest {
	raw, err := json.Marshal(env)
	if err != nil {
		panic(err)
	}
	if path == nil {
		path = []string{}
	}
	if via == nil {
		via = []string{}
	}
	return &relayapi.ForwardRequest{Envelope: raw, Path: path, Via: via}
}

// TestARelayThatForwardsNothingSaysSo: forwarding is something an operator
// asks for, and a relay that was not asked answers before it reads a list, a
// name or an envelope, which is the answer for every relay that has no
// peering.
func TestARelayThatForwardsNothingSaysSo(t *testing.T) {
	h := newHarness(t, Config{Limits: DefaultLimits()})
	user := h.user(t, "alice")
	status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))
	if status != 403 {
		t.Fatalf("status %d: %s", status, body)
	}
	if !strings.Contains(errorText(t, body), relayapi.MsgForwardsNothing) {
		t.Errorf("%s; want %q", errorText(t, body), relayapi.MsgForwardsNothing)
	}
}

// TestAUserMayNotWriteAReturnPath: via is the hops so far, each name written
// by the relay that wrote it, so a user sending one would be forging the path
// a reply comes back along.
func TestAUserMayNotWriteAReturnPath(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, []string{"alpha"}))
	if status != 400 {
		t.Fatalf("status %d: %s", status, body)
	}
	if !strings.Contains(errorText(t, body), relayapi.MsgViaIsACouriers) {
		t.Errorf("%s; want %q", errorText(t, body), relayapi.MsgViaIsACouriers)
	}
	if n := h.outboundRows(t); n != 0 {
		t.Errorf("%d rows queued for a refused request", n)
	}
}

// TestAUserWithNoPathIsSentToTheMailboxRoute: a path is for a recipient who
// is not here, and a recipient who is has a mailbox route.
func TestAUserWithNoPathIsSentToTheMailboxRoute(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), nil, nil))
	if status != 400 {
		t.Fatalf("status %d: %s", status, body)
	}
	if !strings.Contains(errorText(t, body), relayapi.MsgPathNamesARelay) {
		t.Errorf("%s; want %q", errorText(t, body), relayapi.MsgPathNamesARelay)
	}
}

// TestTheAddressRuleRunsBeforeTheEnvelopeIsParsed: a path nobody could route
// costs no parse, which is what the order is for. Each case sends an envelope
// that would itself be refused — no ciphertext — and asserts the address's
// sentence and not the envelope's, so the order is what the test measures.
func TestTheAddressRuleRunsBeforeTheEnvelopeIsParsed(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	unparseable := sealedFor(h.fpOf(t, "bob"), "")
	for _, tc := range []struct {
		name string
		path []string
		want string
	}{
		{"a name that is not a relay name", []string{"con"}, "device name on Windows"},
		// A name over its bytes and an empty one are refused by the same
		// rule and get its one sentence, which names the characters a name
		// may hold and not the length or the emptiness. That is what the
		// rule says today and it is pinned here as it is; the sentence is
		// worth improving, and improving it is not this commit's.
		{"a name over its bytes", []string{strings.Repeat("n", 65)}, "letters, digits"},
		{"an empty name", []string{""}, "letters, digits"},
		{"one relay named twice", []string{"bar", "bar"}, relayapi.MsgAddressRepeats},
		{"named twice, folded", []string{"bar", "Bar"}, relayapi.MsgAddressRepeats},
		{"more relays than max_hops", namesOf(DefaultCourierLimits().MaxHops + 1), "at most"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _, body := h.forward(user, request(unparseable, tc.path, nil))
			if status != 400 {
				t.Fatalf("status %d: %s", status, body)
			}
			got := errorText(t, body)
			if !strings.Contains(got, tc.want) {
				t.Errorf("%s; want %q", got, tc.want)
			}
			if strings.Contains(got, "ciphertext") {
				t.Errorf("%s; the envelope was parsed before the address was judged", got)
			}
		})
	}
}

// namesOf is n distinct relay names.
func namesOf(n int64) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("n%d", i))
	}
	return out
}

// TestMaxHopsIsCountedOverBothLists: the cap is about how far one address
// reaches, so the path and the hops so far are counted together, and the
// relay's own name for the courier is on the list before the counting.
func TestMaxHopsIsCountedOverBothLists(t *testing.T) {
	courier := neighbourID(t, "alpha")
	limits := DefaultCourierLimits()
	limits.MaxHops = 4
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	env := sealedFor(h.fpOf(t, "bob"), "ct")

	// Three names plus the appended alpha is four: at the cap.
	status, _, body := h.forward(courier, request(env, []string{"bar"}, []string{"one", "two"}))
	if status != 201 {
		t.Fatalf("at the cap: status %d: %s", status, body)
	}
	// Four plus the appended alpha is five: one over.
	status, _, body = h.forward(courier, request(sealedFor(h.fpOf(t, "bob"), "ct2"),
		[]string{"bar"}, []string{"one", "two", "three"}))
	if status != 400 {
		t.Fatalf("one over: status %d: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, "names 5 relays; at most 4") {
		t.Errorf("%s; want the count and the cap", got)
	}
}

// TestACourierCannotLeaveItsOwnHopOut: this relay appends its own name for
// the courier before the address rule runs, so a courier that sends a via
// without its own hop does not thereby buy room for another name, and cannot
// hide a loop through itself.
func TestACourierCannotLeaveItsOwnHopOut(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	// The courier claims never to have touched it, and names itself in the
	// path instead: the appended hop makes that a repeat.
	status, _, body := h.forward(courier, request(sealedFor(h.fpOf(t, "bob"), "ct"),
		[]string{"bar", "alpha"}, nil))
	if status != 400 {
		t.Fatalf("status %d: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, relayapi.MsgAddressRepeats) {
		t.Errorf("%s; want the address rule's refusal", got)
	}
}

// TestAnEnvelopeIsHeldToWhatThisRelayKnowsOfOne: parsed strictly, its version
// 1 or more, its recipient a fingerprint, and its ciphertext present —
// before anything is stored, so nothing is queued for a body that is not an
// envelope. A version this relay has never heard of is carried
// (TestTheForwardRouteCarriesAnyVersion); one below 1 is no version.
func TestAnEnvelopeIsHeldToWhatThisRelayKnowsOfOne(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	fp := h.fpOf(t, "bob")
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"the field absent", ``, "carries no envelope"},
		{"the field null", `null`, "carries no envelope"},
		{"not an envelope", `{"nope":1}`, "malformed envelope"},
		{"version 0", `{"v":0,"to":"` + fp + `","ct":"YQ=="}`, "a relay carries any version from 1"},
		{"version -1", `{"v":-1,"to":"` + fp + `","ct":"YQ=="}`, "a relay carries any version from 1"},
		{"to is not a fingerprint", `{"v":1,"to":"bob","ct":"YQ=="}`, "not a fingerprint"},
		{"no ciphertext", `{"v":1,"to":"` + fp + `","ct":""}`, "no ciphertext"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An absent field is the field left out of the object; the
			// others are the value as written.
			body := []byte(`{"path":["bar"],"via":[]}`)
			if tc.raw != "" {
				body = []byte(fmt.Sprintf(`{"envelope":%s,"path":["bar"],"via":[]}`, tc.raw))
			}
			status, body := h.postSigned(t, user, "/v1/forward", body)
			if status != 400 {
				t.Fatalf("status %d: %s", status, body)
			}
			if got := errorText(t, body); !strings.Contains(got, tc.want) {
				t.Errorf("%s; want %q", got, tc.want)
			}
			if n := h.outboundRows(t); n != 0 {
				t.Errorf("%d rows queued for a body that is not an envelope", n)
			}
		})
	}
}

// TestAnUnknownNeighbourIsRefusedBeforeAnythingIsStored: the first name of
// the path is the only one this relay reads for routing, and a name it has no
// entry for is the whole of the discovery there is.
func TestAnUnknownNeighbourIsRefusedBeforeAnythingIsStored(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"baz"}, nil))
	if status != 404 {
		t.Fatalf("status %d: %s", status, body)
	}
	got := errorText(t, body)
	if !strings.Contains(got, relayapi.MsgNoNeighbour) || !strings.Contains(got, `"baz"`) {
		t.Errorf("%s; want the refusal naming baz", got)
	}
	if n := h.outboundRows(t); n != 0 {
		t.Errorf("%d rows queued for an unknown neighbour", n)
	}
	// And nothing was remembered as carried either, so the sender may try
	// again with an address that works.
	if n := h.carriedRows(t); n != 0 {
		t.Errorf("%d hashes remembered for an envelope that was refused", n)
	}
}

// TestAForwardIsQueuedWithItsRowAndItsFile: what a taken envelope leaves
// behind — one row naming the poster, the neighbour and what is left of the
// address, one file holding the bytes as they arrived, and the queue's
// counters moved by exactly one message and its size.
func TestAForwardIsQueuedWithItsRowAndItsFile(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	to := h.fpOf(t, "bob")
	env := sealedFor(to, "ciphertext")
	req := request(env, []string{"bar", "baz"}, nil)

	status, answer, body := h.forward(user, req)
	if status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	if answer.ID == 0 {
		t.Fatal("the answer carries no id")
	}
	row := h.outbound(t, answer.ID)
	switch {
	case row.PosterFP != user.Public().Fingerprint():
		t.Errorf("poster %s, want the caller", row.PosterFP)
	case row.Neighbour != "bar":
		t.Errorf("neighbour %q, want bar", row.Neighbour)
	case row.Path != "baz":
		t.Errorf("path %q, want what is left: baz", row.Path)
	case row.Via != "":
		t.Errorf("via %q, want empty for mail a user posted", row.Via)
	case row.ToFP != to:
		t.Errorf("to %s, want the recipient while it waits", row.ToFP)
	case row.State != OutWaiting:
		t.Errorf("state %q, want %q", row.State, OutWaiting)
	}
	// The bytes are the envelope's own, verbatim: what every hop stores and
	// forwards is what the sender sealed.
	stored, err := h.store.OutboundBody(answer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(req.Envelope) {
		t.Errorf("stored %s, want the envelope as it arrived %s", stored, req.Envelope)
	}
	msgs, bytes := h.queueCounters(t)
	if msgs != 1 || bytes != int64(len(req.Envelope)) {
		t.Errorf("counters %d/%d, want 1/%d", msgs, bytes, len(req.Envelope))
	}
}

// TestACourierHopIsAppendedToTheReturnPath: the name this relay knows the
// courier by goes onto via, which is what makes the reversed list a path
// every hop can read.
func TestACourierHopIsAppendedToTheReturnPath(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	status, answer, body := h.forward(courier,
		request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, []string{"first"}))
	if status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	if row := h.outbound(t, answer.ID); row.Via != "first!alpha" {
		t.Errorf("via %q, want first!alpha", row.Via)
	}
}

// TestAnEnvelopeIsCarriedOnce: the second time an envelope arrives it is
// refused, nothing is stored and no counter moves. The poster of the row that
// holds it learns its id, since that is what an undeliverable coming back
// will name; anybody else gets the bare refusal.
func TestAnEnvelopeIsCarriedOnce(t *testing.T) {
	first := neighbourID(t, "alpha")
	second := neighbourID(t, "beta")
	h := peered(t, []string{"bar"}, []*identity.Identity{first, second}, nil)
	h.enroll(first, second)
	env := sealedFor(h.fpOf(t, "bob"), "the same ciphertext")

	status, answer, body := h.forward(first, request(env, []string{"bar"}, nil))
	if status != 201 {
		t.Fatalf("the first: status %d: %s", status, body)
	}
	rows := h.outboundRows(t)
	wasMsgs, wasBytes := h.queueCounters(t)

	// The same courier again: a retry whose answer was lost.
	status, again, body := h.forward(first, request(env, []string{"bar"}, nil))
	if status != 409 {
		t.Fatalf("the same courier again: status %d: %s", status, body)
	}
	if again.ID != answer.ID {
		t.Errorf("the retry was told id %d, want the row it already has, %d", again.ID, answer.ID)
	}
	// A different courier: the same envelope from another direction, which
	// is a loop dying here. It learns nothing about the first's row.
	status, other, body := h.forward(second, request(env, []string{"bar"}, nil))
	if status != 409 {
		t.Fatalf("a second courier: status %d: %s", status, body)
	}
	if other.ID != 0 {
		t.Errorf("a second courier was told id %d; a row id is its poster's", other.ID)
	}
	if !strings.Contains(errorText(t, body), relayapi.MsgAlreadyCarried) {
		t.Errorf("%s; want %q", errorText(t, body), relayapi.MsgAlreadyCarried)
	}
	// Nothing was stored and nothing charged by either refusal.
	if n := h.outboundRows(t); n != rows {
		t.Errorf("%d rows after two refusals, want %d", n, rows)
	}
	if msgs, bytes := h.queueCounters(t); msgs != wasMsgs || bytes != wasBytes {
		t.Errorf("counters moved on a refusal: %d/%d, want %d/%d", msgs, bytes, wasMsgs, wasBytes)
	}
	// The relay says so in its own log, once a minute, naming the
	// neighbour and no mailbox.
	if logs := h.logs.String(); !strings.Contains(logs, "already carried") {
		t.Errorf("nothing logged about a repeat: %s", logs)
	}
}

// TestTheHashIsOverTheEnvelopeAndNotItsBytes: a hop that re-spaces the JSON
// changes the request's bytes and not the envelope, so the second arrival is
// still refused. Without this the carried table — the whole loop defence —
// is defeated by one space.
func TestTheHashIsOverTheEnvelopeAndNotItsBytes(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	to := h.fpOf(t, "bob")
	compact := `{"v":1,"to":"` + to + `","ct":"YQ=="}`
	spaced := `{ "v": 1, "to": "` + to + `" , "ct": "YQ==" }`
	reordered := `{"ct":"YQ==","to":"` + to + `","v":1}`

	status, _, body := h.forward(courier, &relayapi.ForwardRequest{
		Envelope: json.RawMessage(compact), Path: []string{"bar"}, Via: []string{},
	})
	if status != 201 {
		t.Fatalf("the first: status %d: %s", status, body)
	}
	for _, other := range []string{spaced, reordered, compact} {
		status, _, body := h.forward(courier, &relayapi.ForwardRequest{
			Envelope: json.RawMessage(other), Path: []string{"bar"}, Via: []string{},
		})
		if status != 409 {
			t.Errorf("%s: status %d: %s; the same envelope spelled differently was carried again",
				other, status, body)
		}
	}
	if n := h.outboundRows(t); n != 1 {
		t.Errorf("%d rows, want 1: the same envelope was queued more than once", n)
	}
}

// TestTheChannelIsNotInTheHash: the channel is outside the seal, so a hop can
// change it as freely as whitespace; the same ciphertext is the same message
// however it is filed, and a relay that hashed the channel too would carry
// one envelope once per channel name a liar chose.
func TestTheChannelIsNotInTheHash(t *testing.T) {
	to := strings.Repeat("a", 64)
	first := &relayapi.Carried{V: 1, To: to, CT: []byte("ct"), Ch: "one"}
	second := &relayapi.Carried{V: 1, To: to, CT: []byte("ct"), Ch: "two"}
	if CarriedHash(first) != CarriedHash(second) {
		t.Error("two channels made two hashes of one envelope")
	}
	// And the things that are in it are in it.
	if CarriedHash(first) == CarriedHash(&relayapi.Carried{V: 1, To: to, CT: []byte("other")}) {
		t.Error("two ciphertexts made one hash")
	}
	if CarriedHash(first) == CarriedHash(&relayapi.Carried{V: 1, To: strings.Repeat("b", 64), CT: []byte("ct")}) {
		t.Error("two recipients made one hash")
	}
}

// TestTheCarriedCeilingRefusesRatherThanForgetting: the table is what makes a
// retry idempotent and a loop die, so a hash is never evicted to make room.
// At the ceiling the relay stops taking new mail and says which setting it
// is; a retry of something it already holds is still answered as before,
// since that costs no row.
func TestTheCarriedCeilingRefusesRatherThanForgetting(t *testing.T) {
	limits := DefaultCourierLimits()
	limits.CarriedMaxRows = 2
	h := peered(t, []string{"bar"}, nil, &limits)
	user := h.user(t, "alice")
	to := h.fpOf(t, "bob")

	for i := range 2 {
		status, _, body := h.forward(user, request(sealedFor(to, fmt.Sprintf("ct%d", i)), []string{"bar"}, nil))
		if status != 201 {
			t.Fatalf("%d: status %d: %s", i, status, body)
		}
	}
	status, _, body := h.forward(user, request(sealedFor(to, "one too many"), []string{"bar"}, nil))
	if status != 507 {
		t.Fatalf("at the ceiling: status %d: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, "carried_max_rows") {
		t.Errorf("%s; want the setting named", got)
	}
	// The hashes it holds are still held: the ceiling refuses new mail and
	// forgets nothing.
	if n := h.carriedRows(t); n != 2 {
		t.Errorf("%d hashes, want the 2 it had: a hash was evicted", n)
	}
	// And a repeat is answered as it was before, since it stores nothing.
	status, _, _ = h.forward(user, request(sealedFor(to, "ct0"), []string{"bar"}, nil))
	if status != 409 {
		t.Errorf("a repeat at the ceiling: status %d, want 409", status)
	}
}

// TestTheQueueIsBoundedForEveryoneAndForEachPoster: the relay-wide bound and
// the poster's own, each at the edge and one over, and the poster's proved
// through a second poster who is unaffected by the first's share.
func TestTheQueueIsBoundedForEveryoneAndForEachPoster(t *testing.T) {
	t.Run("one poster's messages", func(t *testing.T) {
		limits := DefaultCourierLimits()
		limits.QueueMaxMessagesPerPoster = 2
		h := peered(t, []string{"bar"}, nil, &limits)
		alice, bob := h.user(t, "alice"), h.user(t, "bob")
		to := h.fpOf(t, "carol")
		for i := range 2 {
			if status, _, body := h.forward(alice, request(sealedFor(to, fmt.Sprintf("a%d", i)), []string{"bar"}, nil)); status != 201 {
				t.Fatalf("%d: status %d: %s", i, status, body)
			}
		}
		status, _, body := h.forward(alice, request(sealedFor(to, "a2"), []string{"bar"}, nil))
		if status != 507 {
			t.Fatalf("one over: status %d: %s", status, body)
		}
		if got := errorText(t, body); !strings.Contains(got, relayapi.MsgQueueFull) {
			t.Errorf("%s; want %q", got, relayapi.MsgQueueFull)
		}
		// The other poster has their own share, which is the point of a
		// per-poster bound: one sender cannot fill the queue for everybody.
		if status, _, body := h.forward(bob, request(sealedFor(to, "b0"), []string{"bar"}, nil)); status != 201 {
			t.Fatalf("a second poster: status %d: %s", status, body)
		}
	})
	t.Run("the relay's bytes", func(t *testing.T) {
		limits := DefaultCourierLimits()
		h := peered(t, []string{"bar"}, nil, &limits)
		user := h.user(t, "alice")
		to := h.fpOf(t, "bob")
		// One envelope through, then the bound set to exactly what is
		// queued: the next is one byte too many.
		req := request(sealedFor(to, "ct"), []string{"bar"}, nil)
		if status, _, body := h.forward(user, req); status != 201 {
			t.Fatalf("status %d: %s", status, body)
		}
		_, queued := h.queueCounters(t)
		limits.QueueMaxBytes = queued
		h2 := serveStore(t, h.store, Config{
			Courier: h.server.courier, CourierLimits: limits, Limits: DefaultLimits(),
		})
		quiet(t, h2)
		status, _, body := h2.forward(user, request(sealedFor(to, "ct2"), []string{"bar"}, nil))
		if status != 507 {
			t.Fatalf("at the relay's bound: status %d: %s", status, body)
		}
		if got := errorText(t, body); !strings.Contains(got, relayapi.MsgQueueFull) {
			t.Errorf("%s; want %q", got, relayapi.MsgQueueFull)
		}
	})
}

// TestACouriersQueueIsTheRelaysBoundAlone: a courier carries many people's
// mail, so holding it to one poster's share would refuse a neighbour's whole
// queue for being busy. The relay-wide bounds and the couriers file are what
// answer that instead — and both of them, which the test below is about.
func TestACouriersQueueIsTheRelaysBoundAlone(t *testing.T) {
	courier := neighbourID(t, "alpha")
	limits := DefaultCourierLimits()
	limits.QueueMaxMessagesPerPoster = 1
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	to := h.fpOf(t, "bob")
	for i := range 3 {
		status, _, body := h.forward(courier, request(sealedFor(to, fmt.Sprintf("ct%d", i)), []string{"bar"}, nil))
		if status != 201 {
			t.Fatalf("%d: status %d: %s; a courier is held to the relay's bound alone", i, status, body)
		}
	}
	// A user on the same relay is still held to theirs.
	user := h.user(t, "alice")
	if status, _, body := h.forward(user, request(sealedFor(to, "u0"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("a user's first: status %d: %s", status, body)
	}
	if status, _, _ := h.forward(user, request(sealedFor(to, "u1"), []string{"bar"}, nil)); status != 507 {
		t.Errorf("a user's second: status %d, want the per-poster bound at 507", status)
	}
}

// TestACourierSpendsItsOwnBudget: a courier's posts are counted against
// courier.posts_per_minute and a user's against posts_per_minute, and the
// refusal says which, so an operator reading a 429 is not left with a user's
// name for a neighbour's rate.
func TestACourierSpendsItsOwnBudget(t *testing.T) {
	courier := neighbourID(t, "alpha")
	limits := DefaultCourierLimits()
	limits.PostsPerMinute = 1
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	to := h.fpOf(t, "bob")
	if status, _, body := h.forward(courier, request(sealedFor(to, "ct0"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	status, _, body := h.forward(courier, request(sealedFor(to, "ct1"), []string{"bar"}, nil))
	if status != 429 {
		t.Fatalf("over the courier's rate: status %d: %s", status, body)
	}
	if logs := h.logs.String(); !strings.Contains(logs, limitCourierPosts) {
		t.Errorf("the refusal does not say which limit: %s", logs)
	}
	// A user's own rate is untouched by the courier's.
	user := h.user(t, "alice")
	if status, _, body := h.forward(user, request(sealedFor(to, "u0"), []string{"bar"}, nil)); status != 201 {
		t.Errorf("a user after a courier's rate ran out: status %d: %s", status, body)
	}
}

// Delivery at the last hop. A courier with an empty path is asking this
// relay to put the envelope into a mailbox here, which is where a journey
// ends. The order is the post route's, and for the post route's reasons; the
// one thing that differs is which sender the allow list is asked about.

// stored is what a mailbox on this relay holds, oldest first.
func (h *harness) stored(t *testing.T, fp string) []Row {
	t.Helper()
	rows, err := h.store.List(fp, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestAnEnvelopeArrivesInAMailboxHere: the whole of delivery, with what it
// leaves behind.
func TestAnEnvelopeArrivesInAMailboxHere(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	bob := h.user(t, "bob")
	to := bob.Fingerprint()

	status, answer, body := h.forward(courier, request(sealedFor(to, "for bob"), nil, []string{"one", "two"}))
	if status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	if answer.ID == 0 {
		t.Error("no id: the answer names the message in the mailbox, which is what the neighbour " +
			"holding the row wants to know it may let go of")
	}

	// In the mailbox, with the hops it came by. This relay's own name for
	// the courier goes on the end, as it does on a forward, so what is
	// stored is the whole way it came and not what the sender wrote.
	msgs := h.stored(t, to)
	if len(msgs) != 1 {
		t.Fatalf("%d messages in the mailbox, want 1", len(msgs))
	}
	if msgs[0].Via != "one!two!alpha" {
		t.Errorf("via %q; want the hops so far with this relay's name for the courier on the end",
			msgs[0].Via)
	}
	if msgs[0].ID != answer.ID {
		t.Errorf("the answer names %d and the mailbox holds %d", answer.ID, msgs[0].ID)
	}
	// Nothing was queued: the journey ended here.
	if n := h.outboundRows(t); n != 0 {
		t.Errorf("%d rows queued for an envelope that was delivered", n)
	}
	// And the hash is remembered, so the same envelope arriving again is
	// refused rather than delivered twice.
	if n := h.carriedRows(t); n != 1 {
		t.Errorf("%d hashes after a delivery, want 1", n)
	}
	status, again, body := h.forward(courier, request(sealedFor(to, "for bob"), nil, []string{"one", "two"}))
	if status != 409 {
		t.Fatalf("the same envelope again: status %d: %s", status, body)
	}
	if msgs := h.stored(t, to); len(msgs) != 1 {
		t.Errorf("%d messages after the repeat, want the one", len(msgs))
	}
	// The repeat is a retry after a lost answer, and learns the id of the
	// message it became, which the neighbour reads as taken (ruling 44).
	if again.ID != answer.ID {
		t.Errorf("the repeat was told id %d, want the delivered message's, %d", again.ID, answer.ID)
	}
}

// TestADeliveryRetryIsAnsweredAfterTheMessageIsGone: the delivered id lives on
// the carried row and not in the mailbox, because bob can read and remove his
// mail while the hash is still kept. Looked up in messages instead, the retry
// of a delivery bob had already removed would come back bare, which is the
// answer a loop gets, and the sender of a delivered message would be told it
// was refused.
func TestADeliveryRetryIsAnsweredAfterTheMessageIsGone(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	bob := h.user(t, "bob")
	to := bob.Fingerprint()
	req := request(sealedFor(to, "read and removed"), nil, []string{"one"})

	status, answer, body := h.forward(courier, req)
	if status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	if removed, err := h.store.Delete(to, answer.ID); err != nil || !removed {
		t.Fatalf("removing bob's message: %v %v", removed, err)
	}
	status, again, body := h.forward(courier, req)
	if status != 409 {
		t.Fatalf("the retry: status %d: %s", status, body)
	}
	if again.ID != answer.ID {
		t.Errorf("the retry was told id %d, want %d: a delivered message is taken whatever bob did with it since",
			again.ID, answer.ID)
	}
	if again.Code != "" || again.Said != "" {
		t.Errorf("a delivery's retry carried code %q said %q; only an ended row has either", again.Code, again.Said)
	}
}

// TestAnEndedRowIsAnsweredWithHowItEnded: ruling 45 at the route. A retry
// from the poster of a row that has ended here learns the code and the
// sentence beside the id; a retry to a row still waiting learns the id alone;
// and another caller learns neither.
func TestAnEndedRowIsAnsweredWithHowItEnded(t *testing.T) {
	first := neighbourID(t, "alpha")
	second := neighbourID(t, "beta")
	h := peered(t, []string{"bar"}, []*identity.Identity{first, second}, nil)
	h.enroll(first, second)
	req := request(sealedFor(h.fpOf(t, "bob"), "ended here"), []string{"bar"}, nil)

	status, answer, body := h.forward(first, req)
	if status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	status, waiting, _ := h.forward(first, req)
	if status != 409 || waiting.ID != answer.ID || waiting.Code != "" || waiting.Said != "" {
		t.Errorf("a retry to a waiting row: %d %+v, want 409 with the id alone", status, waiting)
	}

	if err := h.store.Failed(answer.ID, relayapi.CodeGaveUp, "bar: tried for three days", time.Now()); err != nil {
		t.Fatal(err)
	}
	status, ended, body := h.forward(first, req)
	if status != 409 {
		t.Fatalf("a retry to an ended row: status %d: %s", status, body)
	}
	if ended.ID != answer.ID || ended.Code != relayapi.CodeGaveUp || ended.Said != "bar: tried for three days" {
		t.Errorf("a retry to an ended row was told %+v; want its id, its code and its sentence", ended)
	}
	status, other, _ := h.forward(second, req)
	if status != 409 || other.ID != 0 || other.Code != "" || other.Said != "" {
		t.Errorf("another courier was told %d %+v; how a row ended is its poster's", status, other)
	}
}

// TestTheAllowListIsAskedAboutTheCourier: a relay cannot read an envelope,
// so it cannot know who wrote it; the identity it can prove is the neighbour
// that handed it over, and that is the sender the recipient's list is asked
// about.
//
// So a recipient with a restricted list admits a relay rather than a person,
// and admits everybody behind that relay with it. That is the one place a
// list means something coarser than the fingerprints in it, and the security
// document says so.
func TestTheAllowListIsAskedAboutTheCourier(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	bob := h.user(t, "bob")
	to := bob.Fingerprint()
	stranger := h.user(t, "stranger")

	// A list that names somebody else: the courier is not on it, so nothing
	// it carries arrives, whoever sealed it.
	if status, body, _ := h.pushAllow(bob, bob, time.Now(), stranger.Fingerprint()); status != 204 {
		t.Fatalf("pushing a list: %d %s", status, body)
	}
	status, _, body := h.forward(courier, request(sealedFor(to, "refused"), nil, nil))
	if status != 403 {
		t.Fatalf("status %d: %s", status, body)
	}
	if got := errorText(t, body); got != msgNotAllowed {
		t.Errorf("%q; want %q", got, msgNotAllowed)
	}
	if msgs := h.stored(t, to); len(msgs) != 0 {
		t.Errorf("%d messages stored for a refused sender", len(msgs))
	}

	// The same list with the courier on it: delivered.
	if status, body, _ := h.pushAllow(bob, bob, time.Now().Add(time.Minute),
		stranger.Fingerprint(), courier.Fingerprint()); status != 204 {
		t.Fatalf("pushing the second list: %d %s", status, body)
	}
	if status, _, body := h.forward(courier, request(sealedFor(to, "admitted"), nil, nil)); status != 201 {
		t.Fatalf("with the courier admitted: status %d: %s", status, body)
	}
	if msgs := h.stored(t, to); len(msgs) != 1 {
		t.Errorf("%d messages after admitting the courier, want 1", len(msgs))
	}
}

// TestWhatDeliveryRefusesAndInWhatOrder: the post route's order, for the post
// route's reasons, so that a courier learns nothing about a mailbox here that
// a sender posting directly could not learn.
func TestWhatDeliveryRefusesAndInWhatOrder(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)

	t.Run("no mailbox here", func(t *testing.T) {
		status, _, body := h.forward(courier, request(sealedFor(h.fpOf(t, "nobody"), "x"), nil, nil))
		if status != 404 || errorText(t, body) != "no such mailbox" {
			t.Fatalf("status %d: %s", status, body)
		}
	})
	t.Run("a blocked recipient", func(t *testing.T) {
		blocked := h.user(t, "blocked")
		if err := h.store.SetBlock(blocked.Fingerprint(), "test", h.fpOf(t, "admin"), time.Now()); err != nil {
			t.Fatal(err)
		}
		status, _, body := h.forward(courier, request(sealedFor(blocked.Fingerprint(), "x"), nil, nil))
		if status != 403 || errorText(t, body) != "recipient is blocked on this relay" {
			t.Fatalf("status %d: %s", status, body)
		}
	})
	t.Run("a courier's own mailbox", func(t *testing.T) {
		// A neighbour forwarding to another neighbour's courier is a loop
		// somebody built by hand. It ends here, in the words every refused
		// sender gets, so the answer says nothing about who this relay
		// peers with.
		status, _, body := h.forward(courier, request(sealedFor(courier.Fingerprint(), "x"), nil, nil))
		if status != 403 || errorText(t, body) != msgNotAllowed {
			t.Fatalf("status %d: %s", status, body)
		}
	})
	t.Run("a channel the owner has not published", func(t *testing.T) {
		carol := h.user(t, "carol")
		env := sealedFor(carol.Fingerprint(), "x")
		env.Ch = "work"
		status, _, body := h.forward(courier, request(env, nil, nil))
		if status != 404 {
			t.Fatalf("status %d: %s", status, body)
		}
		if got := errorText(t, body); !strings.Contains(got, "no such channel") {
			t.Errorf("%q; want the channel's own refusal", got)
		}
	})
	t.Run("the default channel, which every mailbox has", func(t *testing.T) {
		dave := h.user(t, "dave")
		if status, _, body := h.forward(courier, request(sealedFor(dave.Fingerprint(), "x"), nil, nil)); status != 201 {
			t.Fatalf("status %d: %s", status, body)
		}
	})
}

// TestARowAndItsFileArriveTogether: the file is placed before the commit, so
// a committed row always has its bytes; a file that cannot be written leaves
// no row at all.
func TestARowAndItsFileArriveTogether(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	// The queue's directory made a file, so the rename into it cannot
	// succeed: the store's own path is taken by something that is not a
	// directory.
	blocked := filepath.Join(h.store.dir, outboundDir)
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))
	if status == 201 {
		t.Fatalf("a forward whose file could not be written was taken: %s", body)
	}
	if n := h.outboundRows(t); n != 0 {
		t.Errorf("%d rows for an envelope whose file could not be written", n)
	}
	if n := h.carriedRows(t); n != 0 {
		t.Errorf("%d hashes for an envelope that was not stored", n)
	}
	msgs, bytes := h.queueCounters(t)
	if msgs != 0 || bytes != 0 {
		t.Errorf("counters %d/%d, want 0/0", msgs, bytes)
	}
}

// TestTheQueuesCountersAreReconciledAtEveryOpen: a counter is wrong the same
// way whether it was a crash between two statements or somebody editing the
// database, and a queue whose bytes read high refuses mail nobody sent.
func TestTheQueuesCountersAreReconciledAtEveryOpen(t *testing.T) {
	dir := t.TempDir()
	db, messages := filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages")
	st, err := OpenStore(db, messages)
	if err != nil {
		t.Fatal(err)
	}
	h := serveStore(t, st, Config{
		Courier: mustCourier(t, []string{"bar"}, nil), CourierLimits: DefaultCourierLimits(),
		Limits: DefaultLimits(),
	})
	quiet(t, h)
	user := h.user(t, "alice")
	req := request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil)
	if status, _, body := h.forward(user, req); status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	if _, err := st.db.Exec(`UPDATE relay_stats SET outbound_messages = 99, outbound_bytes = 99999 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	st.Close()

	again, err := OpenStore(db, messages)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	var msgs, bytes int64
	if err := again.db.QueryRow(`SELECT outbound_messages, outbound_bytes FROM relay_stats WHERE id = 1`).
		Scan(&msgs, &bytes); err != nil {
		t.Fatal(err)
	}
	if msgs != 1 || bytes != int64(len(req.Envelope)) {
		t.Errorf("counters %d/%d after a reopen, want 1/%d", msgs, bytes, len(req.Envelope))
	}
}

// TestLimitAForwardsListsAreHeldToTheirBounds: the two arrays are counts from
// outside, so the bound, one over it, and a length nobody could allocate are
// each fed and each refused before anything is made from them.
func TestLimitAForwardsListsAreHeldToTheirBounds(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	env := sealedFor(h.fpOf(t, "bob"), "ct")
	cap := DefaultCourierLimits().MaxHops

	// At the cap, taken; one over, refused. The first name must be a
	// neighbour for the one at the cap to get that far.
	at := append([]string{"bar"}, namesOf(cap-1)...)
	if status, _, body := h.forward(user, request(env, at, nil)); status != 201 {
		t.Fatalf("%d names: status %d: %s", cap, status, body)
	}
	over := append([]string{"bar"}, namesOf(cap)...)
	status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct2"), over, nil))
	if status != 400 {
		t.Fatalf("%d names: status %d: %s", cap+1, status, body)
	}

	// A list far past anything the cap allows: the refusal comes from the
	// count and nothing is allocated per name beyond the decode of the
	// array itself, which the body's own cap bounds.
	before := heapInUse()
	many := make([]string, 5000)
	for i := range many {
		many[i] = fmt.Sprintf("n%d", i)
	}
	status, _, body2 := h.forward(user, request(env, many, nil))
	if status != 400 {
		t.Fatalf("5000 names: status %d: %s", status, body2)
	}
	if got := errorText(t, body2); !strings.Contains(got, "at most") {
		t.Errorf("%s; want the cap's refusal", got)
	}
	if grew := heapInUse() - before; grew > 64<<20 {
		t.Errorf("the refusal grew the heap by %d bytes", grew)
	}
}

// TestLimitForwardSettingsAreHeldToTheirRanges: every courier setting the
// relay reads, at its edges and past them, through the library's own bounds.
func TestLimitForwardSettingsAreHeldToTheirRanges(t *testing.T) {
	// max_hops is the one the route reads on every request: a setting over
	// the protocol's ceiling is held to the ceiling, and a zero or a
	// negative one to it as well, since the route cannot refuse everything
	// because a setting is nonsense — auu-relay refuses those at startup,
	// which is where an operator sees it.
	for _, hops := range []int64{0, -1, math.MinInt64, relayapi.MaxHops + 1, math.MaxInt64} {
		limits := DefaultCourierLimits()
		limits.MaxHops = hops
		h := peered(t, []string{"bar"}, nil, &limits)
		user := h.user(t, "alice")
		at := append([]string{"bar"}, namesOf(relayapi.MaxHops-1)...)
		if status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), at, nil)); status != 201 {
			t.Errorf("max_hops %d: %d names: status %d: %s", hops, relayapi.MaxHops, status, body)
		}
		over := append([]string{"bar"}, namesOf(relayapi.MaxHops)...)
		if status, _, _ := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct2"), over, nil)); status != 400 {
			t.Errorf("max_hops %d: %d names: status %d, want the ceiling to hold", hops, relayapi.MaxHops+1, status)
		}
	}
}

// TestLimitTheCarriedWindowIsTheEnvelopesRemainingLife: an envelope cannot
// outlive the hops left to carry it, so the window is those hops and this one
// rather than the whole network's worst case, which would hold a hash — and
// the poster's fingerprint on the row beside it — for weeks at the defaults.
func TestLimitTheCarriedWindowIsTheEnvelopesRemainingLife(t *testing.T) {
	c := DefaultCourierLimits()
	for _, tc := range []struct {
		left int
		want time.Duration
	}{
		{0, c.ForwardTTL},
		{1, 2 * c.ForwardTTL},
		{7, 8 * c.ForwardTTL},
		// Never past the whole network's worst case, whatever is claimed.
		{int(c.MaxHops), time.Duration(c.MaxHops) * c.ForwardTTL},
		{1000, time.Duration(c.MaxHops) * c.ForwardTTL},
		{math.MaxInt32, time.Duration(c.MaxHops) * c.ForwardTTL},
	} {
		if got := c.CarriedWindow(tc.left); got != tc.want {
			t.Errorf("%d hops left: window %s, want %s", tc.left, got, tc.want)
		}
	}
}

// mustCourier is a courier for a test that builds its own harness.
func mustCourier(t *testing.T, neighbours []string, accept []*identity.Identity) *Courier {
	t.Helper()
	urls := map[string]string{}
	for i, n := range neighbours {
		// A port nothing listens on, so a worker that gets a turn before a
		// test quiets it is refused at once rather than asking the world's
		// resolvers about a name in the example domain. One port each,
		// since a home refuses to know two relays at one URL.
		urls[n] = fmt.Sprintf("http://127.0.0.1:%d", i+1)
	}
	file := ""
	if len(accept) > 0 {
		file = couriersFile(t, accept...)
	}
	c, err := NewCourier(CourierConfig{
		Home: courierHome(t, urls), AuthorizedFile: file, PublicURL: "https://mine.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// outboundRows is how many rows the queue holds.
func (h *harness) outboundRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM outbound`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// carriedRows is how many envelope hashes the relay remembers.
func (h *harness) carriedRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM carried`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// outbound is one row of the queue, read back.
func (h *harness) outbound(t *testing.T, id int64) *Outbound {
	t.Helper()
	var o Outbound
	var received, lastTry, nextTry, givesUp int64
	err := h.store.db.QueryRow(`SELECT id, poster_fp, neighbour, path, via, to_fp, hash, size, kind,
		received, state, tries, last_try, next_try, gives_up, their_id, code, said FROM outbound WHERE id = ?`, id).
		Scan(&o.ID, &o.PosterFP, &o.Neighbour, &o.Path, &o.Via, &o.ToFP, &o.Hash, &o.Size, &o.Kind,
			&received, &o.State, &o.Tries, &lastTry, &nextTry, &givesUp, &o.TheirID, &o.Code, &o.Said)
	if err != nil {
		t.Fatal(err)
	}
	o.Received = time.Unix(received, 0).UTC()
	return &o
}

// queueCounters is the queue's two totals.
func (h *harness) queueCounters(t *testing.T) (messages, bytes int64) {
	t.Helper()
	if err := h.store.db.QueryRow(`SELECT outbound_messages, outbound_bytes FROM relay_stats WHERE id = 1`).
		Scan(&messages, &bytes); err != nil {
		t.Fatal(err)
	}
	return messages, bytes
}

// user is an identity with a mailbox on this relay, written straight into
// the store: registering over HTTP would spend the registration budgets some
// of these tests are measuring.
func (h *harness) user(t *testing.T, name string) *identity.Identity {
	t.Helper()
	id := neighbourID(t, name)
	h.enroll(id)
	return id
}

// fpOf is the fingerprint of an identity generated under a name, for a
// recipient this relay never has to know anything about.
func (h *harness) fpOf(t *testing.T, name string) string {
	t.Helper()
	return neighbourID(t, name).Public().Fingerprint()
}

// postSigned sends a body exactly as given, signed as the caller, for a test
// whose point is the bytes rather than the type.
func (h *harness) postSigned(t *testing.T, id *identity.Identity, path string, body []byte) (int, []byte) {
	t.Helper()
	return h.do(id, "POST", path, json.RawMessage(body), nil)
}

// heapInUse is the live heap now, for the assertion that a refusal did not
// allocate from a length the caller stated.
func heapInUse() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

// slogDiscard is a logger for a fixture whose log no test reads.
func slogDiscard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestTheSignatureCoversTheForwardsBody: what the two lists say about where
// an envelope goes is under the caller's signature, like everything else this
// relay acts on.
//
// The route has no mailbox fingerprint in its path, so it cannot use the
// wrapper every other body route uses; the wrapper it does use is the one for
// routes without a fingerprint, whose other callers deliberately sign an
// empty body — an upload, whose body is the payload itself, and a listing,
// which has none. If the forward route were given that wrapper, anything able
// to replay one signed request could rewrite the path it names and the relay
// would carry the envelope somewhere else entirely.
func TestTheSignatureCoversTheForwardsBody(t *testing.T) {
	h := peered(t, []string{"bar", "baz"}, nil, nil)
	user := h.user(t, "alice")
	env := sealedFor(h.fpOf(t, "bob"), "ct")
	signed, err := json.Marshal(request(env, []string{"bar"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	sent, err := json.Marshal(request(env, []string{"baz"}, nil))
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", h.srv.URL+"/v1/forward", bytes.NewReader(sent))
	if err != nil {
		t.Fatal(err)
	}
	// Signed over one body, sent with another.
	if err := relayapi.SignRequest(user, req, signed); err != nil {
		t.Fatal(err)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("status %d: %s; a body the signature does not cover was taken", resp.StatusCode, body)
	}
	if n := h.outboundRows(t); n != 0 {
		t.Errorf("%d rows for a request whose body was not signed", n)
	}
	// And the same request signed over what it carries is taken, so the
	// refusal above is the swap and not something else about the request.
	if status, _, body := h.forward(user, request(env, []string{"baz"}, nil)); status != 201 {
		t.Fatalf("the same request signed over its own body: status %d: %s", status, body)
	}
}

// TestABlockedIdentityMayNotForward, and the two checks beside it in the same
// wrapper: the certificate this request arrived on must be the caller's own,
// and the request budget is spent before the handler sees anything.
//
// They are the wrapper's, and the wrapper is new in this commit, so they are
// proved on the one route that uses it rather than assumed from the wrapper
// it was copied from.
func TestABlockedIdentityMayNotForward(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	if err := h.store.SetBlock(user.Fingerprint(), "spam", h.fpOf(t, "boss"), time.Now()); err != nil {
		t.Fatal(err)
	}
	status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))
	if status != 403 {
		t.Fatalf("status %d: %s", status, body)
	}
	if got := errorText(t, body); !strings.Contains(got, msgBlocked) {
		t.Errorf("%s; want %q", got, msgBlocked)
	}
	if n := h.outboundRows(t); n != 0 {
		t.Errorf("%d rows queued by a blocked identity", n)
	}
}

// TestForwardingSpendsTheRequestBudget: the wrapper charges the caller's
// request budget before the handler runs, as every authenticated route does,
// so a caller cannot forward at a rate the relay's own requests limit forbids.
func TestForwardingSpendsTheRequestBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.RequestsPerMinute = 2
	h := newHarness(t, Config{
		Courier: mustCourier(t, []string{"bar"}, nil), CourierLimits: DefaultCourierLimits(),
		Limits: limits,
	})
	user := h.user(t, "alice")
	to := h.fpOf(t, "bob")
	for i := range 2 {
		if status, _, body := h.forward(user, request(sealedFor(to, fmt.Sprintf("ct%d", i)), []string{"bar"}, nil)); status != 201 {
			t.Fatalf("%d: status %d: %s", i, status, body)
		}
	}
	if status, _, _ := h.forward(user, request(sealedFor(to, "ct2"), []string{"bar"}, nil)); status != 429 {
		t.Errorf("past the request budget: status %d, want 429", status)
	}
}

// TestAPostersBytesAreBoundedToo: the per-poster byte bound, which the
// per-poster message bound's test does not reach, since a message count and a
// byte total are two different bounds and either can be the one that binds.
func TestAPostersBytesAreBoundedToo(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	to := h.fpOf(t, "bob")
	req := request(sealedFor(to, "ct"), []string{"bar"}, nil)
	if status, _, body := h.forward(user, req); status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	// The bound set to exactly what this poster has waiting: the next
	// envelope is one byte too many for them, and another poster is
	// unaffected.
	limits := DefaultCourierLimits()
	limits.QueueMaxBytesPerPoster = int64(len(req.Envelope))
	h2 := serveStore(t, h.store, Config{
		Courier: h.server.courier, CourierLimits: limits, Limits: DefaultLimits(),
	})
	quiet(t, h2)
	status, _, body := h2.forward(user, request(sealedFor(to, "ct2"), []string{"bar"}, nil))
	if status != 507 {
		t.Fatalf("at the poster's byte bound: status %d: %s", status, body)
	}
	if got := errorText(t, body); got != relayapi.MsgQueueFull {
		t.Errorf("%q; want exactly %q, which is what a client matches", got, relayapi.MsgQueueFull)
	}
	other := h2.user(t, "carol")
	if status, _, body := h2.forward(other, request(sealedFor(to, "c0"), []string{"bar"}, nil)); status != 201 {
		t.Errorf("another poster: status %d: %s", status, body)
	}
}

// TestACouriersBytesPerHourAreBounded: the other half of a courier's own
// budgets. The rate is counted in bytes as well as in posts, and a courier
// past either is refused.
func TestACouriersBytesPerHourAreBounded(t *testing.T) {
	courier := neighbourID(t, "alpha")
	limits := DefaultCourierLimits()
	limits.PostBytesPerHour = 200
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	to := h.fpOf(t, "bob")
	// Each request is a few hundred bytes, so the first is taken and the
	// second is past the hour's bytes.
	if status, _, body := h.forward(courier, request(sealedFor(to, "ct0"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	if status, _, _ := h.forward(courier, request(sealedFor(to, "ct1"), []string{"bar"}, nil)); status != 429 {
		t.Errorf("past the courier's bytes: status %d, want 429", status)
	}
}

// TestTheQueuesArithmeticCannotWrap: the room is asked by subtraction and
// never by a sum, so a size near the type's maximum is refused rather than
// wrapping negative and reading as room. This is the shape that put a stream
// past a mailbox's quota once; the guard is cheap and the test is the value
// that would have found it.
func TestTheQueuesArithmeticCannotWrap(t *testing.T) {
	// The relay-wide byte bound unlimited, which is what leaves the
	// overflow guard as the only thing standing: with a bound set, the
	// subtraction against it refuses a near-maximum counter anyway, and a
	// test that did not turn it off would pass with the guard deleted.
	limits := DefaultCourierLimits()
	limits.QueueMaxBytes = 0
	limits.QueueMaxBytesPerPoster = 0
	limits.QueueMaxMessages = 0
	limits.QueueMaxMessagesPerPoster = 0
	h := peered(t, []string{"bar"}, nil, &limits)
	user := h.user(t, "alice")
	// A counter close to the maximum, as a corrupted or edited database
	// would have it: one more envelope must not wrap it into room.
	if _, err := h.store.db.Exec(`UPDATE relay_stats SET outbound_bytes = ? WHERE id = 1`,
		int64(math.MaxInt64)-10); err != nil {
		t.Fatal(err)
	}
	status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil))
	if status != 507 {
		t.Fatalf("with the counter near MaxInt64: status %d: %s; the sum wrapped into room", status, body)
	}
	if n := h.outboundRows(t); n != 0 {
		t.Errorf("%d rows stored past a wrapped bound", n)
	}
}

// TestTheHashesPartsCannotBeRunTogether: the parts are length-prefixed, so
// two envelopes whose fields concatenate the same way are still two hashes.
//
// A recipient is 64 hex characters by the time the route has parsed one, so
// today plain concatenation would be injective anyway and nothing in the
// relay can reach this. The prefixes are what keep it true of a later
// envelope whose fields are not fixed, and the property is worth a test
// rather than a comment saying it holds.
func TestTheHashesPartsCannotBeRunTogether(t *testing.T) {
	first := CarriedHash(&relayapi.Carried{To: "aa", CT: []byte("bb")})
	second := CarriedHash(&relayapi.Carried{To: "aab", CT: []byte("b")})
	if first == second {
		t.Error("two envelopes whose fields run together made one hash")
	}
}

// TestTheCarriedTableIsPurged: a hash is kept while the envelope it stands
// for could still be alive ahead of it, and then forgotten. Without this the
// ceiling is reached once and the relay forwards nothing ever again, since a
// hash is the one thing it stores that nobody comes back for.
func TestTheCarriedTableIsPurged(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	if status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	if n := h.carriedRows(t); n != 1 {
		t.Fatalf("%d hashes, want 1", n)
	}
	// Inside the window, it stays. The window is measured from the clock the
	// relay wrote the row by, which is the harness's injected one and not
	// the wall clock.
	window := DefaultCourierLimits().CarriedWindow(0)
	wrote := h.clock.Now()
	if err := h.store.PurgeCarried(wrote.Add(window - time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := h.carriedRows(t); n != 1 {
		t.Errorf("%d hashes inside the window, want 1", n)
	}
	// Past it, it goes.
	if err := h.store.PurgeCarried(wrote.Add(window + time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := h.carriedRows(t); n != 0 {
		t.Errorf("%d hashes past the window, want none", n)
	}
}

// TestTheQueuesFilesAreShared: one relay carrying a great deal for a
// neighbour that is down must not put every envelope in one directory, which
// is why a mailbox's own messages are sharded. The name is still an integer
// this relay allocated, at every part.
func TestTheQueuesFilesAreShared(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	to := h.fpOf(t, "bob")
	var ids []int64
	for i := range 5 {
		status, answer, body := h.forward(user, request(sealedFor(to, fmt.Sprintf("ct%d", i)), []string{"bar"}, nil))
		if status != 201 {
			t.Fatalf("%d: status %d: %s", i, status, body)
		}
		ids = append(ids, answer.ID)
	}
	for _, id := range ids {
		path := h.store.outboundPath(id)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("id %d: %v", id, err)
		}
		rel, err := filepath.Rel(filepath.Join(h.store.dir, outboundDir), path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(rel, string(filepath.Separator)) {
			t.Errorf("id %d is at %q, which is not under a shard", id, rel)
		}
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			if strings.TrimLeft(part, "0123456789") != "" {
				t.Errorf("id %d has a path part %q that is not a number this relay made", id, part)
			}
		}
	}
}

// TestTheCarriedPurgeRuns: the purge is wired into the housekeeping every
// relay does, not merely written.
//
// The test above proves the function; this proves it is called, which is a
// different claim and the one that matters — a purge nothing runs is a
// ceiling that is reached once and never left. Housekeeping runs on every
// hundredth request, as the relay's own does, so the requests here are the
// mechanism and not a detail.
func TestTheCarriedPurgeRuns(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	user := h.user(t, "alice")
	if status, _, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), "ct"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("status %d: %s", status, body)
	}
	if n := h.carriedRows(t); n != 1 {
		t.Fatalf("%d hashes, want 1", n)
	}
	// Past the window, and then enough traffic for housekeeping to come
	// round. Nothing here touches the carried table itself.
	h.clock.advance(DefaultCourierLimits().CarriedWindow(0) + time.Minute)
	for range 101 {
		h.do(user, "GET", "/v1/mailbox/"+user.Fingerprint(), nil, nil)
	}
	if n := h.carriedRows(t); n != 0 {
		t.Errorf("%d hashes after the window and a hundred requests; the purge is written and not run", n)
	}
}

// TestTheRelayWideRowBoundHoldsACourier: a courier is held to both
// relay-wide bounds, and the rows are the one that matters for a courier.
//
// Bytes do not bound rows. The smallest envelope this relay takes is about a
// hundred bytes, so a gigabyte of them — the relay-wide byte default — is ten
// million rows and ten million files, put there by one neighbour carrying for
// a relay that is down. A relay that fills up should say so while it still
// has somewhere to write the saying.
func TestTheRelayWideRowBoundHoldsACourier(t *testing.T) {
	courier := neighbourID(t, "alpha")
	limits := DefaultCourierLimits()
	limits.QueueMaxMessages = 2
	// The per-poster bounds off, so what refuses the third is the
	// relay-wide count and nothing else.
	limits.QueueMaxMessagesPerPoster = 0
	limits.QueueMaxBytesPerPoster = 0
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	to := h.fpOf(t, "bob")

	for i := range 2 {
		status, _, body := h.forward(courier, request(sealedFor(to, fmt.Sprintf("ct%d", i)), []string{"bar"}, nil))
		if status != 201 {
			t.Fatalf("%d: status %d: %s", i, status, body)
		}
	}
	status, _, body := h.forward(courier, request(sealedFor(to, "one too many"), []string{"bar"}, nil))
	if status != 507 {
		t.Fatalf("at the relay's row bound: status %d: %s; a courier is held to it", status, body)
	}
	if got := errorText(t, body); got != relayapi.MsgQueueFull {
		t.Errorf("%q; want exactly %q, which is what a client matches", got, relayapi.MsgQueueFull)
	}
	if n := h.outboundRows(t); n != 2 {
		t.Errorf("%d rows, want the 2 the bound allows", n)
	}
	// A user meets the same bound: it is the relay's, not a courier's.
	user := h.user(t, "alice")
	if status, _, _ := h.forward(user, request(sealedFor(to, "u0"), []string{"bar"}, nil)); status != 507 {
		t.Errorf("a user at the relay's row bound: status %d, want 507", status)
	}
}

// TestOneNeighboursShareOfTheQueue: a courier has a row bound of its own,
// beside the relay-wide pair and in place of the per-poster count.
//
// The relay-wide bound is what stands between every neighbour together and
// the queue; without this one, a single neighbour that has stopped draining —
// its own next hop down, its operator away — reaches that bound by itself and
// every other neighbour's mail is refused on its account. So the bound is per
// courier and the number is larger than a person's, since a courier carries
// many people's mail.
func TestOneNeighboursShareOfTheQueue(t *testing.T) {
	alpha := neighbourID(t, "alpha")
	beta := neighbourID(t, "beta")
	limits := DefaultCourierLimits()
	limits.QueueMaxMessagesPerCourier = 2
	// The relay-wide bounds well clear, so what refuses is this one.
	limits.QueueMaxMessages = 100
	h := peered(t, []string{"bar"}, []*identity.Identity{alpha, beta}, &limits)
	h.enroll(alpha, beta)
	to := h.fpOf(t, "bob")

	for i := range 2 {
		status, _, body := h.forward(alpha, request(sealedFor(to, fmt.Sprintf("a%d", i)), []string{"bar"}, nil))
		if status != 201 {
			t.Fatalf("%d: status %d: %s", i, status, body)
		}
	}
	status, _, body := h.forward(alpha, request(sealedFor(to, "one too many"), []string{"bar"}, nil))
	if status != 507 {
		t.Fatalf("at a neighbour's own row bound: status %d: %s", status, body)
	}
	if got := errorText(t, body); got != relayapi.MsgQueueFull {
		t.Errorf("%q; want exactly %q, which is what a client matches", got, relayapi.MsgQueueFull)
	}

	// The other neighbour is unaffected, which is the whole of what the
	// bound is for: one relay's backlog is not every relay's.
	if status, _, body := h.forward(beta, request(sealedFor(to, "b0"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("the second neighbour: status %d: %s; one neighbour's share is not the other's",
			status, body)
	}
	if n := h.outboundRows(t); n != 3 {
		t.Errorf("%d rows, want alpha's 2 and beta's 1", n)
	}
}

// TestACouriersShareIsItsOwnNumberAndNotAPosters: the two settings are two
// numbers in one comparison, and a courier is held to its own.
//
// One field carries the effective bound, so the rule is in one place; which
// number it holds is decided where the caller is already known to be a
// courier or a user. A test that set both to the same number would pass
// whichever one the code read.
func TestACouriersShareIsItsOwnNumberAndNotAPosters(t *testing.T) {
	courier := neighbourID(t, "alpha")
	limits := DefaultCourierLimits()
	limits.QueueMaxMessagesPerCourier = 3
	limits.QueueMaxMessagesPerPoster = 1
	limits.QueueMaxMessages = 100
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	to := h.fpOf(t, "bob")

	// A user is held to one, the poster's number.
	user := h.user(t, "alice")
	if status, _, body := h.forward(user, request(sealedFor(to, "u0"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("the user's first: status %d: %s", status, body)
	}
	if status, _, _ := h.forward(user, request(sealedFor(to, "u1"), []string{"bar"}, nil)); status != 507 {
		t.Errorf("a user's second at per_poster 1: status %d, want 507", status)
	}
	// The courier is held to three, its own number, and the poster's one
	// does not touch it.
	for i := range 3 {
		if status, _, body := h.forward(courier,
			request(sealedFor(to, fmt.Sprintf("c%d", i)), []string{"bar"}, nil)); status != 201 {
			t.Fatalf("the courier's %d at per_courier 3: status %d: %s; a courier is not held to "+
				"the poster's count", i, status, body)
		}
	}
	if status, _, _ := h.forward(courier, request(sealedFor(to, "c3"), []string{"bar"}, nil)); status != 507 {
		t.Errorf("the courier's fourth at per_courier 3: status %d, want 507", status)
	}
}

// TestACouriersBytesAreNotBoundedPerPoster: the per-poster byte bound still
// does not apply to a courier, which is the half of ruling 21 that this
// setting does not change.
func TestACouriersBytesAreNotBoundedPerPoster(t *testing.T) {
	courier := neighbourID(t, "alpha")
	limits := DefaultCourierLimits()
	limits.QueueMaxBytesPerPoster = 1
	limits.QueueMaxMessagesPerCourier = 10
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	to := h.fpOf(t, "bob")

	if status, _, body := h.forward(courier, request(sealedFor(to, "plenty of bytes"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("a courier at a one-byte per-poster bound: status %d: %s; that bound is not a "+
			"courier's, since one person's worth of bytes would refuse a busy neighbour's queue",
			status, body)
	}
	// A user meets it, so the bound is on and the test is not vacuous.
	user := h.user(t, "alice")
	if status, _, _ := h.forward(user, request(sealedFor(to, "u0"), []string{"bar"}, nil)); status != 507 {
		t.Errorf("a user at a one-byte per-poster bound: status %d, want 507", status)
	}
}

// TestThePerPosterBoundIsAnsweredFromAnIndex: the count of one poster's
// waiting rows is asked inside the transaction that takes every forward, so
// it must not cost the queue's depth.
//
// Before the index that covers it, no index carried both poster_fp and
// state — the poster's own leads on poster_fp and id — so the planner
// reached for the purge's, on state alone, and visited every waiting row in
// the table to count one poster's. On the store's single connection, inside
// a write transaction already open, at a courier's six hundred posts a
// minute and a queue that may hold a hundred thousand rows, that is the
// relay's one writer spending its minute on counting.
//
// The claim is about the plan, so the test reads the plan the relay's own
// schema gives, and a row count on the day somebody runs it decides nothing.
func TestThePerPosterBoundIsAnsweredFromAnIndex(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	rows, err := h.store.db.Query(`EXPLAIN QUERY PLAN
		SELECT COUNT(*), COALESCE(SUM(size), 0) FROM outbound WHERE poster_fp = ? AND state = ?`,
		"whoever", OutWaiting)
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
	got := plan.String()
	if !strings.Contains(got, "outbound_share") {
		t.Errorf("the per-poster count does not use its own index:\n%s", got)
	}
	// Covering, so the bytes come from the index too and no row is read
	// for a question asked on every forward.
	if !strings.Contains(got, "COVERING INDEX") {
		t.Errorf("the per-poster count reads rows to answer:\n%s", got)
	}
	if strings.Contains(got, "SCAN outbound") {
		t.Errorf("the per-poster count scans the table, inside the transaction that takes a "+
			"forward and on the store's one connection:\n%s", got)
	}
}

// TestTheListingSaysHowMailCameAndSaysItAlways: the row a recipient reads
// carries the hops, and carries the empty string for mail that came no
// distance.
//
// Always, because its emptiness is a fact about the message: a reader that
// had to tell an absent field from an empty one would be guessing, and the
// one thing this field decides — where a reply goes — has no safe default.
func TestTheListingSaysHowMailCameAndSaysItAlways(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
	h.enroll(courier)
	bob := h.user(t, "bob")
	alice := h.user(t, "alice")

	// One posted here, one forwarded in.
	if status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "direct"), nil); status != 200 {
		t.Fatalf("a direct post: %d %s", status, body)
	}
	if status, _, body := h.forward(courier,
		request(sealedFor(bob.Fingerprint(), "forwarded"), nil, []string{"one", "two"})); status != 201 {
		t.Fatalf("a forward: %d %s", status, body)
	}

	status, body := h.do(bob, "GET", "/v1/mailbox/"+bob.Fingerprint(), nil, nil)
	if status != 200 {
		t.Fatalf("the listing: %d %s", status, body)
	}
	var page relayapi.ListResponse
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Messages) != 2 {
		t.Fatalf("%d rows, want 2", len(page.Messages))
	}
	if page.Messages[0].Via != "" {
		t.Errorf("the direct message says via %q, want nothing", page.Messages[0].Via)
	}
	if page.Messages[1].Via != "one!two!alpha" {
		t.Errorf("the forwarded message says via %q", page.Messages[1].Via)
	}
	// The key is there on both, which is what "always" means: a reader
	// cannot tell an absent one from an empty one after a decode, so the
	// relay writes it and the wire shows it.
	if !strings.Contains(string(body), `"via":""`) {
		t.Errorf("the direct row omits the key:\n%s", firstRow(string(body)))
	}
}

// firstRow is enough of a listing's bytes to read in a failure.
func firstRow(body string) string {
	if i := strings.Index(body, `"envelope"`); i > 0 {
		return body[:i]
	}
	return body
}

// TestAPosterReadsTheirOwnQueueAndNobodyElses: the queue route is the
// owner's own view of what this relay is still carrying for them.
func TestAPosterReadsTheirOwnQueueAndNobodyElses(t *testing.T) {
	h := peered(t, []string{"bar"}, nil, nil)
	alice := h.user(t, "alice")
	bob := h.user(t, "bob")
	to := h.fpOf(t, "carol")

	// Alice queues two, Bob one.
	for i := range 2 {
		if status, _, body := h.forward(alice,
			request(sealedFor(to, fmt.Sprintf("a%d", i)), []string{"bar"}, nil)); status != 201 {
			t.Fatalf("alice's %d: %d %s", i, status, body)
		}
	}
	if status, _, body := h.forward(bob, request(sealedFor(to, "b0"), []string{"bar"}, nil)); status != 201 {
		t.Fatalf("bob's: %d %s", status, body)
	}

	queued := h.queueOf(t, alice)
	if len(queued) != 2 {
		t.Fatalf("alice reads %d rows, want her own 2", len(queued))
	}
	for _, q := range queued {
		if q.Neighbour != "bar" || q.State != OutWaiting || q.ID == 0 {
			t.Errorf("row %+v", q)
		}
		// Every field is answered, so a reader never tells absent from
		// zero. A row not yet tried has no last try, which is the zero
		// time and a value.
		if !q.LastTry.IsZero() || q.Tries != 0 {
			t.Errorf("a row never tried says %d tries at %s", q.Tries, q.LastTry)
		}
		if q.GivesUp.IsZero() {
			t.Error("a waiting row has no gives_up, which is when its poster stops hoping")
		}
	}
	if b := h.queueOf(t, bob); len(b) != 1 || b[0].ID == queued[0].ID {
		t.Errorf("bob reads %d rows; a poster reads their own and nobody else's", len(b))
	}

	// Somebody else's mailbox is refused, as on every route that reads a
	// mailbox's private state.
	status, body := h.do(alice, "GET", "/v1/mailbox/"+bob.Fingerprint()+"/queue", nil, nil)
	if status != 403 || errorText(t, body) != "not your mailbox" {
		t.Fatalf("alice reading bob's queue: %d %s", status, body)
	}
}

// TestTheQueueRouteAnswersAtMostItsLimit: a page a client cannot hold is a
// page nobody can act on, so the route answers the oldest rows and no more.
func TestTheQueueRouteAnswersAtMostItsLimit(t *testing.T) {
	limits := DefaultCourierLimits()
	// One poster's share of the queue is a hundred rows, which is less than
	// a page: the bound under test here is the route's, so the queue's is
	// turned off rather than worked around.
	limits.QueueMaxMessagesPerPoster = 0
	h := peered(t, []string{"bar"}, nil, &limits)
	alice := h.user(t, "alice")
	to := h.fpOf(t, "carol")
	// Through the store rather than the route: what is under test is the
	// page the route answers, and a couple of hundred posts would spend a
	// user's rate limit on setting the scene.
	now := h.clock.Now()
	for i := range relayapi.MaxQueueLimit + 5 {
		env := sealedFor(to, fmt.Sprintf("m%d", i))
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		row := &Outbound{
			PosterFP: alice.Fingerprint(), Neighbour: "bar", ToFP: to,
			Hash: CarriedHash(carried(env)), Kind: relayapi.KindEnvelope,
			Received: now, GivesUp: now.Add(time.Hour),
		}
		if _, err := h.store.Enqueue(row, raw, limits.Quotas(), now.Add(time.Hour)); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	queued := h.queueOf(t, alice)
	if len(queued) != relayapi.MaxQueueLimit {
		t.Fatalf("%d rows, want %d", len(queued), relayapi.MaxQueueLimit)
	}
	// The oldest, which are the ones that have waited longest and the ones
	// somebody asks about.
	if queued[0].ID != 1 {
		t.Errorf("the page starts at %d, want the oldest", queued[0].ID)
	}
}

// TestARelayThatForwardsNothingHasNoQueue: the answer is that there is
// nowhere for anything to wait, not that nothing is waiting.
func TestARelayThatForwardsNothingHasNoQueue(t *testing.T) {
	h := newHarness(t, Config{Limits: DefaultLimits()})
	alice := h.user(t, "alice")
	status, body := h.do(alice, "GET", "/v1/mailbox/"+alice.Fingerprint()+"/queue", nil, nil)
	if status != 403 || errorText(t, body) != relayapi.MsgForwardsNothing {
		t.Fatalf("%d %s", status, body)
	}
}

// queueOf reads a poster's own queue through the route.
func (h *harness) queueOf(t *testing.T, id *identity.Identity) []relayapi.QueuedMessage {
	t.Helper()
	status, body := h.do(id, "GET", "/v1/mailbox/"+id.Fingerprint()+"/queue", nil, nil)
	if status != 200 {
		t.Fatalf("the queue: %d %s", status, body)
	}
	var out relayapi.QueueResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out.Queued
}

// TestAQueuePageShowsWhatNeedsAnAnswerFirst: a handed row must not push a
// stuck one off the end of the page.
//
// A handed row is kept for as long as something could come back about it —
// three days at the defaults — and nothing bounds how many of them a poster
// has, where the queue's own count bounds the waiting ones. So an active
// sender's page is mostly rows about mail that arrived, and ordering by id
// alone would hide the one message that needs them to do something: absent
// from the listing, uncounted by the inbox's line, and gone at its own
// gives_up with nobody told.
func TestAQueuePageShowsWhatNeedsAnAnswerFirst(t *testing.T) {
	limits := DefaultCourierLimits()
	limits.QueueMaxMessagesPerPoster = 0
	h := peered(t, []string{"bar"}, nil, &limits)
	alice := h.user(t, "alice")
	to := h.fpOf(t, "carol")
	now := h.clock.Now()
	enqueue := func(ct string) int64 {
		t.Helper()
		env := sealedFor(to, ct)
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		id, err := h.store.Enqueue(&Outbound{
			PosterFP: alice.Fingerprint(), Neighbour: "bar", ToFP: to,
			Hash: CarriedHash(carried(env)), Kind: relayapi.KindEnvelope,
			Received: now, GivesUp: now.Add(time.Hour),
		}, raw, limits.Quotas(), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	// A page full of mail that arrived, and then the two rows that matter.
	for i := range relayapi.MaxQueueLimit {
		if err := h.store.Handed(enqueue(fmt.Sprintf("gone%d", i)), int64(i+1), now); err != nil {
			t.Fatal(err)
		}
	}
	stuck := enqueue("still going")
	refused := enqueue("refused")
	if err := h.store.Failed(refused, relayapi.CodeRefused, "bar: no such mailbox", now); err != nil {
		t.Fatal(err)
	}

	queued := h.queueOf(t, alice)
	if len(queued) != relayapi.MaxQueueLimit {
		t.Fatalf("%d rows, want a full page", len(queued))
	}
	var sawStuck, sawRefused bool
	for _, q := range queued {
		switch q.ID {
		case stuck:
			sawStuck = true
		case refused:
			sawRefused = true
		}
	}
	if !sawStuck {
		t.Error("the row still waiting is not on the page: its poster is never told it is stuck")
	}
	if !sawRefused {
		t.Error("the row that failed is not on the page: its poster is never told why")
	}
	// And in that order: what needs an answer, then what failed, then the
	// rest.
	if queued[0].ID != stuck {
		t.Errorf("the page starts at %d, want the waiting row %d", queued[0].ID, stuck)
	}
	if queued[1].ID != refused {
		t.Errorf("the second row is %d, want the failed one %d", queued[1].ID, refused)
	}
	if queued[2].State != OutHanded {
		t.Errorf("the third row is %q, want the handed rows after", queued[2].State)
	}
}

// TestADeliveryIsHeldToTheOperatorsMaxBytes: the cap an operator set means
// the same thing for mail that arrived through a neighbour as for mail posted
// here.
//
// The forward route's body cap is max_bytes plus the framing a request costs,
// so without this check a neighbour's courier could place a message that much
// over the setting into a local mailbox — and an operator's number would mean
// one thing for their own users and another for everybody reached through a
// peer.
func TestADeliveryIsHeldToTheOperatorsMaxBytes(t *testing.T) {
	courier := neighbourID(t, "alpha")
	c, err := NewCourier(CourierConfig{
		Home:           courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"}),
		AuthorizedFile: couriersFile(t, courier), PublicURL: "https://mine.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	const maxBytes = 4096
	h := newHarness(t, Config{Courier: c, CourierLimits: DefaultCourierLimits(),
		Limits: DefaultLimits(), MaxBytes: maxBytes})
	quiet(t, h)
	h.enroll(courier)
	bob := h.user(t, "bob")

	// An envelope over the setting and under the route's own body cap.
	big := sealedFor(bob.Fingerprint(), strings.Repeat("x", 6000))
	status, _, body := h.forward(courier, request(big, nil, nil))
	if status != 413 {
		t.Fatalf("a delivery of %d bytes under max_bytes %d: status %d: %s",
			len(big.CT), maxBytes, status, body)
	}
	if got := errorText(t, body); got != "envelope too large" {
		t.Errorf("%q; want the post route's own sentence", got)
	}
	if msgs := h.stored(t, bob.Fingerprint()); len(msgs) != 0 {
		t.Errorf("%d messages stored over the operator's cap", len(msgs))
	}
	// And the same route takes one under it, so the refusal is the size and
	// not the route.
	if status, _, body := h.forward(courier,
		request(sealedFor(bob.Fingerprint(), "small"), nil, nil)); status != 201 {
		t.Fatalf("a delivery under max_bytes: status %d: %s", status, body)
	}
}
