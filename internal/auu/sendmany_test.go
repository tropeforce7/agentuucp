package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// peersOn enrols people on a relay, each holding and admitting every other.
func peersOn(t *testing.T, relayURL string, names ...string) []*user {
	t.Helper()
	var us []*user
	for _, n := range names {
		us = append(us, newUser(t, n, relayURL))
	}
	for _, u := range us {
		for _, v := range us {
			if u != v {
				u.run("peers", "add", v.exportLine())
			}
		}
		u.run("allow", "push")
	}
	return us
}

func sentMany(t *testing.T, out string) sentManyJSON {
	t.Helper()
	var got sentManyJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("send --json: %v\n%s", err, out)
	}
	return got
}

// A message to several, by --to repeated and by a comma list: every copy
// posted, one line per recipient, the outbox empty after, one sent record
// whose copies say where each went, each recipient holding the message
// under its one id, and --json with recipients and no to.
func TestSendToSeveralPostsEveryCopy(t *testing.T) {
	alice, bob, carol := threePeers(t)
	out := alice.run("send", "--to", "bob", "--to", "carol", "--subject", "the release", "out on Friday")
	for _, want := range []string{"sent to 2 recipients via", "  bob: sent", "  carol: sent", "message: "} {
		if !strings.Contains(out, want) {
			t.Errorf("the send says:\n%s\nwant %q", out, want)
		}
	}
	raw := alice.run("send", "--to", "bob,carol", "--json", "one list")
	got := sentMany(t, raw)
	if strings.Contains(raw, `"to"`) || strings.Contains(raw, `"to_name"`) {
		t.Errorf("--json for several carries to or to_name:\n%s", raw)
	}
	if len(got.Recipients) != 2 || got.Kind != kindEnvelope {
		t.Fatalf("--json: %+v", got)
	}
	for _, r := range got.Recipients {
		if r.RelayID <= 0 || r.Error != "" || r.Waiting {
			t.Errorf("recipient %s: %+v; want placed", r.Name, r)
		}
	}
	if waiting, _ := outboxOf(t, alice); len(waiting) != 0 {
		t.Errorf("%d left in the outbox after every copy was sent", len(waiting))
	}
	m := alice.stored(store.Sent, got.ID)
	if len(m.Copies) != 2 || m.Copies[0].Name != "bob" || m.Copies[1].Name != "carol" ||
		m.Copies[0].RelayID == 0 || m.Copies[1].RelayID == 0 {
		t.Fatalf("the sent record's copies: %+v", m.Copies)
	}
	read := alice.run("read", got.ID)
	if !strings.Contains(read, "bob <") || !strings.Contains(read, ": sent") || !strings.Contains(read, "to:") {
		t.Errorf("read of the sent message does not say who has it:\n%s", read)
	}
	var asJSON messageJSON
	if err := json.Unmarshal([]byte(alice.run("read", got.ID, "--json")), &asJSON); err != nil || len(asJSON.Copies) != 2 {
		t.Errorf("read --json copies: %+v, %v", asJSON.Copies, err)
	}
	for _, u := range []*user{bob, carol} {
		if !strings.Contains(u.run("inbox", "--json"), got.ID) {
			t.Errorf("a recipient does not hold %s", got.ID[:12])
		}
	}
}

// What is refused before anything is asked of the relay or written: a
// recipient twice, by name and by name and fingerprint, an empty element,
// more than the protocol's ceiling.
func TestSendToSeveralRefusesItsListFirst(t *testing.T) {
	alice, bob, _ := threePeers(t)
	before := len(sentBox(t, alice))
	var e *exitError
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--to", "bob,bob"}, `"bob" and "bob" are the same recipient`},
		{[]string{"--to", "bob", "--to", bob.exportFingerprint()}, "are the same recipient"},
		{[]string{"--to", "bob,"}, "has an empty recipient in it"},
		{[]string{"--to", strings.TrimSuffix(strings.Repeat("bob,", 33), ",")}, "33 recipients; a message may go to at most 32"},
	} {
		_, err := alice.tryRun(append(append([]string{"send"}, tc.args...), "hello")...)
		if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v; want the usage error saying %q", tc.args, err, tc.want)
		}
	}
	if waiting, _ := outboxOf(t, alice); len(waiting) != 0 || len(sentBox(t, alice)) != before {
		t.Errorf("a refused list wrote something")
	}
}

// The relay's number, from its health answer, before anything is sealed:
// a list over it is refused naming the relay and the number, and one at it
// is sent.
func TestSendToSeveralIsHeldToTheRelaysNumber(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.MaxRecipients = 2
	us := peersOn(t, startRelayWith(t, limits), "alice", "bob", "carol", "dave")
	alice := us[0]
	_, err := alice.tryRun("send", "--to", "bob,carol,dave", "hello")
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage || !strings.HasPrefix(err.Error(), "3 recipients; ") ||
		!strings.Contains(err.Error(), " takes at most 2 in one message (its max_recipients)") {
		t.Fatalf("three against two: %v", err)
	}
	if waiting, _ := outboxOf(t, alice); len(waiting) != 0 || len(sentBox(t, alice)) != 0 {
		t.Errorf("a list over the relay's number wrote something")
	}
	alice.run("send", "--to", "bob,carol", "hello")
}

// A copy the relay refuses: the others are sent, the line names who did not
// get it and the relay's words, exit 2, the copy waits in the outbox, and
// the sent record says so; once the recipient admits the sender, --resume
// posts it and the sent record says it landed (ruling 74, point 4).
func TestARefusedCopyIsSaidAndThenFinished(t *testing.T) {
	alice, bob, carol := threePeers(t)
	carol.run("peers", "rm", "alice")
	carol.run("allow", "push")
	out, err := alice.tryRun("send", "--to", "bob,carol", "--json", "hello")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), "1 of 2 copies were not sent") {
		t.Fatalf("a send with a copy refused: %v; want exit 2 naming the count", err)
	}
	got := sentMany(t, out)
	if got.Recipients[0].RelayID == 0 || got.Recipients[1].Error == "" || got.Recipients[1].RelayID != 0 {
		t.Fatalf("recipients: %+v", got.Recipients)
	}
	if !strings.Contains(bob.run("inbox", "--json"), got.ID) {
		t.Errorf("bob's copy was not sent beside carol's refusal")
	}
	m := alice.stored(store.Sent, got.ID)
	if m.Copies[1].Refused == "" || m.Copies[1].RelayID != 0 || m.Copies[0].RelayID == 0 {
		t.Errorf("the sent record after the refusal: %+v", m.Copies)
	}
	if read := alice.run("read", got.ID); !strings.Contains(read, "refused: ") {
		t.Errorf("read does not say carol's copy was refused:\n%s", read)
	}

	carol.run("peers", "add", alice.exportLine())
	carol.run("allow", "push")
	alice.run("send", "--resume")
	m = alice.stored(store.Sent, got.ID)
	if m.Copies[1].RelayID == 0 || m.Copies[1].Refused != "" || m.Copies[1].RefusedCode != "" {
		t.Errorf("the sent record after --resume landed carol's copy: %+v", m.Copies[1])
	}
	if !strings.Contains(carol.run("inbox", "--json"), got.ID) {
		t.Errorf("carol's copy did not arrive on the resume")
	}
}

// Copies with no sent record, as a crash between writing the copies and
// writing the record leaves them: --resume finishes them and says nothing
// of the record that is not there.
func TestResumeFinishesCopiesThatHaveNoSentRecord(t *testing.T) {
	alice, _, _ := threePeers(t)
	sealCopies(t, alice, "bob", "carol")
	stderr := captureStderr(t, func() { alice.run("send", "--resume") })
	if strings.Contains(stderr, "sent record") {
		t.Errorf("--resume spoke of a sent record that is not there:\n%s", stderr)
	}
	if waiting, _ := outboxOf(t, alice); len(waiting) != 0 {
		t.Errorf("%d copies still waiting", len(waiting))
	}
}

// copySize is the size the relay charges for one copy of a message to
// these recipients with this text, measured from a seal made the same way:
// the copies of one message differ in nothing that changes their length.
func copySize(t *testing.T, n int, text string) int64 {
	t.Helper()
	from, err := identity.Generate("x")
	if err != nil {
		t.Fatal(err)
	}
	var to []*identity.Public
	for i := range n {
		id, err := identity.Generate(fmt.Sprintf("r%d", i))
		if err != nil {
			t.Fatal(err)
		}
		to = append(to, id.Public())
	}
	envs, _, err := envelope.SealMany(from, to, "", message.Body{
		Type: message.TypeAsk, Thread: strings.Repeat("a", 32), Text: text,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	size, err := client.EnvelopeSize(envs[0])
	if err != nil {
		t.Fatal(err)
	}
	return int64(size)
}

// A relay that asks the sender to wait longer than a minute stops the
// posting (R7): the copies before are sent, that copy and the rest wait in
// the outbox untouched by any refusal, the sentence says how long the relay
// asked for and that --resume finishes them, exit 2. The byte budget takes
// two copies and a half, so the third is the one the relay asks to wait.
func TestASendToSeveralStopsWhenTheRelayAsksForALongWait(t *testing.T) {
	size := copySize(t, 3, "hello")
	limits := relay.DefaultLimits()
	limits.PostBytesPerHour = 2*size + size/2
	us := peersOn(t, startRelayWith(t, limits), "alice", "bob", "carol", "dave")
	alice := us[0]
	// The claim is that the send does not sit through the relay's wait:
	// without the cap the client would wait out thirty seconds three times
	// before the 429 came back, and the send stops at once instead. The
	// bound is far over a send's ordinary second and far under that.
	started := time.Now()
	out, err := alice.tryRun("send", "--to", "bob,carol,dave", "--json", "hello")
	if took := time.Since(started); took > 30*time.Second {
		t.Errorf("the send took %s; it waited on the relay instead of stopping", took)
	}
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), "the relay is limiting this sender and asked for") ||
		!strings.Contains(err.Error(), "finish them with 'auu send --resume'") {
		t.Fatalf("a long wait: %v; want exit 2 with the relay's time and --resume", err)
	}
	got := sentMany(t, out)
	if got.Recipients[0].RelayID == 0 || got.Recipients[1].RelayID == 0 || !got.Recipients[2].Waiting {
		t.Fatalf("recipients: %+v; want two sent and dave's waiting", got.Recipients)
	}
	waiting, _ := outboxOf(t, alice)
	if len(waiting) != 1 || waiting[0].ToName != "dave" || waiting[0].Refused != "" {
		t.Errorf("the outbox after the stop: %+v; want dave's copy, no refusal kept", waiting)
	}
}

// A copy bigger than the sender's whole budget stops the posting too, since
// no wait lets it through, and says so.
func TestASendToSeveralStopsOnOverBudget(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.PostBytesPerHour = 100
	us := peersOn(t, startRelayWith(t, limits), "alice", "bob", "carol")
	out, err := us[0].tryRun("send", "--to", "bob,carol", "--json", "hello")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), "which no wait changes") {
		t.Fatalf("over budget: %v", err)
	}
	if waiting, _ := outboxOf(t, us[0]); len(waiting) != 2 {
		t.Errorf("%d waiting; want both copies", len(waiting))
	}
	// A copy given up is given up in the sent record too, so that read
	// does not go on saying it waits.
	id := sentMany(t, out).ID
	us[0].run("outbox", "drop", id[:8], "carol")
	if m := us[0].stored(store.Sent, id); !m.Copies[1].Dropped || m.Copies[0].Dropped {
		t.Errorf("the sent record after dropping carol's copy: %+v", m.Copies)
	}
	if read := us[0].run("read", id); !strings.Contains(read, "given up with auu outbox drop") {
		t.Errorf("read still says carol's copy waits:\n%s", read)
	}
}

// A relay that refuses this machine, not a copy, stops the posting at the
// first copy, since every other would meet the same refusal; the copies
// wait in the outbox untouched, and the relay's refusal stays in the
// error's chain, so the advice a message to one gets for it is given too.
// The sender's mailbox is gone from the relay, so the relay does not know
// who signed.
func TestASendToSeveralStopsWhenTheRelayRefusesThisMachine(t *testing.T) {
	relayURL, st := startRelayConfig(t, relay.Config{Limits: relay.DefaultLimits()})
	us := peersOn(t, relayURL, "alice", "bob", "carol")
	if _, err := st.Deregister(us[0].exportFingerprint()); err != nil {
		t.Fatal(err)
	}
	_, err := us[0].tryRun("send", "--to", "bob,carol", "hello")
	var e *exitError
	var he *client.HTTPError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), "the relay refused this machine, not one copy") ||
		!errors.As(err, &he) || he.Status != http.StatusUnauthorized {
		t.Fatalf("a refused machine: %v; want exit 2, the sentence and the 401 in the chain", err)
	}
	waiting, _ := outboxOf(t, us[0])
	if len(waiting) != 2 || waiting[0].Refused != "" || waiting[1].Refused != "" {
		t.Errorf("the outbox after the stop: %+v; want both copies, no refusal kept", waiting)
	}
}

// A message to several composed in the editor keeps no draft once its
// copies are in the outbox: --resume finishes it, and a draft to send again
// would send it all over again.
func TestAnEditedSendToSeveralKeepsNoDraftOnceItsCopiesWait(t *testing.T) {
	alice, _, carol := threePeers(t)
	carol.run("peers", "rm", "alice")
	carol.run("allow", "push")
	editor(t, `printf 'from the editor\n' > "$1"`)
	_, err := alice.tryRun("send", "--to", "bob,carol", "--subject", "s", "--edit")
	if err == nil || strings.Contains(err.Error(), "kept at") || !strings.Contains(err.Error(), "finish them with 'auu send --resume'") {
		t.Fatalf("an edited send with a copy refused: %v; want --resume named and no draft", err)
	}
}

// The health answer is asked for a message to several and never for one
// (R9): a proxy in front of the relay counts the asks.
func TestASendToOneNeverAsksHealth(t *testing.T) {
	backend, err := url.Parse(startRelay(t))
	if err != nil {
		t.Fatal(err)
	}
	var health atomic.Int64
	proxy := httputil.NewSingleHostReverseProxy(backend)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			health.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	us := peersOn(t, front.URL, "alice", "bob", "carol")
	health.Store(0)
	us[0].run("send", "--to", "bob", "to one")
	if n := health.Load(); n != 0 {
		t.Errorf("a send to one asked health %d times", n)
	}
	us[0].run("send", "--to", "bob,carol", "to two")
	if n := health.Load(); n == 0 {
		t.Errorf("a send to two never asked the relay's number")
	}
}

// Following up on a thread whose latest message is your own to several
// needs --to PEER, one of its recipients (R6): with none it is refused
// naming them, with somebody who was not one it is refused, and with one
// of them it goes to that person alone.
func TestAFollowUpToYourOwnMessageToSeveralNamesOne(t *testing.T) {
	alice, bob, carol := threePeers(t)
	got := sentMany(t, alice.run("send", "--to", "bob,carol", "--json", "hello"))
	_, err := alice.tryRun("reply", got.Thread, "and another thing")
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "your own message to 2 recipients (bob, carol); name the one to follow up with, as --to PEER") {
		t.Fatalf("a plain follow-up: %v", err)
	}
	t.Setenv("AUU_HOME", alice.home)
	if _, err := alice.tryRun("reply", got.Thread, "--to", "self", "x"); err == nil || !strings.Contains(err.Error(), "is not one of the 2 recipients") {
		t.Errorf("a follow-up to somebody who was not a recipient: %v", err)
	}
	var follow sentJSON
	if err := json.Unmarshal([]byte(alice.run("reply", got.Thread, "--to", "carol", "--json", "for carol alone")), &follow); err != nil {
		t.Fatal(err)
	}
	if follow.ToName != "carol" || !strings.Contains(carol.run("inbox", "--json"), follow.ID) {
		t.Errorf("carol did not get the follow-up: %+v", follow)
	}
	if strings.Contains(bob.run("inbox", "--json"), follow.ID) {
		t.Errorf("bob got carol's follow-up")
	}
}

// outbox drop ID self gives up the owner's own copy of a message to
// several with themselves among its recipients.
func TestOutboxDropTakesSelf(t *testing.T) {
	alice, _, _ := threePeers(t)
	id, _ := sealCopies(t, alice, "bob", "self")
	out := alice.run("outbox", "drop", id[:8], "self")
	if !strings.Contains(out, "dropped the copy of "+id[:12]+" to alice") {
		t.Errorf("drop self said %q", out)
	}
	waiting, _ := outboxOf(t, alice)
	if len(waiting) != 1 || waiting[0].ToName != "bob" {
		t.Errorf("after dropping the copy to self: %+v", waiting)
	}
}

// A message to several that would become a stream is refused in this
// release, before anything is read or written, with what to do instead.
func TestAStreamToSeveralIsRefusedForNow(t *testing.T) {
	alice, _, _ := threePeers(t)
	_, err := alice.tryRun("send", "--to", "bob,carol", "--stream", "hello")
	var e *exitError
	if !asExit(err, &e) || e.code != exitUsage || !strings.Contains(err.Error(), "a message to several goes as one envelope to each in this release") ||
		!strings.Contains(err.Error(), "send it to each recipient on their own") {
		t.Fatalf("a stream to several: %v", err)
	}
	if waiting, _ := outboxOf(t, alice); len(waiting) != 0 || len(sentBox(t, alice)) != 0 {
		t.Errorf("a refused stream to several wrote something")
	}
}

// What stops a send to several, decided by status, code and the wait the
// relay asked for and never by the sentence: an over-budget 429 whatever its
// Retry-After, a 429 asking for more than a minute, and nothing else.
func TestWhatStopsASendToSeveral(t *testing.T) {
	for _, tc := range []struct {
		name string
		he   *client.HTTPError
		stop bool
	}{
		{"over-budget with a short wait", &client.HTTPError{Status: 429, Code: relayapi.CodeOverBudget, RetryAfter: time.Second}, true},
		{"over-budget with no wait", &client.HTTPError{Status: 429, Code: relayapi.CodeOverBudget}, true},
		{"a wait one second over a minute", &client.HTTPError{Status: 429, RetryAfter: manyWait + time.Second}, true},
		{"a wait of a minute", &client.HTTPError{Status: 429, RetryAfter: manyWait}, false},
		{"a refusal that is not a 429", &client.HTTPError{Status: 403, RetryAfter: time.Hour}, false},
		{"a 401, which refuses this machine", &client.HTTPError{Status: 401, Code: relayapi.CodeCertRevoked}, true},
		{"a 401 with no code", &client.HTTPError{Status: 401}, true},
		{"a busy relay asking a minute and a second", &client.HTTPError{Status: 503, RetryAfter: manyWait + time.Second}, true},
		{"a busy relay asking a minute", &client.HTTPError{Status: 503, RetryAfter: manyWait}, false},
		{"over-budget's code on another status", &client.HTTPError{Status: 413, Code: relayapi.CodeOverBudget}, false},
	} {
		if got := stopsSending(tc.he) != nil; got != tc.stop {
			t.Errorf("%s: stops %v; want %v", tc.name, got, tc.stop)
		}
	}
	if stopsSending(errors.New("no answer")) != nil {
		t.Error("an error that is no answer from a relay stopped the send")
	}
}

// frontedPeers is three peers on a relay behind a proxy that hands each
// post to a mailbox, after the first, to answer; the rest it passes on.
func frontedPeers(t *testing.T, answer func(w http.ResponseWriter)) []*user {
	t.Helper()
	backend, err := url.Parse(startRelay(t))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backend)
	var posts atomic.Int64
	var armed atomic.Bool
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if armed.Load() && r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") &&
			strings.Count(r.URL.Path, "/") == 3 && posts.Add(1) > 1 {
			answer(w)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	us := peersOn(t, front.URL, "alice", "bob", "carol", "dave")
	armed.Store(true)
	return us
}

// A copy that gets no answer at all, the relay gone between two posts,
// stops the send as a refusal of the sender does: the copies after it are
// not tried, every one not sent waits in the outbox, and what happened is
// in the error's chain.
func TestASendToSeveralStopsWhenACopyGetsNoAnswer(t *testing.T) {
	us := frontedPeers(t, func(w http.ResponseWriter) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	})
	out, err := us[0].tryRun("send", "--to", "bob,carol,dave", "--json", "hello")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport || !strings.Contains(err.Error(), "a copy could not be posted") ||
		!strings.Contains(err.Error(), "2 of 3 copies were not sent") {
		t.Fatalf("no answer: %v", err)
	}
	got := sentMany(t, out)
	if got.Recipients[0].RelayID == 0 || !got.Recipients[1].Waiting || !got.Recipients[2].Waiting {
		t.Errorf("recipients: %+v; want bob sent and the other two waiting", got.Recipients)
	}
	if waiting, _ := outboxOf(t, us[0]); len(waiting) != 2 {
		t.Errorf("%d waiting; want two", len(waiting))
	}
}

// A relay that refuses this machine's certificate: the advice a message to
// one gets is given, and the sentence that the copies wait and --resume
// finishes them stays beside it.
func TestTheAdviceForThisMachineKeepsTheCopiesWaitingSentence(t *testing.T) {
	us := frontedPeers(t, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"` + relayapi.MsgCertRevoked + `","code":"` + relayapi.CodeCertRevoked + `"}`))
	})
	_, err := us[0].tryRun("send", "--to", "bob,carol,dave", "hello")
	var e *exitError
	if !asExit(err, &e) || e.code != exitTransport {
		t.Fatalf("a revoked certificate: %v", err)
	}
	advised := err
	if !strings.Contains(advised.Error(), "revoked") || !strings.Contains(advised.Error(), "2 of 3 copies were not sent and wait in the outbox; finish them with 'auu send --resume'") {
		t.Errorf("the advice dropped what waits:\n%v", advised)
	}
}

// The two halves of a drop racing a landing in another process: a copy that
// lands is never left given up, and a drop leaves a copy already placed as
// placed, so the sent record is never both, which Load would refuse.
func TestADropAndALandingNeverLeaveACopyBoth(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.PostBytesPerHour = 100
	us := peersOn(t, startRelayWith(t, limits), "alice", "bob", "carol")
	out, _ := us[0].tryRun("send", "--to", "bob,carol", "--json", "hello")
	id := sentMany(t, out).ID
	waiting, _ := outboxOf(t, us[0])
	if len(waiting) != 2 {
		t.Fatalf("%d waiting; want both copies", len(waiting))
	}
	t.Setenv("AUU_HOME", us[0].home)
	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	// Bob's copy is given up in the record by a drop, and then lands in
	// another process that had it in hand.
	updateSentCopy(s, id, waiting[0].To, func(c *store.SentCopy) { c.Dropped = true })
	landCopy(s, waiting[0], 5)
	// Carol's copy lands in another process, and then a drop of it
	// reaches the record.
	updateSentCopy(s, id, waiting[1].To, func(c *store.SentCopy) { c.RelayID = 9 })
	updateSentCopy(s, id, waiting[1].To, dropCopy)
	m, err := s.Load(store.Sent, id)
	if err != nil {
		t.Fatalf("the sent record after a landing and a drop: %v", err)
	}
	want := map[string]int64{waiting[0].To: 5, waiting[1].To: 9}
	for _, c := range m.Copies {
		if c.Dropped || c.RelayID != want[c.Fingerprint] {
			t.Errorf("copy for %s: %+v; want placed at %d and not given up", c.Name, c, want[c.Fingerprint])
		}
	}
}

// The exit code of a send to several with copies left: 2 for what a relay
// said or a copy with no answer, 4 for a key that locked part way, by the
// sentinel and by the agent's sentence alike, and 2 for none at all.
func TestASendToSeveralStoppedByALockedKeyExitsFour(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop error
		want int
	}{
		{"the sentinel", fmt.Errorf("signing a copy: %w", identity.ErrLocked), exitLocked},
		{"the agent's sentence", errors.New("handshake: " + agent.LockedMessage), exitLocked},
		{"a relay's refusal", &client.HTTPError{Status: 401}, exitTransport},
		{"no answer", errors.New("connection reset"), exitTransport},
		{"nothing stopped it", nil, exitTransport},
	} {
		if got := stoppedCode(tc.stop); got != tc.want {
			t.Errorf("%s: exit %d; want %d", tc.name, got, tc.want)
		}
	}
}
