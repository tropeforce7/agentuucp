package auu

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// formGateway is a gateway in front of bob's relay that loses the relay's
// 2xx to the first round's envelope posts and uploads, so the reply is
// stored and serve is told it failed, and writes down every envelope post
// stream open and upload of the retry, as "post PATH", "open PATH" and
// "put PATH".
type formGateway struct {
	losing, dropped, recording atomic.Bool
	// refuse, while set, is the kind of request ("post", "open" or "put")
	// the gateway answers itself with refusal, a definite refusal that
	// stores nothing.
	refuse  atomic.Pointer[string]
	refusal int
	mu      sync.Mutex
	seen    []string
}

// kindOf is what a request to the relay is, for the gateway: an envelope's
// post, a stream's open, an upload, or nothing it watches.
func kindOf(req *http.Request) string {
	switch {
	case req.Method == "POST" && strings.HasSuffix(req.URL.Path, "/streams"):
		return "open"
	case req.Method == "POST" && strings.HasPrefix(req.URL.Path, "/v1/mailbox/"):
		return "post"
	case req.Method == "PUT" && strings.HasPrefix(req.URL.Path, "/v1/uploads/"):
		return "put"
	}
	return ""
}

func (g *formGateway) asked() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.seen...)
}

func startFormGateway(t *testing.T, bob *expert) *formGateway {
	t.Helper()
	_, _, relays := bob.opened()
	target, err := url.Parse(relays[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	g := &formGateway{}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(resp *http.Response) error {
		kind := kindOf(resp.Request)
		if g.recording.Load() && kind != "" {
			g.mu.Lock()
			g.seen = append(g.seen, kind+" "+resp.Request.URL.Path)
			g.mu.Unlock()
		}
		if (kind == "post" || kind == "put") && resp.StatusCode >= 200 && resp.StatusCode < 300 && g.losing.Load() {
			g.dropped.Store(true)
			resp.Body.Close()
			return errors.New("fixture: the relay took it, the gateway lost the answer")
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "upstream response lost", http.StatusBadGateway)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := g.refuse.Load(); want != nil && kindOf(r) == *want {
			http.Error(w, "refused by the fixture", g.refusal)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	repointRelay(t, bob.user, srv.URL)
	return g
}

func setStreamThreshold(t *testing.T, u *user, threshold int64) {
	t.Helper()
	s, _, _ := u.opened()
	cfg, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.StreamThreshold = threshold
	if err := s.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

// A reply kept for its retry goes again in the form it was sealed in when
// stream_threshold changes between the two attempts: an envelope whose
// post the relay took, the answer lost or the ledger not written after it,
// with the threshold then lowered under it, is posted again as that
// envelope, and a stream the relay took with the threshold then raised
// over it is resumed as that stream. Decided
// by the threshold at each attempt, the retry sealed the other form under a
// new id, and the asker held two replies for one question and one run of
// the handler.
func TestServeRetryKeepsTheFormItSealedWhenTheThresholdChanges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		length    int
		threshold int64
		streamed  bool
		// never is what the retry must not ask of the relay: the other
		// form's first request.
		never string
		// ledger says the first round's fault is the ledger not written
		// after the post, rather than the relay's answer lost.
		ledger bool
	}{
		{"an envelope, the threshold lowered under it", 8000, stream.MinChunkSize, false, "open ", false},
		{"a stream, the threshold raised over it", 70000, 1 << 20, true, "post ", false},
		{"an envelope not settled, the threshold lowered under it", 8000, stream.MinChunkSize, false, "open ", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.ledger {
				skipUnlessPermissionsHold(t)
			}
			alice, bob := newExpert(t, modeReadOnly)
			marker := filepath.Join(t.TempDir(), "handler-runs")
			t.Setenv(handlerScript, "append:"+marker+";echo:"+strings.Repeat("x", tc.length))
			sent := alice.ask(t, "jostle", "one request", "question")
			g := startFormGateway(t, bob)
			if tc.ledger {
				// The serve directory made read-only after the handler: the
				// reply goes, and the ledger cannot be written after it, so
				// the reply is sent and not settled.
				bob.row.After = `chmod 500 "$AUU_THREAD_DIR/../.."`
				bob.write(t)
				defer os.Chmod(filepath.Join(bob.home, "serve"), 0o700)
			}
			g.losing.Store(!tc.ledger)
			if _, err := bob.tryRun("serve", "--once", "--json"); err == nil {
				t.Fatal("the first round did not fail")
			}
			g.losing.Store(false)
			if !tc.ledger && !g.dropped.Load() {
				t.Fatal("the gateway never lost an answer, so the test proves nothing")
			}
			if err := os.Chmod(filepath.Join(bob.home, "serve"), 0o700); err != nil {
				t.Fatal(err)
			}
			replies := func() []string {
				var ids []string
				for _, m := range alice.inboxJSON().Messages {
					if m.Type == "reply" && m.Thread == sent.Thread {
						if got := alice.stored(store.Inbox, m.ID).Streamed; got != tc.streamed {
							t.Fatalf("reply %s streamed=%v; want %v", m.ID, got, tc.streamed)
						}
						ids = append(ids, m.ID)
					}
				}
				return ids
			}
			first := replies()
			if len(first) != 1 {
				t.Fatalf("the first attempt delivered %d replies, want 1", len(first))
			}

			setStreamThreshold(t, bob.user, tc.threshold)
			g.recording.Store(true)
			report := bob.round(t)
			g.recording.Store(false)
			if len(report.Answered) != 1 {
				t.Fatalf("the retry: %+v", report)
			}
			for _, a := range g.asked() {
				if strings.HasPrefix(a, tc.never) {
					t.Errorf("the retry asked %s, the other form's request", a)
				}
			}
			after := replies()
			if len(after) != 1 || after[0] != first[0] {
				t.Fatalf("one question has replies %v after the retry; want the one, %s", after, first[0])
			}
			if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
				t.Fatalf("the handler ran %d times", runs)
			}
			if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || e.Reply != first[0] {
				t.Fatalf("the ledger's reply is %+v; want %s", e, first[0])
			}
		})
	}
}

// keptForm holds the answer to the form its kept seal is in only when the
// seal is this answer's, the recipient, the channel, the header and the
// files' names and digests, and the mark says an attempt at it may have
// reached the relay. Without the mark the form is free and the seal still
// this answer's; a seal for another recipient or other files is another
// answer's, and says so, with the id of a stream it kept; no seal, or one
// that does not decode, is none; one that cannot be read is the error.
func TestAKeptSealsFormIsTheAnswersAlone(t *testing.T) {
	alice, _, _ := peered(t)
	s, me, _ := alice.opened()
	bob, err := s.Resolve("bob")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(file, []byte("the notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	attachments := []string{file}
	files, err := keptFiles(attachments)
	if err != nil {
		t.Fatal(err)
	}
	body := message.Body{Type: message.TypeReply, Subject: "a question", Thread: strings.Repeat("a", 32),
		InReplyTo: strings.Repeat("b", 32), Text: "the answer"}

	envelopeSeal := func(to string, data []byte) []byte {
		t.Helper()
		a, err := message.NewAttachment("notes.txt", data)
		if err != nil {
			t.Fatal(err)
		}
		full := body
		full.Attachments = []message.Attachment{a}
		recipient := bob
		if to == "self" {
			recipient = me.Public()
		}
		env, inner, err := envelope.SealFor(me, recipient, "", full)
		if err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(keptSeal{Envelope: env, Inner: inner})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	streamSeal := func(to string, kept []keptFile) []byte {
		t.Helper()
		id, err := envelope.NewID()
		if err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(keptSeal{Stream: &keptStream{MessageID: id, To: to, Body: body, Files: kept}})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	otherFile := []keptFile{{Name: "notes.txt", SHA256: strings.Repeat("0", 64)}}

	for _, tc := range []struct {
		name   string
		data   []byte
		marked bool
		form   sealedForm
		other  bool
		stream bool
	}{
		{"no seal", nil, true, keptAsNeither, false, false},
		{"this answer's envelope, posted", envelopeSeal("bob", []byte("the notes")), true, keptAsEnvelope, false, false},
		{"this answer's envelope, refused", envelopeSeal("bob", []byte("the notes")), false, keptAsNeither, false, false},
		{"this answer's stream, posted", streamSeal(bob.Fingerprint(), files), true, keptAsStream, false, true},
		{"this answer's stream, refused", streamSeal(bob.Fingerprint(), files), false, keptAsNeither, false, true},
		{"an envelope for another recipient", envelopeSeal("self", []byte("the notes")), true, keptAsNeither, true, false},
		{"an envelope with other files", envelopeSeal("bob", []byte("other notes")), true, keptAsNeither, true, false},
		{"a stream for another recipient", streamSeal(me.Public().Fingerprint(), files), true, keptAsNeither, true, true},
		{"a stream with other files", streamSeal(bob.Fingerprint(), otherFile), true, keptAsNeither, true, true},
		{"a seal that does not decode", []byte(`{"envelope":`), true, keptAsNeither, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "sealed.json")
			posted := filepath.Join(dir, "posted.json")
			if tc.data != nil {
				if err := os.WriteFile(path, tc.data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.marked {
				if err := os.WriteFile(posted, []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := keptForm(path, posted, bob, "", body, attachments)
			if err != nil || got.form != tc.form || got.other != tc.other || (got.stream != "") != tc.stream ||
				got.streamIsThis != (tc.stream && !tc.other) {
				t.Fatalf("keptForm: %+v, %v; want form %v, other %v, a stream %v", got, err, tc.form, tc.other, tc.stream)
			}
		})
	}
	t.Run("a seal that cannot be read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sealed.json")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if got, err := keptForm(path, "", bob, "", body, attachments); err == nil {
			t.Fatalf("keptForm of a seal that cannot be read: %+v and no error", got)
		}
	})
}

// A reply the relay refused outright, which stored nothing, is not held to
// the form it was refused in: the retry after the threshold changed goes
// in the form the threshold now says, as it did before the kept form
// decided, and the asker holds the one reply. A stream refused at its open
// is given up in the outbox too, so nothing is left there for a send
// --resume to deliver beside the envelope that went.
func TestServeRetryOfARefusedReplyFollowsTheThreshold(t *testing.T) {
	for _, tc := range []struct {
		name      string
		length    int
		refuse    string
		status    int
		threshold int64
		streamed  bool
	}{
		{"an envelope refused, the threshold lowered under it", 8000, "post", http.StatusRequestEntityTooLarge, stream.MinChunkSize, true},
		{"a stream refused at its open, the threshold raised over it", 70000, "open", http.StatusForbidden, 1 << 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alice, bob := newExpert(t, modeReadOnly)
			t.Setenv(handlerScript, "echo:"+strings.Repeat("x", tc.length))
			sent := alice.ask(t, "jostle", "one request", "question")
			g := startFormGateway(t, bob)
			g.refusal = tc.status
			g.refuse.Store(&tc.refuse)
			if _, err := bob.tryRun("serve", "--once", "--json"); err == nil {
				t.Fatal("the first round did not fail")
			}
			g.refuse.Store(nil)
			if _, err := os.Lstat(postedFile(filepath.Join(bob.home, "serve", "kept", sent.Thread), sent.ID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the mark that the reply may have been posted is there after a refusal: %v", err)
			}

			setStreamThreshold(t, bob.user, tc.threshold)
			if report := bob.round(t); len(report.Answered) != 1 {
				t.Fatalf("the retry: %+v", report)
			}
			var got []string
			for _, m := range alice.inboxJSON().Messages {
				if m.Type == "reply" && m.Thread == sent.Thread {
					if s := alice.stored(store.Inbox, m.ID).Streamed; s != tc.streamed {
						t.Fatalf("the reply streamed=%v; want %v, the form the threshold now says", s, tc.streamed)
					}
					got = append(got, m.ID)
				}
			}
			if len(got) != 1 {
				t.Fatalf("one question has replies %v; want one", got)
			}
			if waiting, broken := outboxOf(t, bob.user); len(waiting) != 0 || len(broken) != 0 {
				t.Fatalf("the outbox keeps %d waiting and %v broken after the reply went", len(waiting), broken)
			}
		})
	}
}

// A stream kept for an answer that is no longer this one, its asker's key
// changed between the attempts, is given up in the outbox before the new
// answer goes, so a send --resume by hand has nothing of the old one to
// deliver beside it, and the retry does not upload it.
func TestServeGivesUpAStreamKeptForAnotherAnswer(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	t.Setenv(handlerScript, "echo:"+strings.Repeat("x", 70000))
	sent := alice.ask(t, "jostle", "one request", "question")
	g := startFormGateway(t, bob)
	// The open answered and the upload refused outright: the stream waits
	// in the outbox, never placed.
	g.refusal = http.StatusForbidden
	put := "put"
	g.refuse.Store(&put)
	if _, err := bob.tryRun("serve", "--once", "--json"); err == nil {
		t.Fatal("the first round did not fail")
	}
	g.refuse.Store(nil)
	waiting, _ := outboxOf(t, bob.user)
	if len(waiting) != 1 {
		t.Fatalf("the outbox keeps %d waiting after the refused upload; want the stream", len(waiting))
	}
	old := waiting[0]

	// The kept seal names another recipient, as a key replaced between
	// the attempts leaves it.
	keptDir := filepath.Join(bob.home, "serve", "kept", sent.Thread)
	var k keptSeal
	if err := json.Unmarshal([]byte(readFile(t, sealedFile(keptDir, sent.ID))), &k); err != nil || k.Stream == nil {
		t.Fatalf("the kept seal: %+v, %v", k, err)
	}
	_, bid, _ := bob.opened()
	k.Stream.To = bid.Public().Fingerprint()
	data, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sealedFile(keptDir, sent.ID), data, 0o600); err != nil {
		t.Fatal(err)
	}

	g.recording.Store(true)
	if report := bob.round(t); len(report.Answered) != 1 {
		t.Fatalf("the retry: %+v", report)
	}
	g.recording.Store(false)
	for _, a := range g.asked() {
		if a == "put /v1/uploads/"+old.Upload {
			t.Errorf("the retry uploaded the stream kept for another answer")
		}
	}
	waiting, _ = outboxOf(t, bob.user)
	for _, p := range waiting {
		if p.MessageID == old.MessageID {
			t.Fatalf("the stream kept for another answer still waits in the outbox, for a send --resume to deliver")
		}
	}
	var got []string
	for _, m := range alice.inboxJSON().Messages {
		if m.Type == "reply" && m.Thread == sent.Thread {
			got = append(got, m.ID)
		}
	}
	if len(got) != 1 || got[0] == old.MessageID {
		t.Fatalf("one question has replies %v; want the one new answer, not %s", got, old.MessageID)
	}
}

// A stream's refusal takes the mark away only while no upload of it has
// been opened: once the outbox names one, a 404 is also what the relay
// answers to an attempt at an upload it finished, its earlier answer lost,
// and the stream may be the asker's already. Before one is opened, a
// refusal stored nothing, and the mark goes.
func TestAStreamsRefusalAfterItsUploadOpenedKeepsTheMark(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	t.Setenv(handlerScript, "echo:"+strings.Repeat("x", 70000))
	alice.ask(t, "jostle", "one request", "question")
	g := startFormGateway(t, bob)
	g.refusal = http.StatusForbidden
	put := "put"
	g.refuse.Store(&put)
	if _, err := bob.tryRun("serve", "--once", "--json"); err == nil {
		t.Fatal("the first round did not fail")
	}
	waiting, _ := outboxOf(t, bob.user)
	if len(waiting) != 1 || waiting[0].Upload == "" {
		t.Fatalf("the outbox keeps %+v; want the stream with its upload opened", waiting)
	}
	s, _, _ := bob.opened()
	refused := func() (sentJSON, error) {
		return sentJSON{}, &client.HTTPError{Status: http.StatusNotFound, Message: "no such upload"}
	}
	for _, tc := range []struct {
		name string
		id   string
		kept bool
	}{
		{"its upload opened", waiting[0].MessageID, true},
		{"nothing opened", strings.Repeat("c", 32), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			posted := filepath.Join(t.TempDir(), "posted.json")
			if _, err := markedSend(s, posted, tc.id, refused); err == nil {
				t.Fatal("the refusal was not returned")
			}
			_, err := os.Lstat(posted)
			if kept := err == nil; kept != tc.kept {
				t.Fatalf("after a 404 with %s the mark is there: %v; want %v", tc.name, kept, tc.kept)
			}
		})
	}
}
