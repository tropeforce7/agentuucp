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
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A reply is sealed once and the same envelope is posted at every attempt
// (G41, R57). A retry after a post the relay took, its answer lost on the
// way back or the ledger not written after it, sealed the reply afresh, so
// the asker held two replies under two ids for one question and one run of
// the handler. Now the asker holds one, by its id, whatever the relay
// stored twice.
func TestServeRetryPostsTheSameReplyOnce(t *testing.T) {
	for _, fault := range []string{"lost post response", "ledger write failure"} {
		t.Run(fault, func(t *testing.T) {
			if fault == "ledger write failure" {
				skipUnlessPermissionsHold(t)
			}
			alice, bob := newExpert(t, modeReadOnly)
			marker := filepath.Join(t.TempDir(), "handler-runs")
			t.Setenv(handlerScript, "append:"+marker+";echo:one answer")
			sent := alice.ask(t, "jostle", "one request", "question")
			var dropped atomic.Bool
			if fault == "lost post response" {
				// A gateway in front of the relay that loses the relay's
				// first 2xx to a mailbox post: the reply is stored, and
				// serve is told it failed.
				_, _, relays := bob.opened()
				target, err := url.Parse(relays[0].URL)
				if err != nil {
					t.Fatal(err)
				}
				proxy := httputil.NewSingleHostReverseProxy(target)
				proxy.ModifyResponse = func(resp *http.Response) error {
					if resp.Request.Method == "POST" && strings.HasPrefix(resp.Request.URL.Path, "/v1/mailbox/") &&
						resp.StatusCode >= 200 && resp.StatusCode < 300 && dropped.CompareAndSwap(false, true) {
						resp.Body.Close()
						return errors.New("fixture: the relay took it, the gateway lost the answer")
					}
					return nil
				}
				proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
					http.Error(w, "upstream response lost", http.StatusBadGateway)
				}
				srv := httptest.NewServer(proxy)
				defer srv.Close()
				repointRelay(t, bob.user, srv.URL)
			} else {
				// The serve directory made read-only after the handler: the
				// post goes, and the ledger cannot be written after it.
				bob.row.After = `chmod 500 "$AUU_THREAD_DIR/../.."`
				bob.write(t)
				defer os.Chmod(filepath.Join(bob.home, "serve"), 0o700)
			}
			if _, err := bob.tryRun("serve", "--once", "--json"); err == nil {
				t.Fatal("the first round did not fail")
			}
			if fault == "lost post response" && !dropped.Load() {
				t.Fatal("the gateway never lost an answer, so the test proves nothing")
			}
			replies := func() []string {
				var ids []string
				for _, m := range alice.inboxJSON().Messages {
					if m.Type == "reply" && m.Thread == sent.Thread {
						ids = append(ids, m.ID)
					}
				}
				return ids
			}
			first := replies()
			if len(first) != 1 {
				t.Fatalf("the first attempt delivered %d replies, want 1", len(first))
			}
			if err := os.Chmod(filepath.Join(bob.home, "serve"), 0o700); err != nil {
				t.Fatal(err)
			}
			// The sent box's copy, where the first post got as far as
			// writing it: the retry leaves it as it was.
			keptCopy := func() *store.Stored {
				s, _, _ := bob.opened()
				m, err := s.Holding(store.Sent, first[0])
				if err != nil {
					t.Fatal(err)
				}
				return m
			}
			before := keptCopy()
			report := bob.round(t)
			if len(report.Answered) != 1 {
				t.Fatalf("the retry: %+v", report)
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
			after2 := keptCopy()
			if after2 == nil {
				t.Fatal("the sent box keeps no copy of the reply")
			}
			if before != nil && after2.RelayID != before.RelayID {
				t.Fatalf("the sent copy was written again: relay id %d, was %d", after2.RelayID, before.RelayID)
			}
		})
	}
}

// An envelope kept for an earlier answer to a message is not posted for a
// new one: when the handler runs for the message afresh, the kept envelope
// goes, and the answer that goes out is the one the handler gave.
func TestServeSealsAFreshAnswerAfresh(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	t.Setenv(handlerScript, "echo:the answer this run gave")
	sent := alice.ask(t, "jostle", "a question", "the first")

	// An envelope for alice, sealed by bob for this message, holding words
	// no run of this handler gave: what an earlier answer's would be.
	_, bid, _ := bob.opened()
	_, aid, _ := alice.opened()
	env, inner, err := envelope.SealFor(bid, aid.Public(), "", message.Body{
		Type: message.TypeReply, Subject: "a question", Thread: sent.Thread, InReplyTo: sent.ID,
		Text: "an earlier answer",
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(keptSeal{Envelope: env, Inner: inner})
	if err != nil {
		t.Fatal(err)
	}
	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	if err := os.MkdirAll(threadDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sealedFile(threadDir, sent.ID), data, 0o600); err != nil {
		t.Fatal(err)
	}
	bob.serve(t)
	if reply := alice.replyOn(t, sent.Thread); reply.Text != "the answer this run gave" {
		t.Fatalf("the reply that went out says %q", reply.Text)
	}
}

// A kept envelope that is not the kept answer's, which an earlier auu that
// made the answer again in between would leave, is sealed again: what goes
// out is the answer on disk, never the envelope's other words.
func TestServeSealsAgainAnEnvelopeThatIsNotTheAnswers(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	t.Setenv(handlerScript, "echo:the answer on disk")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")
	captureStderr(t, func() { bob.tryRun("serve", "--once") })
	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	if _, err := os.Stat(filepath.Join(threadDir, "reply-"+sent.ID+".txt")); err != nil {
		t.Fatalf("no reply was kept: %v", err)
	}

	bob.run("peers", "add", alice.exportLine())
	_, bid, _ := bob.opened()
	_, aid, _ := alice.opened()
	env, inner, err := envelope.SealFor(bid, aid.Public(), "", message.Body{
		Type: message.TypeReply, Subject: "a question", Thread: sent.Thread, InReplyTo: sent.ID,
		Text: "another answer to the same question",
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(keptSeal{Envelope: env, Inner: inner})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sealedFile(threadDir, sent.ID), data, 0o600); err != nil {
		t.Fatal(err)
	}
	bob.serve(t)
	if reply := alice.replyOn(t, sent.Thread); reply.Text != "the answer on disk" {
		t.Fatalf("the reply that went out says %q", reply.Text)
	}
}

// A kept envelope that is there and cannot be read is the message's
// failure, never sealed afresh (G41, R57): a fresh seal would be the second
// message under a new id that keeping the envelope is there to prevent.
// Put right, the retry posts it under the id it was kept with.
func TestServeFailsWhenItCannotReadAKeptEnvelope(t *testing.T) {
	skipUnlessPermissionsHold(t)
	alice, bob := newExpert(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:an answer worth keeping")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.run("inbox")
	threadDir := filepath.Join(bob.home, "serve", "threads", sent.Thread)
	sealed := sealedFile(threadDir, sent.ID)
	_, _, relays := bob.opened()
	target, err := url.Parse(relays[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	// A relay that refuses every mailbox post: the post fails after the
	// seal, so the reply and its envelope are kept and nothing reaches
	// alice.
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/mailbox/") {
			http.Error(w, "not now", http.StatusBadRequest)
			return
		}
		httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
	}))
	defer refusing.Close()
	repointRelay(t, bob.user, refusing.URL)
	captureStderr(t, func() { bob.tryRun("serve", "--once") })
	kept := readFile(t, sealed)
	var k keptSeal
	if err := json.Unmarshal([]byte(kept), &k); err != nil || k.Inner == nil {
		t.Fatalf("no envelope was kept: %v", err)
	}
	if err := os.Chmod(sealed, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(sealed, 0o600) })
	repointRelay(t, bob.user, target.String())

	stderr := captureStderr(t, func() { bob.tryRun("serve", "--once") })
	if !strings.Contains(stderr, "the envelope kept for this message could not be read") {
		t.Fatalf("the failure was said as:\n%s", stderr)
	}
	for _, m := range alice.inboxJSON().Messages {
		if m.Type == "reply" && m.Thread == sent.Thread {
			t.Fatalf("a reply went out over an envelope that could not be read: %+v", m)
		}
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times", runs)
	}

	// Put right, the retry posts the kept envelope, under its id.
	if err := os.Chmod(sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := bob.round(t); len(r.Answered) != 1 {
		t.Fatalf("the retry: %+v", r)
	}
	if reply := alice.replyOn(t, sent.Thread); reply.ID != k.Inner.ID {
		t.Fatalf("the reply that went out is %s; want the kept envelope's %s", reply.ID, k.Inner.ID)
	}
}
