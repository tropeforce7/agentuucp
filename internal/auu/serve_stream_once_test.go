package auu

import (
	"encoding/json"
	"errors"
	"io/fs"
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

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// A reply long enough to go as a stream is sealed once and sent under one
// id at every attempt (G46, R57a), as an envelope is (G41, R57). The
// stream was sealed afresh under a new id at each attempt, so a retry
// after the relay took it, the ledger not written after it or the relay's
// answer lost on the way back, gave the asker two replies for one question
// and one run of the handler; seventy thousand characters is an ordinary
// long answer. Codex's review found it. Now the asker holds one, by its
// id. Each retry is a serve of its own, so the id is kept across a restart.
func TestServeRetrySendsAStreamedReplyOnce(t *testing.T) {
	for _, fault := range []string{"ledger write failure", "lost upload response", "finished by send --resume", "sent record lost"} {
		t.Run(fault, func(t *testing.T) {
			ledgerFault := fault == "ledger write failure" || fault == "sent record lost"
			if ledgerFault {
				skipUnlessPermissionsHold(t)
			}
			alice, bob := newExpert(t, modeReadOnly)
			marker := filepath.Join(t.TempDir(), "handler-runs")
			t.Setenv(handlerScript, "append:"+marker+";echo:"+strings.Repeat("x", 70000))
			sent := alice.ask(t, "jostle", "one request", "question")
			var losing, dropped, recording atomic.Bool
			var mu sync.Mutex
			var seen []string
			if ledgerFault {
				// The serve directory made read-only after the handler: the
				// stream goes, and the ledger cannot be written after it.
				bob.row.After = `chmod 500 "$AUU_THREAD_DIR/../.."`
				bob.write(t)
				defer os.Chmod(filepath.Join(bob.home, "serve"), 0o700)
			}
			// A gateway in front of bob's relay that writes down each
			// stream open and upload of the retry, and, for a lost answer,
			// loses the relay's every 2xx to an upload's body through the
			// first round, the in-turn retries' too: the stream is stored,
			// and serve is told it failed.
			_, _, relays := bob.opened()
			target, err := url.Parse(relays[0].URL)
			if err != nil {
				t.Fatal(err)
			}
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.ModifyResponse = func(resp *http.Response) error {
				req := resp.Request
				upload := req.Method == "PUT" && strings.HasPrefix(req.URL.Path, "/v1/uploads/")
				open := req.Method == "POST" && strings.HasSuffix(req.URL.Path, "/streams")
				if recording.Load() && (upload || open) {
					mu.Lock()
					seen = append(seen, req.Method+" "+req.URL.Path)
					mu.Unlock()
				}
				if upload && resp.StatusCode >= 200 && resp.StatusCode < 300 && losing.Load() {
					dropped.Store(true)
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
			losing.Store(!ledgerFault)
			if _, err := bob.tryRun("serve", "--once", "--json"); err == nil {
				t.Fatal("the first round did not fail")
			}
			losing.Store(false)
			if !ledgerFault && !dropped.Load() {
				t.Fatal("the gateway never lost an answer, so the test proves nothing")
			}
			replies := func() []string {
				var ids []string
				for _, m := range alice.inboxJSON().Messages {
					if m.Type == "reply" && m.Thread == sent.Thread {
						if !alice.stored(store.Inbox, m.ID).Streamed {
							t.Fatal("the reply did not go as a stream, so the test proves nothing")
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
			if err := os.Chmod(filepath.Join(bob.home, "serve"), 0o700); err != nil {
				t.Fatal(err)
			}
			// The upload the outbox kept, which a resume asks for first.
			var kept string
			if waiting, _ := outboxOf(t, bob.user); len(waiting) == 1 {
				kept = waiting[0].Upload
			}
			switch fault {
			case "finished by send --resume":
				// The outbox's copy finished by hand between the rounds:
				// serve's retry finds it sent and sends nothing.
				bob.run("send", "--resume")
			case "sent record lost":
				// As a process stopped between the relay's taking the
				// stream and the sent record leaves it: the retry has
				// neither the outbox's copy nor the record, and seals the
				// stream again under the id it kept, which the asker
				// holds as the one reply.
				s, _, _ := bob.opened()
				if err := s.Remove(store.Sent, first[0]); err != nil {
					t.Fatal(err)
				}
			}
			recording.Store(true)
			report := bob.round(t)
			recording.Store(false)
			if len(report.Answered) != 1 {
				t.Fatalf("the retry: %+v", report)
			}
			// What the retry asked of the relay: nothing when the sent box
			// holds the reply, the kept upload first when the outbox does,
			// and a stream sealed again when neither does.
			mu.Lock()
			asked := append([]string(nil), seen...)
			mu.Unlock()
			switch fault {
			case "ledger write failure", "finished by send --resume":
				if len(asked) != 0 {
					t.Errorf("the retry of a reply the relay took asked %v; want nothing sent", asked)
				}
			case "lost upload response":
				if kept == "" || len(asked) == 0 || asked[0] != "PUT /v1/uploads/"+kept {
					t.Errorf("the retry asked %v; want the upload the outbox kept, %q, first", asked, kept)
				}
			case "sent record lost":
				if len(asked) == 0 || !strings.HasSuffix(asked[0], "/streams") {
					t.Errorf("the retry asked %v; want the stream opened again", asked)
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
			if waiting, broken := outboxOf(t, bob.user); len(waiting) != 0 || len(broken) != 0 {
				t.Fatalf("the outbox keeps %d waiting and %v broken after the reply was settled", len(waiting), broken)
			}
		})
	}
}

// TestLimitAKeptStreamIDIsNotAPath: the id a stream reply is kept under is
// read back from serve's own file in the thread's directory and names the
// outbox's files, so sendStreamOnce holds it to message.ValidID before it
// is used: a kept stream whose id is from the traversal set, the rest of it
// the message being sent, is sealed under a new id of its own, and nothing
// is made or removed outside the outbox.
func TestLimitAKeptStreamIDIsNotAPath(t *testing.T) {
	alice, _, _ := peered(t)
	s, me, rs := alice.opened()
	recipient, err := s.Resolve("bob")
	if err != nil {
		t.Fatal(err)
	}
	set := streamSettings{threshold: stream.DefaultThreshold, chunkSize: stream.MinChunkSize}
	body := message.Body{Type: message.TypeNote, Thread: strings.Repeat("a", 32), Text: strings.Repeat("x", 70000)}
	scratch := t.TempDir()
	for _, v := range pathSet() {
		sealed := filepath.Join(scratch, "sealed.json")
		data, err := json.Marshal(keptSeal{Stream: &keptStream{MessageID: v, To: recipient.Fingerprint(), Body: body}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sealed, data, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := sendStreamOnce(s, me, rs[0], recipient, body, nil, set, sendMode{sealed: sealed})
		if err != nil {
			t.Fatalf("kept id %q: %v", v, err)
		}
		if out.ID == v || message.ValidID(out.ID) != nil {
			t.Errorf("kept id %q: the stream went under %q", v, out.ID)
		}
	}
	err = filepath.WalkDir(filepath.Dir(alice.home), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".stream") && filepath.Dir(path) != outboxDir(s) {
			t.Errorf("a sealed stream was made at %s, outside the outbox", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if under, _ := os.ReadDir(scratch); len(under) != 1 {
		t.Errorf("the kept file's directory holds %d entries, want the kept file alone", len(under))
	}
}
