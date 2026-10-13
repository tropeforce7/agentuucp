package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An expert on more than one relay fetches them in its relays directory's
// order, and a thread's opener is the first of its messages to arrive on
// this machine. So an ask on another's thread that comes in through a
// relay fetched earlier in the same round is answered as the opener, and
// the real opener is denied their thread. This is the residual the security
// model states (D85, option 1): nothing of the opener's reaches the other
// sender, and S20, which binds a thread to its opening message on the
// wire, is what closes it, a wire change for a release of its own.
//
// Alice opens a new thread T through one of bob's relays. Carol, who
// learned T (every co-recipient of a message to several does), asks on T a
// second and more later through bob's other relay. bob's relays are "work"
// (his default) and "personal", and the round fetches "personal" first.
// With carol on "personal", her later ask arrives first: it is answered
// and carol is recorded as the opener, alice's ask and her follow-up are
// left alone, and carol's reply carries her own text and nothing of
// alice's: not alice's text, not her attachment's name or content, not
// alice's reply, which was never written. With alice on "personal", the
// control, alice keeps her thread, so it is the fetch order that decides.
//
// The day S20 lands, this test is turned round again: alice keeps her
// thread in both cases, as the review's test asserted.
func TestAnAskThroughAnotherRelayIsTheResidualS20Closes(t *testing.T) {
	for _, carolFetchedFirst := range []bool{true, false} {
		name := "alice on work, carol on personal"
		if !carolFetchedFirst {
			name = "alice on personal, carol on work"
		}
		t.Run(name, func(t *testing.T) {
			work, personal := startRelay(t), startRelay(t)
			b := onBothRelays(t, "bob", work, personal)
			aliceURL, carolURL := work, personal
			if !carolFetchedFirst {
				aliceURL, carolURL = personal, work
			}
			alice := newUser(t, "alice", aliceURL)
			carol := newUser(t, "carol", carolURL)
			for _, u := range []*user{alice, carol} {
				u.run("peers", "add", b.exportLine())
				b.run("peers", "add", u.exportLine())
			}
			b.run("channel", "create", "jostle")
			if out, err := b.tryRun("channel", "push", "--relay", "personal"); err != nil {
				t.Logf("channel push --relay personal: %v %s", err, out)
			}
			if out, err := b.tryRun("channel", "push", "--relay", "work"); err != nil {
				t.Logf("channel push --relay work: %v %s", err, out)
			}
			t.Setenv(handlerScript, "echo:the expert has spoken")
			bob := &expert{user: b, dir: repo(t), channel: "jostle"}
			bob.row = &serveChannel{Dir: bob.dir, Exec: helperLine(t, "handler"), Mode: modeReadOnly}
			bob.config = &serveConfig{V: 1, Channels: map[string]*serveChannel{"jostle": bob.row}}
			bob.path = filepath.Join(b.home, serveFile)
			bob.write(t)
			bob.serve(t)

			// The handler echoes what it was given, the message and its
			// facts, so anything of alice's handed to it would be in the
			// reply.
			marker := filepath.Join(t.TempDir(), "runs")
			t.Setenv(handlerScript, "append:"+marker+";cat;echo:;echo:--;env")
			const (
				aliceText   = "alice's own question, for bob alone"
				aliceFile   = "alice-private-notes.txt"
				aliceInFile = "the contents of alice's private notes"
				carolText   = "carol's question, sent after alice's"
			)
			attachment := filepath.Join(t.TempDir(), aliceFile)
			if err := os.WriteFile(attachment, []byte(aliceInFile+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var sent sentJSON
			out := alice.run("send", "--to", "bob", "--channel", "jostle", "--subject", "a question",
				"--attach", attachment, "--json", aliceText)
			if err := json.Unmarshal([]byte(out), &sent); err != nil {
				t.Fatal(err)
			}
			// A second and more after alice's, so that the relays' received
			// stamps (whole seconds) put her first.
			time.Sleep(1100 * time.Millisecond)
			late := carol.askOn(t, "jostle", sent.Thread, "carol's question", carolText)
			report, stderr := bob.roundSaid(t)

			if !carolFetchedFirst {
				if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID {
					t.Fatalf("alice's relay is fetched first; want her ask answered alone: %+v\nstderr:\n%s", report, stderr)
				}
				if o := bob.ledgerOf(t).opener(sent.Thread); o != alice.fingerprint() {
					t.Errorf("alice's relay is fetched first and the opener is %q, want alice", o)
				}
				nothingFromBob(t, carol, bob)
				return
			}

			// The ask through the other relay is answered as the opener.
			if len(report.Answered) != 1 || report.Answered[0].ID != late.ID || len(report.Failed) != 0 {
				t.Fatalf("carol's relay is fetched first; want her ask answered alone: %+v\nstderr:\n%s", report, stderr)
			}
			if o := bob.ledgerOf(t).opener(sent.Thread); o != carol.fingerprint() {
				t.Errorf("the thread's opener is %q, want carol, whose ask arrived first", o)
			}
			if want := leftAlone(sent, "alice", carol.fingerprint()); strings.Count(stderr, want) != 1 {
				t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
			}
			unreadAtBob(t, bob, sent.ID)

			// The real opener's follow-up is not answered either.
			follow := alice.askOn(t, "jostle", sent.Thread, "and again", "alice's follow-up")
			again, stderr := bob.roundSaid(t)
			if len(again.Answered)+len(again.Failed) != 0 {
				t.Errorf("alice's follow-up on her own thread was dealt with: %+v", again)
			}
			if want := leftAlone(follow, "alice", carol.fingerprint()); strings.Count(stderr, want) != 1 {
				t.Errorf("stderr:\n%s\nwant once:\n%s", stderr, want)
			}
			unreadAtBob(t, bob, follow.ID)
			nothingFromBob(t, alice, bob)
			if runs := readFile(t, marker); runs != "handler "+late.ID+" 1\n" {
				t.Errorf("the handler ran other than once, for carol:\n%s", runs)
			}

			// Nothing of alice's reaches carol: her reply is her own
			// message and its facts, with no attachment.
			reply := carol.replyOn(t, sent.Thread)
			text, env, _ := strings.Cut(reply.Text, "\n--\n")
			if text != carolText {
				t.Errorf("the handler was given %q, want carol's text", text)
			}
			for _, leak := range []string{aliceText, aliceFile, aliceInFile, sent.ID, "alice's follow-up"} {
				if strings.Contains(reply.Text, leak) || strings.Contains(reply.Subject, leak) {
					t.Errorf("carol's reply carries %q of alice's:\n%s", leak, reply.Text)
				}
			}
			if len(reply.Attachments) != 0 {
				t.Errorf("carol's reply carries attachments: %+v", reply.Attachments)
			}
			if !strings.Contains(env, "AUU_ATTACHMENTS=\n") || !strings.Contains(env, "AUU_MESSAGE_ID="+late.ID+"\n") {
				t.Errorf("the handler's facts are not carol's message's alone:\n%s", env)
			}
			var in inboxJSON
			if err := json.Unmarshal([]byte(carol.run("inbox", "--json")), &in); err != nil {
				t.Fatal(err)
			}
			for _, m := range in.Messages {
				if m.From != bob.fingerprint() && m.From != carol.fingerprint() {
					t.Errorf("carol holds %s from %s", m.ID[:12], m.FromName)
				}
			}
		})
	}
}
