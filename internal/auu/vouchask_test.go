package auu

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// theAsk is the one vouch question in a user's inbox.
func (u *user) theAsk() *store.Stored {
	u.t.Helper()
	var found *store.Stored
	for _, m := range u.inboxOf() {
		if m.Inner.Body.Type == message.TypeVouchAsk {
			found = m
		}
	}
	if found == nil {
		u.t.Fatal("no question in the inbox")
	}
	return found
}

// vouchesIn are the vouch messages in a user's inbox.
func (u *user) vouchesIn() []*store.Stored {
	u.t.Helper()
	var out []*store.Stored
	for _, m := range u.inboxOf() {
		if m.Inner.Body.Type == message.TypeVouch {
			out = append(out, m)
		}
	}
	return out
}

// The question: rita asks victor whether he holds xena, by fingerprint,
// and victor's inbox says so in both states — about a key he holds, under
// his name for it, and about one he does not.
func TestAQuestionArrivesAndSaysWhatItAsks(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	out := rita.run("vouch", "--ask", "victor", xena.exportFingerprint())
	if !strings.Contains(out, "sent to victor") {
		t.Fatalf("the ask said:\n%s", out)
	}
	listing := victor.run("inbox")
	short := xena.exportFingerprint()[:16]
	if !strings.Contains(listing, "vouch-ask") || !strings.Contains(listing, `asks whether you trust `+short+`… "xena"`) {
		t.Fatalf("victor's inbox:\n%s", listing)
	}
	m := victor.theAsk()
	if m.Inner.Body.About != xena.exportFingerprint() || m.Inner.Body.Subject != "do you trust "+short+"…" {
		t.Fatalf("the question: %+v", m.Inner.Body)
	}
	read := victor.run("read", m.Inner.ID[:12])
	if !strings.Contains(read, "asks:    whether you trust "+xena.exportFingerprint()) ||
		!strings.Contains(read, "you hold them as xena; answer with: auu vouch xena --to rita") {
		t.Fatalf("read:\n%s", read)
	}

	// About somebody victor does not hold: said so, and nothing to answer.
	stranger := newUser(t, "stranger", rita.relayURL())
	rita.run("vouch", "--ask", "victor", stranger.exportFingerprint())
	listing = victor.run("inbox")
	if !strings.Contains(listing, "asks whether you trust "+stranger.exportFingerprint()[:16]+"… (not on your list)") {
		t.Fatalf("a question about a stranger:\n%s", listing)
	}
}

// What a question may name: a fingerprint, or a short id of exactly one
// sender in the quarantine; never the asker, the peer asked, or somebody
// already held.
func TestAQuestionIsAboutSomebodyYouDoNotHold(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	stranger := newUser(t, "stranger", rita.relayURL())
	stranger.run("peers", "add", rita.exportLine())
	stranger.run("send", "--to", "rita", "--subject", "hello", "it is me")
	rita.run("inbox")
	for _, c := range []struct {
		args []string
		says string
	}{
		{[]string{"vouch", "--ask", "nobody", xena.exportFingerprint()}, "nobody is not on your peer list, so you cannot ask them"},
		{[]string{"vouch", "--ask", "victor", victor.exportFingerprint()}, "is the peer you would be asking; ask about somebody else"},
		{[]string{"vouch", "--ask", "victor", rita.exportFingerprint()}, "that is you"},
		{[]string{"vouch", "--ask", "victor", "not-hex"}, `"not-hex" is not a fingerprint or a short id`},
		{[]string{"vouch", "--ask", "victor", xena.exportFingerprint()[:16]}, "begins no sender in your quarantine; give the whole fingerprint"},
		{[]string{"vouch", "--ask", "victor"}, "usage: auu vouch --ask PEER FINGERPRINT|SHORT-ID"},
	} {
		_, err := rita.tryRun(c.args...)
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != exitUsage || !strings.Contains(err.Error(), c.says) {
			t.Errorf("auu %s: %v; want %q", strings.Join(c.args, " "), err, c.says)
		}
	}
	// The short id of a quarantined sender names them.
	rita.run("vouch", "--ask", "victor", stranger.exportFingerprint()[:16])
	victor.run("inbox")
	if got := victor.theAsk().Inner.Body.About; got != stranger.exportFingerprint() {
		t.Fatalf("asked about %s, want the stranger", got)
	}
	// Once rita holds xena, asking about her is refused.
	rita.run("peers", "add", xena.exportLine())
	if _, err := rita.tryRun("vouch", "--ask", "victor", xena.exportFingerprint()); err == nil ||
		!strings.Contains(err.Error(), "you hold "+xena.exportFingerprint()[:16]+"… already, as xena") {
		t.Fatalf("asking about somebody held: %v", err)
	}
}

// The setting: off unless typed for, on writes the key and says what it
// discloses, show reads it, and the config's strict decode is unchanged.
func TestTheAnswerSettingSaysWhatItDiscloses(t *testing.T) {
	victor, _, _ := vouchTrio(t)
	if out := victor.run("vouch", "answer", "show"); out != "vouch_answer: off\n" {
		t.Fatalf("show before: %q", out)
	}
	out := victor.run("vouch", "answer", "on")
	for _, want := range []string{
		"vouch_answer: on",
		"that tells a peer you already trust that the key is on your list",
		"serve's own rounds never answer one",
		"a peer who asks about every key they can see learns which of them you hold, and what you call them",
		"Turn this on only if you are content to tell your peers that.",
		"a key unlocked to receive leaves the question for you",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("on lacks %q:\n%s", want, out)
		}
	}
	data, err := os.ReadFile(filepath.Join(victor.home, "config.json"))
	if err != nil || !strings.Contains(string(data), `"vouch_answer": true`) {
		t.Fatalf("config.json after on: %s, %v", data, err)
	}
	if out := victor.run("vouch", "answer", "show"); out != "vouch_answer: on\n" {
		t.Fatalf("show after: %q", out)
	}
	victor.run("vouch", "answer", "off")
	if data, _ := os.ReadFile(filepath.Join(victor.home, "config.json")); strings.Contains(string(data), "vouch_answer") {
		t.Fatalf("off leaves the key written: %s", data)
	}
	if _, err := victor.tryRun("vouch", "answer", "maybe"); err == nil {
		t.Fatal("answer maybe was taken")
	}
}

// With the setting on, a peer's question about a key on the list is
// answered at the next fetch with an introduction that verifies at the
// asker, and the question is marked read; one about a key not on the list
// is left unread and nothing is sent; with the setting off, nothing is
// sent at all.
func TestTheAutomaticAnswer(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		victor, xena, rita := vouchTrio(t)
		rita.run("vouch", "--ask", "victor", xena.exportFingerprint())
		out := victor.run("inbox")
		if strings.Contains(out, "answered") {
			t.Fatalf("answered with the setting off:\n%s", out)
		}
		rita.run("inbox")
		if n := len(rita.vouchesIn()); n != 0 {
			t.Fatalf("rita has %d vouches with the setting off", n)
		}
	})
	t.Run("on", func(t *testing.T) {
		victor, xena, rita := vouchTrio(t)
		victor.run("vouch", "answer", "on")
		stranger := newUser(t, "stranger", rita.relayURL())
		rita.run("vouch", "--ask", "victor", xena.exportFingerprint())
		rita.run("vouch", "--ask", "victor", stranger.exportFingerprint())
		out := victor.run("inbox")
		if !strings.Contains(out, `answered rita: you hold `+xena.exportFingerprint()[:16]+`… as "xena"`) {
			t.Fatalf("victor's inbox:\n%s", out)
		}
		if strings.Count(out, "answered") != 1 {
			t.Fatalf("more than one question answered:\n%s", out)
		}
		for _, m := range victor.inboxOf() {
			if m.Inner.Body.Type != message.TypeVouchAsk {
				continue
			}
			wantRead := m.Inner.Body.About == xena.exportFingerprint()
			if m.Read != wantRead {
				t.Errorf("the question about %s is read %v, want %v", m.Inner.Body.About[:16], m.Read, wantRead)
			}
		}
		rita.run("inbox")
		got := rita.vouchesIn()
		if len(got) != 1 {
			t.Fatalf("rita has %d vouches, want the one answer", len(got))
		}
		s, _, _ := rita.opened()
		j := judgeVouch(s, got[0], time.Now())
		if j.Doc == nil || j.Doc.Subject != xena.exportFingerprint() || j.Doc.Voucher != victor.exportFingerprint() {
			t.Fatalf("the answer at rita: %+v", j)
		}
		// A second fetch answers nothing more: the question is read.
		if out := victor.run("inbox"); strings.Contains(out, "answered") {
			t.Fatalf("answered twice:\n%s", out)
		}
	})
}

// A question from somebody not on the list is in the quarantine and is
// never answered, whatever the setting.
func TestAQuestionFromAStrangerIsNeverAnswered(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	victor.run("vouch", "answer", "on")
	stranger := newUser(t, "stranger", rita.relayURL())
	stranger.run("peers", "add", victor.exportLine())
	stranger.run("vouch", "--ask", "victor", xena.exportFingerprint())
	out := victor.run("inbox")
	if strings.Contains(out, "answered") {
		t.Fatalf("a stranger's question was answered:\n%s", out)
	}
	held := victor.quarantined()
	if len(held) != 1 || held[0].Inner.Body.Type != message.TypeVouchAsk {
		t.Fatalf("the stranger's question is not in quarantine: %d", len(held))
	}
	stranger.run("inbox")
	for _, m := range stranger.inboxOf() {
		if m.Inner.Body.Type == message.TypeVouch {
			t.Fatal("the stranger was sent a vouch")
		}
	}
}

// With the key unlocked to receive, the question stays, unread, and the
// sentence names the unlock that would answer it: signing a vouch is an
// origination.
func TestAQuestionStaysWhenTheKeyCannotSend(t *testing.T) {
	agentEnv(t)
	victor, xena, rita := vouchTrio(t)
	victor.run("vouch", "answer", "on")
	victor.encrypt()
	rita.run("vouch", "--ask", "victor", xena.exportFingerprint())
	out := victor.run("inbox")
	if !strings.Contains(out, "rita asks whether you trust "+xena.exportFingerprint()[:16]+"…; not answered: ") ||
		!strings.Contains(out, agent.ReceiveOnlyMessage) {
		t.Fatalf("victor's inbox unlocked to receive:\n%s", out)
	}
	if victor.theAsk().Read {
		t.Fatal("an unanswered question was marked read")
	}
	rita.run("inbox")
	if n := len(rita.vouchesIn()); n != 0 {
		t.Fatalf("rita has %d vouches from a key that could not send", n)
	}
}

// auu serve never answers a question, whatever the setting: its rounds are
// the expert's, and a vouch is the person's word.
func TestServeNeverAnswersAQuestion(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	carol := newUser(t, "carol", alice.relayURL())
	bob.run("peers", "add", carol.exportLine())
	bob.run("vouch", "answer", "on")
	s, id, relays := alice.opened()
	bobPub, err := s.Resolve("bob")
	if err != nil {
		t.Fatal(err)
	}
	body := message.Body{Type: message.TypeVouchAsk, Subject: "do you trust", About: carol.exportFingerprint()}
	if err := sealAndSend(s, id, relays[0], bobPub, body, nil, sendMode{inline: true, channel: "jostle"}, true); err != nil {
		t.Fatal(err)
	}
	report := bob.round(t)
	if len(report.Answered) != 0 {
		t.Fatalf("serve answered: %+v", report)
	}
	alice.run("inbox")
	for _, m := range alice.inboxOf() {
		if m.Inner.Body.Type == message.TypeVouch {
			t.Fatal("serve sent a vouch")
		}
	}
	if bob.theAsk().Read {
		t.Fatal("serve marked the question read")
	}
}

// A peer asking about themselves is not answered by the setting: the
// answer would be a vouch for them to keep, which is the person's to give
// and never a reply the client sends by itself.
func TestAQuestionAboutTheAskerIsNotAnswered(t *testing.T) {
	victor, _, rita := vouchTrio(t)
	victor.run("vouch", "answer", "on")
	s, id, relays := rita.opened()
	victorPub, err := s.Resolve("victor")
	if err != nil {
		t.Fatal(err)
	}
	body := message.Body{Type: message.TypeVouchAsk, Subject: "do you trust me", About: rita.exportFingerprint()}
	if err := sealAndSend(s, id, relays[0], victorPub, body, nil, sendMode{inline: true}, true); err != nil {
		t.Fatal(err)
	}
	if out := victor.run("inbox"); strings.Contains(out, "answered") {
		t.Fatalf("a question about the asker was answered:\n%s", out)
	}
	if victor.theAsk().Read {
		t.Fatal("a question about the asker was marked read")
	}
	rita.run("inbox")
	if n := len(rita.vouchesIn()); n != 0 {
		t.Fatalf("rita was sent %d vouches about herself", n)
	}
}

// A peer asking about this machine's own key, crafted, since auu vouch
// --ask refuses it: nothing to answer, said so at the line and at read,
// nothing sent, the question left as it is, and no line at each fetch
// about a signature that would refuse.
func TestAQuestionAboutYouIsNotAnswered(t *testing.T) {
	victor, _, rita := vouchTrio(t)
	victor.run("vouch", "answer", "on")
	s, id, relays := rita.opened()
	victorPub, err := s.Resolve("victor")
	if err != nil {
		t.Fatal(err)
	}
	body := message.Body{Type: message.TypeVouchAsk, Subject: "do you trust yourself", About: victor.exportFingerprint()}
	if err := sealAndSend(s, id, relays[0], victorPub, body, nil, sendMode{inline: true}, true); err != nil {
		t.Fatal(err)
	}
	out := victor.run("inbox")
	if strings.Contains(out, "answered") || !strings.Contains(out, "that is you; there is nothing to answer") {
		t.Fatalf("victor's inbox:\n%s", out)
	}
	if read := victor.run("read", victor.theAsk().Inner.ID[:12]); !strings.Contains(read, "that is you; there is nothing to answer") {
		t.Fatalf("read:\n%s", read)
	}
	rita.run("inbox")
	if n := len(rita.vouchesIn()); n != 0 {
		t.Fatalf("rita was sent %d vouches", n)
	}
}
