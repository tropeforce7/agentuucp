package auu

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/vouch"
)

// vouchTrio is victor, who holds both xena and rita; rita, who holds
// victor and not xena; and xena, who holds victor. Victor can introduce
// xena to rita, and rita's machine will take victor's word for her.
func vouchTrio(t *testing.T) (victor, xena, rita *user) {
	t.Helper()
	relayURL := startRelay(t)
	victor = newUser(t, "victor", relayURL)
	xena = newUser(t, "xena", relayURL)
	rita = newUser(t, "rita", relayURL)
	victor.run("peers", "add", xena.exportLine())
	victor.run("peers", "add", rita.exportLine())
	rita.run("peers", "add", victor.exportLine())
	xena.run("peers", "add", victor.exportLine())
	return victor, xena, rita
}

// inboxOf is what a user's inbox holds, as the store has it.
func (u *user) inboxOf() []*store.Stored {
	u.t.Helper()
	s, _, _ := u.opened()
	msgs, err := s.List(store.Inbox)
	if err != nil {
		u.t.Fatal(err)
	}
	return msgs
}

// theVouch is the one vouch message in a user's inbox.
func (u *user) theVouch() *store.Stored {
	u.t.Helper()
	var found *store.Stored
	for _, m := range u.inboxOf() {
		if m.Inner.Body.Type == message.TypeVouch {
			if found != nil {
				u.t.Fatal("more than one vouch in the inbox")
			}
			found = m
		}
	}
	if found == nil {
		u.t.Fatal("no vouch in the inbox")
	}
	return found
}

func (u *user) peersFile() string {
	u.t.Helper()
	data, err := os.ReadFile(filepath.Join(u.home, "authorized_peers"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		u.t.Fatal(err)
	}
	return string(data)
}

// An introduction: victor's vouch for xena, sent to rita, arrives as a
// message of type vouch that verifies at rita under the key rita holds
// for victor; her inbox says who it is for, under victor's name for them,
// and that she does not hold them; and once she does, it says so.
func TestAnIntroductionArrivesAndVerifies(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	// The flag after the positional, which parseArgs exists for.
	out := victor.run("vouch", "xena", "--to", "rita")
	if !strings.Contains(out, "sent to rita") {
		t.Fatalf("vouch said:\n%s", out)
	}
	listing := rita.run("inbox")
	short := xena.exportFingerprint()[:16]
	if !strings.Contains(listing, "vouch") || !strings.Contains(listing, `vouches for "xena" `+short+`… (not on your list)`) {
		t.Fatalf("rita's inbox:\n%s", listing)
	}
	m := rita.theVouch()
	if m.Inner.Body.Subject != "vouch for xena" {
		t.Errorf("the vouch's subject is %q", m.Inner.Body.Subject)
	}
	// The document verifies under the key rita holds for victor, and is
	// for xena's key with victor's name for her.
	s, _, _ := rita.opened()
	held, err := s.Resolve("victor")
	if err != nil {
		t.Fatal(err)
	}
	d, err := vouch.Verify(held, m.Inner.Body.Vouch.Document, m.Inner.Body.Vouch.Signature, time.Now())
	if err != nil || d.Subject != xena.exportFingerprint() || d.Name != "xena" || d.Voucher != victor.exportFingerprint() {
		t.Fatalf("the vouch at rita: %+v, %v", d, err)
	}
	// read shows what it says; --json carries the judgement.
	read := rita.run("read", m.Inner.ID[:12])
	if !strings.Contains(read, "vouch:   victor holds "+xena.exportFingerprint()+` under the name "xena"`) ||
		!strings.Contains(read, "not on your list; add them with: auu peers add --vouched "+m.Inner.ID[:12]) {
		t.Fatalf("read:\n%s", read)
	}
	var j messageJSON
	if err := json.Unmarshal([]byte(rita.run("read", m.Inner.ID[:12], "--json")), &j); err != nil {
		t.Fatal(err)
	}
	if j.Vouch == nil || !j.Vouch.Counts || j.Vouch.Subject != xena.exportFingerprint() || j.Vouch.Name != "xena" || j.Vouch.KnownAs != "" {
		t.Fatalf("read --json's vouch: %+v", j.Vouch)
	}
	// Once rita holds xena under a name of her own, the line says so.
	rita.run("peers", "add", xena.exportLine())
	s, _, _ = rita.opened()
	m = rita.theVouch()
	if line := vouchLine(judgeVouch(s, m, time.Now())); line != `vouches for "xena" `+short+`… (already your peer as xena)` {
		t.Fatalf("the line once rita holds her: %q", line)
	}
}

// The refusals at the sender, each before anything is signed: a subject
// not on the list, a recipient not on the list, one peer as both, and
// this identity in either place.
func TestAVouchIsForOnePeerToAnother(t *testing.T) {
	victor, _, _ := vouchTrio(t)
	for _, c := range []struct {
		args []string
		says string
	}{
		{[]string{"vouch", "nobody", "--to", "rita"}, "nobody is not on your peer list, so you cannot vouch for them"},
		{[]string{"vouch", "xena", "--to", "nobody"}, "nobody is not on your peer list, so a vouch cannot be sent to them"},
		{[]string{"vouch", "self", "--to", "rita"}, "a vouch is for one of your peers, to another; neither may be you"},
		{[]string{"introduce", "xena", "xena"}, "xena would be vouched for to themselves"},
		{[]string{"vouch", "xena"}, "usage: auu vouch PEER --to PEER"},
	} {
		out, err := victor.tryRun(c.args...)
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != exitUsage || !strings.Contains(err.Error(), c.says) {
			t.Errorf("auu %s: %v\n%s; want %q", strings.Join(c.args, " "), err, out, c.says)
		}
	}
	s, _, _ := victor.opened()
	sent, err := s.List(store.Sent)
	if err != nil || len(sent) != 0 {
		t.Fatalf("a refused vouch sent something: %d, %v", len(sent), err)
	}
}

// introduce is two vouches, one each way.
func TestIntroduceSendsTwo(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	victor.run("introduce", "xena", "rita", "--json")
	xena.run("inbox")
	rita.run("inbox")
	at := xena.theVouch().Inner.Body.Vouch
	d, err := vouch.Parse(at.Document)
	if err != nil || d.Subject != rita.exportFingerprint() {
		t.Fatalf("xena was told about %+v, %v; want rita", d, err)
	}
	d, err = vouch.Parse(rita.theVouch().Inner.Body.Vouch.Document)
	if err != nil || d.Subject != xena.exportFingerprint() {
		t.Fatalf("rita was told about %+v, %v; want xena", d, err)
	}
}

// peers add --vouched through a pipe: n leaves the file as it was; y takes
// the voucher's name for her, writes the comment above the entry, marks
// the message read and offers the push; another name typed is taken; and
// peers rm takes the comment with the entry.
func TestAddingAVouchedPeerAtATerminal(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	atTerminal(t)
	victor.run("vouch", "xena", "--to", "rita")
	rita.run("inbox")
	id := rita.theVouch().Inner.ID[:12]
	before := rita.peersFile()

	out, err := rita.answer("n", "peers", "add", "--vouched", id)
	if err != nil || !strings.Contains(out, "nothing added") {
		t.Fatalf("answered n: %v\n%s", err, out)
	}
	if rita.peersFile() != before {
		t.Fatal("answering n changed the peer list")
	}
	for _, want := range []string{
		"fingerprint: " + xena.exportFingerprint(),
		"vouched for by victor (" + victor.exportFingerprint()[:16] + `…), who calls them "xena"`,
		"victor is on your list, so this is victor's word for the key.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("before the question it lacks %q:\n%s", want, out)
		}
	}

	// y, and the offered name: the comment, the entry, the read mark, and
	// with no allow list pushed, the sentence and no question.
	out, err = rita.answer("y\n", "peers", "add", "--vouched", id)
	if err != nil {
		t.Fatalf("answered y: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Local name for "+xena.exportFingerprint()[:16]+" [xena]: ") ||
		!strings.Contains(out, "added "+xena.exportFingerprint()[:16]) || !strings.Contains(out, "on victor's word") ||
		!strings.Contains(out, "run 'auu allow push' if your relay mailbox is restricted") {
		t.Fatalf("answered y:\n%s", out)
	}
	note := regexp.MustCompile(`(?m)^# vouched for by victor \(` + victor.exportFingerprint()[:16] + `\) on \d{4}-\d{2}-\d{2}\n` +
		regexp.QuoteMeta(strings.SplitN(xena.exportLine(), ".", 3)[0]+"."+strings.SplitN(xena.exportLine(), ".", 3)[1]) + `\.xena\n`)
	if !note.MatchString(rita.peersFile()) {
		t.Fatalf("the comment is not directly above the entry:\n%s", rita.peersFile())
	}
	if !rita.theVouch().Read {
		t.Error("the vouch was not marked read")
	}
	// Taken twice is no second entry.
	out, _ = rita.answer("y\n", "peers", "add", "--vouched", id)
	if !strings.Contains(out, "already your peer") {
		t.Fatalf("adding her again:\n%s", out)
	}

	// peers rm takes the comment with the entry and nothing else.
	rita.run("peers", "rm", "xena")
	if strings.Contains(rita.peersFile(), "vouched for by") || rita.peersFile() != victor.exportLine()+"\n" {
		t.Fatalf("after peers rm:\n%s", rita.peersFile())
	}

	// Another name typed is the name taken.
	out, err = rita.answer("y\nXena-from-victor", "peers", "add", "--vouched", id)
	if err != nil || !strings.Contains(out, "Xena-from-victor") {
		t.Fatalf("another name: %v\n%s", err, out)
	}
	if names := rita.peerNames(); len(names) != 2 || names[1] != "Xena-from-victor" {
		t.Fatalf("the names: %v", names)
	}
}

// A name that folds onto a peer's: the voucher's name is not offered when
// it folds onto one, and a typed name that folds onto one is refused as
// AddPeer refuses it, with nothing written.
func TestAVouchedNameIsHeldToThePeerList(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	atTerminal(t)
	// Rita already calls somebody else XENA.
	other := newUser(t, "other", rita.relayURL())
	s, _, _ := rita.opened()
	pub, err := identity.ParseExportLine(other.exportLine())
	if err != nil {
		t.Fatal(err)
	}
	pub.Name = "XENA"
	if _, err := s.AddPeer(pub); err != nil {
		t.Fatal(err)
	}
	victor.run("vouch", "xena", "--to", "rita")
	rita.run("inbox")
	id := rita.theVouch().Inner.ID[:12]
	before := rita.peersFile()
	out, err := rita.answer("y\nvictor", "peers", "add", "--vouched", id)
	if !strings.Contains(out, `"xena" is already the name of `+other.exportFingerprint()[:16]+" on your peer list, so it is not offered") ||
		!strings.Contains(out, "Local name for "+xena.exportFingerprint()[:16]+" [peer-"+xena.exportFingerprint()[:8]+"]: ") {
		t.Fatalf("the offer:\n%s", out)
	}
	var exit *exitError
	if !errors.As(err, &exit) || !strings.Contains(err.Error(), `peer name "victor" is already used by`) {
		t.Fatalf("a typed name that folds onto a peer's: %v", err)
	}
	if rita.peersFile() != before {
		t.Fatal("a refused name changed the peer list")
	}
}

// A vouch from somebody not on the list is quarantined, and peers add
// --vouched refuses it by name with nothing written; one whose voucher is
// not its sender is a carried vouch, and counts for nothing when its
// voucher is not on the list either, whoever carried it.
func TestAVouchFromNobodyYouTrustAddsNobody(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	atTerminal(t)
	stranger := newUser(t, "stranger", rita.relayURL())
	stranger.run("peers", "add", xena.exportLine())
	stranger.run("peers", "add", rita.exportLine())
	stranger.run("vouch", "xena", "--to", "rita")
	rita.run("inbox")
	held := rita.quarantined()
	if len(held) != 1 || held[0].Inner.Body.Type != message.TypeVouch {
		t.Fatalf("quarantine: %d", len(held))
	}
	before := rita.peersFile()
	_, err := rita.answer("y\n", "peers", "add", "--vouched", held[0].Inner.ID[:12])
	if err == nil || !strings.Contains(err.Error(), "is from somebody not on your peer list, so nobody you trust stands behind it; nothing was added") {
		t.Fatalf("a vouch from a stranger: %v", err)
	}
	if rita.peersFile() != before {
		t.Fatal("a refused vouch changed the peer list")
	}

	// A vouch signed by xena, for victor, carried in a message from victor:
	// its voucher is not its sender.
	s, id, relays := victor.opened()
	_, xid, _ := xena.opened()
	ritaPub, err := s.Resolve("rita")
	if err != nil {
		t.Fatal(err)
	}
	self, err := s.Self()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	doc, sig, err := vouch.Sign(xid, &vouch.Document{Subject: self.Fingerprint(), Bundle: self.Bundle(), Name: "victor", Issued: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	body := message.Body{Type: message.TypeVouch, Subject: "vouch for victor", Vouch: &message.Carried{Document: doc, Signature: sig}}
	if err := sealAndSend(s, id, relays[0], ritaPub, body, nil, sendMode{inline: true}, true); err != nil {
		t.Fatal(err)
	}
	listing := rita.run("inbox")
	if !strings.Contains(listing, "a vouch that does not count: its voucher is not on your peer list, so nobody you trust stands behind it") {
		t.Fatalf("a carried vouch in the inbox:\n%s", listing)
	}
	var carried *store.Stored
	for _, m := range rita.inboxOf() {
		if m.Inner.Body.Type == message.TypeVouch && m.Inner.Body.Subject == "vouch for victor" {
			carried = m
		}
	}
	_, err = rita.answer("y\n", "peers", "add", "--vouched", carried.Inner.ID[:12])
	if err == nil || !strings.Contains(err.Error(), "does not count: its voucher is not on your peer list, so nobody you trust stands behind it; nothing was added") {
		t.Fatalf("a carried vouch: %v", err)
	}
	if rita.peersFile() != before {
		t.Fatal("a carried vouch changed the peer list")
	}
}

// Without a terminal and without --yes, the person's decision is refused
// in peers fetch's words; with --yes, the offered name is taken.
func TestAVouchedPeerWithoutATerminal(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	victor.run("vouch", "xena", "--to", "rita")
	rita.run("inbox")
	id := rita.theVouch().Inner.ID[:12]
	_, err := rita.tryRun("peers", "add", "--vouched", id)
	if err == nil || !strings.Contains(err.Error(), "adding a peer is a person's decision: run this at a terminal, or pass --yes from your own script") {
		t.Fatalf("no terminal, no --yes: %v", err)
	}
	if strings.Contains(rita.peersFile(), xena.exportFingerprint()[:16]) {
		t.Fatal("refused, and added anyway")
	}
	rita.run("peers", "add", "--vouched", id, "--yes")
	if names := rita.peerNames(); len(names) != 2 || names[1] != "xena" {
		t.Fatalf("--yes: %v", names)
	}
}

// The allow push is offered when this machine has pushed a list there,
// and answered y it admits the new peer, n leaves the relay as it was.
func TestAVouchedPeerIsOfferedThePush(t *testing.T) {
	for _, answer := range []string{"n", "y"} {
		t.Run(answer, func(t *testing.T) {
			victor, _, rita := vouchTrio(t)
			atTerminal(t)
			rita.run("allow", "push")
			victor.run("vouch", "xena", "--to", "rita")
			rita.run("inbox")
			id := rita.theVouch().Inner.ID[:12]
			out, err := rita.answer("y\n\n"+answer, "peers", "add", "--vouched", id)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if !strings.Contains(out, "Push your allow list to "+rita.relayName()+" now, so xena can write to you? [y/N]: ") {
				t.Fatalf("no offer:\n%s", out)
			}
			pushed := strings.Contains(out, "will now accept mail for you from 2 peer(s) only")
			if pushed != (answer == "y") {
				t.Fatalf("answered %s, pushed %v:\n%s", answer, pushed, out)
			}
		})
	}
}

// What a vouch's name does at a terminal: the escaper runs where the line
// is made, so a name a document could not carry under its rule is still
// shown escaped if a record held one.
func TestAVouchLineIsEscaped(t *testing.T) {
	j := judged{Doc: &vouch.Document{Subject: strings.Repeat("4c", 32), Name: "x\x1b[31mred"}}
	line := vouchLine(j)
	if strings.ContainsRune(line, 0x1b) {
		t.Fatalf("an escape reached the line: %q", line)
	}
	j.Known, j.KnownAs = true, "y\x1b]0;title\x07"
	if line := vouchLine(j); strings.ContainsRune(line, 0x1b) || strings.ContainsRune(line, 0x07) {
		t.Fatalf("an escape reached the line: %q", line)
	}
}

// auu serve answers asks and replies and leaves every vouch type alone: a
// vouch and a vouch question on the served channel are left in the inbox
// unanswered, whatever the round.
func TestServeLeavesVouchesAlone(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	carol := newUser(t, "carol", alice.relayURL())
	alice.run("peers", "add", carol.exportLine())
	s, id, relays := alice.opened()
	bobPub, err := s.Resolve("bob")
	if err != nil {
		t.Fatal(err)
	}
	carolPub, err := s.Resolve("carol")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	doc, sig, err := vouch.Sign(id, &vouch.Document{Subject: carolPub.Fingerprint(), Bundle: carolPub.Bundle(), Name: "carol", Issued: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []message.Body{
		{Type: message.TypeVouch, Subject: "vouch for carol", Vouch: &message.Carried{Document: doc, Signature: sig}},
		{Type: message.TypeVouchAsk, Subject: "do you trust", About: carolPub.Fingerprint()},
	} {
		if err := sealAndSend(s, id, relays[0], bobPub, body, nil, sendMode{inline: true, channel: "jostle"}, true); err != nil {
			t.Fatal(err)
		}
	}
	bob.run("inbox")
	report := bob.round(t)
	if len(report.Answered) != 0 || len(report.Failed) != 0 {
		t.Fatalf("serve answered a vouch: %+v", report)
	}
	types := map[string]bool{}
	for _, m := range bob.inboxOf() {
		types[m.Inner.Body.Type] = true
	}
	if !types[message.TypeVouch] || !types[message.TypeVouchAsk] {
		t.Fatalf("the vouches are not left in the inbox: %v", types)
	}
}

// A vouch from a peer that names that peer as its voucher and does not
// verify under the key held for them does not count, and adds nobody: one
// bit of its signature flipped is enough, since the shape still holds and
// the message still opens.
func TestAVouchThatDoesNotVerifyDoesNotCount(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	atTerminal(t)
	s, id, relays := victor.opened()
	ritaPub, err := s.Resolve("rita")
	if err != nil {
		t.Fatal(err)
	}
	xenaPub, err := s.Resolve("xena")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	doc, sig, err := vouch.Sign(id, &vouch.Document{Subject: xenaPub.Fingerprint(), Bundle: xenaPub.Bundle(), Name: "xena", Issued: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	sig[len(sig)/2] ^= 1
	body := message.Body{Type: message.TypeVouch, Subject: "vouch for xena", Vouch: &message.Carried{Document: doc, Signature: sig}}
	if err := sealAndSend(s, id, relays[0], ritaPub, body, nil, sendMode{inline: true}, true); err != nil {
		t.Fatal(err)
	}
	listing := rita.run("inbox")
	if !strings.Contains(listing, "a vouch that does not count: it does not verify under the key you hold for victor") {
		t.Fatalf("rita's inbox:\n%s", listing)
	}
	before := rita.peersFile()
	_, err = rita.answer("y\n", "peers", "add", "--vouched", rita.theVouch().Inner.ID[:12])
	if err == nil || !strings.Contains(err.Error(), "does not count: it does not verify under the key you hold for victor") {
		t.Fatalf("adding on a vouch that does not verify: %v", err)
	}
	if rita.peersFile() != before || strings.Contains(rita.peersFile(), xena.exportFingerprint()[:16]) {
		t.Fatal("a vouch that does not verify changed the peer list")
	}
}

// A vouch counts only while its voucher is on the list: one that arrived
// while victor was rita's peer counts for nothing once she has removed
// him, at the inbox and at peers add --vouched, with nothing written.
func TestAVouchStopsCountingWhenItsVoucherIsRemoved(t *testing.T) {
	victor, _, rita := vouchTrio(t)
	atTerminal(t)
	victor.run("vouch", "xena", "--to", "rita")
	rita.run("inbox")
	id := rita.theVouch().Inner.ID[:12]
	rita.run("peers", "rm", "victor")
	before := rita.peersFile()
	s, _, _ := rita.opened()
	if line := vouchLine(judgeVouch(s, rita.theVouch(), time.Now())); line != "a vouch that does not count: its sender is not on your peer list, so nobody you trust stands behind it" {
		t.Fatalf("the line once victor is gone: %q", line)
	}
	_, err := rita.answer("y\n", "peers", "add", "--vouched", id)
	if err == nil || !strings.Contains(err.Error(), "does not count: its sender is not on your peer list, so nobody you trust stands behind it; nothing was added") {
		t.Fatalf("adding on the word of somebody removed: %v", err)
	}
	if rita.peersFile() != before {
		t.Fatal("a vouch from a removed voucher changed the peer list")
	}
}

// A carried vouch counts when its voucher is held, whoever carried it: xena
// gives victor a vouch for himself to keep, victor carries it to rita in a
// message of his own, and rita, who holds xena, reads it as xena's word,
// carried by victor.
func TestACarriedVouchCountsWhenItsVoucherIsHeld(t *testing.T) {
	victor, xena, rita := vouchTrio(t)
	rita.run("peers", "add", xena.exportLine())
	xena.run("vouch", "victor", "--to", "victor")
	victor.run("inbox")
	kept, err := func() (message.Carried, error) {
		s, _, _ := victor.opened()
		return s.KeptVouch(xena.exportFingerprint())
	}()
	if err != nil {
		t.Fatalf("victor did not keep xena's vouch for him: %v", err)
	}
	s, id, relays := victor.opened()
	ritaPub, err := s.Resolve("rita")
	if err != nil {
		t.Fatal(err)
	}
	body := message.Body{Type: message.TypeVouch, Subject: "xena vouches for me", Vouch: &kept}
	if err := sealAndSend(s, id, relays[0], ritaPub, body, nil, sendMode{inline: true}, true); err != nil {
		t.Fatal(err)
	}
	listing := rita.run("inbox")
	if !strings.Contains(listing, "(already your peer as victor), xena's vouch carried by victor") {
		t.Fatalf("rita's inbox:\n%s", listing)
	}
}
