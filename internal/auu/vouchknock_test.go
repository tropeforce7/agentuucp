package auu

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/vouch"
)

// knockScene is alice, who takes knocks and holds bob; bob, who holds
// carol and gives her a vouch to keep; carol, a stranger to alice; and
// dave, whom carol holds and alice does not, who gives carol a vouch too.
func knockScene(t *testing.T, relayURL string) (alice, bob, carol, dave *user) {
	t.Helper()
	alice = newUser(t, "alice", relayURL)
	bob = newUser(t, "bob", relayURL)
	carol = newUser(t, "carol", relayURL)
	dave = newUser(t, "dave", relayURL)
	alice.run("card", "push", "--knocks")
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", carol.exportLine())
	dave.run("peers", "add", carol.exportLine())
	carol.run("peers", "add", bob.exportLine())
	carol.run("peers", "add", dave.exportLine())
	bob.run("vouch", "carol", "--to", "carol")
	dave.run("vouch", "carol", "--to", "carol")
	carol.run("inbox")
	return alice, bob, carol, dave
}

// A vouch for you is kept under its voucher's fingerprint, said on its
// line, and replaced by a newer one from the same voucher and not by an
// older one that arrives after it.
func TestAVouchForYouIsKept(t *testing.T) {
	relayURL := startRelay(t)
	_, bob, carol, dave := knockScene(t, relayURL)
	listing := carol.run("inbox", "--no-fetch")
	if !strings.Contains(listing, "bob vouched for you; kept for your knocks") {
		t.Fatalf("carol's inbox:\n%s", listing)
	}
	s, _, _ := carol.opened()
	kept, err := s.KeptVouch(bob.exportFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	first, err := vouch.Parse(kept.Document)
	if err != nil || first.Subject != carol.exportFingerprint() {
		t.Fatalf("the kept vouch: %+v, %v", first, err)
	}
	if _, err := os.Stat(filepath.Join(s.VouchesDir(), bob.exportFingerprint()+".json")); err != nil {
		t.Fatalf("the file: %v", err)
	}

	// An older one, sent after: not kept over the newer.
	bs, bid, relays := bob.opened()
	carolPub, err := bs.Resolve("carol")
	if err != nil {
		t.Fatal(err)
	}
	sendFor := func(subject *identity.Public, issued time.Time) {
		t.Helper()
		doc, sig, err := vouch.Sign(bid, &vouch.Document{Subject: subject.Fingerprint(), Bundle: subject.Bundle(), Name: subject.Name, Issued: issued}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		body := message.Body{Type: message.TypeVouch, Subject: "vouch for carol", Vouch: &message.Carried{Document: doc, Signature: sig}}
		if err := sealAndSend(bs, bid, relays[0], carolPub, body, nil, sendMode{inline: true}, true); err != nil {
			t.Fatal(err)
		}
		carol.run("inbox")
	}
	send := func(issued time.Time) { t.Helper(); sendFor(carolPub, issued) }
	send(first.Issued.Add(-time.Hour))
	kept, _ = s.KeptVouch(bob.exportFingerprint())
	if d, _ := vouch.Parse(kept.Document); !d.Issued.Equal(first.Issued) {
		t.Fatalf("an older vouch replaced the newer: issued %s", d.Issued)
	}
	later := first.Issued.Add(time.Minute)
	send(later)
	kept, _ = s.KeptVouch(bob.exportFingerprint())
	if d, _ := vouch.Parse(kept.Document); !d.Issued.Equal(later) {
		t.Fatalf("a newer vouch did not replace the older: issued %s", d.Issued)
	}

	// An introduction from the same voucher, newer still, is for somebody
	// else: it is not carol's to carry, and the vouch for her stays.
	bob.run("peers", "add", dave.exportLine())
	davePub, err := bs.Resolve("dave")
	if err != nil {
		t.Fatal(err)
	}
	sendFor(davePub, later.Add(time.Minute))
	kept, _ = s.KeptVouch(bob.exportFingerprint())
	if d, _ := vouch.Parse(kept.Document); d.Subject != carol.exportFingerprint() {
		t.Fatalf("an introduction of %s was kept as carol's vouch", d.Subject)
	}
}

// The knock that carries them: alice's quarantine line names bob, whom she
// holds, and counts dave, whom she does not; quarantine trust says whose
// word bob's is before the name is asked, and not dave's.
func TestAKnockCarriesTheVouchesYouKeep(t *testing.T) {
	relayURL := startRelay(t)
	alice, _, carol, _ := knockScene(t, relayURL)
	atTerminal(t)
	// The flag repeated, and after the positional.
	carol.run("knock", alice.exportFingerprint(), "--vouch", "bob", "--vouch", "dave", "--yes")
	alice.run("inbox")
	held := alice.quarantined()
	if len(held) != 1 || len(held[0].Inner.Body.Vouches) != 2 {
		t.Fatalf("alice's quarantine: %d, vouches %d", len(held), len(held[0].Inner.Body.Vouches))
	}
	ls := alice.run("quarantine", "ls")
	if !strings.Contains(ls, "vouched for by bob and 1 you do not know") {
		t.Fatalf("the quarantine line:\n%s", ls)
	}
	var out []messageJSON
	if err := json.Unmarshal([]byte(alice.run("quarantine", "ls", "--json")), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Vouches == nil || len(out[0].Vouches.By) != 1 || out[0].Vouches.By[0] != "bob" || out[0].Vouches.Unknown != 1 {
		t.Fatalf("the quarantine's JSON: %+v", out)
	}
	trust, err := alice.answer("\nn", "quarantine", "trust", held[0].Inner.ID[:12])
	if err != nil {
		t.Fatalf("trust: %v\n%s", err, trust)
	}
	if !strings.Contains(trust, "vouched for by bob: bob is on your list, so this is bob's word for the key") ||
		!strings.Contains(trust, "1 more from people you do not hold, which count for nothing") ||
		strings.Contains(trust, "dave") {
		t.Fatalf("trust:\n%s", trust)
	}
	if !strings.Contains(trust, "Local name for "+carol.exportFingerprint()[:16]) {
		t.Fatalf("the vouches were not said before the name:\n%s", trust)
	}
}

// What --vouch refuses, each before anything is sealed: a peer not on the
// list, one with no vouch kept, five, the same voucher twice, and a kept
// vouch that is not for you or does not verify.
func TestAKnocksVouchesAreHeldBeforeItIsSealed(t *testing.T) {
	relayURL := startRelay(t)
	alice, bob, carol, _ := knockScene(t, relayURL)
	erin := newUser(t, "erin", relayURL)
	carol.run("peers", "add", erin.exportLine())
	s, _, _ := carol.opened()
	for _, c := range []struct {
		args []string
		says string
	}{
		{[]string{"--vouch", "nobody"}, "nobody is not on your peer list, so you hold no vouch from them"},
		{[]string{"--vouch", "erin"}, "you keep no vouch from erin; they can give you one with"},
		{[]string{"--vouch", "bob", "--vouch", "bob"}, "bob is named twice"},
		{[]string{"--vouch", "a", "--vouch", "b", "--vouch", "c", "--vouch", "d", "--vouch", "e"}, "a knock carries at most 4 vouches; 5 were named"},
	} {
		args := append([]string{"knock", alice.exportFingerprint(), "--yes"}, c.args...)
		_, err := carol.tryRun(args...)
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != exitUsage || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%v: %v; want %q", c.args, err, c.says)
		}
	}
	// A kept file whose signature no longer verifies, and one for somebody
	// else, each written over bob's.
	good, err := s.KeptVouch(bob.exportFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.Signature = append([]byte{}, good.Signature...)
	bad.Signature[0] ^= 1
	if err := s.KeepVouch(bob.exportFingerprint(), bad); err != nil {
		t.Fatal(err)
	}
	if _, err := carol.tryRun("knock", alice.exportFingerprint(), "--yes", "--vouch", "bob"); err == nil ||
		!strings.Contains(err.Error(), "the vouch you keep from bob does not verify under the key you hold for them") {
		t.Errorf("a kept vouch that does not verify: %v", err)
	}
	_, bid, _ := bob.opened()
	// A vouch by bob, for erin, put where bob's vouch for carol was.
	erinPub, err := s.Resolve("erin")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	doc, sig, err := vouch.Sign(bid, &vouch.Document{Subject: erinPub.Fingerprint(), Bundle: erinPub.Bundle(), Name: "erin", Issued: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.KeepVouch(bob.exportFingerprint(), message.Carried{Document: doc, Signature: sig}); err != nil {
		t.Fatal(err)
	}
	if _, err := carol.tryRun("knock", alice.exportFingerprint(), "--yes", "--vouch", "bob"); err == nil ||
		!strings.Contains(err.Error(), "the vouch you keep from bob is not for you") {
		t.Errorf("a kept vouch for somebody else: %v", err)
	}
	if held := alice.quarantined(); len(held) != 0 {
		t.Fatalf("a refused knock reached alice: %d", len(held))
	}
}

// A knock over the relay's knock cap is refused before it is sent, with the
// number of vouches to leave off, measured by sealing it: at a cap that
// takes one vouch and not two, carrying two says leave off 1, and one is
// sent.
func TestAKnockOverTheCapSaysHowManyToLeaveOff(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.KnockMaxBytes = 10000
	relayURL := startRelayWith(t, limits)
	alice, _, carol, _ := knockScene(t, relayURL)
	_, err := carol.tryRun("knock", alice.exportFingerprint(), "--yes", "--vouch", "bob", "--vouch", "dave")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage ||
		!strings.Contains(err.Error(), "vouches, and "+carol.relayName()+" takes a knock of at most 10000: leave off 1 of them") {
		t.Fatalf("two vouches over the cap: %v", err)
	}
	if held := alice.quarantined(); len(held) != 0 {
		t.Fatalf("a refused knock reached alice: %d", len(held))
	}
	carol.run("knock", alice.exportFingerprint(), "--yes", "--vouch", "bob")
	alice.run("inbox")
	if held := alice.quarantined(); len(held) != 1 || len(held[0].Inner.Body.Vouches) != 1 {
		t.Fatalf("one vouch under the cap did not arrive")
	}
}

// A cap under the size of any knock: with a vouch, the knock says that it
// does not fit even with every vouch left off; with none, the client does
// not measure it and the relay's own refusal names the setting.
func TestAKnockThatCannotFitSaysSo(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.KnockMaxBytes = 4096
	relayURL := startRelayWith(t, limits)
	alice, _, carol, _ := knockScene(t, relayURL)
	_, err := carol.tryRun("knock", alice.exportFingerprint(), "--yes", "--vouch", "bob")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != exitUsage ||
		!strings.Contains(err.Error(), "takes a knock of at most 4096 even with no vouch on it: shorten the text") {
		t.Errorf("with a vouch: %v", err)
	}
	_, err = carol.tryRun("knock", alice.exportFingerprint(), "--yes")
	if err == nil || !strings.Contains(err.Error(), "knock too large: at most 4096 bytes (knock_max_bytes)") {
		t.Fatalf("a knock with no vouch: %v, want the relay's refusal", err)
	}
	if held := alice.quarantined(); len(held) != 0 {
		t.Fatalf("a refused knock reached alice: %d", len(held))
	}
}

// A knock whose vouch does not verify under the key the receiver holds for
// its voucher, or is for somebody other than the knocker, says so and is
// otherwise a knock: crafted, since carol's own command refuses to send one.
func TestAKnocksVouchThatDoesNotVerifySaysSo(t *testing.T) {
	relayURL := startRelay(t)
	alice, bob, carol, _ := knockScene(t, relayURL)
	cs, _, _ := carol.opened()
	good, err := cs.KeptVouch(bob.exportFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.Signature = append([]byte{}, good.Signature...)
	bad.Signature[0] ^= 1
	as, _, _ := alice.opened()
	m := &store.Stored{Inner: &envelope.Inner{From: carol.exportFingerprint(),
		Body: message.Body{Type: message.TypeKnock, Name: "carol", Text: "hello", Vouches: []message.Carried{bad}}}}
	k := judgeKnockVouches(as, m, time.Now())
	if len(k.Held) != 0 || len(k.Bad) != 1 || k.Bad[0] != "bob" {
		t.Fatalf("a vouch that does not verify: %+v", k)
	}
	if line := knockVouchLine(k); line != "  a vouch that does not verify from bob" {
		t.Fatalf("the line: %q", line)
	}
	// bob's good vouch for carol, presented by somebody else, is for
	// carol and not for them.
	m.Inner.From = bob.exportFingerprint()
	m.Inner.Body.Vouches = []message.Carried{good}
	if k := judgeKnockVouches(as, m, time.Now()); len(k.Held) != 0 || len(k.Bad) != 1 {
		t.Fatalf("a vouch presented by somebody it is not for: %+v", k)
	}
}

// auu serve leaves a knock with vouches alone, as every knock: it is in the
// quarantine, which serve never answers from.
func TestServeLeavesAKnockWithVouchesAlone(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	carol := newUser(t, "carol", alice.relayURL())
	bob.run("card", "push", "--knocks")
	alice.run("peers", "add", carol.exportLine())
	carol.run("peers", "add", alice.exportLine())
	alice.run("vouch", "carol", "--to", "carol")
	carol.run("inbox")
	carol.run("knock", bob.exportFingerprint(), "--yes", "--vouch", "alice")
	bob.run("inbox")
	report := bob.round(t)
	if len(report.Answered) != 0 {
		t.Fatalf("serve answered: %+v", report)
	}
	held := bob.quarantined()
	if len(held) != 1 || len(held[0].Inner.Body.Vouches) != 1 {
		t.Fatalf("the knock is not in bob's quarantine with its vouch: %d", len(held))
	}
}
