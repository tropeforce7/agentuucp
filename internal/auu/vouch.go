package auu

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/vouch"
)

// A vouch is this machine's word that it holds a peer, signed and sent to
// another peer inside an ordinary sealed message. Both ends of it are here:
// sending one (auu vouch, auu introduce), and judging one that arrived
// (the inbox line, auu read, auu peers add --vouched). Nothing here adds a
// peer without a person: the receiver is told what a vouch says and who
// stands behind it, and decides.

// cmdVouch is 'auu vouch X --to R': sign a vouch for X, a peer, and send it
// to R, another peer, as a message of type vouch. Signing is an
// origination, so it needs the key unlocked to send.
func cmdVouch(args []string) error {
	if len(args) > 0 && args[0] == "answer" {
		return vouchAnswer(args[1:])
	}
	fs := newFlagSet("vouch")
	to := fs.String("to", "", "the peer to send the vouch to")
	ask := fs.String("ask", "", "ask this peer whether they hold the key named, instead of vouching")
	relay := relayFlag(fs)
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if *ask != "" {
		if len(positional) != 1 || *to != "" {
			return usageErrf("usage: %s vouch --ask PEER FINGERPRINT|SHORT-ID [--relay NAME]", prog)
		}
		return askVouch(*ask, positional[0], *relay, *asJSON)
	}
	if len(positional) != 1 || *to == "" {
		return usageErrf("usage: %s vouch PEER --to PEER [--relay NAME]", prog)
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	subject, recipient, err := vouchPair(s, id, positional[0], *to)
	if err != nil {
		return err
	}
	return sendVouch(s, id, *relay, subject, recipient, *asJSON)
}

// cmdIntroduce is 'auu introduce X R': two vouches, X to R and R to X, so
// each is told about the other.
func cmdIntroduce(args []string) error {
	fs := newFlagSet("introduce")
	relay := relayFlag(fs)
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 2 {
		return usageErrf("usage: %s introduce PEER PEER [--relay NAME]", prog)
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	a, b, err := vouchPair(s, id, positional[0], positional[1])
	if err != nil {
		return err
	}
	// Both are checked before either is sent, so a refusal sends nothing;
	// the second is sent only if the first was.
	if err := sendVouch(s, id, *relay, a, b, *asJSON); err != nil {
		return err
	}
	return sendVouch(s, id, *relay, b, a, *asJSON)
}

// vouchPair resolves a subject and a recipient, both on the peer list, and
// refuses the pairs that are not an introduction: the same peer twice,
// which is a vouch to keep and not yet sent from here, and this identity
// in either place.
func vouchPair(s *store.Store, id *identity.Identity, subjectQuery, recipientQuery string) (*identity.Public, *identity.Public, error) {
	subject, err := s.Resolve(subjectQuery)
	if err != nil {
		return nil, nil, usageErrf("%s is not on your peer list, so you cannot vouch for them: %v", subjectQuery, err)
	}
	recipient, err := s.Resolve(recipientQuery)
	if err != nil {
		return nil, nil, usageErrf("%s is not on your peer list, so a vouch cannot be sent to them: %v", recipientQuery, err)
	}
	if subject.Fingerprint() == id.Fingerprint() || recipient.Fingerprint() == id.Fingerprint() {
		return nil, nil, usageErrf("a vouch is for one of your peers, to another; neither may be you")
	}
	if subject.Fingerprint() == recipient.Fingerprint() {
		return nil, nil, usageErrf("%s would be vouched for to themselves; introduce two different peers",
			identity.Printable(orNone(subject.Name)))
	}
	return subject, recipient, nil
}

// sendVouch signs this machine's vouch for subject and sends it to
// recipient. The name in it is this machine's own label for the subject,
// which the receiver is offered as a default and is free to refuse.
func sendVouch(s *store.Store, id *identity.Identity, relayName string, subject, recipient *identity.Public, asJSON bool) error {
	r, err := selectRelay(s, relayName)
	if err != nil {
		return err
	}
	name := subject.Name
	if name == "" {
		name = fallbackName(subject.Fingerprint())
	}
	now := time.Now()
	doc, sig, err := vouch.Sign(id, &vouch.Document{
		Subject: subject.Fingerprint(),
		Bundle:  subject.Bundle(),
		Name:    name,
		Issued:  now.UTC(),
	}, now)
	if err != nil {
		// A key locked, or unlocked to receive, says so in the agent's own
		// sentence, which names the unlock.
		return err
	}
	body := message.Body{
		Type:    message.TypeVouch,
		Subject: "vouch for " + name,
		Vouch:   &message.Carried{Document: doc, Signature: sig},
	}
	// Inline: a vouch is one envelope, and a stream has nowhere to carry it.
	return sealAndSend(s, id, r, recipient, body, nil, sendMode{inline: true}, asJSON)
}

// errCarried is a vouch inside a message whose document names somebody
// other than the message's sender as its voucher: a vouch carried for
// somebody else, which is decided where it is carried, on a knock.
var errCarried = errors.New("the vouch inside is not its sender's own")

// judged is what this machine makes of one vouch message.
type judged struct {
	// Doc is the document, set only when the vouch counts: its voucher is
	// the sender, on the peer list, and it verifies under the key this
	// machine holds for them.
	Doc *vouch.Document
	// Why is the sentence for one that does not count.
	Why error
	// Voucher is this machine's name for the voucher.
	Voucher string
	// KnownAs is this machine's name for the subject, when the subject is
	// already a peer, and Self says the subject is this identity.
	KnownAs string
	Known   bool
	Self    bool
}

// judgeVouch applies the rule for whether a vouch counts. The message has
// opened and its sender's signature verified before this runs. Then the
// document's voucher is the sender (a vouch carried for somebody else is
// another thing); the voucher is on the peer list; the signature verifies
// under the key the list holds for them, never the bundle the message
// carried; and the subject is somebody, this identity or a peer or a
// stranger. No chains and no arithmetic.
func judgeVouch(s *store.Store, m *store.Stored, now time.Time) judged {
	c := m.Inner.Body.Vouch
	if m.Inner.Body.Type != message.TypeVouch || c == nil {
		return judged{Why: errors.New("it is not a vouch")}
	}
	parsed, err := vouch.Parse(c.Document)
	if err != nil {
		return judged{Why: err}
	}
	if parsed.Voucher != m.Inner.From {
		return judged{Why: errCarried}
	}
	held, err := s.Resolve(parsed.Voucher)
	if err != nil || held.Fingerprint() != parsed.Voucher {
		return judged{Why: errors.New("its sender is not on your peer list, so nobody you trust stands behind it")}
	}
	d, err := vouch.Verify(held, c.Document, c.Signature, now)
	if err != nil {
		return judged{Why: fmt.Errorf("it does not verify under the key you hold for %s: %v", orNone(held.Name), err)}
	}
	out := judged{Doc: d, Voucher: held.Name}
	if self, err := s.Self(); err == nil && self.Fingerprint() == d.Subject {
		out.Self = true
		return out
	}
	if known, err := s.Resolve(d.Subject); err == nil && known.Fingerprint() == d.Subject {
		out.Known, out.KnownAs = true, known.Name
	}
	return out
}

// vouchLine is what the inbox prints in a vouch message's subject column:
// who is vouched for, under the voucher's name for them, escaped, and what
// they are to this machine.
func vouchLine(j judged) string {
	switch {
	case j.Doc == nil:
		// The sentence can carry what the decoder quoted from a document,
		// so it is escaped as every word from outside is.
		return "a vouch that does not count: " + identity.PrintableText(j.Why.Error())
	case j.Self:
		return "vouched for you"
	case j.Known:
		return fmt.Sprintf("vouches for %q %s… (already your peer as %s)",
			identity.Printable(j.Doc.Name), j.Doc.Subject[:identity.ShortIDLen], identity.Printable(orNone(j.KnownAs)))
	default:
		return fmt.Sprintf("vouches for %q %s… (not on your list)",
			identity.Printable(j.Doc.Name), j.Doc.Subject[:identity.ShortIDLen])
	}
}

// vouchJSON is a vouch message's judgement for --json.
type vouchJSON struct {
	Counts  bool      `json:"counts"`
	Why     string    `json:"why,omitempty"`
	Voucher string    `json:"voucher,omitempty"`
	Subject string    `json:"subject,omitempty"`
	Name    string    `json:"name,omitempty"`
	Issued  time.Time `json:"issued,omitzero"`
	KnownAs string    `json:"known_as,omitempty"`
	You     bool      `json:"you,omitempty"`
}

func vouchToJSON(j judged) *vouchJSON {
	if j.Doc == nil {
		return &vouchJSON{Why: j.Why.Error()}
	}
	return &vouchJSON{Counts: true, Voucher: j.Doc.Voucher, Subject: j.Doc.Subject, Name: j.Doc.Name,
		Issued: j.Doc.Issued, KnownAs: j.KnownAs, You: j.Self}
}

// printVouch is auu read's account of a vouch: what it says, and what it is
// to this machine.
func printVouch(id string, j judged) {
	if j.Doc == nil {
		fmt.Printf("vouch:   does not count: %s\n", identity.PrintableText(j.Why.Error()))
		return
	}
	fmt.Printf("vouch:   %s holds %s under the name %q, as of %s\n",
		identity.Printable(orNone(j.Voucher)), j.Doc.Subject, identity.Printable(j.Doc.Name),
		j.Doc.Issued.Local().Format("2006-01-02 15:04"))
	switch {
	case j.Self:
		fmt.Println("         that is you")
	case j.Known:
		fmt.Printf("         already your peer as %s\n", identity.Printable(orNone(j.KnownAs)))
	default:
		fmt.Printf("         not on your list; add them with: %s peers add --vouched %s\n", prog, id[:12])
	}
}

// peersAddVouched is 'auu peers add --vouched ID [--yes]': add the subject
// of a vouch that counts, at a terminal, under a name the person chooses,
// with the voucher's name for them offered, a comment above the entry
// saying whose word it was, the message marked read, and the allow push
// offered as quarantine trust offers it.
func peersAddVouched(args []string) error {
	fs := newFlagSet("peers add")
	vouched := fs.String("vouched", "", "the id of a vouch message in your inbox")
	yes := fs.Bool("yes", false, "add without asking, under the name offered; for a person's own script, never an agent")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if *vouched == "" || len(positional) != 0 {
		return usageErrf("usage: %s peers add --vouched MESSAGE-ID [--yes]", prog)
	}
	s, _, err := requireIdentity()
	if err != nil {
		return err
	}
	box, m, err := s.Find(*vouched)
	if err != nil {
		return usageErrf("%v", err)
	}
	if m.Inner.Body.Type != message.TypeVouch {
		return usageErrf("%s is a %s, not a vouch", m.Inner.ID[:12], m.Inner.Body.Type)
	}
	if box != store.Inbox {
		return usageErrf("%s is from somebody not on your peer list, so nobody you trust stands behind it; nothing was added",
			m.Inner.ID[:12])
	}
	j := judgeVouch(s, m, time.Now())
	if j.Doc == nil {
		return usageErrf("%s does not count: %s; nothing was added", m.Inner.ID[:12], identity.PrintableText(j.Why.Error()))
	}
	if j.Self {
		return usageErrf("%s is a vouch for you; there is nobody to add", m.Inner.ID[:12])
	}
	if j.Known {
		fmt.Printf("already your peer: %s… %s\n", j.Doc.Subject[:identity.ShortIDLen], identity.Printable(orNone(j.KnownAs)))
		return nil
	}
	voucher := identity.Printable(orNone(j.Voucher))
	fmt.Printf("fingerprint: %s\n", j.Doc.Subject)
	fmt.Printf("vouched for by %s (%s…), who calls them %q\n", voucher, j.Doc.Voucher[:identity.ShortIDLen],
		identity.Printable(j.Doc.Name))
	fmt.Printf("%s is on your list, so this is %s's word for the key.\n", voucher, voucher)
	if !*yes {
		if !stdinIsTerminal() {
			return usageErrf("adding a peer is a person's decision: run this at a terminal, or pass --yes from your own script")
		}
		if !confirm(fmt.Sprintf("Add %s… as a peer?", j.Doc.Subject[:identity.ShortIDLen])) {
			fmt.Println("nothing added")
			return nil
		}
	}
	pub, err := identity.ParseBundle(j.Doc.Bundle)
	if err != nil {
		return err
	}
	// The voucher's name for them is offered when the peer list is not
	// already using it for somebody else, by the rule the knock uses.
	name, takenBy := freeName(s, j.Doc.Subject, j.Doc.Name)
	if takenBy != "" {
		fmt.Printf("%q is already the name of %s on your peer list, so it is not offered\n",
			j.Doc.Name, takenBy[:identity.ShortIDLen])
	}
	if !*yes {
		name = promptName(j.Doc.Subject, name)
	}
	pub.Name = name
	if err := s.NameFree(pub); err != nil {
		return usageErrf("%v", err)
	}
	note := fmt.Sprintf("%s%s (%s) on %s", store.VouchedPrefix, orNone(j.Voucher),
		j.Doc.Voucher[:identity.ShortIDLen], time.Now().Format("2006-01-02"))
	added, err := s.AddPeerNoted(pub, note)
	if err != nil {
		return usageErrf("%v", err)
	}
	if !added {
		fmt.Printf("already known: %s  %s\n", pub.Short(), orNone(pub.Name))
		return nil
	}
	if err := s.MarkRead(box, m.Inner.ID); err != nil {
		return err
	}
	fmt.Printf("added %s  %s, on %s's word\n", pub.Short(), identity.Printable(orNone(pub.Name)), voucher)
	return offerAllowPushFor(s, m, pub.Name)
}

// freeName is the name offered for a subject: the claimed one when no
// other peer folds to it, and otherwise the fallback with the fingerprint
// of the peer using it, so the collision can be said before the question.
// It is knockName's rule with the claim passed in.
func freeName(s *store.Store, fp, claimed string) (name string, takenBy string) {
	if claimed == "" || identity.ValidName(claimed) != nil {
		return fallbackName(fp), ""
	}
	peers, _ := s.Peers()
	for _, other := range peers {
		if other.Fingerprint() != fp && strings.EqualFold(other.Name, claimed) {
			return fallbackName(fp), other.Fingerprint()
		}
	}
	return claimed, ""
}

// askVouch is 'auu vouch --ask V X': ask V, a peer, whether they hold X.
// X is a fingerprint, or a short id that names exactly one sender in the
// quarantine, since the person asking holds no entry for X by definition.
// The answer is a vouch or nothing; there is no signed no.
func askVouch(peerQuery, about, relayName string, asJSON bool) error {
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	asked, err := s.Resolve(peerQuery)
	if err != nil {
		return usageErrf("%s is not on your peer list, so you cannot ask them: %v", peerQuery, err)
	}
	if asked.Fingerprint() == id.Fingerprint() {
		return usageErrf("that is you")
	}
	fp, err := askedAbout(s, about)
	if err != nil {
		return err
	}
	switch {
	case fp == id.Fingerprint():
		return usageErrf("that is you")
	case fp == asked.Fingerprint():
		return usageErrf("%s is the peer you would be asking; ask about somebody else", identity.Printable(orNone(asked.Name)))
	}
	if known, err := s.Resolve(fp); err == nil && known.Fingerprint() == fp {
		return usageErrf("you hold %s… already, as %s", fp[:identity.ShortIDLen], identity.Printable(orNone(known.Name)))
	}
	r, err := selectRelay(s, relayName)
	if err != nil {
		return err
	}
	body := message.Body{
		Type:    message.TypeVouchAsk,
		Subject: "do you trust " + fp[:identity.ShortIDLen] + "…",
		About:   fp,
	}
	return sealAndSend(s, id, r, asked, body, nil, sendMode{inline: true}, asJSON)
}

// askedAbout turns what the person typed into the fingerprint asked about:
// a whole fingerprint as it is, or a short id that begins exactly one
// quarantined sender's fingerprint.
func askedAbout(s *store.Store, about string) (string, error) {
	if identity.ValidFingerprint(about) {
		return about, nil
	}
	if !identity.ValidShortID(about) {
		return "", usageErrf("%q is not a fingerprint or a short id", about)
	}
	held, err := s.List(store.Quarantine)
	if err != nil {
		return "", err
	}
	found := ""
	for _, m := range held {
		if strings.HasPrefix(m.Inner.From, about) && m.Inner.From != found {
			if found != "" {
				return "", usageErrf("%s begins more than one sender in your quarantine; give the whole fingerprint", about)
			}
			found = m.Inner.From
		}
	}
	if found == "" {
		return "", usageErrf("%s begins no sender in your quarantine; give the whole fingerprint", about)
	}
	return found, nil
}

// askLine is the inbox's column for a question: what is asked about, and
// what that key is to this machine.
func askLine(s *store.Store, m *store.Stored) string {
	about := m.Inner.Body.About
	if !identity.ValidFingerprint(about) {
		return "a question about nothing"
	}
	if self, err := s.Self(); err == nil && self.Fingerprint() == about {
		return "that is you; there is nothing to answer"
	}
	if known, err := s.Resolve(about); err == nil && known.Fingerprint() == about {
		return fmt.Sprintf("asks whether you trust %s… %q", about[:identity.ShortIDLen], identity.Printable(orNone(known.Name)))
	}
	return fmt.Sprintf("asks whether you trust %s… (not on your list)", about[:identity.ShortIDLen])
}

// askJSON is a question's account for --json: the fingerprint asked about
// and, when it is on the list, this machine's name for it.
type askJSON struct {
	About   string `json:"about"`
	KnownAs string `json:"known_as,omitempty"`
	Known   bool   `json:"known"`
}

func askToJSON(s *store.Store, m *store.Stored) *askJSON {
	out := &askJSON{About: m.Inner.Body.About}
	if known, err := s.Resolve(out.About); err == nil && known.Fingerprint() == out.About {
		out.Known, out.KnownAs = true, known.Name
	}
	return out
}

// printAsk is auu read's account of a question, with the one command that
// answers it when it can be answered.
func printAsk(s *store.Store, m *store.Stored) {
	about := m.Inner.Body.About
	fmt.Printf("asks:    whether you trust %s\n", about)
	if self, err := s.Self(); err == nil && self.Fingerprint() == about {
		fmt.Println("         that is you; there is nothing to answer")
		return
	}
	if known, err := s.Resolve(about); err == nil && known.Fingerprint() == about {
		fmt.Printf("         you hold them as %s; answer with: %s vouch %s --to %s\n",
			identity.Printable(orNone(known.Name)), prog, identity.Printable(orNone(known.Name)),
			identity.Printable(orNone(m.SenderName)))
		return
	}
	fmt.Println("         not on your list; there is nothing to answer, and silence is the answer")
}

// vouchAnswer is 'auu vouch answer on|off|show': whether this machine
// answers a peer's question by itself.
func vouchAnswer(args []string) error {
	if len(args) != 1 {
		return usageErrf("usage: %s vouch answer on|off|show", prog)
	}
	s, _, err := requireIdentity()
	if err != nil {
		return err
	}
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	switch args[0] {
	case "show":
		fmt.Printf("vouch_answer: %s\n", onOff(cfg.VouchAnswer))
		return nil
	case "on", "off":
		cfg.VouchAnswer = args[0] == "on"
		if err := s.SaveConfig(cfg); err != nil {
			return err
		}
		if cfg.VouchAnswer {
			fmt.Println("vouch_answer: on")
			fmt.Println("auu inbox and auu wait now answer a peer who asks whether you hold a key that is on your list,")
			fmt.Println("by sending them your vouch for it: that tells a peer you already trust that the key is on your list.")
			fmt.Println("Each answer carries your name for the key and your signature, and nothing limits how many a peer may ask:")
			fmt.Println("a peer who asks about every key they can see learns which of them you hold, and what you call them.")
			fmt.Println("Turn this on only if you are content to tell your peers that.")
			fmt.Println("A question about a key you do not hold is left for you; serve's own rounds never answer one;")
			fmt.Println("and signing an answer needs your key unlocked to send, so a key unlocked to receive leaves the question for you.")
			return nil
		}
		fmt.Println("vouch_answer: off; questions are left for you")
		return nil
	default:
		return usageErrf("usage: %s vouch answer on|off|show", prog)
	}
}

// answerAsks is the automatic answer, run by auu inbox and auu wait after
// a fetch and never by serve: with vouch_answer on, each unread question
// from a peer about a key on the list is answered with this machine's
// vouch for that key, sent to the asker by the relay the question came
// through, and marked read, with one line saying so. A question about a key
// not on the list is left as it is and nothing is sent; one from somebody
// not on the list is in the quarantine and never looked at. Signing is an
// origination: a key that cannot sign leaves the question, says why, and
// the rest of the command goes on.
func answerAsks(s *store.Store, id *identity.Identity, out io.Writer) {
	cfg, err := s.Config()
	if err != nil || !cfg.VouchAnswer {
		return
	}
	msgs, err := s.List(store.Inbox)
	if err != nil {
		return
	}
	for _, m := range msgs {
		if m.Read || m.Inner.Body.Type != message.TypeVouchAsk {
			continue
		}
		about := m.Inner.Body.About
		// A question about this identity is nobody's to answer: a voucher
		// does not vouch for themselves, and the signature would only say
		// so at every fetch.
		if about == id.Fingerprint() {
			continue
		}
		subject, err := s.Resolve(about)
		if err != nil || subject.Fingerprint() != about {
			continue
		}
		asker, err := s.Resolve(m.Inner.From)
		if err != nil || asker.Fingerprint() != m.Inner.From || asker.Fingerprint() == about {
			continue
		}
		r, err := relayOf(s, m, "")
		if err != nil {
			continue
		}
		name := subject.Name
		if name == "" {
			name = fallbackName(about)
		}
		now := time.Now()
		doc, sig, err := vouch.Sign(id, &vouch.Document{Subject: about, Bundle: subject.Bundle(), Name: name, Issued: now.UTC()}, now)
		if err == nil {
			body := message.Body{Type: message.TypeVouch, Subject: "vouch for " + name,
				Vouch: &message.Carried{Document: doc, Signature: sig}}
			_, _, err = sendSealed(s, id, r, asker, body, nil, sendMode{inline: true})
		}
		if err != nil {
			fmt.Fprintf(out, "%s asks whether you trust %s…; not answered: %s\n",
				identity.Printable(orNone(asker.Name)), about[:identity.ShortIDLen], identity.PrintableText(err.Error()))
			continue
		}
		if err := s.MarkRead(store.Inbox, m.Inner.ID); err != nil {
			fmt.Fprintf(out, "answered %s, but the question could not be marked read: %v\n", identity.Printable(orNone(asker.Name)), err)
			continue
		}
		fmt.Fprintf(out, "answered %s: you hold %s… as %q\n", identity.Printable(orNone(asker.Name)),
			about[:identity.ShortIDLen], identity.Printable(name))
	}
}
