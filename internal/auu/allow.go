package auu

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// cmdAllow sets who may queue mail for you, on every relay you are on, as
// a list signed by your identity key: the relay verifies it before storing
// it and again every time it enforces it, so a row edited on the relay's
// host refuses everyone rather than admitting a stranger.
//
// Your peer list is one list wherever your mail arrives, so the policy that
// follows from it is one policy. --relay narrows it to a single relay for the
// case where somebody wants two different answers, which is unusual enough to
// have to be asked for.
func cmdAllow(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s allow push|clear|show|add|rm", prog)
	}
	sub, rest := args[0], args[1:]
	// add and rm are about couriers and nothing else. A person's peers are
	// what push sends, and they are added and removed with 'peers add' and
	// 'peers rm', so an allow list has no separate membership of its own to
	// edit; a courier is the one sender that is not a peer, having no place
	// on a peer list because nothing about it is a person.
	if sub == "add" || sub == "rm" {
		return allowCourier(sub, rest)
	}
	if sub != "push" && sub != "clear" && sub != "show" {
		return usageErrf("unknown allow subcommand %q", sub)
	}
	fs := newFlagSet("allow " + sub)
	relay := relayFlag(fs)
	var asJSON *bool
	if sub == "show" {
		asJSON = fs.Bool("json", false, "machine readable output")
	}
	positional, err := parseArgs(fs, rest)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	relays, err := selectedRelays(s, *relay)
	if err != nil {
		return err
	}
	if sub == "show" {
		return allowShow(s, id, relays, *asJSON)
	}

	var peerFPs []string
	if sub == "push" {
		peers, err := s.Peers()
		if err != nil {
			return err
		}
		peerFPs = make([]string, 0, len(peers))
		for _, p := range peers {
			peerFPs = append(peerFPs, p.Fingerprint())
		}
	}
	// The peer list is the same everywhere; the couriers are not. A courier
	// is a relay's own identity enrolled at its neighbour, so the fingerprint
	// that carries mail to one of this identity's relays means nothing at
	// another — which is why the document is built per relay here rather than
	// once outside the loop as it was when the peer list was the whole of it.
	now := time.Now()
	for _, r := range relays {
		fps := peerFPs
		var couriers []store.AdmittedCourier
		if sub == "push" {
			couriers, err = s.Couriers(r.Name)
			if err != nil {
				return err
			}
			fps = withCouriers(peerFPs, couriers, id.Fingerprint())
		}
		d := &allowlist.Document{Issued: now, Senders: fps}
		// The relay's own check, run here on this machine's clock before any
		// request. issued is that clock's now, so it fails only on a clock
		// that steps back between the two readings or stands outside the
		// years this program writes; a hand-signed document is the relay's
		// to refuse.
		if err := allowlist.CheckIssued(d, time.Now()); err != nil {
			return err
		}
		doc, sig, err := allowlist.Sign(id, d)
		if err != nil {
			return err
		}
		c, err := dial(s, id, r)
		if err != nil {
			return err
		}
		err = c.SetAllowlist(ctx(), doc, sig)
		if httpErr, ok := newerHeld(err, relayapi.CodeNewerAllowList); ok {
			// Another machine of this identity pushed a list issued later
			// than now, by its clock. There is nothing to pull: the list is
			// the peer list, and that machine's differs.
			return &exitError{code: exitTransport, err: fmt.Errorf(
				"%s: holds a newer allow list, %s, from another machine of yours; '%s allow show --relay %s' shows it",
				r.Name, issuedWhen(httpErr), prog, r.Name)}
		}
		if err != nil {
			return transportErr(fmt.Errorf("%s: %w", r.Name, err))
		}
		if sub == "push" {
			if err := s.SetAllowPushed(r, now); err != nil {
				return err
			}
			// The counts are of what was signed and not of what the two
			// sources hold: withCouriers drops a fingerprint that is both a
			// peer and a courier, and drops this identity's own, so the file's
			// row count can overstate the document. A line that overstated it
			// would be the one place a person is told their list is wider
			// than it is.
			fmt.Println(allowPushedLine(r.Name, len(fps), signedCouriers(fps, couriers)))
			// What a person needs to hear is about the document that just
			// went, and the document is per relay now, so this is too. An
			// empty one admits every registered sender, which is the warning
			// that matters and which a home with couriers at one relay and
			// none at another would otherwise get wrongly or not at all.
			if len(fps) == 0 {
				fmt.Println("warning: your peer list is empty, so this admits any registered sender; add peers and push again")
			} else if len(peerFPs) == 0 {
				// Not empty, so it does not admit everybody — but everything
				// it admits came through a relay, and a courier admits
				// whoever posts through it.
				fmt.Printf("  it names no peers, so nothing reaches you except mail forwarded through %s\n",
					plural(len(couriers), "courier"))
			}
		} else {
			if err := s.ClearAllowPushed(r); err != nil {
				return err
			}
			fmt.Printf("%s: allow list cleared; any registered user there can queue mail for you\n", r.Name)
		}
	}
	if sub == "clear" {
		fmt.Println("(messages from senders outside your peer list still land in quarantine)")
	}
	return nil
}

// allowPushedLine is what a push says it did, in one place: 'auu allow
// push' prints it, and a command that pushes as part of something else
// prints it or holds it back, as 'auu knock --json' does, which owes its
// caller one object and nothing else.
// allowPushedLine describes the document that was signed, and takes its total
// rather than the two sources' row counts.
//
// The sources overlap and can shrink: withCouriers drops a fingerprint that is
// both a peer and a courier, and drops this identity's own. Counting the rows
// would make the line say the list admits more than it does, which is the one
// place somebody is told how wide their mailbox is now open, so it is the one
// place an overstatement is least affordable.
//
// The couriers are named separately because they are a different kind of
// sender: each admits everybody who can post through that relay, so a reader
// who saw only a total would read a restricted list as narrower than it is.
func allowPushedLine(relay string, signed, couriers int) string {
	if couriers == 0 {
		return fmt.Sprintf("%s will now accept mail for you from %d peer(s) only", relay, signed)
	}
	return fmt.Sprintf("%s will now accept mail for you from %d sender(s), of which %d forward mail to you from other relays",
		relay, signed, couriers)
}

// withCouriers is the senders one relay's document names: this identity's peers
// and the couriers admitted at that relay.
//
// Two things are dropped rather than passed on to be refused. A fingerprint
// that is both a peer and a courier appears once, since a document listing one
// twice is refused by the signer; and this identity's own fingerprint is left
// out, since the owner is always admitted and naming them as a sender is
// refused too. The second can really happen: somebody who runs a relay and is
// a user of their own neighbour would find their own identity in the couriers
// list they just fetched.
func withCouriers(peers []string, couriers []store.AdmittedCourier, own string) []string {
	out := make([]string, 0, len(peers)+len(couriers))
	seen := make(map[string]bool, len(peers)+len(couriers))
	for _, fp := range append(append([]string{}, peers...), courierFPs(couriers)...) {
		if fp == own || seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, fp)
	}
	return out
}

// signedCouriers is how many of those couriers the document really names,
// which is not always how many the file holds: one that is also a peer is
// named once, and this identity's own is not named at all.
func signedCouriers(signed []string, couriers []store.AdmittedCourier) int {
	in := make(map[string]bool, len(signed))
	for _, fp := range signed {
		in[fp] = true
	}
	n := 0
	for _, c := range couriers {
		if in[c.FP] {
			n++
		}
	}
	return n
}

// courierFPs is the fingerprints of those couriers, in order.
func courierFPs(couriers []store.AdmittedCourier) []string {
	out := make([]string, 0, len(couriers))
	for _, c := range couriers {
		out = append(out, c.FP)
	}
	return out
}

// pushAllowTo pushes this machine's peer list to one relay, quietly: the
// same work 'auu allow push --relay NAME' does, without its line, for a
// caller that says the line itself or says nothing. It reports how many
// senders the list names.
func pushAllowTo(s *store.Store, id *identity.Identity, r *store.Relay) (signedCount, courierCount int, err error) {
	peers, err := s.Peers()
	if err != nil {
		return 0, 0, err
	}
	peerFPs := make([]string, 0, len(peers))
	for _, p := range peers {
		peerFPs = append(peerFPs, p.Fingerprint())
	}
	// That relay's couriers as well, and this is the half it is easy to miss:
	// this helper is what a knock and a fetch push with, so a document built
	// from the peer list alone would quietly drop every courier the person had
	// admitted and their forwarded mail would stop arriving, with nothing said
	// and the cause two commands away from the symptom.
	couriers, err := s.Couriers(r.Name)
	if err != nil {
		return 0, 0, err
	}
	fps := withCouriers(peerFPs, couriers, id.Fingerprint())
	now := time.Now()
	d := &allowlist.Document{Issued: now, Senders: fps}
	// The relay's own check, run here before any request, as above.
	if err := allowlist.CheckIssued(d, time.Now()); err != nil {
		return 0, 0, err
	}
	doc, sig, err := allowlist.Sign(id, d)
	if err != nil {
		return 0, 0, err
	}
	c, err := dial(s, id, r)
	if err != nil {
		return 0, 0, err
	}
	if err := c.SetAllowlist(ctx(), doc, sig); err != nil {
		if httpErr, ok := newerHeld(err, relayapi.CodeNewerAllowList); ok {
			return 0, 0, &exitError{code: exitTransport, err: fmt.Errorf(
				"%s: holds a newer allow list, %s, from another machine of yours; '%s allow show --relay %s' shows it",
				r.Name, issuedWhen(httpErr), prog, r.Name)}
		}
		return 0, 0, transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	if err := s.SetAllowPushed(r, now); err != nil {
		return 0, 0, err
	}
	// What was signed, not what the two sources hold: the same reason
	// allowPushedLine takes a total.
	return len(fps), signedCouriers(fps, couriers), nil
}

// newerHeld is the relay's 409 for a push of an allow list or a card when
// it holds one issued later, known by its code (ruling 68): another machine
// of this identity pushed it, and there is nothing to pull.
func newerHeld(err error, code string) (*client.HTTPError, bool) {
	var httpErr *client.HTTPError
	ok := errors.As(err, &httpErr) && httpErr.Status == http.StatusConflict && httpErr.Code == code
	return httpErr, ok
}

// issuedWhen says when the newer allow list or card a relay holds was
// issued, in this zone, from the time its 409 carries as data; a refusal
// without one is said in the relay's own sentence. Nothing is read out of
// the sentence (ruling 68).
func issuedWhen(httpErr *client.HTTPError) string {
	if httpErr.At.IsZero() {
		return httpErr.Message
	}
	return "issued " + stampLocal(httpErr.At)
}

// allowShowJSON is 'auu allow show --json' for one relay.
type allowShowJSON struct {
	Relay   string            `json:"relay"`
	State   string            `json:"state"`
	Issued  *time.Time        `json:"issued,omitempty"`
	Senders []allowSenderJSON `json:"senders"`
	Error   string            `json:"error,omitempty"`
}

type allowSenderJSON struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name,omitempty"`
}

// allowShow fetches what each relay holds for this identity and verifies
// it with this identity's own key, never trusting the relay's parse: a
// pair that does not verify here — a row with no signature included — is
// broken whatever the relay says, and exits 1. A state word this build
// does not know is printed as it came, for the day another is added.
func allowShow(s *store.Store, id *identity.Identity, relays []*store.Relay, asJSON bool) error {
	var (
		out    []allowShowJSON
		broken bool
	)
	for _, r := range relays {
		one := allowShowJSON{Relay: r.Name, Senders: []allowSenderJSON{}}
		c, err := dial(s, id, r)
		var res *client.AllowlistResult
		if err == nil {
			res, err = c.Allowlist(ctx())
		}
		if err != nil {
			return transportErr(fmt.Errorf("%s: %w", r.Name, err))
		}
		var d *allowlist.Document
		switch {
		case res.None:
			one.State = relayapi.AllowNone
		default:
			one.State = relayapi.AllowSigned
			if d, err = allowlist.Verify(id.Public(), res.Document, res.Signature); err != nil {
				one.State, d = relayapi.AllowBroken, nil
			}
		}
		if d != nil {
			issued := d.Issued
			one.Issued = &issued
			for _, fp := range d.Senders {
				one.Senders = append(one.Senders, allowSenderJSON{Fingerprint: fp, Name: s.PeerName(fp)})
			}
		}
		if one.State == relayapi.AllowBroken {
			one.Error = allowWarning(r.Name, one.State, time.Time{}, false)
			broken = true
		}
		out = append(out, one)
	}
	if asJSON {
		if err := printJSON(out); err != nil {
			return err
		}
	} else {
		for _, one := range out {
			printAllowShow(one)
		}
	}
	if broken {
		return &exitError{code: exitUsage, err: errors.New("an allow list does not verify")}
	}
	return nil
}

// printAllowShow is one relay's list as a person reads it: the state, the
// issue time and the count on one line, then the senders by peer name where
// the peer list knows them and by fingerprint otherwise.
func printAllowShow(one allowShowJSON) {
	switch one.State {
	case relayapi.AllowNone:
		fmt.Printf("%s: no allow list; any registered sender may post to you there\n", one.Relay)
		return
	case relayapi.AllowBroken:
		fmt.Printf("%s: %s\n", one.Relay, one.Error)
		return
	case relayapi.AllowSigned:
		fmt.Printf("%s: signed, issued %s, %s\n", one.Relay, stampLocal(*one.Issued), plural(len(one.Senders), "sender"))
	default:
		// A word this build does not know, printed as the relay gave it.
		fmt.Printf("%s: %s\n", one.Relay, one.State)
		return
	}
	if len(one.Senders) == 0 {
		fmt.Println("  nobody is named, so any registered sender may post")
	}
	for _, sender := range one.Senders {
		if sender.Name != "" {
			fmt.Printf("  %s  %s\n", sender.Fingerprint[:identity.ShortIDLen], sender.Name)
		} else {
			fmt.Printf("  %s\n", sender.Fingerprint)
		}
	}
}

// allowWarning is what an owner is told about the state of their list on
// one relay, or nothing. signed is nothing; none is nothing unless this
// machine pushed a list there, in which case the relay has lost it; broken
// is a list that refuses everyone. The listing's word is one of the three
// by the time it reaches here, the client having refused any other.
func allowWarning(relay, state string, pushed time.Time, wasPushed bool) string {
	switch state {
	case relayapi.AllowBroken:
		return fmt.Sprintf("your allow list on %s does not verify, so nobody can post to you there; run %s allow push, and if you did not change it, tell the relay's operator", relay, prog)
	case relayapi.AllowNone:
		if wasPushed {
			return fmt.Sprintf("your allow list on %s is missing, though you pushed one on %s; run %s allow push and tell the relay's operator",
				relay, pushed.Local().Format(time.DateOnly), prog)
		}
	}
	return ""
}

// warnAllowState says, on stderr, what a fetch's listing said about this
// identity's allow list on one relay, when there is something to say.
func warnAllowState(s *store.Store, r *store.Relay, state string) error {
	if state == relayapi.AllowSigned {
		return nil
	}
	pushed, wasPushed, err := s.AllowPushed(r)
	if err != nil {
		return err
	}
	if msg := allowWarning(r.Name, state, pushed, wasPushed); msg != "" {
		fmt.Fprintf(os.Stderr, "%s: %s\n", prog, msg)
	}
	return nil
}

// allowCourier admits or withdraws one relay's courier at one relay: the
// fingerprint that carries somebody else's mail here, which a restricted
// mailbox must admit before anything forwarded can arrive.
//
// It is not a peer, and the difference is the whole reason this is a separate
// subcommand rather than 'peers add'. A peer is a person whose key seals mail
// to you; a courier is a relay whose identity hands an envelope over on
// somebody else's behalf, and it can read nothing. Admitting one says "mail
// that came through this relay may be delivered to me", not "I trust whoever
// sent it" — the sender is inside the envelope and no relay along the way knows
// who it is. That is why admitting a courier admits everybody behind it, which
// is the one place an allow list means something coarser than the fingerprints
// in it, and why the confirmation says so before anything is written.
//
// The name is resolved against the relay's own route and never assumed: a name
// that relay does not list is refused with the names it does, since a courier
// this relay has not got is one no mail can arrive through and a file naming it
// would be a quiet mistake.
func allowCourier(sub string, args []string) error {
	fs := newFlagSet("allow " + sub)
	relay := relayFlag(fs)
	courier := fs.String("courier", "", "the relay whose courier to admit, by the name your relay gives it")
	yes := fs.Bool("yes", false, "admit without asking; for a person's own script, never an agent")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	if *courier == "" {
		return usageErrf("usage: %s allow %s --courier NAME [--relay NAME] [--yes]", prog, sub)
	}
	// The name is held to the rule here, before a relay is dialled, because it
	// is the rule both ends run over the same name. A name that cannot be one
	// is a usage error and not a relay's refusal. It does not become a path
	// segment at this end — only the local relay's name does — so the reason is
	// the shared rule and nothing about directories.
	if err := store.ValidRelayName(*courier); err != nil {
		return usageErrf("%v", err)
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	relays, err := selectedRelays(s, *relay)
	if err != nil {
		return err
	}
	if len(relays) != 1 {
		return usageErrf("admitting a courier is about one relay: name it with --relay, since a courier's " +
			"fingerprint means nothing at another relay")
	}
	r := relays[0]

	if sub == "rm" {
		removed, err := s.RemoveCourier(r.Name, *courier)
		if err != nil {
			return err
		}
		if !removed {
			// relay couriers and not allow show: a courier is not a peer, so
			// allow show prints it as sixty-four characters with no name,
			// which is no use to somebody who has just mistyped a name.
			return usageErrf("%s: %q is not a courier you admit there; '%s relay couriers --relay %s' lists the ones you do",
				r.Name, *courier, prog, r.Name)
		}
		fmt.Printf("%s: no longer admitting %s\n", r.Name, identity.PrintableText(*courier))
		fmt.Printf("  run '%s allow push --relay %s' to make that take effect\n", prog, r.Name)
		return nil
	}

	c, err := dial(s, id, r)
	if err != nil {
		return transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	list, err := c.Couriers(ctx())
	if err != nil {
		return transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	var found *relayapi.Courier
	names := make([]string, 0, len(list))
	for i := range list {
		names = append(names, list[i].Name)
		if list[i].Name == *courier {
			found = &list[i]
		}
	}
	if found == nil {
		if len(names) == 0 {
			return usageErrf("%s accepts no forwarded mail, so it has no couriers to admit", r.Name)
		}
		return usageErrf("%s has no courier called %q; it accepts forwarded mail from %s",
			r.Name, *courier, strings.Join(names, ", "))
	}
	health, err := c.HealthInfo(ctx())
	if err != nil {
		return transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	fmt.Printf("%s: courier %s\n", r.Name, identity.PrintableText(found.Name))
	fmt.Printf("  %s\n", found.FP)
	fmt.Printf("\nThe relay is not a trust anchor: the relay %s.\n", registrationMeans(health.Registration, "this courier"))
	fmt.Printf("Admitting it lets %s deliver mail that came through %s to you, whoever sent it:\n",
		r.Name, identity.PrintableText(found.Name))
	fmt.Println("  a relay cannot open an envelope, so the sender it proves is the neighbour that handed")
	fmt.Println("  it over, and admitting one admits everybody who can post through it.")
	if !*yes {
		if !stdinIsTerminal() {
			return usageErrf("admitting a courier is a person's decision: run this at a terminal, " +
				"or pass --yes from your own script")
		}
		if !confirm(fmt.Sprintf("Admit %s as a courier at %s?", found.Name, r.Name)) {
			fmt.Println("nothing admitted")
			return nil
		}
	}
	if err := s.AddCourier(r.Name, found.FP, found.Name); err != nil {
		return err
	}
	fmt.Printf("\nadmitted %s  %s\n", identity.PrintableText(found.Name), found.FP[:16])
	fmt.Printf("  run '%s allow push --relay %s' to send the list; nothing changes at the relay until you do\n",
		prog, r.Name)
	return nil
}
