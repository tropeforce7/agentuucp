package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/vouch"
)

// knockJSON is 'auu knock --json': what was sent, to whom, and what this
// machine did afterwards.
type knockJSON struct {
	Relay       string `json:"relay"`
	Fingerprint string `json:"fingerprint"`
	Short       string `json:"short"`
	// ClaimedName is the name the other end put on their card, their own
	// claim; KnownAs is the local label this machine now uses for them.
	ClaimedName string `json:"claimed_name,omitempty"`
	KnownAs     string `json:"known_as"`
	ID          string `json:"id"`
	Thread      string `json:"thread"`
	RelayID     int64  `json:"relay_id"`
	Text        string `json:"text"`
	// AllowPushed says this machine pushed its allow list to the relay
	// after the knock, which it does when it holds a marker for one.
	AllowPushed bool `json:"allow_pushed"`
}

// cmdKnock sends one knock: the first and only message to somebody who has
// not admitted you, carried by the knock route of a relay whose card for
// them says they take knocks.
//
// The order matters and is the plan's. The peer list first, since a knock
// to somebody already known is an ordinary message and is refused here by
// name. Then the target, resolved and verified exactly as 'peers fetch'
// resolves it, printed the same way, with the sentence that says what the
// relay's admission makes of a name found there. Then the person is asked,
// and asked the local name, before anything leaves: a name is a decision
// and a refusal at the prompt must cost nothing. Then the knock is sealed
// and posted. Only then is anything written here: the peer added, and the
// allow list pushed again when this machine holds a marker for that relay,
// so that the reply lands in the inbox rather than the other end's
// quarantine. A command that can fail on something remote does that part
// first and writes once it has succeeded.
func cmdKnock(args []string) error {
	fs := newFlagSet("knock")
	relay := relayFlag(fs)
	text := fs.String("text", "", "one line to say who you are (default: NAME would like to exchange keys)")
	yes := fs.Bool("yes", false, "knock without asking, under the name offered; for a person's own script, never an agent")
	asJSON := fs.Bool("json", false, "machine readable output")
	var vouchers stringList
	fs.Var(&vouchers, "vouch", "carry the vouch this peer gave you (repeatable, at most four)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s knock NAME|SHORT-ID|FINGERPRINT [--text \"...\"] [--vouch PEER]... [--relay NAME] [--yes]", prog)
	}
	if len(vouchers) > message.MaxKnockVouches {
		return usageErrf("a knock carries at most %d vouches; %d were named", message.MaxKnockVouches, len(vouchers))
	}
	query := positional[0]
	// A knock takes no path. It is a request to a mailbox's own relay for
	// its owner's card — the one message somebody who is not yet a peer may
	// send — and it is answered by that relay from what it holds. Nothing
	// carries one to a neighbour, and a bang in the name would otherwise be
	// looked up as a peer and not found, which says nothing about why.
	if path, _ := store.SplitAddress(query); len(path) > 0 {
		return usageErrf("a knock goes to the relay that holds the mailbox and takes no path: "+
			"%q names relays to go by way of", query)
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	// The peer list before the relay is asked anything: a local name, a
	// fingerprint or a short id this machine already knows is somebody to
	// write to with send, and this says so without a request. A name on
	// somebody's card that this machine does not use for them is not
	// found here, and is caught after the look, by fingerprint.
	if query == id.Fingerprint() {
		return usageErrf("that is you")
	}
	if known, err := s.Resolve(query); err == nil {
		return alreadyKnown(query, orNone(known.Name))
	}
	r, err := selectRelay(s, *relay)
	if err != nil {
		return err
	}
	c, err := dial(s, id, r)
	if err != nil {
		return err
	}
	health, err := c.HealthInfo(ctx())
	if err != nil {
		return transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	found, err := findOnRelay(c, r, query)
	if err != nil {
		return err
	}
	out := describeFound(s, id, found.Public, found.Registered, health.Registration)
	// The look is for a person deciding; --json is a script's, and prints
	// one object and nothing else.
	if !*asJSON {
		printFound(out, r, found.Public)
	}
	switch out.KnownAs {
	case "self":
		return usageErrf("that is you")
	case "":
	default:
		return alreadyKnown(found.Public.Short(), out.KnownAs)
	}

	// The text before the question, so that a text the rule refuses costs
	// nothing and nothing is sealed with it.
	said := *text
	if said == "" {
		said = id.Name + " would like to exchange keys"
	}
	carried, err := carriedVouches(s, id, vouchers)
	if err != nil {
		return err
	}
	body := message.Body{Type: message.TypeKnock, Text: said, Name: id.Name, Vouches: carried}
	body.Thread, err = envelope.NewID()
	if err != nil {
		return err
	}
	if err := body.Validate(); err != nil {
		return usageErrf("%v", err)
	}
	// The relay's knock cap, before anything is asked or sent: a knock
	// that would be refused for its size is refused here, with how many
	// vouches to leave off, measured by sealing it rather than estimated.
	if err := knockFits(id, found.Public, body, health.KnockMaxBytes, r.Name); err != nil {
		return err
	}

	if !*asJSON {
		fmt.Printf("\nThe relay is not a trust anchor: the relay %s.\n", registrationMeans(health.Registration, "this identity"))
	}
	if !*yes {
		if !stdinIsTerminal() {
			return usageErrf("knocking adds a peer, which is a person's decision: run this at a terminal, " +
				"or pass --yes from your own script")
		}
		if !confirm(fmt.Sprintf("Knock on %s as %s?", found.Public.Short(), identity.Printable(id.Name))) {
			fmt.Println("nothing sent")
			return nil
		}
	}
	// The local name, asked and checked before the post, as 'peers fetch'
	// asks it: the name that came with the identity is offered when the
	// peer list is not using it for somebody else, and the collision is
	// said before the question so a refusal costs nothing.
	name, takenBy := suggestedName(s, found)
	if takenBy != "" && !*asJSON {
		fmt.Printf("%q is already the name of %s on your peer list, so it is not offered\n",
			found.Suggested, takenBy[:identity.ShortIDLen])
	}
	if !*yes {
		name = promptName(found.Public.Fingerprint(), name)
	}
	pub := found.Public
	pub.Name = name
	// The name is checked against the peer list before the knock goes,
	// not after: AddPeer refuses a name another peer folds to, and that
	// refusal after a delivered knock would leave the knock sent and the
	// peer unadded. promptName has already held it to the export line's
	// rule; this is the other half of what AddPeer refuses.
	if err := s.NameFree(pub); err != nil {
		return usageErrf("%v", err)
	}

	env, inner, err := envelope.SealFor(id, found.Public, "", body)
	if err != nil {
		return usageErrf("%v", err)
	}
	relayID, err := c.Knock(ctx(), env)
	if err != nil {
		return transportErr(fmt.Errorf("%s: %w", r.Name, knockHint(err, found.Public, r)))
	}

	// Posted. Now this machine's own records, in the order that leaves
	// the least wrong if one fails: the peer, then the allow list.
	added, addErr := s.AddPeer(pub)
	if addErr != nil {
		// The knock is gone and cannot be unsent; the export line is
		// what makes the peer addable by hand.
		fmt.Fprintf(os.Stderr, "warning: the knock was sent but the peer could not be added (%v)\n", addErr)
		fmt.Fprintf(os.Stderr, "add them with: %s peers add '%s'\n", prog, pub.ExportLine())
		return &exitError{code: exitUsage, err: fmt.Errorf("the peer was not added")}
	}
	if !added {
		// The peer list gained them between the check at the top and
		// here, which only another process of this home could do.
		fmt.Fprintf(os.Stderr, "note: %s was already on your peer list by the time the knock was sent\n", pub.Short())
	}
	// This machine's own copy of what it sent, as every send keeps one:
	// the reply comes back on this thread, and without the copy the
	// thread would begin at the reply.
	if err := s.Save(store.Sent, &store.Stored{
		RelayID:    relayID,
		Relay:      r.Name,
		Received:   time.Now().UTC().Truncate(time.Second),
		Read:       true,
		Inner:      inner,
		SenderName: pub.Name,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: the knock was sent but the local copy failed: %v\n", err)
	}
	pushed, pushErr := pushAllowAfterKnock(s, id, r, *asJSON)

	if *asJSON {
		if err := printJSON(knockJSON{
			Relay: r.Name, Fingerprint: pub.Fingerprint(), Short: pub.Short(),
			ClaimedName: found.Suggested, KnownAs: pub.Name,
			ID: inner.ID, Thread: body.Thread, RelayID: relayID, Text: said,
			AllowPushed: pushed,
		}); err != nil {
			return err
		}
	} else {
		fmt.Printf("knocked on %s  %s\n", pub.Short(), orNone(pub.Name))
		fmt.Printf("added them to your peer list; they will see your knock in their quarantine\n")
		if pushed {
			fmt.Printf("your allow list went to %s with them in it, so their reply reaches you\n", r.Name)
		}
	}
	return pushErr
}

// alreadyKnown is the refusal for a knock to somebody the peer list has:
// a knock is the first message to a stranger, and a message to a peer is
// what send is for.
func alreadyKnown(query, known string) error {
	return usageErrf("%s is already a peer (%s); use '%s send' to write to them",
		identity.Printable(query), identity.Printable(known), prog)
}

// pushAllowAfterKnock pushes this machine's allow list to the relay the
// knock went through, when this machine holds a marker saying it has
// pushed one there: without it the other end's reply is refused by the
// relay, since the list this machine pushed does not name them yet. With
// no marker the mailbox admits every registered sender and there is
// nothing to do.
//
// A push that fails after the knock has gone is said in one sentence
// naming the repair, and the command exits 2: the knock is delivered and
// cannot be unsent, so this is a thing left undone rather than a failure
// of the knock.
func pushAllowAfterKnock(s *store.Store, id *identity.Identity, r *store.Relay, quiet bool) (pushed bool, err error) {
	if _, found, ferr := s.AllowPushed(r); ferr != nil || !found {
		return false, nil
	}
	peers, couriers, perr := pushAllowTo(s, id, r)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "warning: the knock was sent but your allow list was not pushed to %s (%v)\n", r.Name, perr)
		return false, &exitError{code: exitTransport, err: fmt.Errorf(
			"run '%s allow push --relay %s' so their reply reaches you", prog, r.Name)}
	}
	// The push's own line, except under --json, which owes its caller one
	// object on standard output and nothing else; the object says
	// allow_pushed instead.
	if !quiet {
		fmt.Println(allowPushedLine(r.Name, peers, couriers))
	}
	return true, nil
}

// knockHint turns the relay's refusals into what the person can do. The
// 403 the relay gives a mailbox that takes no knocks is one sentence
// whatever the reason — no card, a card that says no, a card that does
// not verify — so this says what the other person can run, and no more,
// since the state of their card is not ours to report.
func knockHint(err error, pub *identity.Public, r *store.Relay) error {
	if !isNoKnocks(err) {
		return err
	}
	return fmt.Errorf("%w; %s takes no knocks on %s: ask them out of band to run '%s card push --knocks'",
		err, pub.Short(), r.Name, prog)
}

// isNoKnocks reports whether a refusal is the relay's for a mailbox that
// takes no knocks. The status and the code together (ruling 68): a 403 of
// another kind is something else.
func isNoKnocks(err error) bool {
	var httpErr *client.HTTPError
	return errors.As(err, &httpErr) &&
		httpErr.Status == http.StatusForbidden &&
		httpErr.Code == relayapi.CodeNoKnocks
}

// carriedVouches reads the vouch kept from each peer named, and refuses any
// that will not do on a knock: a peer not on the list, no vouch kept from
// them, or one that no longer verifies under the key held for them or no
// longer names this identity. Each is said by name before anything is
// sealed.
func carriedVouches(s *store.Store, id *identity.Identity, names []string) ([]message.Carried, error) {
	var out []message.Carried
	seen := map[string]bool{}
	now := time.Now()
	for _, q := range names {
		v, err := s.Resolve(q)
		if err != nil {
			return nil, usageErrf("%s is not on your peer list, so you hold no vouch from them: %v", q, err)
		}
		if seen[v.Fingerprint()] {
			return nil, usageErrf("%s is named twice; a knock carries one vouch from each voucher", identity.Printable(orNone(v.Name)))
		}
		seen[v.Fingerprint()] = true
		c, err := s.KeptVouch(v.Fingerprint())
		if errors.Is(err, store.ErrNoVouch) {
			return nil, usageErrf("you keep no vouch from %s; they can give you one with: %s vouch <their name for you> --to <the same>",
				identity.Printable(orNone(v.Name)), prog)
		}
		if err != nil {
			return nil, err
		}
		d, err := vouch.Verify(v, c.Document, c.Signature, now)
		if err != nil {
			return nil, usageErrf("the vouch you keep from %s does not verify under the key you hold for them: %s",
				identity.Printable(orNone(v.Name)), identity.PrintableText(err.Error()))
		}
		if d.Subject != id.Fingerprint() {
			return nil, usageErrf("the vouch you keep from %s is not for you", identity.Printable(orNone(v.Name)))
		}
		out = append(out, c)
	}
	return out, nil
}

// knockFits seals a knock that carries vouches as it would be posted and
// holds it to the relay's knock cap. Over it, the vouches are left off one
// at a time and sealed again until it fits, so the sentence says the number
// to drop from real sizes rather than an estimate; a knock over the cap with
// none left says so too. A knock with no vouch is not measured here: what it costs is the text the person
// wrote, and the relay's own refusal names the setting.
func knockFits(id *identity.Identity, to *identity.Public, body message.Body, cap int64, relayName string) error {
	if len(body.Vouches) == 0 {
		return nil
	}
	size := func(n int) (int64, error) {
		b := body
		b.Vouches = body.Vouches[:n]
		env, _, err := envelope.SealFor(id, to, "", b)
		if err != nil {
			return 0, err
		}
		raw, err := json.Marshal(env)
		return int64(len(raw)), err
	}
	n := len(body.Vouches)
	whole, err := size(n)
	if err != nil {
		return err
	}
	if whole <= cap {
		return nil
	}
	for k := n - 1; k >= 0; k-- {
		got, err := size(k)
		if err != nil {
			return err
		}
		if got <= cap {
			return usageErrf("this knock is %d bytes with %d vouches, and %s takes a knock of at most %d: leave off %d of them",
				whole, n, relayName, cap, n-k)
		}
	}
	return usageErrf("this knock is %d bytes, and %s takes a knock of at most %d even with no vouch on it: shorten the text",
		whole, relayName, cap)
}
