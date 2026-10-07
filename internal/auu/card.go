package auu

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// cmdCard says, on every relay you are on, whether the relay may list you
// to every registered identity and whether your mailbox takes knocks from
// senders your allow list does not name, as a card signed by your identity
// key: the relay verifies it before storing it and again every time it
// lets a knock through, and a reader of the listing verifies it against
// your bundle, so a row edited on the relay's host unlists you and closes
// your mailbox rather than the reverse.
//
// The card this machine last pushed is card.json, and a bare push signs
// and pushes it again: the repair the inbox names when a relay has lost
// it. --listed and --knocks change what it says, --listed=false and
// --knocks=false the other way, and only a flag actually typed changes
// anything. --relay narrows the push to one relay, which is unusual enough
// to have to be asked for.
func cmdCard(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s card push|clear|show", prog)
	}
	sub, rest := args[0], args[1:]
	if sub != "push" && sub != "clear" && sub != "show" {
		return usageErrf("unknown card subcommand %q", sub)
	}
	fs := newFlagSet("card " + sub)
	var asJSON, listed, knocks *bool
	// A clear is every relay, and takes no --relay: a card that says
	// nothing on one relay and something on another is not what the file
	// could say.
	relay := new(string)
	switch sub {
	case "show":
		relay = relayFlag(fs)
		asJSON = fs.Bool("json", false, "machine readable output")
	case "push":
		relay = relayFlag(fs)
		listed = fs.Bool("listed", false, "let the relay list you to every registered identity")
		knocks = fs.Bool("knocks", false, "let a knock past your allow list, into quarantine")
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
		return cardShow(s, id, relays, *asJSON)
	}

	// The card as this machine last pushed it is the starting point, so
	// that a bare push says again what was said, and a flag actually
	// typed is what changes a word: a flag left off must not overwrite the
	// file's word with its own default.
	d := &card.Document{Name: id.Name}
	if sub == "push" {
		if last, found, err := s.Card(); err != nil {
			return err
		} else if found {
			d.Listed, d.Knocks = last.Listed, last.Knocks
		}
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "listed":
				d.Listed = *listed
			case "knocks":
				d.Knocks = *knocks
			}
		})
	}
	// One document for every relay, issued now: the same card, the same
	// bytes, wherever it goes.
	now := time.Now()
	d.Issued = now
	doc, sig, err := card.Sign(id, d)
	if err != nil {
		return err
	}
	// The file is written once the first relay has taken the card, and
	// not before: a push that reaches no relay leaves the home as it was,
	// and from the moment any relay holds the new words the file holds
	// them too, so a bare push after a failure halfway retries what was
	// typed rather than putting the old words back on the relays that
	// took the new ones. The second reader found the file written last,
	// after every relay, which did exactly that.
	written := false
	for _, r := range relays {
		c, err := dial(s, id, r)
		if err != nil {
			return err
		}
		err = c.SetCard(ctx(), doc, sig)
		if httpErr, ok := newerHeld(err, relayapi.CodeNewerCard); ok {
			// Another machine of this identity pushed a card issued later
			// than now, by its clock.
			return &exitError{code: exitTransport, err: fmt.Errorf(
				"%s: holds a newer card, %s, from another machine of yours; '%s card show --relay %s' shows it",
				r.Name, issuedWhen(httpErr), prog, r.Name)}
		}
		if err != nil {
			return transportErr(fmt.Errorf("%s: %w", r.Name, err))
		}
		if !written {
			if err := s.SetCard(d); err != nil {
				return err
			}
			written = true
		}
		if sub == "push" {
			if err := s.SetCardPushed(r, now); err != nil {
				return err
			}
			fmt.Printf("%s: card pushed; %s\n", r.Name, cardWords(d))
		} else {
			if err := s.ClearCardPushed(r); err != nil {
				return err
			}
			fmt.Printf("%s: card cleared; %s\n", r.Name, cardWords(d))
		}
	}
	return nil
}

// cardWords is what a card means, as a person reads it.
func cardWords(d *card.Document) string {
	listed := "you are not listed there"
	if d.Listed {
		listed = "you are listed there"
	}
	knocks := "your mailbox takes no knocks"
	if d.Knocks {
		knocks = "your mailbox takes knocks"
	}
	return listed + " and " + knocks
}

// cardShowJSON is 'auu card show --json' for one relay.
type cardShowJSON struct {
	Relay  string     `json:"relay"`
	State  string     `json:"state"`
	Issued *time.Time `json:"issued,omitempty"`
	Name   string     `json:"name,omitempty"`
	Listed bool       `json:"listed"`
	Knocks bool       `json:"knocks"`
	Error  string     `json:"error,omitempty"`
}

// cardShow fetches what each relay holds for this identity and verifies
// it with this identity's own key, never trusting the relay's parse: a
// pair that does not verify here — a row with no signature included — is
// broken whatever the relay says, and exits 1. The state word is the
// client's, held to the three, so a fourth is refused before it is here.
func cardShow(s *store.Store, id *identity.Identity, relays []*store.Relay, asJSON bool) error {
	var (
		out    []cardShowJSON
		broken bool
	)
	for _, r := range relays {
		one := cardShowJSON{Relay: r.Name}
		c, err := dial(s, id, r)
		var res *client.CardResult
		if err == nil {
			res, err = c.Card(ctx())
		}
		if err != nil {
			return transportErr(fmt.Errorf("%s: %w", r.Name, err))
		}
		var d *card.Document
		switch {
		case res.None:
			one.State = relayapi.CardNone
		default:
			one.State = relayapi.CardSigned
			if d, err = card.Verify(id.Public(), res.Document, res.Signature); err != nil {
				one.State, d = relayapi.CardBroken, nil
			}
		}
		if d != nil {
			issued := d.Issued
			one.Issued = &issued
			one.Name, one.Listed, one.Knocks = d.Name, d.Listed, d.Knocks
		}
		if one.State == relayapi.CardBroken {
			one.Error = cardWarning(r.Name, one.State, time.Time{}, false)
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
			printCardShow(one)
		}
	}
	if broken {
		return &exitError{code: exitUsage, err: errors.New("a card does not verify")}
	}
	return nil
}

// printCardShow is one relay's card as a person reads it. The name is
// this identity's own, signed by it and verified just now, and is
// printed through the escaper all the same, as the last line under the
// rule.
func printCardShow(one cardShowJSON) {
	switch one.State {
	case relayapi.CardNone:
		fmt.Printf("%s: no card; you are not listed there and your mailbox takes no knocks\n", one.Relay)
	case relayapi.CardBroken:
		fmt.Printf("%s: %s\n", one.Relay, one.Error)
	case relayapi.CardSigned:
		fmt.Printf("%s: signed, issued %s, name %s; %s\n", one.Relay, stampLocal(*one.Issued),
			identity.Printable(one.Name), cardWords(&card.Document{Listed: one.Listed, Knocks: one.Knocks}))
	}
}

// cardWarning is what an owner is told about the state of their card on
// one relay, or nothing. signed is nothing; none is nothing unless this
// machine pushed a card there, in which case the relay has lost it;
// broken is a card that lists nobody and takes no knocks.
func cardWarning(relay, state string, pushed time.Time, wasPushed bool) string {
	switch state {
	case relayapi.CardBroken:
		return fmt.Sprintf("your card on %s does not verify, so nobody can knock and you are not listed there; run %s card push, and if you did not change it, tell the relay's operator", relay, prog)
	case relayapi.CardNone:
		if wasPushed {
			return fmt.Sprintf("your card on %s is missing, though you pushed one on %s; run %s card push and tell the relay's operator",
				relay, pushed.Local().Format(time.DateOnly), prog)
		}
	}
	return ""
}

// warnCardState says, on stderr, what a fetch's listing said about this
// identity's card on one relay, when there is something to say.
func warnCardState(s *store.Store, r *store.Relay, state string) error {
	if state == relayapi.CardSigned {
		return nil
	}
	pushed, wasPushed, err := s.CardPushed(r)
	if err != nil {
		return err
	}
	if msg := cardWarning(r.Name, state, pushed, wasPushed); msg != "" {
		fmt.Fprintf(os.Stderr, "%s: %s\n", prog, msg)
	}
	return nil
}
