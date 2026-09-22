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
		return usageErrf("usage: %s allow push|clear|show", prog)
	}
	sub, rest := args[0], args[1:]
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

	var fps []string
	if sub == "push" {
		peers, err := s.Peers()
		if err != nil {
			return err
		}
		fps = make([]string, 0, len(peers))
		for _, p := range peers {
			fps = append(fps, p.Fingerprint())
		}
	}
	// One document for every relay, issued now: the same list, the same
	// bytes, wherever it goes. Sign sorts the senders and writes a list of
	// nobody as [], which is what clear means.
	now := time.Now()
	doc, sig, err := allowlist.Sign(id, &allowlist.Document{Issued: now, Senders: fps})
	if err != nil {
		return err
	}
	for _, r := range relays {
		c, err := dial(s, id, r)
		if err != nil {
			return err
		}
		err = c.SetAllowlist(ctx(), doc, sig)
		var httpErr *client.HTTPError
		if errors.As(err, &httpErr) && httpErr.Status == http.StatusConflict {
			// Another machine of this identity pushed a list issued later
			// than now, by its clock. There is nothing to pull: the list is
			// the peer list, and that machine's differs.
			return &exitError{code: exitTransport, err: fmt.Errorf(
				"%s: holds a newer allow list, %s, from another machine of yours; '%s allow show --relay %s' shows it",
				r.Name, issuedFrom(httpErr.Message), prog, r.Name)}
		}
		if err != nil {
			return transportErr(fmt.Errorf("%s: %w", r.Name, err))
		}
		if sub == "push" {
			if err := s.SetAllowPushed(r, now); err != nil {
				return err
			}
			fmt.Println(allowPushedLine(r.Name, len(fps)))
		} else {
			if err := s.ClearAllowPushed(r); err != nil {
				return err
			}
			fmt.Printf("%s: allow list cleared; any registered user there can queue mail for you\n", r.Name)
		}
	}
	if sub == "push" && len(fps) == 0 {
		fmt.Println("warning: your peer list is empty, so this admits any registered sender; add peers and push again")
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
func allowPushedLine(relay string, senders int) string {
	return fmt.Sprintf("%s will now accept mail for you from %d peer(s) only", relay, senders)
}

// pushAllowTo pushes this machine's peer list to one relay, quietly: the
// same work 'auu allow push --relay NAME' does, without its line, for a
// caller that says the line itself or says nothing. It reports how many
// senders the list names.
func pushAllowTo(s *store.Store, id *identity.Identity, r *store.Relay) (senders int, err error) {
	peers, err := s.Peers()
	if err != nil {
		return 0, err
	}
	fps := make([]string, 0, len(peers))
	for _, p := range peers {
		fps = append(fps, p.Fingerprint())
	}
	now := time.Now()
	doc, sig, err := allowlist.Sign(id, &allowlist.Document{Issued: now, Senders: fps})
	if err != nil {
		return 0, err
	}
	c, err := dial(s, id, r)
	if err != nil {
		return 0, err
	}
	if err := c.SetAllowlist(ctx(), doc, sig); err != nil {
		var httpErr *client.HTTPError
		if errors.As(err, &httpErr) && httpErr.Status == http.StatusConflict {
			return 0, &exitError{code: exitTransport, err: fmt.Errorf(
				"%s: holds a newer allow list, %s, from another machine of yours; '%s allow show --relay %s' shows it",
				r.Name, issuedFrom(httpErr.Message), prog, r.Name)}
		}
		return 0, transportErr(fmt.Errorf("%s: %w", r.Name, err))
	}
	if err := s.SetAllowPushed(r, now); err != nil {
		return 0, err
	}
	return len(fps), nil
}

// issuedFrom takes "issued T" out of the relay's 409 sentence, "a newer
// allow list is already there (issued T)", and says it in this zone; a
// sentence without it is passed as it came.
func issuedFrom(msg string) string {
	const mark = "(issued "
	i := strings.LastIndex(msg, mark)
	if i < 0 || !strings.HasSuffix(msg, ")") {
		return msg
	}
	t, err := time.Parse(time.RFC3339, msg[i+len(mark):len(msg)-1])
	if err != nil {
		return msg
	}
	return "issued " + stampLocal(t)
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
