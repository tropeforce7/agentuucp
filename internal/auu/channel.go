package auu

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// The channel directory: the local file is the truth, as authorized_peers
// is for the allow list, and a push signs it and hands it to every relay.

// pushOutcome is what pushing one directory to a set of relays came to.
// Conflict means some relay holds a newer issue, from another machine of
// this identity, and the local file must not be written over what that
// machine knows; Failed means some relay refused for another reason or
// could not be reached, which the local file survives and 'auu channel
// push' repairs later.
type pushOutcome struct {
	Conflict bool
	Failed   bool
	Pushed   int
}

// pushDirectory signs d as id and pushes it to each relay, printing one line
// per relay. A relay's 409 is looked up rather than parsed: the relay's own
// copy is fetched, verified under this identity's key, and its issue time
// printed, so the sentence never comes from the refusal's text.
func pushDirectory(s *store.Store, id *identity.Identity, relays []*store.Relay, d *channels.Directory) (pushOutcome, error) {
	var out pushOutcome
	// Said here before any request, as the relay would refuse it. A push
	// of the stored directory sends its stored issue, which a clock that
	// has since gone back can leave ahead; any change to a channel issues
	// the directory anew.
	if err := channels.CheckIssued(d, time.Now()); err != nil {
		if errors.Is(err, channels.ErrBound) {
			return out, usageErrf("the directory cannot be pushed: %v; update that channel's bound", err)
		}
		return out, usageErrf("the directory cannot be pushed: %v; create, update or close a channel to issue it anew", err)
	}
	doc, sig, err := channels.Sign(id, d)
	if err != nil {
		return out, err
	}
	for _, r := range relays {
		c, err := dial(s, id, r)
		if err != nil {
			fmt.Printf("%s: could not push the directory: %v\n", r.Name, err)
			out.Failed = true
			continue
		}
		err = c.SetDirectory(ctx(), doc, sig)
		var httpErr *client.HTTPError
		switch {
		case err == nil:
			fmt.Printf("%s: directory pushed (%s)\n", r.Name, plural(len(d.Channels), "channel"))
			out.Pushed++
		case errors.As(err, &httpErr) && httpErr.Status == http.StatusConflict:
			// The preflight did not see this one: another machine pushed
			// between the look and the push.
			issued := "an unknown time"
			if held, err := relayDirectory(c, id.Public()); err == nil && held != nil {
				issued = held.Issued.Local().Format(time.RFC3339)
			}
			fmt.Println(newerElsewhere(r.Name, issued))
			out.Conflict = true
		default:
			fmt.Printf("%s: could not push the directory: %v\n", r.Name, storageFaultHint(err))
			out.Failed = true
		}
	}
	return out, nil
}

// newerElsewhere is the sentence for a relay holding a directory issued
// later than this machine's: another machine of this identity pushed it,
// and this one takes it before it edits, rather than writing over it.
func newerElsewhere(relay, issued string) string {
	return fmt.Sprintf("%s holds a directory issued %s, newer than this machine's; "+
		"run '%s channel pull --relay %s' to take it first", relay, issued, prog, relay)
}

// preflight looks at what every selected relay holds for this identity
// before an edit changes anything: a relay holding a directory issued later
// than the local file's has a newer one from another machine of this
// identity, and an edit here would write over it with a fresh issue time —
// the very silence the monotonic issued exists to prevent. A relay that
// cannot be reached is not known to be ahead; the push after will fail for
// it, and a 409 there is caught by the push. A relay serving a directory
// for this identity that does not verify under its key is refused
// outright: nothing pushed anywhere on the word of a relay that lies.
func preflight(s *store.Store, id *identity.Identity, relays []*store.Relay, localIssued time.Time) error {
	for _, r := range relays {
		c, err := dial(s, id, r)
		if err != nil {
			continue
		}
		held, err := relayDirectory(c, id.Public())
		if errors.Is(err, channels.ErrSignature) || errors.Is(err, channels.ErrOwner) {
			return &exitError{code: exitTransport, err: fmt.Errorf(
				"the directory %s serves for you does not verify against your key; do not trust it", r.Name)}
		}
		if err != nil || held == nil {
			continue
		}
		if held.Issued.After(localIssued) {
			return &exitError{code: exitTransport,
				err: errors.New(newerElsewhere(r.Name, held.Issued.Local().Format(time.RFC3339)))}
		}
	}
	return nil
}

// afterPreflight runs between the preflight and the push, so a test can
// put a newer directory on a relay in the gap the preflight cannot see.
var afterPreflight = func() {}

// editAndPush is the tail of every editing command: the preflight, then the
// directory issued now, signed and pushed to every selected relay, then the
// local file — unless a relay answered 409, in which case the file is left
// as it was, since what that relay holds is what this machine should take
// first. A relay that refused for another reason or could not be reached
// is reported and the command exits 2 with the file written, for 'auu
// channel push' to repair.
func editAndPush(s *store.Store, id *identity.Identity, relays []*store.Relay, d *channels.Directory, localIssued time.Time) error {
	if err := relaysCanHold(s, id, relays, d); err != nil {
		return err
	}
	if err := preflight(s, id, relays, localIssued); err != nil {
		return err
	}
	firstRule(s, d)
	afterPreflight()
	d.Issued = time.Now().UTC()
	out, err := pushDirectory(s, id, relays, d)
	if err != nil {
		return err
	}
	if out.Conflict {
		return &exitError{code: exitTransport, err: fmt.Errorf("%s was not written", s.ChannelsPath())}
	}
	if err := s.SetDirectory(d); err != nil {
		return err
	}
	if out.Failed {
		return &exitError{code: exitTransport, err: fmt.Errorf(
			"%s is written; run '%s channel push' once the relay above can be reached", s.ChannelsPath(), prog)}
	}
	return nil
}

// relaysCanHold is asked before any push of a directory that carries a
// rule, a version 2 document: every selected relay's health answer must
// say wire level 2 or more, and one that says less refuses the whole edit
// naming it; and every channel's max_bytes must be within each relay's
// ceiling, its health answer's channel-max-bytes, the relay named
// otherwise, before any relay is pushed to, since a directory is one
// document for all of an identity's relays. A relay that cannot be reached
// is one that cannot confirm, and refuses the edit too, naming it (R7). A
// version 1 directory asks nothing: any relay takes it, and one that
// cannot be reached is the push's failure as before. This promises only
// that no push starts when a selected relay is known not to take the
// document or cannot be asked; the pushes after go relay by relay (R11).
func relaysCanHold(s *store.Store, id *identity.Identity, relays []*store.Relay, d *channels.Directory) error {
	if channels.OldestVersion(d) < channels.Version2 {
		return nil
	}
	for _, r := range relays {
		c, err := dial(s, id, r)
		if err == nil {
			_, err = c.HealthInfo(ctx())
		}
		if err != nil {
			return &exitError{code: exitTransport, err: fmt.Errorf(
				"relay %s could not be asked whether it can hold a channel rule (%v); nothing was pushed, "+
					"so try again when it answers, or leave it out with --relay", r.Name, err)}
		}
		if c.WireLevel() < 2 {
			return usageErrf("relay %s is at wire level %d and cannot hold a channel rule; "+
				"update it, or drop --max-bytes, --no-streams and --no-forwards", r.Name, c.WireLevel())
		}
		// The relay's own number, as its push will hold the channel to it
		// (R19): a channel may be tighter than every selected relay, never
		// looser than one.
		ceiling := c.ChannelCeiling()
		if ceiling == 0 {
			return usageErrf("relay %s did not say the largest max_bytes a channel on it may name, "+
				"so it cannot be asked to hold a channel rule; update it", r.Name)
		}
		for _, ch := range d.Channels {
			if ch.MaxBytes > ceiling {
				return usageErrf("channel %q: --max-bytes %d is over the %d relay %s takes", ch.Name, ch.MaxBytes, ceiling, r.Name)
			}
		}
	}
	return nil
}

// firstRule says once, on standard error, what setting the first rule on a
// directory that carried none means for peers on older builds (D91), in
// the words their build will use, and that this home cannot go back.
func firstRule(s *store.Store, d *channels.Directory) {
	if channels.OldestVersion(d) < channels.Version2 {
		return
	}
	if before, found, err := s.Directory(); err == nil && found && channels.OldestVersion(before) >= channels.Version2 {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: a channel rule makes your directory version 2. Peers on v0.17.0 or earlier "+
		"will say it 'does not verify against the key you hold; do not trust it' until they update auu: "+
		"that is their old build meeting a newer document, not a key problem. Their 'auu watch' on you "+
		"stops and 'auu channel ls' refuses it; they still send to your channels, but when a send names "+
		"a channel you do not have their hint says the same instead of naming the channels. So set a rule once the peers "+
		"who watch you or list your channels are on v0.18.0; and this home cannot go back below v0.18.0 "+
		"without dropping the rule first\n", prog)
}

// relayDirectory fetches the directory a relay holds for the caller's own
// mailbox and verifies it under the caller's key, so a relay can say what it
// holds but never what it says.
func relayDirectory(c *client.Client, self *identity.Public) (*channels.Directory, error) {
	res, err := c.Directory(ctx(), self.Fingerprint())
	if err != nil {
		return nil, err
	}
	if res.None {
		return nil, nil
	}
	return channels.Verify(self, res.Document, res.Signature)
}

// parseWhen reads a period bound as a person writes one: RFC 3339, or a
// date alone taken as local midnight. none clears a bound where the caller
// allows it, and comes back as cleared.
func parseWhen(flag, value string) (t *time.Time, cleared bool, err error) {
	value = strings.TrimSpace(value)
	if value == "none" {
		return nil, true, nil
	}
	if at, err := time.Parse(time.RFC3339, value); err == nil {
		return &at, false, nil
	}
	if day, err := time.ParseInLocation("2006-01-02", value, time.Local); err == nil {
		return &day, false, nil
	}
	return nil, false, usageErrf("%s wants a time as 2026-10-01T09:00:00+10:00 or a day as 2026-10-01, not %q", flag, value)
}

// foldLines folds every line break and every other control white-space
// character in a description to one space, so a description typed across
// lines or pasted with tabs is one line as the directory wants it. Runs
// fold together, and \r\n is one break. Other white space is kept as given.
func foldLines(desc string) string {
	var b strings.Builder
	folding := false
	for _, r := range desc {
		if unicode.Is(unicode.Cc, r) && unicode.IsSpace(r) {
			if !folding {
				b.WriteByte(' ')
				folding = true
			}
			continue
		}
		folding = false
		b.WriteRune(r)
	}
	return b.String()
}

// plural says n of a thing.
func plural(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

// warnDirectoryState says, on stderr, what a fetch's listing said about
// this identity's channel directory on one relay, when there is something
// to say. Only broken: a relay that holds none is a relay this machine
// has pushed none to, since a push is the only thing that makes one, and
// there is no marker file for it as there is for the allow list and the
// card — a home with no directory has published no names, and nothing is
// missing.
func warnDirectoryState(r *store.Relay, state string) error {
	if state != relayapi.DirectoryBroken {
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s: your channel directory on %s does not verify, so every post to you is refused "+
		"there; run %s channel push, and if you did not change it, tell the relay's operator\n",
		prog, r.Name, prog)
	return nil
}
