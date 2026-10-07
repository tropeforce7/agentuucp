package auu

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// The sender's half of channels: the flag, and the two refusals a relay
// answers a post with, turned into the sentences a person acts on.

func channelFlag(fs *flag.FlagSet) *string {
	return fs.String("channel", "", "the recipient's channel to post to; their default when not given")
}

// validChannelFlag refuses a name no directory could hold before anything
// is sealed or dialled.
func validChannelFlag(name string) error {
	if name == "" {
		return nil
	}
	if err := channels.ValidName(name); err != nil {
		return usageErrf("--channel %q: %v", name, err)
	}
	return nil
}

// channelSuffix is what the sent line adds for a named channel.
func channelSuffix(channel string) string {
	if channel == "" {
		return ""
	}
	return fmt.Sprintf(" to channel %q", channel)
}

// channelHint rewrites the relay's two channel refusals, known by their
// codes. A no-such-channel 404 becomes the recipient's channels, fetched
// from the relay and verified against the key held for them, so the sender
// can pick one; a channel-closed 403 becomes the relay's own sentence with
// the time it carries said in local form beside it, where that reads
// otherwise than the UTC the sentence names. Anything else passes through.
func channelHint(err error, s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay, recipient peerish, channel string) error {
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) {
		return err
	}
	switch {
	case httpErr.Status == http.StatusNotFound && httpErr.Code == relayapi.CodeNoSuchChannel:
		return noSuchChannel(s, id, c, r, recipient, channel)
	case httpErr.Status == http.StatusForbidden && httpErr.Code == relayapi.CodeChannelClosed && !httpErr.At.IsZero():
		return errors.New(closedSentence(httpErr, time.Local))
	}
	return err
}

// peerish is what the two send paths know about the recipient: a key for an
// envelope, a fingerprint and a name for a stream found in the outbox.
type peerish interface {
	Fingerprint() string
}

// noSuchChannel says what channels the recipient has, from a directory the
// relay serves and the key held for them verifies, and what to do. A note
// to yourself is verified under your own key and said in the second
// person: the channels are yours, and the sentence should not name you as
// somebody else.
func noSuchChannel(s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay, recipient peerish, channel string) error {
	var who *identity.Public
	var has, whose, mailbox, served, key string
	// The name to show: a person who passed no --channel posted to
	// default, and the relay refused "default", so that is the name in
	// the sentence rather than an empty pair of quotes. The branches
	// below still read channel itself, since "they removed their default
	// channel" and "they have no channel x" are different things to say.
	shown := channel
	if shown == "" {
		shown = channels.Default
	}
	if recipient.Fingerprint() == id.Fingerprint() {
		who = id.Public()
		has, whose, mailbox, served, key = "you have", "your", "your mailbox", "serves for you", "your key"
	} else {
		peer, err := s.Resolve(recipient.Fingerprint())
		if err != nil {
			// Not on the list: a stream resumed for somebody since removed.
			// The relay's word is all there is, and it is not to be
			// trusted for a listing.
			return fmt.Errorf("%s has no channel %q on %s, and their directory cannot be checked: %v",
				recipient.Fingerprint()[:16], shown, r.Name, err)
		}
		who = peer
		label := peerLabel(peer)
		has, whose, mailbox, served, key = label+" has", "their", label+"'s mailbox", "served for "+label, "the key you hold"
	}
	res, err := c.Directory(ctx(), who.Fingerprint())
	if err != nil {
		return fmt.Errorf("%s no channel %q on %s, and %s channels could not be listed: %v",
			has, shown, r.Name, whose, err)
	}
	if res.None {
		if channel == "" {
			// The relay refused default and now says there is no directory:
			// it changed under us. Say what it says now.
			return fmt.Errorf("%s has the one channel, default, on %s; try again", mailbox, r.Name)
		}
		return fmt.Errorf("%s has the one channel, default; drop --channel", mailbox)
	}
	d, err := channels.Verify(who, res.Document, res.Signature)
	if err != nil {
		return fmt.Errorf("%s no channel %q on %s, and the directory %s %s does not verify "+
			"against %s; do not trust it", has, shown, r.Name, r.Name, served, key)
	}
	var b strings.Builder
	if channel == "" {
		fmt.Fprintf(&b, "%s removed %s default channel; choose one with --channel:", has, whose)
	} else {
		fmt.Fprintf(&b, "%s no channel %q; %s channels are:", has, shown, whose)
	}
	if len(d.Channels) == 0 {
		b.WriteString(" none; their directory is empty, so nobody can post to them")
		return errors.New(b.String())
	}
	now := time.Now()
	for _, ch := range d.Channels {
		state := "open"
		if open, _ := ch.OpenAt(now); !open {
			// The bound itself, from the verified directory, in this zone.
			if ch.NotBefore != nil && now.Before(*ch.NotBefore) {
				state = "opens " + stampLocal(*ch.NotBefore)
			} else if ch.NotAfter != nil {
				state = "closed " + stampLocal(*ch.NotAfter)
			}
		}
		if ch.Description == "" {
			fmt.Fprintf(&b, "\n  %s (%s)", ch.Name, state)
		} else {
			fmt.Fprintf(&b, "\n  %s: %s (%s)", ch.Name, ch.Description, state)
		}
	}
	return errors.New(b.String())
}

// closedSentence is a channel-closed refusal as a person in zone reads it.
// The relay's sentence names the time in UTC, for a person reading the
// answer by hand; the time itself comes as data and is said beside it in
// zone, never read out of the sentence, where zone reads it otherwise.
func closedSentence(httpErr *client.HTTPError, zone *time.Location) string {
	utc := httpErr.At.UTC().Format(time.RFC3339)
	if here := httpErr.At.In(zone).Format(time.RFC3339); here != utc {
		return fmt.Sprintf("%s (%s here)", httpErr.Message, here)
	}
	return httpErr.Message
}

// streamChannelHint is channelHint for a stream, whose recipient is the
// fingerprint and name recorded beside the sealed file.
func streamChannelHint(err error, s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay, p *pending) error {
	return channelHint(err, s, id, c, r, fingerprintOnly(p.To), p.Channel)
}

type fingerprintOnly string

func (f fingerprintOnly) Fingerprint() string { return string(f) }
