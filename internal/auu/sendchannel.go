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

// channelHint rewrites the relay's two channel refusals. A 404 that begins
// "no such channel" becomes the recipient's channels, fetched from the
// relay and verified against the key held for them, so the sender can pick
// one; a 403 for a channel outside its period becomes the relay's own
// sentence with the time in local form. Anything else passes through.
func channelHint(err error, s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay, recipient peerish, channel string) error {
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) {
		return err
	}
	switch {
	case httpErr.Status == http.StatusNotFound && strings.HasPrefix(httpErr.Message, "no such channel"):
		return noSuchChannel(s, id, c, r, recipient, channel)
	case httpErr.Status == http.StatusForbidden && strings.Contains(httpErr.Message, relayapi.MsgChannelClosed):
		return errors.New(localTime(httpErr.Message))
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
				recipient.Fingerprint()[:16], channel, r.Name, err)
		}
		who = peer
		label := peerLabel(peer)
		has, whose, mailbox, served, key = label+" has", "their", label+"'s mailbox", "served for "+label, "the key you hold"
	}
	res, err := c.Directory(ctx(), who.Fingerprint())
	if err != nil {
		return fmt.Errorf("%s no channel %q on %s, and %s channels could not be listed: %v",
			has, channel, r.Name, whose, err)
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
			"against %s; do not trust it", has, channel, r.Name, r.Name, served, key)
	}
	var b strings.Builder
	if channel == "" {
		fmt.Fprintf(&b, "%s removed %s default channel; choose one with --channel:", has, whose)
	} else {
		fmt.Fprintf(&b, "%s no channel %q; %s channels are:", has, channel, whose)
	}
	if len(d.Channels) == 0 {
		b.WriteString(" none; their directory is empty, so nobody can post to them")
		return errors.New(b.String())
	}
	now := time.Now()
	for _, ch := range d.Channels {
		state := "open"
		if open, why := ch.OpenAt(now); !open {
			state = localTime(why)
		}
		if ch.Description == "" {
			fmt.Fprintf(&b, "\n  %s (%s)", ch.Name, state)
		} else {
			fmt.Fprintf(&b, "\n  %s: %s (%s)", ch.Name, ch.Description, state)
		}
	}
	return errors.New(b.String())
}

// localTime rewrites the RFC 3339 time a sentence ends with into the
// reader's zone, and leaves a sentence that does not end with one alone.
func localTime(sentence string) string {
	i := strings.LastIndexByte(sentence, ' ')
	if i < 0 {
		return sentence
	}
	t, err := time.Parse(time.RFC3339, sentence[i+1:])
	if err != nil {
		return sentence
	}
	return sentence[:i+1] + t.Local().Format(time.RFC3339)
}

// streamChannelHint is channelHint for a stream, whose recipient is the
// fingerprint and name recorded beside the sealed file.
func streamChannelHint(err error, s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay, p *pending) error {
	return channelHint(err, s, id, c, r, fingerprintOnly(p.To), p.Channel)
}

type fingerprintOnly string

func (f fingerprintOnly) Fingerprint() string { return string(f) }
