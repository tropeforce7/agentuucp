package auu

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/term"
)

// A message to several (D45, D46, D48): one seal per recipient, every copy
// carrying the recipients section, every copy written to the outbox before
// any is posted, and then each posted in the order given.

// manyWait is the longest Retry-After a send to several waits out before it
// stops posting and leaves the rest in the outbox (R7): a relay that asks for
// longer is one a person would rather hear from than wait on.
const manyWait = 60 * time.Second

// addressed is one recipient as the command was given it: their key on this
// machine and the relays the copy to them goes by.
type addressed struct {
	pub  *identity.Public
	path []string
}

// splitTo is every --to as elements: each value split on its commas, which a
// peer name, a fingerprint and a bang path never contain (identity.ValidName
// refuses one), so the split is the person's and nothing else's. An empty
// element is a list typed wrong, and is said so.
func splitTo(values []string) ([]string, error) {
	var out []string
	for _, v := range values {
		for _, e := range strings.Split(v, ",") {
			if e == "" {
				return nil, usageErrf("--to %q has an empty recipient in it; give each name once, separated by commas", v)
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// resolveSeveral resolves every element as a single --to is resolved, each
// with its own path or --via's, and refuses a recipient named twice, since a
// message goes once to each person whatever it was called. cmdSend has
// held the list to the protocol's ceiling already, before the home was
// opened.
func resolveSeveral(s *store.Store, elems []string, via string) ([]addressed, error) {
	var out []addressed
	seen := map[string]string{}
	for _, e := range elems {
		path, peer, err := address(e, via)
		if err != nil {
			return nil, err
		}
		pub, err := s.Resolve(peer)
		if err != nil {
			return nil, usageErrf("%v", err)
		}
		fp := pub.Fingerprint()
		if first, ok := seen[fp]; ok {
			return nil, usageErrf("%q and %q are the same recipient, %s; name each once", first, e, pub.Short())
		}
		seen[fp] = e
		out = append(out, addressed{pub: pub, path: path})
	}
	return out, nil
}

// publicsOf is the recipients' keys, in order.
func publicsOf(to []addressed) []*identity.Public {
	out := make([]*identity.Public, len(to))
	for i, a := range to {
		out[i] = a.pub
	}
	return out
}

// copyResult is what became of one copy.
type copyResult struct {
	to      addressed
	relayID int64
	err     error
	waiting bool
}

// recipientJSON is one recipient of a message to several in --json.
type recipientJSON struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name,omitempty"`
	Path        string `json:"path,omitempty"`
	RelayID     int64  `json:"relay_id,omitempty"`
	Code        string `json:"code,omitempty"`
	Error       string `json:"error,omitempty"`
	// Waiting says the copy is in the outbox, not posted, since what
	// stopped the send was about the sender and not this copy: a long
	// wait, the whole budget, this machine refused, or no answer at all.
	Waiting bool `json:"waiting,omitempty"`
}

// sentManyJSON is a message to several as --json prints it: no to and no
// to_name, which a message to one has, and recipients in their place.
type sentManyJSON struct {
	ID         string          `json:"id"`
	Thread     string          `json:"thread"`
	InReplyTo  string          `json:"in_reply_to,omitempty"`
	Kind       string          `json:"kind"`
	Bytes      int             `json:"bytes"`
	Channel    string          `json:"channel,omitempty"`
	Recipients []recipientJSON `json:"recipients"`
}

// sendToSeveral sends one message to several recipients and says what
// became of each copy. Everything that can be refused is refused before
// anything is written: the shape of the message, the relay's number, the
// seal; then every copy goes to the outbox, the sent record is written, and
// the copies are posted in order. A refused copy stays in the outbox with
// the relay's words and the rest go on; a refusal of the sender and not the
// copy, a long wait, the whole budget, this machine refused, or no answer at
// all, stops the posting, and what is left waits in the outbox for --resume.
// Any copy not placed is exit 2, or 4 for a key that is not here.
func sendToSeveral(s *store.Store, id *identity.Identity, r *store.Relay, to []addressed,
	body message.Body, attachments []string, mode sendMode, asJSON bool) error {

	if mode.stream && mode.inline {
		return usageErrf("--stream and --inline contradict each other")
	}
	newThread := body.Thread == ""
	if newThread {
		tid, err := envelope.NewID()
		if err != nil {
			return err
		}
		body.Thread = tid
	}
	if err := message.ValidHeader(body.Type, body.Thread, body.InReplyTo, body.Subject); err != nil {
		return usageErrf("%v", err)
	}
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	set, err := settingsFrom(cfg)
	if err != nil {
		return err
	}
	raw, err := estimateSize(body, attachments)
	if err != nil {
		return err
	}
	estimate := raw + raw/3
	// A stream to several is a later release's (D49); until then a message
	// that would be one is refused here, before anything is read.
	if mode.stream || (!mode.inline && estimate > set.threshold) {
		return usageErrf("a message to several goes as one envelope to each in this release, and this one is "+
			"about %s, over the %s at which a message becomes a stream; send it to each recipient on their own, "+
			"or wait for the release that sends a stream to several",
			term.HumanBytes(estimate), term.HumanBytes(set.threshold))
	}
	if estimate > relayapi.DefaultMaxBytes {
		return usageErrf("message is about %s once encoded, over the %s relay limit%s",
			term.HumanBytes(estimate), term.HumanBytes(relayapi.DefaultMaxBytes), largestAttachmentHint(attachments))
	}
	loaded, err := loadAttachments(attachments)
	if err != nil {
		return err
	}
	body.Attachments = loaded

	// The relay's number, asked before anything is sealed: a list it would
	// refuse is said here, naming the relay and the number, and not by a
	// copy refused part way.
	c, err := dial(s, id, r)
	if err != nil {
		return err
	}
	c.SetMaxRetryWait(manyWait)
	limit, err := c.RecipientCap(ctx())
	if err != nil {
		return transportErr(err)
	}
	if len(to) > limit {
		return usageErrf("%d recipients; %s takes at most %d in one message (its max_recipients)", len(to), r.Name, limit)
	}

	pubs := make([]*identity.Public, len(to))
	for i, a := range to {
		pubs[i] = a.pub
	}
	envs, inners, err := envelope.SealMany(id, pubs, mode.channel, body, nil)
	if err != nil {
		return usageErrf("%v", err)
	}
	size := 0
	for _, env := range envs {
		n, err := client.EnvelopeSize(env)
		if err != nil {
			return err
		}
		if int64(n) > relayapi.DefaultMaxBytes {
			return usageErrf("message is %s, over the %s relay limit%s",
				term.HumanBytes(int64(n)), term.HumanBytes(relayapi.DefaultMaxBytes), largestAttachmentHint(attachments))
		}
		size = n
	}

	copies := make([]sealedCopy, len(envs))
	for i := range envs {
		copies[i] = sealedCopy{env: envs[i], inner: inners[i], toName: to[i].pub.Name, path: to[i].path}
	}
	written, err := writeCopies(s, r, mode.channel, copies)
	if err != nil {
		return err
	}
	// The sent record, before the first post: every copy is in the outbox
	// and none is placed, and each landing or refusal from here on updates
	// it, in this command or in --resume.
	sent := &store.Stored{
		Relay:      r.Name,
		Received:   time.Now().UTC().Truncate(time.Second),
		Read:       true,
		Inner:      inners[0],
		SenderName: to[0].pub.Name,
		Channel:    mode.channel,
	}
	for _, a := range to {
		sent.Copies = append(sent.Copies, store.SentCopy{
			Fingerprint: a.pub.Fingerprint(), Name: a.pub.Name, Path: store.JoinAddress(a.path),
		})
	}
	if err := s.Save(store.Sent, sent); err != nil {
		fmt.Fprintf(os.Stderr, "warning: the local copy of the message failed: %v\n", err)
	}

	results := make([]copyResult, len(written))
	var stop error
	for i, p := range written {
		results[i].to = to[i]
		if stop != nil {
			results[i].waiting = true
			continue
		}
		relayID, err := postCopy(c, s, p)
		if err == nil {
			landCopy(s, p, relayID)
			results[i].relayID = relayID
			continue
		}
		if stopsSendingAll(err) {
			// The relay refused this sender and not this copy, or the copy
			// never reached an answer: this copy and the rest stay in the
			// outbox as they are, and what happened is said.
			stop = err
			results[i].waiting = true
			continue
		}
		refuseCopy(s, p, err)
		if len(to[i].path) == 0 {
			err = channelHint(err, s, id, c, r, to[i].pub, mode.channel)
			err = notRegisteredHint(storageFullHint(err, to[i].pub), s, to[i].pub, r)
		}
		results[i].err = err
	}

	failed := 0
	for _, res := range results {
		if res.err != nil || res.waiting {
			failed++
		}
	}
	if asJSON {
		out := sentManyJSON{
			ID: inners[0].ID, Thread: body.Thread, InReplyTo: body.InReplyTo,
			Kind: kindEnvelope, Bytes: size, Channel: mode.channel,
		}
		for _, res := range results {
			rj := recipientJSON{
				Fingerprint: res.to.pub.Fingerprint(), Name: res.to.pub.Name,
				Path: store.JoinAddress(res.to.path), RelayID: res.relayID,
			}
			var he *client.HTTPError
			switch {
			case res.waiting:
				rj.Waiting = true
				rj.Error = waitingSentence(stop)
				if errors.As(stop, &he) {
					rj.Code = he.Code
				}
			case res.err != nil:
				rj.Error = res.err.Error()
				if errors.As(res.err, &he) {
					rj.Code = he.Code
				}
			}
			out.Recipients = append(out.Recipients, rj)
		}
		if err := printJSON(out); err != nil {
			return err
		}
	} else {
		fmt.Printf("sent to %d recipients via %s%s\n", len(to), r.Name, channelSuffix(mode.channel))
		for _, res := range results {
			label := peerLabel(res.to.pub)
			if len(res.to.path) > 0 {
				label += " by " + store.JoinAddress(res.to.path)
			}
			switch {
			case res.waiting:
				fmt.Printf("  %s: waiting in the outbox\n", identity.Printable(label))
			case res.err != nil:
				fmt.Printf("  %s: not sent: %s\n", identity.Printable(label), res.err)
			default:
				fmt.Printf("  %s: sent\n", identity.Printable(label))
			}
		}
		fmt.Printf("message: %s\n", inners[0].ID)
		fmt.Printf("thread:  %s\n", body.Thread)
		fmt.Printf("size:    %s each\n", term.HumanBytes(int64(size)))
		if newThread && failed < len(results) {
			fmt.Printf("\nWait for an answer with: %s wait --thread %s\n", prog, body.Thread)
		}
	}
	if failed == 0 {
		return nil
	}
	msg := fmt.Sprintf("%d of %d copies were not sent and wait in the outbox; finish them with '%s send --resume'",
		failed, len(results), prog)
	final := errors.New(msg)
	if stop != nil {
		// What stopped the send stays in the chain, so that the advice a
		// send to one gets for it, a certificate to renew or a relay to
		// enrol on, is the advice this gets too.
		final = fmt.Errorf("%s; %s: %w", waitingSentence(stop), msg, stop)
	}
	return &exitError{code: stoppedCode(stop), err: copiesWaiting{error: final, note: msg}}
}

// stoppedCode is the exit code of a send to several with copies not sent:
// 2, a transport failure, as any final refusal is; and 4 when what stopped
// it is a key that is not here, which is the person's to unlock, as it is
// for a message to one.
func stoppedCode(stop error) int {
	if isLocked(stop) {
		return exitLocked
	}
	return exitTransport
}

// copiesWaiting marks an error from a send to several after its copies were
// written: the message is in the outbox and the sent record, so it is
// finished by --resume and never sent again from a kept draft. note is the
// sentence that says so, which run keeps when it puts advice in place of the
// rest.
type copiesWaiting struct {
	error
	note string
}

func (c copiesWaiting) Unwrap() error { return c.error }

// stopsSendingAll is whether an error ends a send to several: a relay's
// refusal of the sender, as stopsSending says, or no answer at all, a relay
// gone or a key locked part way, which every other copy would meet too.
func stopsSendingAll(err error) bool {
	var he *client.HTTPError
	if !errors.As(err, &he) {
		return true
	}
	return stopsSending(err) != nil
}

// stopsSending is the refusal that ends a send to several (R7): one about
// the sender and not the copy, which every other copy would meet too. A 429
// or a 503 the relay asked a wait of more than a minute for; a 429 marked
// over-budget, which no wait lets through whatever Retry-After it carries;
// and a 401, which refuses this machine, its certificate or its identity,
// whatever the copy. Any other refusal is one copy's, and the send goes on
// to the next.
func stopsSending(err error) *client.HTTPError {
	var he *client.HTTPError
	if !errors.As(err, &he) {
		return nil
	}
	switch he.Status {
	case http.StatusUnauthorized:
		return he
	case http.StatusTooManyRequests:
		if he.Code == relayapi.CodeOverBudget || he.RetryAfter > manyWait {
			return he
		}
	case http.StatusServiceUnavailable:
		if he.RetryAfter > manyWait {
			return he
		}
	}
	return nil
}

// waitingSentence is what stopped a send to several: how long the relay
// asked the sender to wait, and when that is, in the reader's zone; that no
// wait lets the message through; that the relay refused this machine; or
// that a copy got no answer at all.
func waitingSentence(err error) string {
	var he *client.HTTPError
	if !errors.As(err, &he) {
		return "a copy could not be posted"
	}
	switch {
	case he.Status == http.StatusUnauthorized:
		return "the relay refused this machine, not one copy"
	case he.Code == relayapi.CodeOverBudget:
		return "the relay refused a copy as bigger than this sender's whole post budget, which no wait changes"
	case he.Status == http.StatusServiceUnavailable:
		return fmt.Sprintf("the relay is busy and asked for %d seconds, until about %s",
			int64(he.RetryAfter/time.Second), time.Now().Add(he.RetryAfter).Local().Format("15:04"))
	}
	until := time.Now().Add(he.RetryAfter).Local().Format("15:04")
	return fmt.Sprintf("the relay is limiting this sender and asked for %d seconds, until about %s",
		int64(he.RetryAfter/time.Second), until)
}

// followUpCopy is the copy of your own message to several that a follow-up
// on its thread answers, named by --to: one of its recipients, by the name
// this machine has for them or their fingerprint. With none named it is
// refused, naming them, since following up with the first recipient alone
// would say nothing of the rest.
func followUpCopy(s *store.Store, original *store.Stored, to string) (store.SentCopy, error) {
	var names []string
	for _, c := range original.Copies {
		names = append(names, identity.Printable(orNone(c.Name)))
	}
	if to == "" {
		return store.SentCopy{}, usageErrf("the latest on thread %s is your own message to %d recipients (%s); "+
			"name the one to follow up with, as --to PEER",
			original.Inner.Body.Thread[:12], len(original.Copies), strings.Join(names, ", "))
	}
	_, peer := store.SplitAddress(to)
	pub, err := s.Resolve(peer)
	if err != nil {
		return store.SentCopy{}, usageErrf("%v", err)
	}
	for _, c := range original.Copies {
		if c.Fingerprint == pub.Fingerprint() {
			return c, nil
		}
	}
	return store.SentCopy{}, usageErrf("%s is not one of the %d recipients of your message on thread %s (%s)",
		peerLabel(pub), len(original.Copies), original.Inner.Body.Thread[:12], strings.Join(names, ", "))
}
