package auu

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/term"
)

// The machinery of auu watch: what one relay is watched for, the poll that
// asks the relay to hold its listing open, and the events a poll turns
// into. A watch changes nothing unless asked to fetch: no spool, no cursor,
// no lock. It reports what the relay reported.

// The two kinds of event.
const (
	eventMessage   = "message"
	eventDirectory = "directory"
)

// messageEvent is a row the relay holds past this machine's cursor: a
// post, or a completed stream, that a fetch would deliver.
type messageEvent struct {
	Type     string    `json:"type"`
	Relay    string    `json:"relay"`
	Channel  string    `json:"channel"`
	Kind     string    `json:"kind"`
	Size     int64     `json:"size"`
	ID       int64     `json:"id"`
	Received time.Time `json:"received"`
	// Messages is what --fetch delivered for this row, as the inbox shows
	// a message; absent without --fetch, and for a row another machine
	// collected before the fetch got to it.
	Messages []messageJSON `json:"messages,omitempty"`
	// Fetch is the fetch --fetch made from this relay, as inbox --json
	// counts one, on every message event from the relay.
	Fetch *fetchResult `json:"fetch,omitempty"`
}

// directoryEvent is a watched peer having replaced their channel
// directory on the relay: what was added, removed and updated, by name,
// against the directory held when the watch began, and the channels as
// they are now.
type directoryEvent struct {
	Type    string    `json:"type"`
	Relay   string    `json:"relay"`
	Peer    string    `json:"peer"`
	Issued  time.Time `json:"issued"`
	Added   []string  `json:"added"`
	Removed []string  `json:"removed"`
	// Updated names every channel whose description or period differs;
	// closed is the ones among them whose only change is a not_after now
	// in the past, which the plain output says as closed.
	Updated  []string      `json:"updated"`
	Channels []channelJSON `json:"channels"`
	closed   map[string]bool
}

type watchJSON struct {
	Events []any  `json:"events"`
	Waited string `json:"waited"`
}

// watchOptions are the flags, checked.
type watchOptions struct {
	messages    bool
	directories bool
	// channels keeps only message events under these names; empty keeps
	// every one.
	channels map[string]bool
	// peers names whose directories to watch; nil is every peer and self.
	peers    []string
	interval time.Duration
	deadline time.Time // zero for no limit
	fetch    bool
}

// watchedPeer is one directory a relay watch follows.
type watchedPeer struct {
	pub   *identity.Public
	label string // the peer's name, or "you"
	self  bool
	// held is the directory as last seen and verified, the default-only
	// directory for a peer who has pushed none; issued is its issue time,
	// zero for that case, which the relay is told as Unix zero.
	held   *channels.Directory
	issued time.Time
}

// relayOutcome is how one relay's watch ended: with events, or for good
// with an error. A watch cut off by the context reports nothing.
type relayOutcome struct {
	relay  *store.Relay
	events []any
	// delivered is what --fetch brought into the spool for the events, as
	// stored, for the plain output to list as the inbox does.
	delivered []*store.Stored
	err       error
}

// watchSleep is the pause between polls of one relay. A test replaces it,
// since the interval is at least five seconds and a test of the polling is
// not a test of the clock.
var watchSleep = pauseUntil

// pauseUntil waits for d, or until the watch ends.
func pauseUntil(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// watchRelay watches one relay until it has events to report, fails for a
// reason no interval will change, or the context ends. The failure policy
// is wait's: a delay the relay asked for floors the interval; a failure
// waiting may outlast is said once per run of failures and tried again at
// the interval; anything else ends this relay's watch.
func watchRelay(ctx context.Context, s *store.Store, id *identity.Identity, r *store.Relay, opts watchOptions, out chan<- relayOutcome) {
	var (
		c      *client.Client
		cursor int64
		// after is where the listing is asked from: the cursor, until rows
		// have been listed and dismissed by the channel filter, and then
		// past them, so the relay can hold again rather than answer at
		// once with the same unwanted rows every poll.
		after  int64
		peers  []*watchedPeer
		ready  bool
		warned bool
		floor  time.Duration
	)
	// fail ends this relay's watch for good, unless the context has ended,
	// in which case nobody is listening.
	fail := func(err error) {
		if ctx.Err() != nil {
			return
		}
		out <- relayOutcome{relay: r, err: err}
	}
	// retry says a failure waiting may outlast, once per run of them, and
	// reports whether to go on.
	retry := func(err error) bool {
		if ctx.Err() != nil {
			return false
		}
		if d, temporary := relayAskedToWait(err); temporary {
			floor = max(floor, d)
			return true
		}
		if !pollFailedForNow(err) {
			fail(transportErr(fmt.Errorf("%s: %w", r.Name, err)))
			return false
		}
		if !warned {
			fmt.Fprintf(os.Stderr, "%s: unreachable (%v); trying again in %s\n",
				r.Name, err, max(opts.interval, floor).Round(time.Second))
			warned = true
		}
		return true
	}
	for {
		began := time.Now()
		if !ready {
			var err error
			c, cursor, peers, err = watchSetup(ctx, s, id, r, opts)
			var judged *exitError
			if errors.As(err, &judged) {
				// Already judged, with its code and its sentence: a usage
				// error, or the refusal of a directory that does not
				// verify. A person's, and no interval changes it.
				fail(err)
				return
			}
			if err != nil {
				if !retry(err) {
					return
				}
				watchSleep(ctx, max(opts.interval-time.Since(began), floor))
				continue
			}
			ready, warned = true, false
			after = cursor
		}
		req := client.ListRequest{After: after, Limit: relayapi.MaxListLimit, Wait: holdFor(opts.interval, opts.deadline)}
		if len(peers) > 0 {
			req.Peers = make(map[string]time.Time, len(peers))
			for _, p := range peers {
				req.Peers[p.pub.Fingerprint()] = p.issued
			}
		}
		listing, err := c.ListWait(ctx, req)
		if err != nil {
			if !retry(err) {
				return
			}
			watchSleep(ctx, max(opts.interval-time.Since(began), floor))
			continue
		}
		warned, floor = false, 0
		// A cursor past everything the relay holds is classified as a
		// fetch classifies it (reset.go): the rows nothing here matches
		// are what is new, and they are what this watch says; the rest is
		// mail this machine has. The watch writes nothing: the fetch that
		// follows, or --fetch's, resets the cursor itself.
		past := after == cursor && len(listing.Messages) == 0 && cursor > listing.Last
		if past {
			classified, err := classifyPast(ctx, s, c, r, listing.Last)
			if err != nil {
				if !retry(err) {
					return
				}
				watchSleep(ctx, max(opts.interval-time.Since(began), floor))
				continue
			}
			listing.Messages = classified.fresh
		}
		events, ids := messageEvents(r, listing, opts)
		if !past && after == cursor && len(listing.Messages) == 0 && listing.Queued > 0 {
			// Nothing after the cursor, and yet the relay holds mail: the
			// diagnosis a fetch makes, at its exit code, since only a
			// person can decide the cursor is wrong. Less what this
			// machine left there on purpose.
			left, err := s.LeftOn(r.Name)
			if err != nil {
				fail(err)
				return
			}
			if listing.Queued > left {
				fail(s.CursorSkipsMail(r, listing.Queued-left))
				return
			}
		}
		for _, fp := range listing.DirectoriesChanged {
			ev, err := directoryChanged(ctx, c, r, peers, fp)
			if err != nil {
				fail(err)
				return
			}
			if ev != nil {
				events = append(events, ev)
			}
		}
		if len(events) == 0 {
			// Rows listed and dismissed are behind the next ask; after a
			// cursor past everything, all of the relay's rows are.
			if n := len(listing.Messages); n > 0 {
				after = listing.Messages[n-1].ID
			}
			if past {
				// Answered at once, since the relay saw the cursor past
				// everything, and nothing in it new: the hold this watch
				// is for starts now, not an interval from now.
				after = listing.Last
				continue
			}
			watchSleep(ctx, max(opts.interval-time.Since(began), floor))
			if ctx.Err() != nil {
				return
			}
			continue
		}
		var delivered []*store.Stored
		if opts.fetch && len(ids) > 0 {
			if delivered, err = fetchForEvents(ctx, s, id, c, r, events, ids); err != nil {
				fail(err)
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		out <- relayOutcome{relay: r, events: events, delivered: delivered}
		return
	}
}

// watchSetup is everything a relay watch does before its first hold: the
// dial, the cursor, and for a directory watch each watched peer's directory
// fetched and verified under the key held for them, so that a later
// change can be said as what changed.
func watchSetup(ctx context.Context, s *store.Store, id *identity.Identity, r *store.Relay, opts watchOptions) (*client.Client, int64, []*watchedPeer, error) {
	c, err := dial(s, id, r)
	if err != nil {
		return nil, 0, nil, err
	}
	cursor, err := s.CursorFor(r)
	if err != nil {
		return nil, 0, nil, err
	}
	if !opts.directories {
		return c, cursor, nil, nil
	}
	pubs, err := watchedPublics(s, opts.peers)
	if err != nil {
		return nil, 0, nil, err
	}
	var peers []*watchedPeer
	for _, pub := range pubs {
		p := &watchedPeer{pub: pub, label: peerLabel(pub), self: pub.Fingerprint() == id.Fingerprint()}
		if p.self {
			p.label = "you"
		}
		res, err := c.Directory(ctx, pub.Fingerprint())
		var httpErr *client.HTTPError
		switch {
		case errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound:
			// No mailbox on this relay: nothing to watch here, and nothing
			// to say, since the peer may well be on another.
			continue
		case errors.As(err, &httpErr) && httpErr.Status == http.StatusForbidden:
			// A peer who has not admitted this identity: said once, and
			// their channels are theirs to keep.
			fmt.Fprintf(os.Stderr, "%s: %s does not let you post, so their channels are not watched\n", r.Name, p.label)
			continue
		case err != nil:
			return nil, 0, nil, err
		case res.None:
			p.held = &channels.Directory{Channels: []channels.Channel{{Name: channels.Default}}}
		default:
			d, err := channels.Verify(pub, res.Document, res.Signature)
			if err != nil {
				return nil, 0, nil, untrustedDirectory(r, p)
			}
			p.held, p.issued = d, d.Issued
		}
		peers = append(peers, p)
	}
	if len(peers) > relayapi.MaxWatchPeers {
		return nil, 0, nil, usageErrf("too many peers to watch on %s (%d); narrow with --peer", r.Name, len(peers))
	}
	return c, cursor, peers, nil
}

// untrustedDirectory is the refusal for a relay serving a directory that
// does not verify: preflight's sentence for your own, channel ls's for a
// peer's. A relay that lies is not one to hold a request open with.
func untrustedDirectory(r *store.Relay, p *watchedPeer) error {
	if p.self {
		return &exitError{code: exitTransport, err: fmt.Errorf(
			"the directory %s serves for you does not verify against your key; do not trust it", r.Name)}
	}
	return &exitError{code: exitTransport, err: fmt.Errorf(
		"the directory %s served for %s does not verify against the key you hold; do not trust it", r.Name, p.label)}
}

// watchedPublics is whose directories a directory watch follows: the
// names given, or every peer in authorized_peers and self.
func watchedPublics(s *store.Store, names []string) ([]*identity.Public, error) {
	if names == nil {
		peers, err := s.Peers()
		if err != nil {
			return nil, err
		}
		self, err := s.Self()
		if err != nil {
			return nil, err
		}
		return append(peers, self), nil
	}
	var out []*identity.Public
	seen := map[string]bool{}
	for _, name := range names {
		pub, err := s.Resolve(name)
		if err != nil {
			return nil, usageErrf("--peer %s: %v", name, err)
		}
		if !seen[pub.Fingerprint()] {
			seen[pub.Fingerprint()] = true
			out = append(out, pub)
		}
	}
	return out, nil
}

// messageEvents turns the rows a listing carries into events, keeping
// only the channels asked for, and returns the relay ids kept.
func messageEvents(r *store.Relay, listing client.Listing, opts watchOptions) ([]any, []int64) {
	if !opts.messages {
		return nil, nil
	}
	var events []any
	var ids []int64
	for _, m := range listing.Messages {
		if len(opts.channels) > 0 && !opts.channels[m.Channel] {
			continue
		}
		events = append(events, &messageEvent{Type: eventMessage, Relay: r.Name, Channel: m.Channel,
			Kind: m.Kind, Size: m.Size, ID: m.ID, Received: m.Received})
		ids = append(ids, m.ID)
	}
	return events, ids
}

// directoryChanged is the event for a peer the relay named in
// directories_changed: their directory fetched and verified again, and
// diffed by name against the one held. A peer the watch does not hold —
// named by a relay that has lost its mind — is nothing. A re-issue that
// diffs to nothing is still an event, with three empty lists: the relay
// said something changed, and the issue time did.
func directoryChanged(ctx context.Context, c *client.Client, r *store.Relay, peers []*watchedPeer, fp string) (*directoryEvent, error) {
	var p *watchedPeer
	for _, w := range peers {
		if w.pub.Fingerprint() == fp {
			p = w
		}
	}
	if p == nil {
		return nil, nil
	}
	res, err := c.Directory(ctx, fp)
	var httpErr *client.HTTPError
	if errors.As(err, &httpErr) && (httpErr.Status == http.StatusNotFound || httpErr.Status == http.StatusForbidden) {
		// Gone, or no longer ours to see, between the relay's word and
		// the fetch: nothing to say about it.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if res.None {
		return nil, nil
	}
	d, err := channels.Verify(p.pub, res.Document, res.Signature)
	if err != nil {
		return nil, untrustedDirectory(r, p)
	}
	now := time.Now()
	ev := &directoryEvent{Type: eventDirectory, Relay: r.Name, Peer: p.label, Issued: d.Issued,
		Added: []string{}, Removed: []string{}, Updated: []string{}, Channels: channelRows(d, now), closed: map[string]bool{}}
	if ev.Channels == nil {
		ev.Channels = []channelJSON{}
	}
	for _, ch := range d.Channels {
		old := p.held.Find(ch.Name)
		switch {
		case old == nil:
			ev.Added = append(ev.Added, ch.Name)
		case old.Description != ch.Description || !sameBound(old.NotBefore, ch.NotBefore) || !sameBound(old.NotAfter, ch.NotAfter):
			ev.Updated = append(ev.Updated, ch.Name)
			// Closed: the one change is not_after, and it is now past.
			if old.Description == ch.Description && sameBound(old.NotBefore, ch.NotBefore) &&
				ch.NotAfter != nil && !ch.NotAfter.After(now) {
				ev.closed[ch.Name] = true
			}
		}
	}
	for _, ch := range p.held.Channels {
		if d.Find(ch.Name) == nil {
			ev.Removed = append(ev.Removed, ch.Name)
		}
	}
	p.held, p.issued = d, d.Issued
	return ev, nil
}

func sameBound(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// fetchForEvents is --fetch: the relay's mailbox drained into the spool,
// and the messages delivered for the events' rows put on them. A row the
// fetch did not deliver — another machine took it — keeps its event and
// gets no messages. Every message event from the relay carries the fetch's
// count, as inbox --json prints it.
func fetchForEvents(ctx context.Context, s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay, events []any, ids []int64) ([]*store.Stored, error) {
	res, _, err := fetch(ctx, s, id, c, r, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := s.List(store.Inbox)
	if err != nil {
		return nil, err
	}
	byID := map[int64][]messageJSON{}
	var delivered []*store.Stored
	for _, m := range msgs {
		if m.Relay != r.Name {
			continue
		}
		for _, id := range ids {
			if m.RelayID == id {
				byID[id] = append(byID[id], toJSON(s, store.Inbox, m, false))
				delivered = append(delivered, m)
			}
		}
	}
	for _, ev := range events {
		if me, ok := ev.(*messageEvent); ok {
			me.Messages = byID[me.ID]
			fetched := res
			me.Fetch = &fetched
		}
	}
	return delivered, nil
}

// printEvents is the plain output: one line per relay per channel for
// messages, one per directory change, then under --fetch the messages
// delivered as the inbox lists them.
func printEvents(s *store.Store, events []any, delivered []*store.Stored) {
	type key struct{ relay, channel string }
	var order []key
	sizes := map[key][]string{}
	for _, ev := range events {
		me, ok := ev.(*messageEvent)
		if !ok {
			continue
		}
		k := key{me.Relay, me.Channel}
		if _, seen := sizes[k]; !seen {
			order = append(order, k)
		}
		sizes[k] = append(sizes[k], term.HumanBytes(me.Size))
	}
	for _, k := range order {
		fmt.Printf("%s: %s in %q (%s)\n", k.relay, plural(len(sizes[k]), "message"), k.channel, strings.Join(sizes[k], ", "))
	}
	for _, ev := range events {
		de, ok := ev.(*directoryEvent)
		if !ok {
			continue
		}
		fmt.Printf("%s: %s\n", de.Relay, de.sentence())
	}
	if len(delivered) == 0 {
		return
	}
	fmt.Println()
	for _, m := range delivered {
		printInboxLine(s, m)
	}
	fmt.Printf("\nRead one with: %s read <id>\n", prog)
}

// sentence is the change as a person reads it: what a peer added, closed,
// updated and removed, or that you changed your channels elsewhere, or
// that a peer re-issued them with nothing different.
func (ev *directoryEvent) sentence() string {
	if ev.Peer == "you" {
		return fmt.Sprintf("you changed your channels elsewhere (issued %s)", stampLocal(ev.Issued))
	}
	var parts []string
	add := func(verb string, names []string) {
		for _, n := range names {
			parts = append(parts, fmt.Sprintf("%s %q", verb, n))
		}
	}
	add("added", ev.Added)
	var closed, updated []string
	for _, n := range ev.Updated {
		if ev.closed[n] {
			closed = append(closed, n)
		} else {
			updated = append(updated, n)
		}
	}
	add("closed", closed)
	add("updated", updated)
	add("removed", ev.Removed)
	if len(parts) == 0 {
		return fmt.Sprintf("%s changed their channels (issued %s)", identity.Printable(ev.Peer), stampLocal(ev.Issued))
	}
	return identity.Printable(ev.Peer) + " " + strings.Join(parts, ", ")
}
