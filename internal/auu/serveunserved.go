package auu

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// An ask on a channel serve does not serve (D178).
//
// An ask sent without --channel lands on the expert's default, which no
// entry of serve.json need name, and channelFor calls it none of serve's
// business; left there, it sat unread with no word to anybody, and its
// sender took the expert for gone. So a peer's ask on a channel neither
// serve.json nor a route of handle.json names is told, once, which channels
// this home does answer on, and nothing of it is read: no turn, no thread
// directory, no worktree, no handler.
//
// Only an ask, and only a peer's. A reply is never told, so a reply to the
// telling is left alone as every reply serve did not answer is, and two
// serves pointed at each other exchange at most one message each way. The
// owner's own asks, which several agents under one identity send one
// another on channels of the mailbox (docs/client.md 1.13), are not a peer's
// and are left alone too.

// unservedDir is where the reply's sealed envelope is kept between
// attempts, a directory per ask under the serve directory, removed once the
// ledger has the reply or the retries have run out.
const unservedDir = "unserved"

// unservedRetries is how many attempts a telling is given: there is no
// channel to read a count from, so it is the default a channel has.
const unservedRetries = defaultRetries

// unserved is the channel an ask in the inbox is to be told about, or ""
// for a message this is not for. pending has already left out a message
// the ledger has settled and a stream waiting for a newer auu.
func (r *serveRun) unserved(m *store.Stored) string {
	if !r.telling || m.Inner.Body.Type != message.TypeAsk {
		return ""
	}
	channel := channelOf(m)
	if r.cfg.Channels[channel] != nil {
		return ""
	}
	// The fetch holds a channel to its rule, so only a record written by
	// hand breaks it, and the name goes into the ledger, whose loader
	// would then refuse it at the next start.
	if channels.ValidName(channel) != nil {
		return ""
	}
	handled, ok := r.handleChannels()
	if !ok || slices.Contains(handled, channel) {
		return ""
	}
	if m.Inner.From == r.id.Fingerprint() {
		return ""
	}
	// An ask the ledger holds for a channel serve answered on once, since
	// taken out of serve.json, is left as it is today: its entry is on a
	// thread, and the telling is only for asks that were never serve's.
	if e := r.led.Messages[m.Inner.ID]; e != nil && e.Unserved == "" {
		return ""
	}
	// The id names the directory the envelope is kept in; every record in
	// the spool has met the rule, so this is met only by one written by
	// hand, which is left alone.
	if message.ValidID(m.Inner.ID) != nil {
		return ""
	}
	if _, err := r.s.Resolve(m.Inner.From); err != nil {
		return ""
	}
	return channel
}

// startTelling begins the telling on a home, once. Its mark is the
// unserved directory, outside the ledger so that a v0.20.0 serve reads the
// ledger as it did: a home whose serve ran before this release has asks on
// unserved channels in its inbox that nobody was told about, perhaps for
// months, and perhaps answered by hand since, and telling them all at once
// at the upgrade is what the first-start rule exists to prevent. So on a
// home with a ledger and no mark, every such ask is written down as
// skipped, said in one sentence, and then the mark is made; a first start
// leaves its old mail to recordBacklog, which tells it with --backlog.
// While handle.json will not read nothing can say which asks are handle's,
// so the start waits for a round in which it reads.
func (r *serveRun) startTelling(first bool) error {
	if r.telling {
		return nil
	}
	mark := filepath.Join(r.root, unservedDir)
	if _, err := os.Stat(mark); err == nil {
		r.telling = true
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, ok := r.handleChannels(); !ok {
		return nil
	}
	r.telling = true
	if !first {
		msgs, err := r.s.List(store.Inbox)
		if err != nil {
			return err
		}
		n := 0
		for _, m := range msgs {
			if m.Newer != "" || r.led.Messages[m.Inner.ID] != nil || r.unserved(m) == "" {
				continue
			}
			r.entry(m, channelOf(m)).Skipped = true
			n++
		}
		if n > 0 {
			if err := r.led.save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s: %s on channels this expert does not answer on already in the inbox, left alone; an ask from now on is told which channels it does\n",
				prog, plural(n, "ask"))
		}
	}
	return os.MkdirAll(mark, 0o700)
}

// untellable says that an ask whose telling is pending, a post that failed
// and has retries left, is not to be told any more: its channel is served
// now, or a route of a handle.json that reads takes it, or its sender is
// not a peer. forgetUnserved then lets the entry go.
func (r *serveRun) untellable(m *store.Stored) bool {
	channel := channelOf(m)
	if r.cfg.Channels[channel] != nil {
		return true
	}
	if handled, ok := r.handleChannels(); ok && slices.Contains(handled, channel) {
		return true
	}
	// Not a peer is a lookup that missed in a peer list that read: one that
	// will not read says nothing of the sender, and letting the telling go
	// then would seal it afresh once the list reads, though the post the
	// relay took with its answer lost may already be the asker's.
	if _, err := r.s.Resolve(m.Inner.From); err != nil {
		_, listed := r.s.Peers()
		return listed == nil
	}
	return false
}

// forgetUnserved lets go of an ask's pending telling, its entry and its
// kept envelope, so that the ask is what it would have been had serve
// never tried to tell it: a served channel's ask answered on its thread as
// any other, handle's ask handle's, and a stranger's left alone. An entry
// on no thread made into a served thread's would be no turn and no opener,
// and its follow-ups would be nobody's.
func (r *serveRun) forgetUnserved(m *store.Stored) error {
	delete(r.led.Messages, m.Inner.ID)
	if err := r.led.save(); err != nil {
		return err
	}
	os.RemoveAll(filepath.Join(r.root, unservedDir, m.Inner.ID))
	fmt.Fprintf(os.Stderr, "%s: %s from %s was to be told that this expert does not answer on channel %q, which no longer holds; not told\n",
		prog, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), channelOf(m))
	return nil
}

// handleChannels is the channels handle.json's routes take, sorted and each
// once, read afresh once a round so that a route added while serve runs is
// handle's at once; none when the home has no handle.json. ok is false
// while the file is there and will not read: nothing can then say which
// asks are handle's, so none is told, and that is said once a run.
func (r *serveRun) handleChannels() (channels []string, ok bool) {
	if r.handleRead {
		return r.handled, r.handleOK
	}
	r.handleRead = true
	r.handled, r.handleOK = nil, true
	path := filepath.Join(r.s.Root(), handleFile)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, true
	}
	cfg, err := loadHandleConfig(path)
	if err != nil {
		r.handleOK = false
		if !r.handleBad {
			r.handleBad = true
			fmt.Fprintf(os.Stderr, "%s: %s will not read, so an ask on a channel this expert does not answer on is left alone until it does: %v\n",
				prog, path, identity.PrintableText(err.Error()))
		}
		return nil, false
	}
	r.handleBad = false
	for _, channel := range cfg.channels() {
		if !slices.Contains(r.handled, channel) {
			r.handled = append(r.handled, channel)
		}
	}
	slices.Sort(r.handled)
	return r.handled, true
}

// unservedText is the reply's one paragraph: the channel the ask came on,
// the channels serve answers on and, with a handle.json in the home, the
// channels its routes take. Each list is held to the relay's own count of
// channels in a directory, and every name to its length by the rule
// serve.json and handle.json were checked with, so the text is bounded by
// what the relay bounds.
func (r *serveRun) unservedText(channel string) string {
	text := fmt.Sprintf("This expert does not answer on channel %q. It answers on these channels: %s.",
		channel, strings.Join(firstChannels(r.cfg.names()), ", "))
	if handled, _ := r.handleChannels(); len(handled) > 0 {
		text += fmt.Sprintf(" It takes jobs on these channels: %s.", strings.Join(firstChannels(handled), ", "))
	}
	return text + " Send the ask again on one of them, with --channel NAME. " +
		"This message was not answered and nothing of it was read by the expert."
}

// firstChannels is a sorted list of names held to relayapi.MaxChannels, the
// most a mailbox's directory can hold and so the most an asker can reach.
func firstChannels(names []string) []string {
	return names[:min(len(names), relayapi.MaxChannels)]
}

// tell is the reply to one ask on a channel serve does not serve: sealed
// once and posted on the relay the ask came by, recorded in the ledger
// under unserved, and the ask marked read. A post that fails is the ask's
// failure, tried next round from the same envelope.
func (r *serveRun) tell(m *store.Stored, channel string) error {
	dir := filepath.Join(r.root, unservedDir, m.Inner.ID)
	recipient, err := r.s.Resolve(m.Inner.From)
	if err != nil {
		return r.untold(m, channel, dir, fmt.Sprintf("%s is not in your peer list any more", m.Inner.From[:16]))
	}
	relay, err := relayOf(r.s, m, "")
	if err != nil {
		return r.untold(m, channel, dir, err.Error())
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// The words of an envelope already sealed for this ask, whose post may
	// have reached the relay, are the ones posted again: made afresh from a
	// serve.json or handle.json edited since, they would be another answer,
	// sealed again under another id, and the asker told twice.
	sealed := filepath.Join(dir, "sealed.json")
	text := r.unservedText(channel)
	if k, err := readKeptSeal(sealed); err == nil && k != nil && k.Inner != nil && k.Inner.Body.InReplyTo == m.Inner.ID {
		text = k.Inner.Body.Text
	}
	body := message.Body{
		Type:      message.TypeReply,
		Subject:   m.Inner.Body.Subject,
		Thread:    m.Inner.Body.Thread,
		InReplyTo: m.Inner.ID,
		Text:      text,
	}
	out, _, err := sendSealed(r.s, r.id, relay, recipient, body, nil,
		sendMode{sealed: sealed, posted: filepath.Join(dir, "posted.json")})
	if err != nil {
		if isLocked(err) {
			return err
		}
		if isReceiveOnly(err) {
			return needsSendErr("serve")
		}
		return r.untold(m, channel, dir, err.Error())
	}
	e := r.unservedEntry(m, channel)
	e.Handled = time.Now().UTC().Truncate(time.Second)
	e.Tried = e.Handled
	e.Reply = out.ID
	if err := r.led.save(); err != nil {
		// Not recorded, so the next round posts the kept envelope again.
		return err
	}
	if err := r.s.MarkRead(store.Inbox, m.Inner.ID); err != nil {
		return err
	}
	os.RemoveAll(dir)
	r.out.Unserved = append(r.out.Unserved, handledJSON{ID: m.Inner.ID, Channel: channel, Thread: m.Inner.Body.Thread})
	if !r.asJSON {
		_, err := fmt.Printf("%s: %s from %s asked on channel %q, which this expert does not answer on; told it the channels it does (reply %s)\n",
			prog, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), channel, shortID(out.ID))
		if err != nil && r.writeErr == nil {
			r.writeErr = err
		}
	}
	return nil
}

// untold counts one failed attempt to tell an ask, gives up when the
// retries have run out, and says why, as failed does for an answer. The ask
// stays unread.
func (r *serveRun) untold(m *store.Stored, channel, dir, why string) error {
	e := r.unservedEntry(m, channel)
	e.Failures++
	e.Tried = time.Now().UTC().Truncate(time.Second)
	e.GaveUp = e.Failures >= unservedRetries
	if err := r.led.save(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: the ledger could not be written: %v\n", prog, err)
	}
	if e.GaveUp {
		os.RemoveAll(dir)
	}
	r.out.Failed = append(r.out.Failed, handledJSON{ID: m.Inner.ID, Channel: channel, Thread: m.Inner.Body.Thread})
	tail := fmt.Sprintf("attempt %d of %d", e.Failures, unservedRetries)
	if e.GaveUp {
		tail = fmt.Sprintf("given up after %s", plural(e.Failures, "attempt"))
	}
	fmt.Fprintf(os.Stderr, "%s: %s from %s asked on channel %q, which this expert does not answer on, and could not be told so: %s (%s)\n",
		prog, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), channel, identity.PrintableText(why), tail)
	return nil
}

// unservedEntry is an ask's ledger record, made with its sender if it has
// none. It is on no thread and no channel of serve's: every count and
// lookup by thread passes it by, so it is nobody's turn and opens nothing,
// and Unserved names the channel it came on.
func (r *serveRun) unservedEntry(m *store.Stored, channel string) *ledgerEntry {
	e := r.led.entry(m.Inner.ID, "", "")
	e.Unserved = channel
	if e.From == "" {
		setSender(e, m)
	}
	return e
}
