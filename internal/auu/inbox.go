package auu

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
	"github.com/tropeforce7/agentuucp/internal/term"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// fetchResult summarises one drain of a relay mailbox.
type fetchResult struct {
	Delivered   int `json:"delivered"`
	Quarantined int `json:"quarantined"`
	// Unreadable is every message nobody will read: kept under damaged/,
	// too large to keep, or dropped by the relay as damaged there. Kept
	// is the first of those alone, so a sentence about damaged/ never
	// claims a file that is not there.
	Unreadable int `json:"unreadable"`
	Kept       int `json:"kept"`
	// Duplicate counts the rows that were a message already held here from
	// the same relay and sender, a copy posted twice: acknowledged, not
	// delivered again, the record as it was.
	Duplicate int `json:"duplicate"`
	// Newer is the streams left on the relay for a newer auu (D42), by
	// the critical section each carries, which a build that knows it
	// fetches whole.
	Newer []string `json:"newer,omitempty"`
	// Gone counts the messages delivered under each channel that is no
	// longer in this machine's directory: a channel deleted with mail
	// still queued, which arrives as usual and is filed under its name.
	Gone map[string]int `json:"channels_gone,omitempty"`
}

func (f *fetchResult) add(o fetchResult) {
	f.Delivered += o.Delivered
	f.Quarantined += o.Quarantined
	f.Unreadable += o.Unreadable
	f.Kept += o.Kept
	f.Duplicate += o.Duplicate
	f.Newer = append(f.Newer, o.Newer...)
	for name, n := range o.Gone {
		if f.Gone == nil {
			f.Gone = map[string]int{}
		}
		f.Gone[name] += n
	}
}

// empty reports that a fetch delivered, held, kept and noted nothing.
func (f fetchResult) empty() bool {
	return f.Delivered == 0 && f.Quarantined == 0 && f.Unreadable == 0 && f.Kept == 0 && len(f.Gone) == 0
}

// noteGone records a delivered message's channel when this machine's
// directory no longer lists it. A home with no directory defines nothing
// and says nothing.
func (f *fetchResult) noteGone(d *channels.Directory, channel string) {
	if d == nil {
		return
	}
	if channel == "" {
		channel = channels.Default
	}
	if d.Find(channel) != nil {
		return
	}
	if f.Gone == nil {
		f.Gone = map[string]int{}
	}
	f.Gone[channel]++
}

// relayFetch is what one relay gave up, or why it did not.
type relayFetch struct {
	Relay string `json:"relay"`
	URL   string `json:"url"`
	fetchResult
	// Queued is what this relay said it holds in all when the fetch
	// finished: with a channel set to keep, the mail read and left there,
	// which 'auu rm' is what removes.
	Queued int64 `json:"queued"`
	// First and Last are the lowest and highest ids that relay said it
	// holds for this mailbox, zero for an empty one: a cursor above Last is
	// past everything there, and the fetch resets it.
	First int64 `json:"first"`
	Last  int64 `json:"last"`
	// Outbound is this identity's own rows in that relay's forwarding
	// queue, when it forwards at all: mail on its way to another relay.
	// Absent on a relay that forwards nothing, which answers the route
	// with a refusal rather than an empty list.
	Outbound []relayapi.QueuedMessage `json:"outbound,omitempty"`
	// Allow is the state of this identity's allow list on the relay, as
	// the relay said it: signed, none or broken. Card is the same for the
	// card, and Directory for the channel directory.
	Allow     string `json:"allow,omitempty"`
	Card      string `json:"card,omitempty"`
	Directory string `json:"directory,omitempty"`
	Error     string `json:"error,omitempty"`
}

// relaySaid is what a relay's last listing said beside the messages: how
// many it holds in all, which the refresh and the caller's count line
// read, and the state of the allow list, which the warning after the
// messages reads.
type relaySaid struct {
	Queued      int64
	First, Last int64
	Allow       string
	Card        string
	Directory   string
}

// fetch drains one relay's mailbox into the local spool.
//
// The order matters: a message is only acknowledged to the relay after it is
// safely on local disk, and the cursor only advances after the acknowledgement.
// A crash anywhere in between costs a duplicate fetch, never a lost message.
//
// Each relay has its own cursor, in its own directory, because the ids are
// each relay's own counter and mean nothing at another.
//
// ctx bounds every request made here. A drain has no deadline of its own
// and passes ctx(); a wait passes its own deadline, so that a relay which
// accepts and never answers is cut off when the wait is over.
//
// hold is passed to the first page's listing and no further: a wait asks
// the relay to hold that page open until something arrives, so a reply
// comes back when it is sent rather than at the next poll; every page
// after the first has mail to fetch, and a drain asks for no hold at all.
// A relay over its cap on holds answers at once, and nothing here can tell.
func fetch(ctx context.Context, s *store.Store, id *identity.Identity, c *client.Client, r *store.Relay, hold time.Duration) (fetchResult, relaySaid, error) {
	// The local directory, for saying which delivered mail was for a
	// channel no longer in it. Read through the damaged path: a file this
	// machine cannot read is a person's to look at, whichever command met
	// it.
	directory, _, err := s.Directory()
	if err != nil {
		return fetchResult{}, relaySaid{}, err
	}
	// This machine's own policy per channel, read once before anything is
	// fetched: a file that will not read decides nothing here, and
	// guessing at it would acknowledge away mail its owner meant to keep.
	settings, err := s.ChannelSettings()
	if err != nil {
		return fetchResult{}, relaySaid{}, err
	}
	var (
		res fetchResult
		// said is what the relay said beside the messages, from the last
		// page of this fetch.
		said relaySaid
	)
	// The peer list is what sorts what arrives into the inbox and the
	// quarantine, so it is read once, before anything is fetched: a line
	// that will not parse is refused by number here, where before it made
	// every sender a stranger and said nothing about why. The container
	// suite's K18 found the quarantine full and the file unmentioned.
	if _, err := s.Peers(); err != nil {
		return res, said, err
	}
	// One fetch at a time per relay, for the length of the fetch: two
	// running at once on one machine list the same messages, save them
	// twice and count them twice, and one advances the cursor past mail
	// the other had not yet saved. The lock is a file in the relay's own
	// directory, so it is per relay and per home, and the kernel releases
	// it however this process ends. The container suite's N03 found both
	// of two fetches delivering all three messages.
	// The wait for it runs under ctx too: a wait's poll that meets the
	// lock is cut off at the wait's deadline, like one that meets a relay
	// which never answers. Anything that waits inside a poll takes the
	// poll's context.
	lock, waited, err := lockfile.Take(ctx, filepath.Join(s.RelayDir(r), fetchLockName), fetchLockWait, fetchLockSleep)
	if errors.Is(err, lockfile.ErrHeld) {
		return res, said, transportErr(fmt.Errorf("another %s is fetching from %s; try again in a moment: %w",
			prog, r.Name, err))
	}
	if err != nil {
		// The lock is a file in this home: one that cannot be made is
		// this home's trouble, not the relay's, and is said with the path
		// at the plain exit code, as a message that cannot be saved is.
		// The container suite's K29 found a read-only home reported as a
		// transport failure.
		return res, said, fmt.Errorf("taking the fetch lock for %s: %w", r.Name, err)
	}
	defer lock.Release()
	if waited {
		fmt.Fprintf(os.Stderr, "%s: another %s was fetching from %s; it has finished, carrying on\n", prog, prog, r.Name)
	}
	cursor, err := s.CursorFor(r)
	if err != nil {
		return res, said, err
	}
	// What this machine already holds from this relay is met, not saved,
	// on every fetch (reset.go).
	met, err := newMeeter(s, r)
	if err != nil {
		return res, said, err
	}
	// A stream that waited on this relay for the build this now is.
	if err := fetchKnownNow(ctx, s, id, c, r, settings, &res); err != nil {
		return res, said, err
	}
	var (
		// reset is the re-fetch from the relay's first id, while it runs;
		// reckoned says the cursor has been held against the relay's span
		// once in this run, which is all it needs, and marked that the
		// marks on what was left there are as fresh as the relay's rows.
		reset            *resetRun
		reckoned, marked bool
	)
	for {
		page, err := c.ListWait(ctx, client.ListRequest{After: cursor, Limit: relayapi.MaxListLimit, Wait: hold})
		if err != nil {
			return res, said, transportErr(err)
		}
		hold = 0
		said = relaySaid{Queued: page.Queued, First: page.First, Last: page.Last,
			Allow: page.Allow, Card: page.Card, Directory: page.Directory}
		if len(page.Messages) == 0 && !reckoned && cursor > page.Last {
			// A cursor past everything the relay holds: reset.go says
			// what it is and what is done about it, here and in a watch.
			reckoned = true
			past, err := classifyPast(ctx, s, c, r, page.Last)
			if err != nil {
				return res, said, transportErr(err)
			}
			if len(past.fresh) == 0 {
				// All of it is mail this machine has: the newest was
				// removed. The cursor goes back to the relay's last id,
				// and nothing is said or downloaded.
				if _, err := settleMatched(ctx, s, c, r.Name, past); err != nil {
					return res, said, err
				}
				cursor, marked = page.Last, true
			} else {
				reset = startReset(r, cursor, page, past, met)
				cursor = max(page.First-1, 0)
			}
			// Written before the fetch that relies on it.
			if err := s.SetCursorFor(r, cursor); err != nil {
				return res, said, err
			}
			continue
		}
		if len(page.Messages) == 0 && reset != nil {
			if err := reset.finish(s); err != nil {
				return res, said, err
			}
			reset, marked = nil, true
		}
		if len(page.Messages) == 0 {
			if err := met.settle(s); err != nil {
				return res, said, err
			}
			// Everything after the cursor is here; now the marks on what
			// was left behind, which another machine or an administrator
			// may have removed since, unless a reset has just made them
			// from the relay's own rows. Before the count below, so that
			// it counts what is there: after a relay's numbering began
			// again, a mark on a message under an id a new message now
			// has is cleared here, and the new one is then said to be
			// skipped in this fetch rather than the next.
			if !marked {
				refreshKept(ctx, s, c, r, page.Queued)
			}
			// Nothing after the cursor, and yet the relay holds mail: the
			// cursor is past it. The relay says how many, the sentence
			// names the file, and neither the cursor nor the relay is
			// touched, since only a person can decide the cursor is wrong. Zero is an empty
			// mailbox, which is silence. The container suite's K17 found
			// mail sitting on the relay with nothing to say so.
			//
			// Less what this machine left there on purpose: mail fetched
			// from a channel set to keep, a stranger's stream quarantined
			// from its manifest with the payload left on the relay until
			// a person decides, and a message removed here alone. The
			// relay counts them; this machine knows it did that. The
			// spool is read only here, on an empty page beside a count,
			// so an ordinary fetch does not read it.
			if page.Queued != 0 {
				left, err := s.LeftOn(r.Name)
				if err != nil {
					return res, said, err
				}
				if page.Queued > left {
					return res, said, s.CursorSkipsMail(r, page.Queued-left)
				}
			}
			return res, said, nil
		}
		for _, m := range page.Messages {
			if m.IsStream() {
				if err := fetchOneStream(ctx, s, id, c, r, m, directory, settings, &res, met); err != nil {
					return res, said, transportErr(err)
				}
				cursor = m.ID
				if err := s.SetCursorFor(r, cursor); err != nil {
					return res, said, err
				}
				continue
			}
			inner, sender, err := envelope.Open(id, m.Envelope)
			if isLocked(err) {
				// Not unreadable: the key is not here. The agent locked
				// between the start of this command and now, and the
				// message stays queued for the next fetch.
				return res, said, err
			}
			// A message with a critical section this build does not know,
			// signed by the sender Open names: kept, said to be, and
			// acknowledged, as a damaged message is, and told apart from
			// one (D29, R8).
			var newer *wire.NeedsNewerError
			if errors.As(err, &newer) && sender != nil {
				met.fresh++
				if err := keepNewer(s, r, m, newer.Name, sender.Fingerprint(), &res); err != nil {
					return res, said, err
				}
				if err := c.Ack(ctx, m.ID); err != nil {
					return res, said, transportErr(err)
				}
				cursor = m.ID
				if err := s.SetCursorFor(r, cursor); err != nil {
					return res, said, err
				}
				continue
			}
			if err == nil {
				meeting, err := met.meet(ctx, s, c, m, inner.ID, sender.Fingerprint())
				if err != nil {
					return res, said, err
				}
				if meeting == collided {
					met.fresh++
					if err := keepCollided(s, r, m.ID, m.Received, m.Raw, &res); err != nil {
						return res, said, err
					}
					if err := c.Ack(ctx, m.ID); err != nil {
						return res, said, transportErr(err)
					}
				}
				if meeting == metAgain {
					res.Duplicate++
				}
				if meeting != notHeld {
					cursor = m.ID
					if err := s.SetCursorFor(r, cursor); err != nil {
						return res, said, err
					}
					continue
				}
			}
			met.fresh++
			o := openOne(s, r, m, inner, sender, err, settings, fetchChecks)
			switch o.verdict {
			case unreadable:
				// Nobody will ever be able to read this, so leaving it queued
				// would block the mailbox forever. Keep the bytes, say why
				// in a word, and acknowledge it.
				if err := keepDamaged(s, r, m.ID, m.Received, m.Raw, o.cause, &res); err != nil {
					return res, said, err
				}
			case miskinded:
				if err := keepMiskinded(s, r, m.ID, m.Received, m.Raw, m.Kind, o.typ, &res); err != nil {
					return res, said, err
				}
			case misfiled:
				if err := keepMisfiled(s, r, m.ID, m.Received, m.Raw, o.filedAs, o.sealed, &res); err != nil {
					return res, said, err
				}
			}
			if o.verdict != opened {
				if err := c.Ack(ctx, m.ID); err != nil {
					return res, said, transportErr(err)
				}
				cursor = m.ID
				if err := s.SetCursorFor(r, cursor); err != nil {
					return res, said, err
				}
				continue
			}
			if err := s.Save(o.box, o.stored); err != nil {
				return res, said, fmt.Errorf("saving message locally: %w", err)
			}
			if !o.stored.OnRelay {
				if err := c.Ack(ctx, m.ID); err != nil {
					return res, said, transportErr(err)
				}
			}
			cursor = m.ID
			if err := s.SetCursorFor(r, cursor); err != nil {
				return res, said, err
			}
			channel := o.stored.Channel
			box := o.box
			if box == store.Inbox {
				res.Delivered++
				res.noteGone(directory, channel)
			} else {
				res.Quarantined++
			}
		}
	}
}

// verdict is what the open path makes of one envelope.
type verdict int

const (
	// opened is a message to file: stored, in box.
	opened verdict = iota
	// unreadable is one that did not open, for a reason in cause.
	unreadable
	// miskinded is one the relay listed under a kind its sealed type is
	// not: typ is the sealed type.
	miskinded
	// misfiled is one the relay filed under a channel it was not sealed
	// for: filedAs is where the relay put it, sealed where it was sealed.
	misfiled
)

// opening is the open path's verdict on one envelope and what goes with it.
type opening struct {
	verdict         verdict
	cause           string
	typ             string
	filedAs, sealed string
	stored          *store.Stored
	box             store.Box
}

// checks says which of the open path's checks against the listing can run.
// The fetch has the listing and runs both. A message kept as newer by an
// earlier release has no record of what the listing said: reopening it
// skips the kind check, which the envelope has no half of, and checks the
// channel against the envelope's own alone.
type checks struct {
	// kind is the listed kind against the sealed type.
	kind bool
	// listedChannel is the listed channel against the sealed one; the
	// envelope's outer channel is checked against the sealed one always.
	listedChannel bool
}

var fetchChecks = checks{kind: true, listedChannel: true}

// openOne is the open path the fetch and auu damaged reopen share, from
// Open's answer to the record that would be saved, in the fetch's order:
// an envelope that did not open, then the kind the relay listed it under,
// then the channel it was filed under, then the peer rule. It keeps
// nothing, acknowledges nothing and counts nothing: those are the
// caller's, since the fetch keeps what fails and reopen leaves it where
// it is. Open has already been called, and its locked and newer answers,
// and meeting an id already held, are the caller's too.
func openOne(s *store.Store, r *store.Relay, m client.Message, inner *envelope.Inner, sender *identity.Public, openErr error,
	settings store.ChannelSettings, run checks) opening {
	if openErr != nil {
		return opening{verdict: unreadable, cause: openCause(openErr)}
	}
	// The kind the relay listed it under, against the type inside the
	// signature. A knock came in past the allow list because the owner's
	// card admits knocks, so a row that says knock outside and something
	// else inside, or the reverse, is obeyed in neither direction: kept,
	// said to be, and acknowledged, as a message filed under the wrong
	// channel is.
	if run.kind && !knockAgrees(m.Kind, inner.Body.Type) {
		return opening{verdict: miskinded, typ: inner.Body.Type}
	}
	// The channel it was sealed for, against the one the relay posted and
	// listed it under. A relay that filed it elsewhere is found out here,
	// not obeyed: the message is kept, said to be, and acknowledged like
	// the other kept ones.
	if !run.listedChannel {
		m.Channel = inner.Channel
		if m.Channel == "" {
			m.Channel = channels.Default
		}
	}
	channel, filedAs, agrees := filedUnder(inner.Channel, m.Envelope.Ch, m)
	if !agrees {
		return opening{verdict: misfiled, filedAs: filedAs, sealed: inner.Channel}
	}
	box := store.Quarantine
	if s.IsAuthorized(sender.Fingerprint()) {
		box = store.Inbox
	}
	// Kept on the relay, or acknowledged away, as this machine's setting
	// for the channel says. Kept is the default, and the record says so,
	// since nothing else would remember. A knock is never kept, whatever
	// the channel says: the recipient's copy is the one that matters, and
	// a kept knock would count against the relay's max_knocks_waiting for
	// ever, closing the mailbox to every other knocker.
	keep := keepFor(settings, channel) && inner.Body.Type != message.TypeKnock
	// The sections it came with, kept as they came at or under the kept
	// size and counted over it (D31).
	var dropped int
	inner.Sections, dropped = keptSections(inner.Sections)
	return opening{verdict: opened, box: box, stored: &store.Stored{
		DroppedSections: dropped,
		RelayID:         m.ID,
		Relay:           r.Name,
		Received:        m.Received,
		RelaySize:       m.Size,
		Inner:           inner,
		SenderName:      s.PeerName(sender.Fingerprint()),
		Channel:         channel,
		OnRelay:         keep,
		// Where it has been, which only the person receiving it can
		// judge, and which a reply goes back along. The client held these
		// names to the relay-name rule before this listing was read.
		Via: m.Via,
	}}
}

type attachmentJSON struct {
	Name   string `json:"name"`
	Media  string `json:"media"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type messageJSON struct {
	ID        string    `json:"id"`
	Thread    string    `json:"thread"`
	InReplyTo string    `json:"in_reply_to,omitempty"`
	Type      string    `json:"type"`
	Subject   string    `json:"subject"`
	From      string    `json:"from"`
	FromName  string    `json:"from_name"`
	Time      time.Time `json:"time"`
	Received  time.Time `json:"received"`
	Read      bool      `json:"read"`
	Box       string    `json:"box"`
	// ThreadSubject is the subject the thread was opened with, which is
	// this message's own unless it was given one of its own. Set where a
	// whole message is shown — read, wait and quarantine show — and not in
	// a listing, where every line is its own message's subject.
	ThreadSubject string `json:"thread_subject,omitempty"`
	// Room is this machine's name for the people a message to several
	// went to, where a saved room holds exactly them (D60); empty otherwise.
	Room        string           `json:"room,omitempty"`
	Text        string           `json:"text,omitempty"`
	Attachments []attachmentJSON `json:"attachments"`
	// Channel is the channel the message is filed under, default when the
	// sender named none.
	Channel string `json:"channel"`
	// Via is the relays the message came through before the one it arrived
	// at, nearest the sender first and joined by "!". Absent for mail
	// posted to that relay directly, which is most mail; a reader that
	// wants to know whether a message crossed a relay asks whether this is
	// there.
	Via string `json:"via,omitempty"`
	// ClaimedName is the name a knock's sender called themselves, their
	// own claim and never a label: present on a knock alone, and set
	// beside from_name, which is what this machine calls them, empty
	// until somebody accepts one.
	ClaimedName string `json:"claimed_name,omitempty"`
	// OnRelay says the message is still queued on the relay it came
	// through, and PayloadOnRelay that a quarantined stream's body is.
	OnRelay        bool `json:"on_relay,omitempty"`
	PayloadOnRelay bool `json:"payload_on_relay,omitempty"`
	// Newer names the critical section a stream carries that this build
	// does not know, for a stream that waits on the relay for a newer auu
	// (D42); nothing of what it carries is said beside it.
	Newer string `json:"newer,omitempty"`
	// IgnoredSections names the sections the message came with that this
	// build does not know and kept as they came (D31), and DroppedSections
	// counts those it did not keep for being over the kept size.
	IgnoredSections []string `json:"ignored_sections,omitempty"`
	DroppedSections int      `json:"dropped_sections,omitempty"`
	// Vouch is a vouch message's judgement here: whether it counts and
	// why not, and what it says when it does. On a vouch alone.
	Vouch *vouchJSON `json:"vouch,omitempty"`
	// Ask is a vouch question's account: the fingerprint asked about and
	// whether this machine holds it. On a vouch-ask alone.
	Ask *askJSON `json:"ask,omitempty"`
	// Vouches is what this machine makes of the vouches a knock carries:
	// the vouchers it holds whose vouch counts, those whose does not
	// verify, and how many are from people it does not hold. On a knock
	// that carries any.
	Vouches *knockVouchesJSON `json:"vouches,omitempty"`
	// Copies is a sent message to several: each recipient, and whether the
	// relay has their copy, as the sent record says. Absent for any other.
	Copies []copyJSON `json:"copies,omitempty"`
	// Recipients is everybody a message to several went to, as its sender
	// listed them, each by fingerprint and the name this machine has for
	// them, the reader's own among them; absent for a message to one.
	Recipients []recipientNameJSON `json:"recipients,omitempty"`
}

// recipientNameJSON is one recipient of a message to several, the shape an
// allow list's senders have.
type recipientNameJSON struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name,omitempty"`
}

// recipientsOf is the list a message to several names, as its sender wrote
// it, held to its rule when the record was loaded; nothing for a message to
// one.
func recipientsOf(m *store.Stored) []string {
	list, err := recipients.CheckSections(m.Inner.Sections, m.Inner.Body.Type, m.Inner.To)
	if err != nil {
		return nil
	}
	return list.To
}

// printRecipients says, for a message to several, who else it went to:
// each by the name this machine has for them, the short fingerprint for one
// it does not know, and you for the reader, every name escaped.
func printRecipients(s *store.Store, m *store.Stored) {
	list := recipientsOf(m)
	if len(list) < 2 {
		return
	}
	self := ""
	if me, err := s.Self(); err == nil {
		self = me.Fingerprint()
	}
	names := make([]string, len(list))
	for i, fp := range list {
		switch name := s.PeerName(fp); {
		case fp == self:
			names[i] = "you"
		case name != "":
			names[i] = identity.Printable(name)
		default:
			names[i] = "<" + fp[:16] + ">"
		}
	}
	fmt.Printf("to:      %s\n", strings.Join(names, ", "))
}

// copyJSON is one copy of a sent message to several in --json.
type copyJSON struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name,omitempty"`
	Path        string `json:"path,omitempty"`
	RelayID     int64  `json:"relay_id,omitempty"`
	Code        string `json:"code,omitempty"`
	Error       string `json:"error,omitempty"`
	Dropped     bool   `json:"dropped,omitempty"`
}

// printCopies says, for a sent message to several, who has it and who does
// not yet: each recipient by the name this machine gave them, the path the
// copy went by, and the relay's words for one it refused, all escaped. A
// record with no copies says nothing here.
func printCopies(m *store.Stored) {
	for i, c := range m.Copies {
		head := "to:"
		if i > 0 {
			head = ""
		}
		label := identity.Printable(orNone(c.Name))
		if c.Path != "" {
			label += " by " + identity.Printable(c.Path)
		}
		state := "sent"
		switch {
		case c.Dropped:
			state = "given up with auu outbox drop"
			if c.Refused != "" {
				state += "; refused: " + identity.PrintableText(c.Refused)
			}
		case c.Refused != "":
			state = "refused: " + identity.PrintableText(c.Refused)
		case c.RelayID == 0:
			state = "waiting in the outbox"
		}
		fmt.Printf("%-8s %s <%s>: %s\n", head, label, c.Fingerprint[:16], state)
	}
}

func toJSON(s *store.Store, box store.Box, m *store.Stored, includeText bool) messageJSON {
	out := messageJSON{
		ID:          m.Inner.ID,
		Thread:      m.Inner.Body.Thread,
		InReplyTo:   m.Inner.Body.InReplyTo,
		Type:        m.Inner.Body.Type,
		Subject:     m.Inner.Body.Subject,
		From:        m.Inner.From,
		FromName:    m.SenderName,
		Time:        m.Inner.Time,
		Received:    m.Received,
		Read:        m.Read,
		Box:         string(box),
		Attachments: make([]attachmentJSON, 0, len(m.Inner.Body.Attachments)),
		Channel:     channelName(m.Channel),
		Via:         m.Via,
		ClaimedName: m.Inner.Body.Name,

		OnRelay:        m.OnRelay,
		PayloadOnRelay: m.PayloadOnRelay,
	}
	for _, fp := range recipientsOf(m) {
		name := ""
		if s != nil {
			name = s.PeerName(fp)
		}
		out.Recipients = append(out.Recipients, recipientNameJSON{Fingerprint: fp, Name: name})
	}
	for _, c := range m.Copies {
		out.Copies = append(out.Copies, copyJSON{
			Fingerprint: c.Fingerprint, Name: c.Name, Path: c.Path, RelayID: c.RelayID,
			Code: c.RefusedCode, Error: c.Refused, Dropped: c.Dropped,
		})
	}
	if m.Inner.Body.Type == message.TypeVouch && s != nil {
		out.Vouch = vouchToJSON(judgeVouch(s, m, time.Now()))
	}
	if m.Inner.Body.Type == message.TypeVouchAsk && s != nil {
		out.Ask = askToJSON(s, m)
	}
	if m.Inner.Body.Type == message.TypeKnock && len(m.Inner.Body.Vouches) > 0 && s != nil {
		k := judgeKnockVouches(s, m, time.Now())
		out.Vouches = &knockVouchesJSON{By: k.Held, NotVerifying: k.Bad, Unknown: k.Unknown}
	}
	out.Newer = m.Newer
	out.DroppedSections = m.DroppedSections
	for _, sec := range m.Inner.Sections {
		if !wire.Known(sec.Name) {
			out.IgnoredSections = append(out.IgnoredSections, sec.Name)
		}
	}
	if includeText && m.Newer == "" {
		out.Text = m.Inner.Body.Text
	}
	for _, a := range m.Inner.Body.Attachments {
		out.Attachments = append(out.Attachments, attachmentJSON{
			Name: a.Name, Media: a.Media, Size: a.Size, SHA256: a.SHA256,
		})
	}
	return out
}

type inboxJSON struct {
	Fetch fetchResult `json:"fetch"`
	// Relays says what each relay gave up, or why it did not. The totals in
	// Fetch are the sum of them.
	Relays   []relayFetch  `json:"relays"`
	Messages []messageJSON `json:"messages"`
}

// fetchEvery drains every relay given, each with its own cursor.
//
// A relay that cannot be reached is reported and skipped: mail on the others
// is still mail, and one relay being down must not stop somebody reading it.
// The exception is a run narrowed to one relay, where a failure is the
// command's failure, because there is nothing else it could have been doing.
func fetchEvery(s *store.Store, id *identity.Identity, relays []*store.Relay, narrowed bool) (fetchResult, []relayFetch, error) {
	var (
		total    fetchResult
		reports  []relayFetch
		firstErr error
		ok       int
	)
	for _, r := range relays {
		report := relayFetch{Relay: r.Name, URL: r.URL}
		c, err := dial(s, id, r)
		if err == nil {
			var said relaySaid
			report.fetchResult, said, err = fetch(ctx(), s, id, c, r, 0)
			report.Queued, report.Allow, report.Card = said.Queued, said.Allow, said.Card
			report.First, report.Last = said.First, said.Last
			report.Directory = said.Directory
		}
		if err == nil {
			// A relay this identity has drained is a relay it has a mailbox
			// on, whatever the home thought before. An empty mailbox writes
			// no cursor of its own, so say it here.
			err = s.MarkRegistered(r)
		}
		if err == nil {
			// What this identity still has on its way out through that
			// relay. Deliberately not part of the fetch's error: a relay
			// that forwards nothing refuses the route, and most relays
			// forward nothing, so a failure here is silence and never a
			// reason for the inbox to fail.
			if queued, qerr := c.Queue(ctx()); qerr == nil {
				report.Outbound = queued
			}
		}
		if err != nil {
			// A damaged file is not a relay that could not be reached: it
			// is a person's to look at, whichever relay it was met at, and
			// the command stops there so that its code says so. Carrying
			// on would print the sentence as one relay's trouble among
			// several and exit 0 on the strength of the others.
			if narrowed || errors.Is(err, store.ErrDamaged) {
				return total, nil, err
			}
			report.Error = err.Error()
			fmt.Fprintf(os.Stderr, "%s: %s could not be reached: %v\n", prog, r.Name, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", r.Name, err)
			}
		} else {
			ok++
			total.add(report.fetchResult)
		}
		reports = append(reports, report)
	}
	// Every relay failed: there is no mail to show and nothing succeeded, so
	// this is a failure like any other.
	if ok == 0 && firstErr != nil {
		return total, reports, firstErr
	}
	return total, reports, nil
}

func cmdInbox(args []string) error {
	fs := newFlagSet("inbox")
	asJSON := fs.Bool("json", false, "machine readable output")
	noFetch := fs.Bool("no-fetch", false, "list what is already local, without contacting the relay")
	channel := fs.String("channel", "", "list only the messages filed under this channel; the fetch is whole")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	if err := validChannelFlag(*channel); err != nil {
		return err
	}
	// Listing what is on disk needs no key. Fetching does, and is what
	// asks for the agent.
	s, _, err := requireIdentity()
	if err != nil {
		return err
	}

	var (
		res     fetchResult
		reports []relayFetch
	)
	if !*noFetch {
		var id *identity.Identity
		if s, id, err = loadIdentity(); err != nil {
			return err
		}
		relays, err := selectedRelays(s, *relay)
		if err != nil {
			return err
		}
		narrowed := len(relays) == 1
		if res, reports, err = fetchEvery(s, id, relays, narrowed); err != nil {
			return err
		}
		// A peer's question, answered here when the person has turned
		// that on, and never in serve. Its line goes beside the listing,
		// or to standard error under --json so the answer stays one object.
		answered := io.Writer(os.Stdout)
		if *asJSON {
			answered = os.Stderr
		}
		keepVouches(s, answered)
		answerAsks(s, id, answered)
	}

	msgs, err := s.List(store.Inbox)
	if err != nil {
		return err
	}
	// A local filter only: the fetch above was the whole mailbox, and the
	// cursor is one per relay.
	if *channel != "" {
		kept := msgs[:0:0]
		for _, m := range msgs {
			if channelName(m.Channel) == *channel {
				kept = append(kept, m)
			}
		}
		msgs = kept
	}
	if *asJSON {
		out := inboxJSON{Fetch: res, Relays: reports, Messages: make([]messageJSON, 0, len(msgs))}
		for _, m := range msgs {
			out.Messages = append(out.Messages, toJSON(s, store.Inbox, m, false))
		}
		return printJSON(out)
	}

	if res.Delivered > 0 || res.Quarantined > 0 || res.Duplicate > 0 {
		fmt.Printf("fetched %d new message(s)", res.Delivered)
		if res.Quarantined > 0 {
			fmt.Printf(", %d quarantined from unknown senders", res.Quarantined)
		}
		if res.Duplicate > 0 {
			fmt.Printf(", %d already held", res.Duplicate)
		}
		fmt.Println()
	}
	if len(msgs) == 0 {
		fmt.Println("inbox is empty")
	} else {
		for _, m := range msgs {
			printInboxLine(s, m)
		}
		fmt.Printf("\nRead one with: %s read <id>\n", prog)
	}
	if res.Quarantined > 0 {
		fmt.Printf("Unknown senders are held back: %s quarantine ls\n", prog)
	}
	// What waits on a relay for a newer auu is said every time, as what is
	// under damaged/ is: it stays until a build that knows its section
	// fetches it, and the point of the record is that a person knows.
	if waiting := waitingForNewer(s); len(waiting) > 0 {
		fmt.Printf("%d stream(s) wait on the relay for a newer auu (section %s); update auu to fetch them\n",
			len(waiting), strings.Join(waiting, ", "))
	}
	// What each relay is still holding, which with a channel set to keep
	// is the mail already read: the count is the relay's own, and 'auu
	// rm' is what brings it down.
	for _, rep := range reports {
		if rep.Queued > 0 {
			fmt.Printf("%s: %d message(s) on the relay; %s rm removes them\n", rep.Relay, rep.Queued, prog)
		}
	}
	// What is still on its way out, per relay: mail this machine addressed
	// to somebody on another relay and this one has not handed over. It is
	// the other half of "what is my mail doing" and the only party who
	// knows is the relay holding it.
	for _, rep := range reports {
		if line := queueLine(rep); line != "" {
			fmt.Println(line)
		}
	}
	// What each relay said about this identity's allow list and card
	// there, after the messages and on stderr: a warning, and the run's
	// own exit code stands.
	for _, rep := range reports {
		if rep.Error != "" {
			continue
		}
		if r, err := s.Relay(rep.Relay); err == nil {
			if err := warnAllowState(s, r, rep.Allow); err != nil {
				return err
			}
			if err := warnCardState(s, r, rep.Card); err != nil {
				return err
			}
			if err := warnDirectoryState(r, rep.Directory); err != nil {
				return err
			}
		}
	}
	if len(res.Gone) > 0 {
		names := make([]string, 0, len(res.Gone))
		n := 0
		for name, count := range res.Gone {
			names = append(names, fmt.Sprintf("%q", name))
			n += count
		}
		sort.Strings(names)
		fmt.Printf("%d message(s) arrived for channels no longer in your directory: %s\n", n, strings.Join(names, ", "))
	}
	// What is under damaged/ is said every time, not only the time it was
	// kept: it stays until a person removes it, and the point of keeping
	// it is that a person knows it is there.
	if kept, _, err := s.DamagedKept(); err == nil && kept > 0 {
		newer, err := s.DamagedNeedingNewer()
		if err != nil {
			newer = 0
		}
		if newer > 0 {
			fmt.Printf("%d message(s) kept under %s need a newer auu; update auu and open them with %s damaged reopen --all\n", newer, s.DamagedDir(), prog)
		}
		if rest := kept - newer; rest > 0 {
			fmt.Printf("%d damaged message(s) kept under %s; ask their senders to send them again\n", rest, s.DamagedDir())
		}
	}
	return nil
}

// printQuarantineLine is one message as the quarantine lists it. A knock
// has no subject and carries its sender's own name and one line instead,
// both said as theirs and both escaped here, as every word from outside
// is wherever it is printed.
func printQuarantineLine(s *store.Store, m *store.Stored) {
	if m.Inner.Body.Type == message.TypeKnock {
		vouched := ""
		if s != nil {
			vouched = knockVouchLine(judgeKnockVouches(s, m, time.Now()))
		}
		fmt.Printf("%s  knock  from %s  %s  %s%s%s\n", m.Inner.ID[:12], m.Inner.From[:16],
			truncate(orNone(identity.Printable(m.Inner.Body.Name)), 20),
			truncate(identity.PrintableText(m.Inner.Body.Text), 40), vouched, whereElse(m))
		return
	}
	fmt.Printf("%s  from %s  %s%s\n", m.Inner.ID[:12], m.Inner.From[:16],
		truncate(orNone(identity.PrintableText(m.Inner.Body.Subject)), 40), whereElse(m))
}

// printInboxLine is one message as the inbox lists it: unread flag, the
// id, sender, type, subject, when it arrived, attachments, channel, and
// where it still is besides here.
func printInboxLine(s *store.Store, m *store.Stored) {
	flag := " "
	if !m.Read {
		flag = "*"
	}
	att := ""
	if n := len(m.Inner.Body.Attachments); n > 0 {
		att = fmt.Sprintf("  [%d file(s)]", n)
	}
	ch := ""
	if m.Channel != "" {
		ch = fmt.Sprintf("  in %q", m.Channel)
	}
	// A message to several says how many it went to; read says who.
	if n := len(recipientsOf(m)); n > 1 {
		att += fmt.Sprintf("  (to %d)", n)
	}
	// A vouch's column is what it vouches for and what that is to this
	// machine, judged here against the peer list, in place of a subject
	// the sender chose.
	what := truncate(orNone(identity.PrintableText(m.Inner.Body.Subject)), 32)
	if m.Inner.Body.Type == message.TypeVouch && s != nil {
		what = vouchLine(judgeVouch(s, m, time.Now()))
	}
	if m.Inner.Body.Type == message.TypeVouchAsk && s != nil {
		what = askLine(s, m)
	}
	fmt.Printf("%s %s  %-14s %-8s %-32s %s%s%s%s\n",
		flag,
		m.Inner.ID[:12],
		truncate(orNone(identity.Printable(m.SenderName)), 14),
		m.Inner.Body.Type,
		what,
		m.Received.Local().Format("2006-01-02 15:04"),
		att, ch, whereElse(m))
}

// whereElse says what of a message is not here: the message itself still
// queued on the relay it came through, kept there by its channel's setting
// until 'auu rm' removes it, and a quarantined stream whose body was never
// fetched, which waits on a decision about its sender. The second is a
// statement about this machine, so it holds whether or not the relay still
// has the body to give.
func whereElse(m *store.Stored) string {
	switch {
	case m.Newer != "":
		return fmt.Sprintf("  needs a newer auu (section %q)", m.Newer)
	case m.PayloadOnRelay && m.PayloadGone:
		return "  body not fetched, and gone from the relay"
	case m.OnRelay && m.PayloadOnRelay:
		return "  on relay, body not fetched"
	case m.OnRelay:
		return "  on relay"
	case m.PayloadOnRelay:
		return "  body not fetched"
	}
	return ""
}

func cmdRead(args []string) error {
	fs := newFlagSet("read")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s read MESSAGE-ID", prog)
	}
	s, _, err := requireIdentity()
	if err != nil {
		return err
	}
	box, m, err := s.Find(positional[0])
	if err != nil {
		return usageErrf("%v", err)
	}
	if m.Newer != "" {
		if *asJSON {
			return printJSON(toJSON(s, box, m, false))
		}
		fmt.Println(waitsForNewer(m))
		return nil
	}
	if err := s.MarkRead(box, m.Inner.ID); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(wholeMessage(s, box, m))
	}
	printMessage(s, box, m)
	return nil
}

// waitingForNewer is each stream recorded as waiting on a relay for a
// newer auu, in the inbox and the quarantine, by its section's name quoted,
// leaving out one whose payload is gone, which was said when it went.
func waitingForNewer(s *store.Store) []string {
	var out []string
	for _, box := range []store.Box{store.Inbox, store.Quarantine} {
		msgs, err := s.ListQuietly(box)
		if err != nil {
			continue
		}
		for _, m := range msgs {
			if m.Newer != "" && !m.PayloadGone {
				out = append(out, fmt.Sprintf("%q", m.Newer))
			}
		}
	}
	return out
}

// waitsForNewer is the one sentence for a stream that waits on the relay
// for a newer auu (D42): read, reply and the quarantine's show and trust
// each say it and nothing of what the stream carries, since this build has
// not read it. The section's name passed the name rule; it is quoted all
// the same.
func waitsForNewer(m *store.Stored) string {
	return fmt.Sprintf("message %s waits on the relay for a newer auu (section %q); update auu to fetch it",
		m.Inner.ID[:12], m.Newer)
}

// threadSubject is the subject the thread was opened with, which is the
// subject of the first message on it. Nothing on the thread being here is
// not possible from a message that is, so the error is the store's to
// report and this answers with the message's own subject either way.
func threadSubject(s *store.Store, m *store.Stored) string {
	if thread := m.Inner.Body.Thread; thread != "" {
		if _, first, err := s.FirstOnThread(thread); err == nil {
			return first.Inner.Body.Subject
		}
	}
	return m.Inner.Body.Subject
}

// wholeMessage is one message in full, with the thread's subject alongside
// its own.
func wholeMessage(s *store.Store, box store.Box, m *store.Stored) messageJSON {
	out := toJSON(s, box, m, true)
	out.ThreadSubject = threadSubject(s, m)
	out.Room = roomOfMessage(s, m)
	return out
}

// roomOfMessage is the saved room a message to several went to, by this
// machine's own label for the people in it (D60): the other people, the
// sender and the recipients with the reader taken out, against each room's
// members with self taken out, equal as sets and not empty. For a message
// this machine sent, the other people are the copies' recipients. The first
// such room in the file's order is the one named. A message to one names
// no room, and neither does a rooms file that does not read: the label is
// a convenience, and read does not fail for want of it.
func roomOfMessage(s *store.Store, m *store.Stored) string {
	self := ""
	if me, err := s.Self(); err == nil {
		self = me.Fingerprint()
	}
	others := map[string]bool{}
	if len(m.Copies) > 0 {
		for _, c := range m.Copies {
			others[c.Fingerprint] = true
		}
	} else {
		list := recipientsOf(m)
		if len(list) < 2 {
			return ""
		}
		others[m.Inner.From] = true
		for _, fp := range list {
			others[fp] = true
		}
	}
	delete(others, self)
	if len(others) == 0 {
		return ""
	}
	rooms, err := s.Rooms()
	if err != nil {
		return ""
	}
	for _, r := range rooms {
		members := map[string]bool{}
		for _, mem := range r.Members {
			if mem.FP != self {
				members[mem.FP] = true
			}
		}
		if len(members) != len(others) {
			continue
		}
		same := true
		for fp := range others {
			if !members[fp] {
				same = false
				break
			}
		}
		if same {
			return r.Name
		}
	}
	return ""
}

func printMessage(s *store.Store, box store.Box, m *store.Stored) {
	if box == store.Quarantine {
		fmt.Println("!! QUARANTINED: this sender is not in your peer list.")
	}
	// Everything the sender wrote goes through an escaper here, though the
	// rule at Validate has refused what would need one: a record from
	// before the rule, or written by hand, is still in the spool.
	fmt.Printf("from:    %s <%s>\n", orNone(identity.Printable(m.SenderName)), m.Inner.From[:16])
	printCopies(m)
	if len(m.Copies) == 0 {
		printRecipients(s, m)
	}
	// This machine's own name for those people, where a saved room holds
	// exactly them; it says nothing the to: line did not (D60).
	if room := roomOfMessage(s, m); room != "" {
		fmt.Printf("room:    %s\n", identity.Printable(room))
	}
	fmt.Printf("type:    %s\n", m.Inner.Body.Type)
	// A knock carries the sender's own name, which is a claim and not a
	// label: said as theirs, escaped as every word from outside is, and
	// never written into the peer list unless a person accepts it.
	if m.Inner.Body.Type == message.TypeKnock {
		fmt.Printf("claims:  %s (their own claim, not a name you gave)\n", identity.Printable(m.Inner.Body.Name))
	}
	if m.Inner.Body.Type == message.TypeVouch {
		printVouch(m.Inner.ID, judgeVouch(s, m, time.Now()))
	}
	if m.Inner.Body.Type == message.TypeVouchAsk {
		printAsk(s, m)
	}
	// The thread's subject, and under it this message's own when it was
	// given one: a reply can be about something of its own without
	// starting a thread of its own, and both are worth seeing.
	subject := threadSubject(s, m)
	fmt.Printf("subject: %s\n", orNone(identity.PrintableText(subject)))
	if m.Inner.Body.Subject != subject {
		fmt.Printf("%-9s%s\n", "  "+m.Inner.Body.Type+":", orNone(identity.PrintableText(m.Inner.Body.Subject)))
	}
	fmt.Printf("channel: %s\n", identity.PrintableText(channelName(m.Channel)))
	// The relays it came through, nearest the sender first, for a message
	// that crossed any: it is where this mail has been, which nobody but
	// the person reading it can judge, and it is the way a reply goes back.
	// Left out for mail that came no distance, which is most mail and where
	// a line saying "none" would be noise.
	//
	// Escaped, as every string from a relay that reaches a terminal is. The
	// names were held to the relay-name rule before the listing was read,
	// and this is the last line under that rule rather than the rule.
	if m.Via != "" {
		fmt.Printf("via:     %s\n", identity.PrintableText(m.Via))
	}
	// Where it is besides here: kept on the relay until 'auu rm' removes
	// it, or acknowledged away when it was fetched.
	if m.RelayID != 0 {
		relayState := "removed"
		if m.OnRelay {
			relayState = "kept"
		}
		fmt.Printf("relay:   %s\n", relayState)
	}
	fmt.Printf("thread:  %s\n", m.Inner.Body.Thread)
	fmt.Printf("id:      %s\n", m.Inner.ID)
	// The sender's stamp, labelled as theirs: it is their word, bounded at
	// open to no later than now, and orders nothing here.
	fmt.Printf("sent:    %s (the sender's clock)\n", m.Inner.Time.Local().Format(time.RFC1123))
	fmt.Printf("received: %s\n", m.Received.Local().Format(time.RFC1123))
	if len(m.Inner.Body.Attachments) > 0 {
		fmt.Println("files:")
		for _, a := range m.Inner.Body.Attachments {
			fmt.Printf("  %-32s %10s  %s\n", identity.PrintableText(a.Name), term.HumanBytes(a.Size), a.SHA256[:16])
		}
		if box == store.Sent && m.Streamed {
			// A sent stream was read from the sender's own files and never
			// copied. Listing them is useful; offering to save them is not.
			fmt.Println("  sent as a stream, from your own copies of these files")
		} else {
			fmt.Printf("  save them with: %s extract %s\n", prog, m.Inner.ID[:12])
		}
	}
	fmt.Printf("\n%s\n", identity.PrintableLines(strings.TrimRight(m.Inner.Body.Text, "\n")))
}

// wroteLine is what extract says of one file: the path it wrote and the
// size, and, when the name is not the one the sender gave, the sender's
// name too, escaped, so that a person sees what was written and why it
// differs.
func wroteLine(path string, a message.Attachment) string {
	line := fmt.Sprintf("wrote %s (%s)", path, term.HumanBytes(a.Size))
	if filepath.Base(path) != a.Name {
		line += fmt.Sprintf("; the sender named it %s", identity.Printable(a.Name))
	}
	return line
}

func cmdExtract(args []string) error {
	fs := newFlagSet("extract")
	out := fs.String("out", "", "directory to write into (default ./auu-attachments/<id>)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return usageErrf("usage: %s extract MESSAGE-ID [--out DIR]", prog)
	}
	s, _, err := requireIdentity()
	if err != nil {
		return err
	}
	box, m, err := s.Find(positional[0])
	if err != nil {
		return usageErrf("%v", err)
	}
	if len(m.Inner.Body.Attachments) == 0 {
		return usageErrf("message %s has no attachments", m.Inner.ID[:12])
	}
	if box == store.Sent && m.Streamed {
		return usageErrf("message %s was sent as a stream: its files were read from your own disk "+
			"and never copied into the store, so there is nothing here to extract",
			m.Inner.ID[:12])
	}
	if m.PayloadGone {
		return bodyGone(m)
	}
	if m.Newer != "" {
		return usageErrf("%s", waitsForNewer(m))
	}
	if m.PayloadOnRelay {
		return usageErrf("message %s is from somebody you have not added as a peer, so its "+
			"attachments are still on the relay; run '%s quarantine trust %s' to fetch them",
			m.Inner.ID[:12], prog, m.Inner.ID[:12])
	}
	dir := *out
	if dir == "" {
		dir = filepath.Join("auu-attachments", m.Inner.ID)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	written, err := extractInto(s, box, m, dir)
	if err != nil {
		return err
	}
	for i, path := range written {
		fmt.Println(wroteLine(path, m.Inner.Body.Attachments[i]))
	}
	fmt.Println("\nThese files came from another machine. Read them; do not run them.")
	return nil
}

// extractInto writes a message's attachments into a directory that already
// exists, and answers with what it wrote, in the order the message carries
// them. It is the whole of 'auu extract' but the printing and the refusals
// that are a person's: serve uses it to put the files an asker sent where
// the handler can read them.
//
// A receiver never depends on the sender's name: each file is written
// under message.SafeName of it, and made unique at the write by an
// exclusive create and a numbered suffix — x-2.txt, x-3.txt — so that
// whatever already stands there, and whatever this filesystem folds
// (case, a Unicode form), is settled by the filesystem's own answer and
// nothing is overwritten. Every file's digest is checked again as it is
// written rather than only when the message was opened, and a streamed
// one is copied without ever being held in memory.
func extractInto(s *store.Store, box store.Box, m *store.Stored, dir string) ([]string, error) {
	var written []string
	for i, a := range m.Inner.Body.Attachments {
		// A streamed attachment's bytes are checked against the digest as
		// they are copied; an envelope's are in the record and are checked
		// here. Everything but the bytes, Load has held the record to.
		if !m.Streamed {
			check := message.Attachment{Name: a.Name, Media: a.Media, Size: a.Size, SHA256: a.SHA256, Data: a.Data}
			if err := check.Validate(); err != nil {
				return written, fmt.Errorf("refusing to write %q: %w", a.Name, err)
			}
		}
		target, err := writeUnique(s, box, m, i, a, dir, message.SafeName(a.Name))
		if err != nil {
			return written, err
		}
		written = append(written, target)
	}
	return written, nil
}

// maxNameTries is how many numbered names writeUnique tries before it
// gives up on a directory.
const maxNameTries = 1000

// hardLinks says whether an extract takes an attachment's name by linking
// the verified temporary to it; false is the path a filesystem that
// refuses hard links takes, and a test sets it to walk that path here.
var hardLinks = true

// beforeLink, when a test sets it, runs between the temporary's
// verification and the link that takes the name, with the temporary's
// path: the window in which a directory somebody else can write to could
// change what stands under the temporary's name.
var beforeLink func(tmp string)

// writeUnique writes attachment i of m under dir as safe, a name SafeName
// made, or as the first of safe-2, safe-3, … that nothing stands under,
// and returns the path it made.
//
// The bytes are written once, to a temporary file of the program's own
// name in the same directory, created exclusively by the handle, and
// held to the record's size and digest there; only then is the name
// taken, by linking the temporary to it. A link is an exclusive create:
// whatever already stands under the name — a file, a directory, a
// device, a link — is a name that stands (see stands) and the next
// candidate is tried, nothing is renamed onto a
// name from outside, and the name appears only with verified content, so
// a process killed mid-copy leaves the hidden temporary and never a
// partial file under the attachment's name. The link resolves the
// temporary by its name, which a directory somebody else can write to
// could have changed under the extract — a symbolic link put there is
// followed by link on some platforms — so what the name now stands for
// is compared with the handle the bytes were written through, and a name
// that is not that file is removed and the extract refused. Each
// candidate is cut to the safe cap, so the loop's names are safe names
// too; after maxNameTries the directory is refused by name. The
// temporary goes whether the name was taken or not.
//
// A filesystem that refuses hard links — FAT or exFAT on a stick, some
// network shares — is met by the exclusive create of the name and a copy
// from the verified temporary through the same handle, the path every
// extract took before the link; on such a filesystem a kill mid-copy can
// leave a partial file under the name, and the next extract writes
// beside it.
func writeUnique(s *store.Store, box store.Box, m *store.Stored, i int, a message.Attachment, dir, safe string) (string, error) {
	f, tmp, err := writeTemp(s, box, m, i, a, dir)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	defer f.Close()
	written, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("writing %q: %w", a.Name, err)
	}
	if beforeLink != nil {
		beforeLink(tmp)
	}
	for n := 1; n <= maxNameTries; n++ {
		target := filepath.Join(dir, message.Numbered(safe, n))
		if !hardLinks {
			return copyFromTemp(f, dir, safe, n)
		}
		err := os.Link(tmp, target)
		if err == nil {
			// The name stands for the file the bytes went into, or for
			// something put under the temporary's name meanwhile, which
			// is not the attachment and is not left under its name.
			now, err := os.Lstat(target)
			if err != nil || !os.SameFile(now, written) {
				os.Remove(target)
				return target, fmt.Errorf("refusing to write %q: the directory changed under the extract; nothing was written", a.Name)
			}
			return target, nil
		}
		if stands(err) {
			continue
		}
		// Not a name that stands, but the filesystem's refusal of the
		// link itself: the exclusive create and the copy from here on.
		return copyFromTemp(f, dir, safe, n)
	}
	return "", fmt.Errorf("%s holds %d files named like %q already; choose another --out directory", dir, maxNameTries, safe)
}

// tempPrefix is what an extract's temporary file is called, a hidden name
// of the program's own beside the attachment it becomes.
const tempPrefix = ".auu-extract-"

// writeTemp writes attachment i of m to a temporary file of the program's
// own name under dir, created exclusively by the handle, synced, and held
// to the record's size and digest, and returns the open handle, which is
// the caller's to close and is the one thing the bytes are read back
// through, and the path. On any error what it made is removed.
func writeTemp(s *store.Store, box store.Box, m *store.Stored, i int, a message.Attachment, dir string) (*os.File, string, error) {
	var out *os.File
	var tmp string
	for try := 0; ; try++ {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", err
		}
		tmp = filepath.Join(dir, tempPrefix+hex.EncodeToString(suffix[:]))
		f, err := regular.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			out = f
			break
		}
		if !stands(err) || try >= 8 {
			return nil, "", fmt.Errorf("writing %q: %w", a.Name, err)
		}
	}
	var err error
	if m.Streamed {
		// A streamed attachment is already a file in the spool, kept by
		// its position and never by its name, and may be far larger than
		// memory, so it is copied rather than loaded.
		src := filepath.Join(s.AttachmentDir(box, m.Inner.ID), stream.SpoolName(i))
		err = copyStreamed(src, out, a)
	} else {
		_, err = out.Write(a.Data)
	}
	if err == nil {
		err = out.Sync()
	}
	if err != nil {
		out.Close()
		os.Remove(tmp)
		return nil, "", err
	}
	return out, tmp, nil
}

// copyFromTemp takes the first of safe-n, safe-n+1, … that nothing stands
// under by the exclusive create and copies the verified temporary into
// it, read back through the handle it was written by: the path for a
// filesystem that refuses hard links. On any error after the create,
// what this call made is removed.
func copyFromTemp(f *os.File, dir, safe string, n int) (string, error) {
	for ; n <= maxNameTries; n++ {
		target := filepath.Join(dir, message.Numbered(safe, n))
		out, err := regular.Create(target, 0o600)
		if stands(err) {
			continue
		}
		if err != nil {
			return target, err
		}
		if _, err = f.Seek(0, io.SeekStart); err == nil {
			_, err = io.Copy(out, f)
		}
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			os.Remove(target)
			return target, err
		}
		return target, nil
	}
	return "", fmt.Errorf("%s holds %d files named like %q already; choose another --out directory", dir, maxNameTries, safe)
}

// stands says an exclusive create or a link found an entry under the
// name, so the next candidate is tried: os.ErrExist, which every platform
// answers for a file, a link or a device there and Linux and macOS answer
// for a directory too; and EISDIR, which Windows answers for a directory,
// since CreateFile refuses one opened for writing as access denied and
// Go's syscall.Open reports that as EISDIR rather than as an existing
// entry. The first Windows run of the regular package's tests is where
// the second word was learned; without it a directory at an attachment's
// name refused the extract there instead of the file going beside it.
func stands(err error) bool {
	return os.IsExist(err) || errors.Is(err, syscall.EISDIR)
}

// copyStreamed copies a streamed attachment from its spool file into out,
// holding what arrives to the record's size and digest: a record whose
// bytes are not what it says is refused, and out's caller removes what
// was written.
func copyStreamed(src string, out *os.File, a message.Attachment) error {
	in, err := regular.Open(src)
	if err != nil {
		return fmt.Errorf("reading %q: %w", a.Name, err)
	}
	defer in.Close()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), in)
	if err != nil {
		return fmt.Errorf("reading %q: %w", a.Name, err)
	}
	if n != a.Size {
		return fmt.Errorf("refusing to write %q: size %d does not match %d bytes of data", a.Name, a.Size, n)
	}
	// The record's digest is lowercase hex by the rule at Load; the data
	// is held to it exactly, as Validate holds an inline attachment.
	if a.SHA256 != hex.EncodeToString(h.Sum(nil)) {
		return fmt.Errorf("refusing to write %q: sha256 does not match data", a.Name)
	}
	return nil
}

type waitJSON struct {
	Found   bool         `json:"found"`
	Message *messageJSON `json:"message,omitempty"`
	Waited  string       `json:"waited"`
}

func cmdWait(args []string) error {
	fs := newFlagSet("wait")
	thread := fs.String("thread", "", "thread id to wait on")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up after this long")
	interval := fs.Duration("interval", 20*time.Second, "how often to check the relay")
	asJSON := fs.Bool("json", false, "machine readable output")
	relay := relayFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return usageErrf("unexpected argument %q", positional[0])
	}
	if *thread == "" {
		return usageErrf("--thread is required")
	}
	if *interval < 5*time.Second {
		return usageErrf("--interval must be at least 5s; polling harder does not make replies arrive sooner")
	}
	if *timeout <= 0 {
		return usageErrf("--timeout must be more than nothing; a wait of %s is over before it starts", *timeout)
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	// A reply comes back the way the thread came, so that is the relay to
	// watch. A thread with nothing stored — waiting on an id somebody was
	// given out of band — could be anywhere, so every relay is watched.
	relays, err := waitRelays(s, *thread, *relay)
	if err != nil {
		return err
	}

	// Anything already in the thread is old news: wait means wait for new.
	seen := map[string]bool{}
	existing, err := s.List(store.Inbox)
	if err != nil {
		return err
	}
	for _, m := range existing {
		if m.Inner.Body.Thread == *thread {
			seen[m.Inner.ID] = true
		}
	}

	start := time.Now()
	deadline := start.Add(*timeout)
	// Every request made by every poll runs under the wait's own deadline,
	// so a relay that accepts a connection and never answers is cut off
	// when the wait is over, rather than when the transport gives up on
	// it. The container suite's N02 found a ten-second wait answering
	// after the transport's handshake timeout, with the transport's exit
	// code.
	pollCtx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	// What a relay says about this identity's allow list is said once per
	// run, at the first poll that hears it, not at every poll.
	warned := map[string]bool{}
	for {
		// floor is a delay a relay asked for, which the poll interval must
		// not undercut.
		var (
			floor    time.Duration
			ok       int
			firstErr error
		)
		began := time.Now()
		// Each poll asks the relay to hold its first listing open, so a
		// reply arrives when it is sent; a relay over its cap on holds
		// answers at once and the poll sleeps the interval.
		hold := holdFor(*interval, deadline)
		for _, r := range relays {
			c, err := dial(s, id, r)
			var said relaySaid
			if err == nil {
				_, said, err = fetch(pollCtx, s, id, c, r, hold)
			}
			if err == nil && !warned[r.Name] {
				warned[r.Name] = true
				err = warnAllowState(s, r, said.Allow)
				if err == nil {
					err = warnCardState(s, r, said.Card)
				}
				if err == nil {
					err = warnDirectoryState(r, said.Directory)
				}
			}
			if err == nil {
				ok++
				continue
			}
			// A relay that is refusing requests for now has told us how long
			// to leave it alone, and waiting is what this command does.
			if d, temporary := relayAskedToWait(err); temporary {
				if d > floor {
					floor = d
				}
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", r.Name, err)
			}
		}
		// Every relay failed outright. A failure that waiting may outlast
		// — the relay unreachable, the connection lost, the relay failing
		// — is said and tried again at the next interval, since the point
		// of this command is to wait; one that will not pass without a
		// person, or the deadline itself, ends it.
		// The pause before the next poll is what is left of the interval
		// since this one began: a relay that held the listing for the
		// whole interval is asked again at once, and one that answered in
		// a moment is asked again after the interval, as before. A delay
		// the relay asked for is a floor under it either way.
		pause := max(*interval-time.Since(began), floor)
		if ok == 0 && firstErr != nil {
			if !pollFailedForNow(firstErr) {
				return firstErr
			}
			if pollCtx.Err() == nil {
				fmt.Fprintf(os.Stderr, "warning: %v; trying again in %s\n",
					firstErr, min(pause, time.Until(deadline)).Round(time.Second))
			}
		}
		if ok > 0 {
			// A question that arrived during the wait, answered as auu inbox
			// answers it, to standard error since what this command prints
			// on standard output is the message waited for.
			keepVouches(s, os.Stderr)
			answerAsks(s, id, os.Stderr)
			msgs, err := s.List(store.Inbox)
			if err != nil {
				return err
			}
			for _, m := range msgs {
				if m.Inner.Body.Thread == *thread && !seen[m.Inner.ID] {
					if err := s.MarkRead(store.Inbox, m.Inner.ID); err != nil {
						return err
					}
					if *asJSON {
						out := wholeMessage(s, store.Inbox, m)
						return printJSON(waitJSON{Found: true, Message: &out, Waited: time.Since(start).Round(time.Second).String()})
					}
					printMessage(s, store.Inbox, m)
					return nil
				}
			}
		}
		// The pause is capped at what is left of the wait, and the deadline
		// is looked at after it rather than before, so a pause that ran to
		// the deadline is followed by the timeout and not by a poll that
		// would leave this machine with its context already expired. A
		// poll that ran to the deadline itself has nothing to pause for
		// and meets the same check. A pause that ended a moment early is
		// followed by one more poll, which asks for no hold; that is the
		// clock's, and watch is the same.
		if pause = min(pause, time.Until(deadline)); pause > 0 {
			waitSleep(pause)
		}
		if time.Until(deadline) <= 0 {
			if *asJSON {
				if err := printJSON(waitJSON{Found: false, Waited: time.Since(start).Round(time.Second).String()}); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(os.Stderr, "no reply on thread %s after %s\n", *thread, timeout.String())
			}
			return &exitError{code: exitTimeout, err: fmt.Errorf("timed out waiting for thread %s", *thread)}
		}
	}
}

// holdMargin is how much shorter than what is left of a wait its last hold
// is asked for, so the relay's answer arrives before the deadline rather
// than being cut off by it: the request's round trip, with room to spare.
const holdMargin = time.Second

// holdFor is how long a poll asks the relay to hold its listing open: the
// interval, or the relay's ceiling if that is shorter, or what is left
// before the deadline less the margin if that is shorter still, so the
// last hold ends inside the deadline, answered by the relay rather than
// cut off here. A zero deadline is none. A hold of nothing or less asks
// for no hold at all.
func holdFor(interval time.Duration, deadline time.Time) time.Duration {
	hold := min(interval, relayapi.MaxWait)
	if !deadline.IsZero() {
		hold = min(hold, time.Until(deadline)-holdMargin)
	}
	return hold
}

// fetchLockName is the file under a relay's directory that a fetch holds.
const fetchLockName = "fetch.lock"

// fetchLockWait is how long a fetch waits for another to finish before
// giving up: longer than any one fetch should take, shorter than a person's
// patience. A test shortens it.
var fetchLockWait = time.Minute

// fetchLockSleep is the pause between asks for the lock. A test replaces it
// to see the ask.
var fetchLockSleep = time.Sleep

// waitSleep is the pause between polls. A test replaces it, since the
// interval is at least five seconds and a test of the polling is not a test
// of the clock.
var waitSleep = time.Sleep

// pollFailedForNow reports a poll failure that waiting may outlast: the
// relay unreachable or the connection lost, a 5xx from it, or the wait's
// own deadline cutting the request off. A refused or unverifiable
// certificate, a locked agent, a 4xx the relay meant, and this machine's
// own files are a person's, and no interval will change them.
func pollFailedForNow(err error) bool {
	if isLocked(err) || client.VerificationFailure(err) {
		return false
	}
	var refused *client.CertRefused
	if errors.As(err, &refused) {
		return false
	}
	var httpErr *client.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Status >= 500
	}
	var urlErr *url.Error
	// Another fetch on this machine finishing is exactly the kind of
	// thing waiting outlasts.
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, lockfile.ErrHeld) || errors.As(err, &urlErr)
}

// waitRelays is what a wait watches: the relay the thread's latest message
// came through, or every relay the home is on when the thread is new here.
// --relay narrows it either way.
func waitRelays(s *store.Store, thread, flag string) ([]*store.Relay, error) {
	if strings.TrimSpace(flag) != "" {
		r, err := selectRelay(s, flag)
		if err != nil {
			return nil, err
		}
		return []*store.Relay{r}, nil
	}
	if _, latest, err := s.FindThread(thread); err == nil && latest.Relay != "" {
		if r, err := s.Relay(latest.Relay); err == nil {
			return []*store.Relay{r}, nil
		}
	}
	return selectedRelays(s, "")
}

// relayAskedToWait reports the delay a relay asked for when it refused a
// request for now rather than for good.
func relayAskedToWait(err error) (time.Duration, bool) {
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) {
		return 0, false
	}
	if httpErr.Status != http.StatusTooManyRequests && httpErr.Status != http.StatusServiceUnavailable {
		return 0, false
	}
	if httpErr.Status == http.StatusTooManyRequests && httpErr.Code == relayapi.CodeOverBudget {
		return 0, false
	}
	return httpErr.RetryAfter, true
}

func cmdQuarantine(args []string) error {
	if len(args) == 0 {
		return usageErrf("usage: %s quarantine ls|show|trust", prog)
	}
	sub, rest := args[0], args[1:]
	s, _, err := requireIdentity()
	if err != nil {
		return err
	}
	switch sub {
	case "ls", "list":
		fs := newFlagSet("quarantine ls")
		asJSON := fs.Bool("json", false, "machine readable output")
		positional, err := parseArgs(fs, rest)
		if err != nil {
			return err
		}
		if len(positional) > 0 {
			return usageErrf("unexpected argument %q", positional[0])
		}
		msgs, err := s.List(store.Quarantine)
		if err != nil {
			return err
		}
		if *asJSON {
			out := make([]messageJSON, 0, len(msgs))
			for _, m := range msgs {
				out = append(out, toJSON(s, store.Quarantine, m, false))
			}
			return printJSON(out)
		}
		if len(msgs) == 0 {
			fmt.Println("quarantine is empty")
			return nil
		}
		for _, m := range msgs {
			printQuarantineLine(s, m)
		}
		fmt.Println("\nThese senders are not in your peer list. Confirm who they are out of band,")
		fmt.Printf("then run: %s quarantine trust <id>\n", prog)
		return nil

	case "show":
		fs := newFlagSet("quarantine show")
		asJSON := fs.Bool("json", false, "machine readable output")
		positional, err := parseArgs(fs, rest)
		if err != nil {
			return err
		}
		if len(positional) != 1 {
			return usageErrf("usage: %s quarantine show MESSAGE-ID", prog)
		}
		m, err := s.Load(store.Quarantine, positional[0])
		if err != nil {
			box, found, ferr := s.Find(positional[0])
			if ferr != nil || box != store.Quarantine {
				return usageErrf("no quarantined message %s", positional[0])
			}
			m = found
		}
		if m.Newer != "" {
			if *asJSON {
				return printJSON(toJSON(s, store.Quarantine, m, false))
			}
			fmt.Println(waitsForNewer(m))
			return nil
		}
		if *asJSON {
			return printJSON(wholeMessage(s, store.Quarantine, m))
		}
		printMessage(s, store.Quarantine, m)
		return nil

	case "trust":
		if len(rest) != 1 {
			return usageErrf("usage: %s quarantine trust MESSAGE-ID", prog)
		}
		box, m, err := s.Find(rest[0])
		if err != nil {
			return usageErrf("%v", err)
		}
		if box != store.Quarantine {
			return usageErrf("message %s is not in quarantine", rest[0])
		}
		if m.Newer != "" {
			return usageErrf("%s", waitsForNewer(m))
		}
		pub, err := identity.ParseBundle(m.Inner.FromBundle)
		if err != nil {
			return fmt.Errorf("quarantined message carries a malformed sender key: %w", err)
		}
		if pub.Fingerprint() != m.Inner.From {
			return fmt.Errorf("quarantined message has an inconsistent sender key")
		}
		// A knock carries the sender's own name: offered at the prompt as
		// the default, as a card's name is at 'peers fetch', and taken
		// only where a person is there to accept it. A name the peer list
		// already uses for somebody else is not offered, and the sentence
		// says whose it is, so a refusal costs nothing.
		//
		// Without a terminal nothing from the wire is offered: the prompt
		// takes its default at end of input, and this command, unlike
		// 'knock' and 'peers fetch', does not refuse without one, so an
		// offer made here would write a stranger's chosen name into the
		// peer list with nobody answering. peer-<fp8> is this machine's
		// own, and 'auu peers rm' and 'peers add' are the repair for
		// somebody who meant the other.
		// Who vouches for them, among the people this machine holds, each
		// with whose word it is; the rest are counted and nothing else.
		if m.Inner.Body.Type == message.TypeKnock {
			kv := judgeKnockVouches(s, m, time.Now())
			for _, v := range kv.Held {
				fmt.Printf("vouched for by %s: %s is on your list, so this is %s's word for the key\n", v, v, v)
			}
			for _, v := range kv.Bad {
				fmt.Printf("the vouch from %s does not verify under the key you hold for them, and counts for nothing\n", v)
			}
			if kv.Unknown > 0 {
				fmt.Printf("%d more from people you do not hold, which count for nothing\n", kv.Unknown)
			}
		}
		offered, takenBy := knockName(s, m)
		if offered != fallbackName(pub.Fingerprint()) && !stdinIsTerminal() {
			fmt.Printf("they call themselves %s, which is their own claim; without a terminal it is not offered\n",
				identity.Printable(m.Inner.Body.Name))
			offered = fallbackName(pub.Fingerprint())
		} else if takenBy != "" {
			fmt.Printf("%q is already the name of %s, so it is not offered\n",
				identity.Printable(m.Inner.Body.Name), takenBy)
		} else if offered != fallbackName(pub.Fingerprint()) {
			fmt.Printf("they call themselves %s; that is their own claim, not a name you gave\n",
				identity.Printable(m.Inner.Body.Name))
		}
		pub.Name = promptName(pub.Fingerprint(), offered)
		if _, err := s.AddPeer(pub); err != nil {
			return usageErrf("%v", err)
		}
		m.SenderName = pub.Name
		// A quarantined stream has only its manifest: the payload is still on
		// the relay, deliberately, so that a stranger cannot make anybody
		// download two gigabytes. Trusting them is what fetches it.
		if box == store.Sent && m.Streamed {
			return usageErrf("message %s was sent as a stream: its files were read from your own disk "+
				"and never copied into the store, so there is nothing here to extract",
				m.Inner.ID[:12])
		}
		if m.PayloadGone {
			// Its relay id names other mail now, or nothing: the relay
			// is not asked under it.
			return bodyGone(m)
		}
		if m.PayloadOnRelay {
			_, id, err := loadIdentity()
			if err != nil {
				return err
			}
			// The payload is on the relay the manifest came through, and on
			// no other: a relay id means nothing anywhere else.
			r, err := relayOf(s, m, "")
			if err != nil {
				return err
			}
			c, err := dial(s, id, r)
			if err != nil {
				return err
			}
			opened, _, err := fetchManifest(ctx(), c, id, m.RelayID)
			if err != nil {
				// The body was never fetched, and the relay no longer
				// has it: an administrator's purge, or another machine
				// of this identity removing the message. Nothing here
				// changes; the record still says the body is not here.
				if isMissingOnRelay(err) {
					return bodyGone(m)
				}
				return transportErr(err)
			}
			if opened.Sender.Fingerprint() != m.Inner.From {
				return fmt.Errorf("the stream on the relay is no longer the one that was quarantined")
			}
			// The body is here now, so the payload is no longer on the
			// relay; whether the message is depends on the channel, as
			// it does for any other fetch.
			keep, err := s.KeepOnRelay(m.Channel)
			if err != nil {
				return err
			}
			if err := deliverStream(ctx(), s, id, c, r, relayCopy{m.RelayID, m.Received, m.RelaySize}, opened, store.Quarantine, keep); err != nil {
				// The body was never fetched, and the relay no longer
				// has it: an administrator's purge, or another machine
				// of this identity removing the message. Nothing here
				// changes; the record still says the body is not here.
				if isMissingOnRelay(err) {
					return bodyGone(m)
				}
				return transportErr(err)
			}
			if !keep {
				if err := c.Ack(ctx(), m.RelayID); err != nil {
					return transportErr(err)
				}
			}
			trusted, err := s.Load(store.Quarantine, m.Inner.ID)
			if err != nil {
				return err
			}
			trusted.SenderName = pub.Name
			m = trusted
		}
		if err := s.Save(store.Quarantine, m); err != nil {
			return err
		}
		if err := s.Move(store.Quarantine, store.Inbox, m.Inner.ID); err != nil {
			return err
		}
		fmt.Printf("trusted %s and moved message %s to the inbox\n", pub.Fingerprint()[:16], m.Inner.ID[:12])
		return offerAllowPush(s, m)

	default:
		return usageErrf("unknown quarantine subcommand %q", sub)
	}
}

// knockName is the name offered at the local-name prompt when a knock is
// trusted: the name its sender called themselves, when the export line's
// rule takes it and no peer's name folds equal to it, and peer-<fp8>
// otherwise. A suggestion and never the label. Taken is what AddPeer
// refuses on, so the offer and the refusal agree.
func knockName(s *store.Store, m *store.Stored) (name string, takenBy string) {
	fp := m.Inner.From
	if m.Inner.Body.Type != message.TypeKnock {
		return fallbackName(fp), ""
	}
	// A peer list that cannot be read is AddPeer's error to report, a
	// moment later, so the offer stands.
	return freeName(s, fp, m.Inner.Body.Name)
}

// offerAllowPush is what a newly trusted sender needs before they can
// write: on a relay this machine has pushed an allow list to, the list
// no longer names everyone the person trusts, and the sender is refused
// until it is pushed again. With the marker, the person is asked and the
// push is run on yes; without one, or without a terminal, the sentence
// that says to run it is printed as it always was. The push is a
// send-scope signature, so an agent unlocked to receive asks for the
// passphrase, which is why it is a question and not something done
// silently.
func offerAllowPush(s *store.Store, m *store.Stored) error {
	return offerAllowPushFor(s, m, m.SenderName)
}

// offerAllowPushFor is offerAllowPush naming the person who can now write,
// who is not the message's sender when the message was a vouch for them.
func offerAllowPushFor(s *store.Store, m *store.Stored, who string) error {
	r, err := relayOf(s, m, "")
	if err != nil {
		// Not a failure of the trust, which is done: the relay the
		// message came through is not one this machine has any more.
		fmt.Printf("run '%s allow push' if your relay mailbox is restricted\n", prog)
		return nil
	}
	if _, found, err := s.AllowPushed(r); err != nil || !found {
		fmt.Printf("run '%s allow push' if your relay mailbox is restricted\n", prog)
		return nil
	}
	// Asked, not gated on a terminal: the person is already answering the
	// local-name prompt in this command, through the same reader, and an
	// empty answer — end of input on a pipe — is a no, which prints the
	// push to run later.
	if !confirm(fmt.Sprintf("Push your allow list to %s now, so %s can write to you?",
		r.Name, identity.Printable(who))) {
		fmt.Printf("nothing pushed; run '%s allow push --relay %s' when you are ready\n", prog, r.Name)
		return nil
	}
	_, id, err := loadIdentity()
	if err != nil {
		return err
	}
	peers, couriers, err := pushAllowTo(s, id, r)
	if err != nil {
		// The trust is done and the line above said so; what failed is the
		// push, and saying which is not a nicety here. Since the push now
		// reads that relay's couriers file, one of the ways this can fail is
		// a file the person edited by hand for an entirely different reason,
		// and its own sentence names the file, the line and the remedy — but
		// only this wrapper can say that it was the push and not the trust
		// that tripped on it. The knock's path says the same thing in the
		// same shape.
		fmt.Fprintf(os.Stderr, "warning: the sender is trusted but your allow list was not pushed to %s (%v)\n",
			r.Name, err)
		return &exitError{code: exitTransport, err: fmt.Errorf(
			"run '%s allow push --relay %s' so they can write to you", prog, r.Name)}
	}
	fmt.Println(allowPushedLine(r.Name, peers, couriers))
	return nil
}

// bodyGone is the answer when a quarantined stream's body is no longer on
// the relay to fetch: the message left the mailbox while its body sat
// there unfetched, and nothing this machine holds can replace it.
func bodyGone(m *store.Stored) error {
	return &exitError{code: exitTransport, err: fmt.Errorf(
		"%s: its body is no longer on the relay; ask the sender to send it again", m.Inner.ID[:12])}
}

// fallbackName is the local name offered for a peer nobody has named: the
// first eight characters of the fingerprint, which is a label and not a
// name anybody claimed.
func fallbackName(fp string) string { return "peer-" + fp[:8] }

// channelName is a stored channel for printing: default when none.
func channelName(channel string) string {
	if channel == "" {
		return channels.Default
	}
	return channel
}
