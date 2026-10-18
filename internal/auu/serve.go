package auu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// auu serve: an expert that answers a channel.
//
// A round is a fetch, then every message the file says this machine answers
// for and the ledger has not settled, oldest first and one at a time, each
// handed to the channel's handler in a git worktree and each answered with
// what the handler printed. One message at a time is deliberate: an expert
// need not answer at once, a read-only channel's one worktree and one warm
// session could not be shared anyway, and serial is what makes the ledger
// and the worktrees simple to reason about.

// serveLockName is the one-serve-per-home lock, under the serve directory.
const serveLockName = "lock"

// serveRun is one run of the command: what it was told, and what it needs.
type serveRun struct {
	s   *store.Store
	id  *identity.Identity
	cfg *serveConfig
	led *ledger
	// root is the serve directory in the home.
	root   string
	asJSON bool
	// out is what this round did, for --json.
	out roundJSON
	// unreachable says the last fetch reached no relay at all, so that the
	// sentence about it is said once per run of failures.
	unreachable bool
	// source is where a token for the handler comes from: the proxy in
	// this process, or the split proxy over its control socket; nil for a
	// host whose serve.json has no proxy section.
	source tokenSource
	// renamed is the follow-ups already said to name another thread than
	// the reply they answer, so each is said once per run.
	renamed map[string]bool
	// otherParty is the messages already said to be on a thread another
	// peer opened, so each is said once per run.
	otherParty map[string]bool
	// noOpener is the messages already said to be on a thread tried or
	// answered before the upgrade whose opener the ledger does not name,
	// so each is said once per run: one serveRun is the whole process,
	// every round and sweep of a long serve, so a message left in the
	// inbox is not said again at each.
	noOpener map[string]bool
	// retryAt is when the long run's next round is due for a message that
	// failed and has retries left, zero when there is none: the hold
	// between rounds ends there if no mail has ended it first (G48, R63).
	retryAt time.Time
}

// roundJSON is one round as --json gives it.
type roundJSON struct {
	Answered []handledJSON `json:"answered"`
	Failed   []handledJSON `json:"failed"`
	Skipped  []handledJSON `json:"skipped"`
}

// handledJSON is one message in a round's report.
type handledJSON struct {
	ID      string `json:"id"`
	Channel string `json:"channel"`
	Thread  string `json:"thread"`
}

func cmdServe(args []string) error {
	fs := newFlagSet("serve")
	once := fs.Bool("once", false, "one round: fetch, answer what is pending, and stop")
	backlog := fs.Bool("backlog", false, "on a first start, answer the mail already in the inbox instead of leaving it")
	config := fs.String("config", "", "the file to read instead of serve.json in the home")
	asJSON := fs.Bool("json", false, "machine readable output")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	switch {
	case len(positional) == 1 && positional[0] == "check":
		return serveCheck(*config)
	case len(positional) == 1 && positional[0] == "ls":
		return serveLs(*config, *asJSON)
	case len(positional) == 1 && positional[0] == "proxy":
		return serveProxy(*config)
	case len(positional) > 0:
		return usageErrf("usage: %s serve [--once] [--backlog] [--config FILE] [--json], or %s serve check|ls|proxy", prog, prog)
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	cfg, err := loadServeConfig(servePath(s, *config))
	if err != nil {
		return err
	}
	if err := cfg.check(); err != nil {
		return err
	}
	// Speaking for this identity from here on, and in send scope for the
	// whole run: every reply originates, and an expert answers unattended
	// by design. A home under a passphrase says so now, at exit 4, rather
	// than after a handler has run — locked, or unlocked only to receive,
	// each in its own sentence, and never a prompt, since a service has no
	// terminal and a person at one is told the unlock to make. Before
	// loadIdentity, which would prompt a person into receive scope.
	if enc, err := s.Encrypted(); err != nil {
		return err
	} else if enc {
		if err := serveNeedsSend(s); err != nil {
			return err
		}
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	root := s.ServeDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	lock, err := takeServeLock(root)
	if err != nil {
		return err
	}
	defer lock.Release()

	led, err := loadLedger(filepath.Join(root, ledgerFile))
	if err != nil {
		return err
	}
	if err := fillSenders(s, led); err != nil {
		return err
	}
	if *backlog && led.existed {
		return usageErrf("--backlog answers the mail that was in the inbox before serve ever ran here, " +
			"and this home has a ledger already; there is no backlog to answer")
	}
	warnKept(s, cfg)
	warnCredentials(cfg)

	// A signal is how a service is stopped, and the only way the long run
	// ends of its own accord. It ends the handler that is running as well:
	// the message is left exactly as it was, with nothing written down
	// against it, so the next serve picks it up.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	run := &serveRun{s: s, id: id, cfg: cfg, led: led, root: root, asJSON: *asJSON}
	switch {
	case cfg.Proxy == nil:
	case cfg.Proxy.Control != "":
		// The split proxy, another account's process: a token is asked
		// for per invocation, and nothing about the key is here.
		run.source = &controlSource{path: cfg.Proxy.Control}
		fmt.Fprintf(os.Stderr, "%s: proxy: asking %s for a token per invocation\n", prog, cfg.Proxy.Control)
	default:
		// The key is read once, here, under the lock, and lives in this
		// process alone; the file is not read again.
		key, err := readKeyFile(cfg.Proxy.KeyFile)
		if err != nil {
			return err
		}
		proxy, err := startKeyProxy(cfg.Proxy, key, func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, prog+": "+format+"\n", a...)
		})
		if err != nil {
			return err
		}
		defer proxy.Close()
		run.source = inProcess{proxy}
		fmt.Fprintf(os.Stderr, "%s: proxy: holding the key from %s, listening on %s, upstream %s\n",
			prog, cfg.Proxy.KeyFile, proxy.ln.Addr(), cfg.Proxy.Upstream)
	}
	if *once {
		return run.once(ctx, *backlog)
	}
	return run.long(ctx, *backlog)
}

// serveNeedsSend reads the agent's scope for a home under a passphrase and
// refuses locked and receive scope: serve is the one accepted exception to
// sending needing a person, and the exception is an unlock made for it. A
// send scope with an expiry is let through with a warning that names the
// time, because a person who ran 'auu unlock --send' without --ttl 0 may
// have meant a short run; when it ends, serve stops with the same sentence.
func serveNeedsSend(s *store.Store) error {
	c, err := agent.NewClient(s.Root())
	if err != nil {
		return err
	}
	st, err := c.Status()
	if errors.Is(err, agent.ErrNotRunning) {
		return lockedErr()
	}
	if err != nil {
		return err
	}
	if st.Locked {
		return lockedErr()
	}
	if st.Scope != agent.ScopeSend {
		return serveNeedsSendErr()
	}
	if !st.SendUntil.IsZero() {
		fmt.Fprintf(os.Stderr, "%s: the agent's send scope ends at %s and serve will stop then; '%s unlock --send --ttl 0' lasts until '%s lock'\n",
			prog, st.SendUntil.Local().Format("2006-01-02 15:04"), prog, prog)
	}
	return nil
}

// serveNeedsSendErr is serve's own exit 4: the agent is unlocked, but to
// receive, and serve originates. It names the unlock an expert needs
// rather than the ten-minute one, so it is not the agent's sentence.
func serveNeedsSendErr() error {
	return &exitError{code: exitLocked, err: fmt.Errorf(
		"the agent is unlocked to receive, and serve originates every reply: run '%s unlock --send --ttl 0' at a terminal, which lasts until '%s lock'",
		prog, prog)}
}

// once is one round, and the exit code that says how it went.
func (r *serveRun) once(ctx context.Context, backlog bool) error {
	if err := r.sweep(); err != nil {
		return err
	}
	if err := r.round(ctx, backlog, false); err != nil {
		return err
	}
	if r.asJSON {
		if err := printJSON(r.out); err != nil {
			return err
		}
	} else if !r.did() {
		fmt.Println("nothing to answer")
	}
	if n := len(r.out.Failed); n > 0 {
		return usageErrf("%s went unanswered; the failures are above, and the next round tries again", plural(n, "message"))
	}
	return nil
}

// long is the service: rounds, with a hold on the relays between them. It
// ends when the operator stops it, which is not a failure, or when every
// relay's watch has ended for a reason no interval will change, which is.
func (r *serveRun) long(ctx context.Context, backlog bool) error {
	if err := r.sweep(); err != nil {
		return err
	}
	for {
		if err := r.round(ctx, backlog, true); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		backlog = false
		if err := r.sweep(); err != nil {
			return err
		}
		if err := r.hold(ctx); err != nil {
			if ctx.Err() == nil && !r.retryAt.IsZero() && errors.Is(err, context.DeadlineExceeded) {
				// The hold's own deadline, not the caller's: a failed
				// message is due again, and the next round retries it.
				continue
			}
			// A stop is the end whichever way the hold saw it, the
			// hold's deadline among them when the stop came as it passed.
			if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return err
		}
	}
}

// round is a fetch and then every message that is pending, one at a time,
// oldest first.
//
// In the long run a fetch that reached no relay at all is not the end of
// the service: the watch that follows has its own policy for a relay that
// is down, and it is the one that decides when there is nothing left to
// wait for. Under --once it is this run's failure, since there is nothing
// else this run was going to do.
func (r *serveRun) round(ctx context.Context, backlog, longRun bool) error {
	r.out = roundJSON{}
	relays, err := selectedRelays(r.s, "")
	if err != nil {
		return err
	}
	if _, _, err := fetchEvery(ctx, r.s, r.id, relays, len(relays) == 1); err != nil {
		// A stop is the round's end in the long run too, as it is at the
		// hold: the fetch takes the round's context, so a stop does not
		// wait out a request in flight (G38, R54).
		if !longRun || ctx.Err() != nil {
			return err
		}
		if !r.unreachable {
			// Once per run of failures: the relay said why, and saying it
			// again every time one arrives would bury what did happen.
			r.unreachable = true
			fmt.Fprintf(os.Stderr, "%s: no relay could be reached; waiting for one to come back\n", prog)
		}
	} else {
		r.unreachable = false
	}
	// Whether this is a first start is settled before anything is looked
	// at: pending writes a waiting stream's reason into the ledger, and a
	// ledger once written exists, which would make a first start look
	// like a later round and answer the old mail it must leave alone.
	//
	// It is one of two guards on that rule, and both stay. The other is
	// waitsForNewer, which writes nothing on a first start, so that a crash
	// between it and the backlog's save cannot leave a ledger behind. Each
	// alone holds the rule today, and a reviewer's break of this one passed
	// for that reason; the two cover different faults, an order inside one
	// round and a file across two runs, and a change to either should not
	// rest on the other.
	first := !r.led.existed
	pending, err := r.pending()
	if err != nil {
		return err
	}
	if first {
		// A first start does not answer old mail: an expert set up today
		// must not reply to a year of it at once. Every message in the
		// inbox is written down as skipped, so that a channel added to the
		// file later is not a year of answers either.
		skipped, err := r.recordBacklog(backlog)
		if err != nil {
			return err
		}
		if !backlog {
			pending = nil
			if skipped > 0 {
				fmt.Fprintf(os.Stderr,
					"%s: %s already in the inbox, left alone; '%s serve --once --backlog' on a first start answers them instead\n",
					prog, plural(skipped, "message"), prog)
			}
		}
	}
	for _, m := range pending {
		if err := r.handle(ctx, m); err != nil {
			return err
		}
	}
	r.retryAt = r.nextRetry(pending)
	if longRun && r.asJSON && r.did() {
		// One object per round that did something, one to a line: a quiet
		// expert writes nothing, and a log is the record of what it
		// answered.
		return printJSONLine(r.out)
	}
	return nil
}

// did says this round had something to report.
func (r *serveRun) did() bool {
	return len(r.out.Answered)+len(r.out.Failed)+len(r.out.Skipped) > 0
}

// hold waits on the relays for the next message.
//
// No channel filter, deliberately. A follow-up arrives on the default
// channel — 'auu reply' sends to the recipient's default, since a channel
// is the receiver's sorting and not a thread's property — so a watch
// narrowed to the served channels would sleep through every follow-up
// there is. The round's own rules decide what is answered; a wake-up that
// turns out to be nothing costs one fetch.
//
// A message that failed and has retries left bounds the hold: it ends at
// retryAt with context.DeadlineExceeded, which long takes as the cue for
// the next round, so that a quiet mailbox does not leave the retries the
// channel promises unspent until unrelated mail arrives (G48, R63). With
// nothing to retry the hold has no end but mail or a stop.
func (r *serveRun) hold(ctx context.Context) error {
	relays, err := selectedRelays(r.s, "")
	if err != nil {
		return err
	}
	_, err = awaitEvents(ctx, r.s, r.id, relays,
		watchOptions{messages: true, interval: serveInterval, deadline: r.retryAt})
	return err
}

// serveRetryCap is the longest the long run holds before a failed message's
// next attempt. The hold doubles from serveInterval at each failure, so that
// a message that keeps failing on a quiet mailbox is not tried every
// interval, and five minutes is where the doubling stops: a channel with
// many retries should spend them within the hour, not over a day, and one
// attempt every five minutes is one handler run. It bounds the hold and
// nothing else: a round that mail or another message's retry starts tries
// every message still pending, as every round has.
const serveRetryCap = 5 * time.Minute

// retryBackoff is how long after a failed attempt the next one is due:
// serveInterval for the first failure, twice that for the second, and so on
// up to serveRetryCap. failures comes from the ledger, which holds it to
// zero or more and no higher than the type; the doubling stops at the cap,
// so a count of any size neither overflows nor runs long.
func retryBackoff(failures int) time.Duration {
	d := serveInterval
	for i := 1; i < failures && d < serveRetryCap; i++ {
		d *= 2
	}
	return min(d, serveRetryCap)
}

// nextRetry is when the earliest of this round's messages that failed and
// has retries left is due again, zero when there is none. Only messages the
// round took are counted: one that has left the inbox, or that another
// rule now holds back, is not work the next round would do.
//
// It is never sooner than one serveInterval from now, the watcher's own
// pause between polls, and every failure has just moved its message's
// Tried to now, so a round is never followed at once by another: the long
// run does not spin on a message that fails at once.
func (r *serveRun) nextRetry(pending []*store.Stored) time.Time {
	var at time.Time
	for _, m := range pending {
		e := r.led.Messages[m.Inner.ID]
		if e == nil || e.settled() || e.Failures == 0 {
			continue
		}
		due := e.Tried.Add(retryBackoff(e.Failures))
		if at.IsZero() || due.Before(at) {
			at = due
		}
	}
	if at.IsZero() {
		return at
	}
	if floor := time.Now().Add(serveInterval); at.Before(floor) {
		return floor
	}
	return at
}

// pending is every message this run is to answer, oldest first: on a served
// channel, admitted by the rule that stops two experts talking for ever,
// and not settled in the ledger.
//
// Oldest is the inbox's order, store.ArrivalOrder: by when each record
// arrived here, then the relay's own counter, the relay's received, the
// sender's stamp and the id, so that two runs agree.
func (r *serveRun) pending() ([]*store.Stored, error) {
	msgs, err := r.s.List(store.Inbox)
	if err != nil {
		return nil, err
	}
	var out []*store.Stored
	for _, m := range msgs {
		if m.Newer != "" {
			if err := r.waitsForNewer(m); err != nil {
				return nil, err
			}
			continue
		}
		if e, ok := r.led.Messages[m.Inner.ID]; ok && e.settled() {
			continue
		}
		if r.channelFor(m) == nil {
			continue
		}
		if !r.answerable(m) {
			continue
		}
		out = append(out, m)
	}
	slices.SortStableFunc(out, store.ArrivalOrder)
	return out, nil
}

// waitsForNewer writes down, once, that a message on a served channel is a
// stream waiting on the relay for a newer auu: pending with that reason, and
// neither skipped, answered nor counted as a turn, so that the round after
// the upgrade, which finds it delivered, answers it.
func (r *serveRun) waitsForNewer(m *store.Stored) error {
	if r.channelFor(m) == nil {
		return nil
	}
	e := r.entry(m, channelOf(m))
	if e.Newer == m.Newer {
		return nil
	}
	e.Newer = m.Newer
	fmt.Fprintf(os.Stderr, "%s: %s from %s waits on the relay for a newer auu (section %q); left pending\n",
		prog, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), m.Newer)
	// On a first start the ledger is not written here: a file written
	// before the first start's own record of the backlog would make the
	// next start, after a crash between the two, take itself for a later
	// one and answer the old mail. The backlog's save writes this too.
	if !r.led.existed {
		return nil
	}
	return r.led.save()
}

// channelFor is the channel whose handler answers a message, or nil for one
// that is none of serve's business.
//
// An ask names its own channel. A follow-up does not: 'auu reply' sends to
// the recipient's default channel, because a channel is the receiver's
// sorting and not a thread's property, so a reply to an expert arrives
// under default however the ask was addressed. The channel that answered
// the thread is the one that answers the rest of it, and the ledger is
// where that is written down.
//
// That lookup is also the rule that stops two experts talking to each other
// for ever: a reply serve has no record of sending belongs to no channel
// here, whoever it is from and whatever it is about; and so does a reply
// to something serve sent that names a thread other than the one it was
// sent on, since the turns are counted by thread and a follow-up that
// chose its own would be on turn one every time.
//
// And a thread is a conversation with the peer who opened it. Any peer may
// name any thread id with 'auu send --thread', and a co-recipient of a
// message to several knows the thread it opened; so a message on a thread
// whose opener is somebody else belongs to no channel here either. It is
// left in the inbox for the owner, unanswered, uncounted, and given no
// worktree and no directory of the opener's.
func (r *serveRun) channelFor(m *store.Stored) *serveChannel {
	var ch *serveChannel
	if m.Inner.Body.Type == message.TypeReply {
		e := r.led.repliedWith(m.Inner.Body.InReplyTo)
		if e == nil {
			return nil
		}
		if e.Thread != m.Inner.Body.Thread {
			r.sayRenamed(m, e)
			return nil
		}
		ch = r.cfg.Channels[e.Channel]
	} else {
		ch = r.cfg.Channels[channelOf(m)]
	}
	if ch == nil {
		return nil
	}
	// The message itself is a candidate while nothing on the thread has
	// been tried or answered: a message has no entry until it is, and an
	// entry another peer's message made in the same round, a stream held
	// for a newer auu, must not open a thread whose asker's message arrived
	// before it. Once anything on the thread has been tried or answered,
	// the thread is its opener's whatever any later message's arrival says:
	// an entry an earlier release wrote holds the relay's clock, and this
	// machine's clock may be set back, and neither may move a thread that
	// has a conversation in it. A thread with a conversation and no opener
	// at all is one a v0.17.0 ledger carried over whose messages the owner
	// has removed: whose it was is gone, so it is nobody's, and a peer
	// with something to say opens a thread of their own (D81).
	id, e := r.led.openerEntry(m.Inner.Body.Thread)
	if e == nil && r.led.tried(m.Inner.Body.Thread) {
		r.sayNoOpener(m)
		return nil
	}
	if e != nil && e.From != m.Inner.From &&
		!(!r.led.tried(m.Inner.Body.Thread) &&
			arrivedBefore(m.Arrived.UTC(), m.RelayID, m.Inner.ID, e.Arrived, e.RelayID, id)) {
		r.sayOtherParty(m, e.From)
		return nil
	}
	return ch
}

// fillSenders gives an entry from a v0.17.0 ledger, which kept no senders,
// a sender. An answered entry takes it first from the copy of the reply
// serve sent, which this home wrote (fromSentCopy); any other, or one whose
// sent copy is gone, from its message when that message is still in the
// inbox. Serve leaves what it answered there, marked read. Every entry it
// fills is marked carried, once, and openerEntry reads a thread with any
// carried entry serve tried in tiers. So a thread
// carried over the upgrade takes its opener from the earliest of its
// messages still in the inbox, verified as every message's sender is when
// it was opened. A thread whose opener's messages the owner has removed
// may take another sender's. One with none of its messages left has no
// opener, and is nobody's once anything on it was tried or answered
// (channelFor).
//
// A message id and a thread id are the sender's to choose, so a record is
// taken as an entry's message only when it is on the entry's thread and,
// on a thread serve tried or answered, an earlier release fetched it no
// later than the thread's last attempt and the relay's skew (ownMessage).
// A record that fails is said, once a run, and the entry stays without a
// sender.
//
// What it fills is written at once: a round that answers nothing saves
// nothing, and an owner who removed the message after such a round would
// otherwise leave the thread with no sender on disk for anybody to adopt.
func fillSenders(s *store.Store, led *ledger) error {
	msgs, err := s.ListQuietly(store.Inbox)
	if err != nil {
		return err
	}
	filled := false
	for _, e := range led.Messages {
		if e.From == "" && e.Reply != "" && fromSentCopy(s, e) {
			filled = true
		}
	}
	for _, m := range msgs {
		e, ok := led.Messages[m.Inner.ID]
		if !ok || e.From != "" {
			continue
		}
		if !ownMessage(led, e, m) {
			sayNotItsMessage(m, e)
			continue
		}
		setSender(e, m)
		e.Carried = true
		if e.triedHere() {
			e.Arrived = e.servedAt().UTC()
		}
		filled = true
	}
	if !filled {
		return nil
	}
	return led.save()
}

// fromSentCopy fills an answered entry from the copy of the reply serve
// sent, which this home wrote (R21, R21a): its Inner.To is the asker,
// since serve resolves the message's verified sender alone and sends it one
// copy, so a sent record of serve's has no Copies. The entry's Arrived is
// its answer, serve's own clock, and its RelayID the reply's counter on the
// relay it went by, never zero, so that nothing among carried entries
// falls to an id a sender chose. A sent copy that is
// gone, which the owner's auu rm does or a local save that failed after
// the send leaves, or that does not read as one of serve's, fills nothing,
// and the entry falls to its inbox record. Load holds the id to its rule
// and the record's recipient to a fingerprint.
func fromSentCopy(s *store.Store, e *ledgerEntry) bool {
	m, err := s.Load(store.Sent, e.Reply)
	if err != nil || len(m.Copies) > 0 {
		return false
	}
	e.From = m.Inner.To
	e.Arrived = e.servedAt().UTC()
	e.RelayID = m.RelayID
	e.Carried = true
	return true
}

// ownMessage says whether an inbox record may be the message a sender-less
// entry was written for (R9, R9a). Only a v0.17.0 ledger has such entries,
// and a message id and a thread id are the sender's to choose. The record
// must be on the entry's thread. On a thread serve tried or answered, it
// must be one an earlier release fetched, since the entry's message was in
// the inbox when that release's serve tried it: such a record has no
// arrival of its own and Load lends it the relay's received, which shows
// as the two being equal, and it must have arrived no later than the
// thread's last attempt, read across its entries so an entry nothing was
// tried on cannot reopen a thread that was, allowed the skew the relay's
// clock is held to. A record with this release's own arrival was fetched
// after the upgrade, and after every attempt the earlier release made.
// The arrival is kept to the second, as the attempt is. A thread nothing
// was tried on takes a sender from a record on it, since nothing on it is
// anybody's yet.
func ownMessage(led *ledger, e *ledgerEntry, m *store.Stored) bool {
	if m.Inner.Body.Thread != e.Thread {
		return false
	}
	last := led.lastTried(e.Thread)
	if last.IsZero() {
		return true
	}
	if !m.Arrived.Equal(m.Received) {
		return false
	}
	return !m.Arrived.Truncate(time.Second).After(last.Add(relayapi.MaxSkew))
}

// sayNotItsMessage says that a record was not taken as a carried-over
// entry's message, naming the id and the entry's thread, in the shape of
// sayNoOpener. fillSenders runs once at a start, so it is said once a run.
func sayNotItsMessage(m *store.Stored, e *ledgerEntry) {
	fmt.Fprintf(os.Stderr, "%s: %s from %s has the id of a message serve carried over from before the upgrade on thread %s, "+
		"and is not that message; the thread takes no sender from it\n",
		prog, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), shortID(e.Thread))
}

// setSender writes who sent a message and when it arrived here, the facts a
// thread's opener is read from.
func setSender(e *ledgerEntry, m *store.Stored) {
	e.From = m.Inner.From
	e.Arrived = m.Arrived.UTC()
	e.RelayID = m.RelayID
}

// entry is a message's ledger record, made with its sender if it has none,
// which is what the thread's opener is read from.
func (r *serveRun) entry(m *store.Stored, channel string) *ledgerEntry {
	e := r.led.entry(m.Inner.ID, m.Inner.Body.Thread, channel)
	if e.From == "" {
		setSender(e, m)
	}
	return e
}

// sayOtherParty says, once per message per run, that a message was left
// alone for being on a thread another peer opened, in the shape of
// sayRenamed and for the same reason.
func (r *serveRun) sayOtherParty(m *store.Stored, opener string) {
	if r.otherParty == nil {
		r.otherParty = map[string]bool{}
	}
	if r.otherParty[m.Inner.ID] {
		return
	}
	r.otherParty[m.Inner.ID] = true
	fmt.Fprintf(os.Stderr, "%s: %s from %s is on thread %s, which %s opened; left alone\n",
		prog, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), shortID(m.Inner.Body.Thread),
		opener[:16])
}

// sayNoOpener says, once per message per run, that a message was left
// alone for being on a thread tried or answered before the upgrade whose
// opener the ledger does not name, in the shape of sayOtherParty.
func (r *serveRun) sayNoOpener(m *store.Stored) {
	if r.noOpener == nil {
		r.noOpener = map[string]bool{}
	}
	if r.noOpener[m.Inner.ID] {
		return
	}
	r.noOpener[m.Inner.ID] = true
	fmt.Fprintf(os.Stderr, "%s: %s from %s is on thread %s, which was tried or answered before the upgrade for a peer this ledger does not name; left alone\n",
		prog, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), shortID(m.Inner.Body.Thread))
}

// sayRenamed says, once per message per run, that a follow-up was left
// alone for naming another thread than the reply it answers was sent on.
// pending asks channelFor every round, and the message stays in the inbox
// unread like any other that is none of serve's business, so without the
// once it would be said at every round for as long as it is there.
func (r *serveRun) sayRenamed(m *store.Stored, e *ledgerEntry) {
	if r.renamed == nil {
		r.renamed = map[string]bool{}
	}
	if r.renamed[m.Inner.ID] {
		return
	}
	r.renamed[m.Inner.ID] = true
	fmt.Fprintf(os.Stderr, "%s: %s from %s answers reply %s on thread %s but names thread %s; left alone\n",
		prog, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), shortID(m.Inner.Body.InReplyTo),
		shortID(e.Thread), shortID(m.Inner.Body.Thread))
}

// answerable is the rest of the rule: a question is answered and a
// statement is not, and a thread that has had its turns is done, so that
// two experts pointed at each other stop. Whether a reply is serve's to
// answer at all is channelFor's: it is the same lookup as the channel, and
// it has held the reply's thread to the one the ledger sent the answer
// on, so the count below is on a thread the ledger has already seen.
func (r *serveRun) answerable(m *store.Stored) bool {
	ch := r.channelFor(m)
	if ch == nil {
		return false
	}
	if r.led.answered(m.Inner.Body.Thread) >= ch.MaxTurns {
		return false
	}
	switch m.Inner.Body.Type {
	case message.TypeAsk, message.TypeReply:
		return true
	default:
		// A note and an acknowledgement are not questions.
		return false
	}
}

// recordBacklog writes the whole inbox into a new ledger as skipped, and
// says how many. With --backlog the messages this run is about to answer
// are left out of it, since they are not being skipped.
func (r *serveRun) recordBacklog(backlog bool) (int, error) {
	msgs, err := r.s.List(store.Inbox)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range msgs {
		if _, ok := r.led.Messages[m.Inner.ID]; ok {
			continue
		}
		// A stream waiting for a newer auu is never backlog: the round
		// after the upgrade is when it arrives.
		if m.Newer != "" {
			continue
		}
		if backlog && r.answerable(m) {
			continue
		}
		e := r.entry(m, channelOf(m))
		e.Skipped = true
		if !r.answerable(m) {
			// Written down, so that a channel added to the file later is
			// not a year of answers either, but not reported: a note and a
			// message on a channel nobody serves were never work.
			continue
		}
		n++
		r.out.Skipped = append(r.out.Skipped, r.report(m))
	}
	return n, r.led.save()
}

// handle is one message, from the worktree to the reply. An error here ends
// the run: it is this machine's own trouble — a disk, a lock, a key, git
// failing, the channel's directory gone — and not the message's, which is
// what the ledger's failure count is for. The one thing of the message's
// that the paths below are made from is its thread id, and that is the
// message's: a bad one is its failure, recorded and stepped over, so that
// nothing a peer can write in a message stops the expert for good.
func (r *serveRun) handle(ctx context.Context, m *store.Stored) error {
	// pending decided the round's messages before any was answered, so a
	// message it took may since have become another peer's thread, or
	// lost its turn: two asks on one new thread in one round, or two asks
	// on one thread with a turn left between them. pending takes them in
	// order of arrival, so the first to arrive is tried first and is now
	// the opener, or has had the last turn. Asked again here, the other
	// is left as pending leaves it: not settled, not failed, not
	// reported, and in the inbox.
	ch := r.channelFor(m)
	if ch == nil {
		return nil
	}
	if !r.answerable(m) {
		return nil
	}
	thread := m.Inner.Body.Thread
	short := shortID(thread)

	// Every message in the spool has been through Validate, which holds a
	// thread id to the shape of a message id, so this is met only by a
	// record written by hand; it is checked here all the same, before the
	// id is joined onto anything.
	if err := message.ValidID(thread); err != nil {
		r.failed(m, ch, "its thread id is "+err.Error())
		return nil
	}
	threadDir := filepath.Join(r.root, "threads", thread)
	channelDir := filepath.Join(r.root, "channels", ch.name)
	for _, dir := range []string{threadDir, channelDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	stateDir := threadDir
	if ch.Mode == modeReadOnly {
		stateDir = channelDir
	}
	newThread := !r.led.touched(thread)
	worktree, base, remade, err := worktreeFor(r.root, ch, thread, stateDir, newThread)
	var unmendable *unmendableError
	var left *leftByHandlerError
	if errors.As(err, &unmendable) || errors.As(err, &left) {
		// What a handler left at the path, or in the base file, is a
		// message's failure, so that it is retried and given up on rather
		// than met at every start.
		r.failed(m, ch, err.Error())
		return nil
	}
	if err != nil {
		return err
	}
	if remade {
		lost := ""
		if ch.Mode == modeSideCopy {
			lost = "; the thread's work in it is gone"
		}
		fmt.Fprintf(os.Stderr, "%s: worktree %s was not a git worktree and was made again%s\n", prog, worktree, lost)
	}

	facts := runFacts{
		m: m, channel: ch.name, relay: m.Relay, mode: ch.Mode,
		turn:      r.led.answered(thread) + 1,
		worktree:  worktree,
		base:      base,
		threadDir: threadDir, channelDir: channelDir,
		proxied: r.cfg.Proxy != nil,
	}
	// The files the asker sent, where the handler can read them. A retry
	// finds them already there and leaves them alone: they were checked
	// against their digests when they were written, and writing them again
	// would only be a second chance to get it wrong.
	//
	// They are unpacked under a name of their own and renamed when they are
	// all there, so that a run which stopped part way — a crash, a disk
	// that filled — cannot leave a directory that the next retry reads as
	// the files and hands to the handler half full without a word.
	if len(m.Inner.Body.Attachments) > 0 {
		in := filepath.Join(threadDir, "in", m.Inner.ID)
		if _, err := os.Stat(in); err != nil {
			tmp := in + ".tmp"
			if err := os.RemoveAll(tmp); err != nil {
				return err
			}
			if err := os.MkdirAll(tmp, 0o700); err != nil {
				return err
			}
			if _, err := extractInto(r.s, store.Inbox, m, tmp); err != nil {
				os.RemoveAll(tmp)
				r.failed(m, ch, fmt.Sprintf("the files it sent could not be unpacked: %v", err))
				return nil
			}
			if err := os.Rename(tmp, in); err != nil {
				return err
			}
		}
		facts.attachments = in
	}

	replyPath := runFile(threadDir, "reply", m.Inner.ID)
	patchDir := filepath.Join(threadDir, "patch-"+m.Inner.ID)
	// A reply the handler has already written and serve could not send —
	// the relay was down, the mailbox full — is sent from the file, with
	// the patch that was made for it. The handler is not run twice for one
	// answer, and neither are the hooks. A reply and its patch are kept
	// together or not at all: one kept without its own patch, which an
	// auu before the answer's own directory left, is answered again.
	text, ok, err := keptReply(replyPath)
	if err != nil {
		r.failed(m, ch, fmt.Sprintf("the reply it was answered with could not be read: %v", err))
		return nil
	}
	if ok {
		if patch, ok := keptPatch(ch, patchDir, thread); ok {
			return r.send(m, ch, text, patch, facts)
		}
		if err := os.Remove(replyPath); err != nil {
			return err
		}
	}

	// The handler runs for this message afresh, so an envelope kept for an
	// earlier answer to it is not this one's.
	if err := os.Remove(sealedFile(threadDir, m.Inner.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	afterPath := runFile(threadDir, "after", m.Inner.ID)
	if ch.Before != "" {
		beforePath := runFile(threadDir, "before", m.Inner.ID)
		before, err := r.runOne(ctx, ch.Before, beforePath, facts.env(false, ""), nil, ch, facts, short)
		if err != nil {
			return err
		}
		if !before.ok() {
			// The handler never runs, and the after hook is told so, since
			// its job is to undo what before did.
			if ch.After != "" {
				if _, err := r.runOne(ctx, ch.After, afterPath, facts.env(false, statusBefore), nil, ch, facts, short); err != nil {
					return err
				}
			}
			r.failed(m, ch, "before "+said(before, beforePath))
			return nil
		}
	}

	stdinPath := runFile(threadDir, "msg", m.Inner.ID)
	if err := writeNew(stdinPath, []byte(m.Inner.Body.Text)); err != nil {
		return err
	}
	stdin, err := regular.Open(stdinPath)
	if err != nil {
		return err
	}
	outPath := runFile(threadDir, "out", m.Inner.ID)
	errPath := runFile(threadDir, "err", m.Inner.ID)
	stdout, err := createNew(outPath)
	if err != nil {
		stdin.Close()
		return err
	}
	stderr, err := createNew(errPath)
	if err != nil {
		stdin.Close()
		stdout.Close()
		return err
	}
	// The handler's environment, and with a proxy the token of this
	// invocation: minted just before the handler starts, revoked just
	// after it exits and before the after hook runs, so the hooks never
	// hold one. A token the proxy will not issue is the handler's failure.
	env := facts.env(true, "")
	release := func() {}
	if r.source != nil {
		token, baseURL, rel, err := r.source.mint()
		if err != nil {
			stdin.Close()
			stdout.Close()
			stderr.Close()
			r.failed(m, ch, err.Error())
			return nil
		}
		release = rel
		env = append(env, envBaseURL+"="+baseURL, envAPIKey+"="+token)
	}
	run, runErr := runProgram(ctx, ch.Exec, worktree, env, stdin, stdout, stderr, ch.timeout)
	release()
	stdin.Close()
	stdout.Close()
	stderr.Close()
	prefixedTo(os.Stderr, errPath, short)
	if runErr != nil {
		return runErr
	}

	// The after hook runs whichever way the handler ended, and is told
	// which way that was: it is where a side copy's tests go, and where a
	// service the project needs is stopped again.
	after := programRun{}
	if ch.After != "" {
		if after, err = r.runOne(ctx, ch.After, afterPath, facts.env(false, run.status()), nil, ch, facts, short); err != nil {
			return err
		}
	}
	switch {
	case !run.ok():
		r.failed(m, ch, said(run, errPath))
		return nil
	case ch.After != "" && !after.ok():
		// A handler that answered and an after that refused: the answer
		// does not go out, and the whole message is tried again.
		r.failed(m, ch, "after "+said(after, afterPath))
		return nil
	}
	// What the handler printed is read back from its file: one that is
	// gone or cannot be read is the message's failure, tried again and
	// given up on, never an answer of nothing.
	text, has, err := output(outPath)
	if err != nil {
		r.failed(m, ch, fmt.Sprintf("what the handler printed could not be read: %v", err))
		return nil
	}
	if !has {
		// Nothing to say is an answer: the message is settled, and no
		// reply goes out. In a side copy that means the change stays in
		// the worktree and travels nowhere, since a patch goes with an
		// answer and is not one by itself.
		return r.settle(m, ch, "")
	}
	// After the hooks, so that an after that refuses a red side copy has
	// already refused it, and before the reply is kept, so that a patch
	// that cannot be taken leaves no reply to be sent without it: the
	// message is tried again whole, as when the after hook refuses.
	patch, err := patchFor(ch, worktree, base, patchDir, thread)
	if err != nil {
		r.failed(m, ch, err.Error())
		return nil
	}
	if err := os.Rename(outPath, replyPath); err != nil {
		return err
	}
	return r.send(m, ch, text, patch, facts)
}

// runOne runs a hook: no standard input, its two streams in one file, and
// that file printed prefixed afterwards.
func (r *serveRun) runOne(ctx context.Context, line, outPath string, env []string, stdin *os.File, ch *serveChannel, facts runFacts, short string) (programRun, error) {
	f, err := createNew(outPath)
	if err != nil {
		return programRun{}, err
	}
	run, runErr := runProgram(ctx, line, facts.worktree, env, stdin, f, f, ch.timeout)
	f.Close()
	prefixedTo(os.Stderr, outPath, short)
	return run, runErr
}

// send is the reply: sealed and posted on the relay the message came
// through, recorded in the ledger, and the message marked read. A send that
// fails is the message's failure and is tried again next round, from the
// reply already on disk.
func (r *serveRun) send(m *store.Stored, ch *serveChannel, text, patch string, facts runFacts) error {
	recipient, err := r.s.Resolve(m.Inner.From)
	if err != nil {
		r.failed(m, ch, fmt.Sprintf("%s is not in your peer list any more", m.Inner.From[:16]))
		return nil
	}
	relay, err := relayOf(r.s, m, "")
	if err != nil {
		r.failed(m, ch, err.Error())
		return nil
	}
	// The sentence is put on here rather than into the kept reply, so that
	// a resend of that file says the same thing without saying it twice.
	var attach []string
	if patch != "" {
		attach = []string{patch}
		text += fmt.Sprintf("\n\nThe changes so far are attached as %s; apply with git apply.", filepath.Base(patch))
	}
	body := message.Body{
		Type:      message.TypeReply,
		Subject:   m.Inner.Body.Subject,
		Thread:    m.Inner.Body.Thread,
		InReplyTo: m.Inner.ID,
		Text:      text,
	}
	// Sealed once and kept beside the reply until the message is settled,
	// so that every retry posts the same envelope under the same id
	// (sealOnce, G41, R57).
	out, _, err := sendSealed(r.s, r.id, relay, recipient, body, attach,
		sendMode{sealed: sealedFile(facts.threadDir, m.Inner.ID)})
	if err != nil {
		if isLocked(err) {
			// The keys went away under a running service. Nothing is
			// recorded against the message, the reply is on disk, and the
			// next serve sends it without running the handler again.
			return err
		}
		if isReceiveOnly(err) {
			// Send scope ended under a running service: the same, said in
			// serve's words, which name the unlock that would not have.
			return serveNeedsSendErr()
		}
		r.failed(m, ch, err.Error())
		return nil
	}
	return r.settle(m, ch, out.ID)
}

// settle records a message as answered and marks it read: the reply is the
// acknowledgement, and the owner's own inbox shows what has been dealt
// with.
func (r *serveRun) settle(m *store.Stored, ch *serveChannel, replyID string) error {
	e := r.entry(m, ch.name)
	e.Handled = time.Now().UTC().Truncate(time.Second)
	e.Tried = e.Handled
	e.Reply = replyID
	e.Newer = ""
	if err := r.led.save(); err != nil {
		return err
	}
	if err := r.s.MarkRead(store.Inbox, m.Inner.ID); err != nil {
		return err
	}
	r.out.Answered = append(r.out.Answered, r.report(m))
	if !r.asJSON {
		switch {
		case replyID == "":
			fmt.Printf("%s: %s from %s had nothing to say\n", ch.name, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)))
		default:
			fmt.Printf("%s: answered %s from %s (reply %s)\n",
				ch.name, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), shortID(replyID))
		}
	}
	return nil
}

// failed counts one attempt against a message, gives up when the count has
// run out, and says why on standard error. The message stays unread, so the
// owner's inbox shows it for what it is.
func (r *serveRun) failed(m *store.Stored, ch *serveChannel, why string) {
	e := r.entry(m, ch.name)
	e.Failures++
	e.Tried = time.Now().UTC().Truncate(time.Second)
	gaveUp := e.Failures >= ch.Retries
	e.GaveUp = gaveUp
	if err := r.led.save(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: the ledger could not be written: %v\n", prog, err)
	}
	r.out.Failed = append(r.out.Failed, r.report(m))
	tail := fmt.Sprintf("attempt %d of %d", e.Failures, ch.Retries)
	if gaveUp {
		tail = fmt.Sprintf("given up after %s", plural(e.Failures, "attempt"))
	}
	// why holds a handler's first line, or git's own words about a tree
	// the handler wrote, and is printed escaped (P1).
	fmt.Fprintf(os.Stderr, "%s: %s from %s was not answered: %s (%s)\n",
		ch.name, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), identity.PrintableText(why), tail)
}

// report is one message as --json names it, under the channel that answers
// it rather than the one it arrived on, which for a follow-up is default.
func (r *serveRun) report(m *store.Stored) handledJSON {
	channel := channelOf(m)
	if ch := r.channelFor(m); ch != nil {
		channel = ch.name
	}
	return handledJSON{ID: m.Inner.ID, Channel: channel, Thread: m.Inner.Body.Thread}
}

// said is why a program's run was not a success, with the first thing it
// wrote about it.
func said(run programRun, path string) string {
	what := "exited " + strconv.Itoa(run.exit)
	if run.timedOut {
		what = "was killed at the timeout"
	}
	if line := firstLine(path); line != "" {
		return what + ": " + line
	}
	return what
}

// output is what the handler printed, as the reply's text. Trailing blank
// space is not an answer; a handler with nothing to say prints nothing.
//
// A Windows line ending is folded to a line break first, as the sender's
// own command folds it for a typed message: a handler on Windows, or any
// tool in text mode there, prints CRLF, and the text rule would refuse
// the reply for U+000D at every retry with the answer on disk the whole
// time. A carriage return on its own is left for the rule, which fails
// the round with its sentence, recorded as that message's failure.
//
// A file that is there and says nothing is no answer, and is told apart
// from one that is not there or cannot be read, which is the error (G39,
// R55): an answer the program cannot read back was settled as nothing to
// say, and lost without a word.
func output(path string) (string, bool, error) {
	data, err := regular.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	text := strings.TrimRight(foldCRLF(string(data)), " \t\r\n")
	return text, strings.TrimSpace(text) != "", nil
}

// sealedFile is where the envelope a message's reply was sealed as is kept
// between attempts to post it.
func sealedFile(threadDir, id string) string {
	return filepath.Join(threadDir, "sealed-"+id+".json")
}

// keptReply is a reply written by an earlier round whose send did not get
// through. No file is no reply kept; one that is there and cannot be read
// is the error.
func keptReply(path string) (string, bool, error) {
	text, ok, err := output(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	return text, ok, err
}

// channelOf is the channel a message is filed under, by name: the empty
// string on the wire is default's own name.
func channelOf(m *store.Stored) string {
	if m.Channel == "" {
		return channels.Default
	}
	return m.Channel
}

// shortID is what people read: the first twelve characters of an id.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// takeServeLock is one serve per home. The pid goes in the file once the
// lock is held, so that the second one can say who to look for.
func takeServeLock(root string) (*lockfile.Lock, error) {
	path := filepath.Join(root, serveLockName)
	lock, err := lockfile.Try(path)
	if errors.Is(err, lockfile.ErrHeld) {
		return nil, transportErr(fmt.Errorf("another %s serve is running in this home%s; stop it first",
			prog, holder(path)))
	}
	if err != nil {
		return nil, fmt.Errorf("taking the serve lock: %w", err)
	}
	os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	return lock, nil
}

// holder is what the lock file says about whoever holds it, for the
// sentence. A file with nothing in it is a serve that had not written its
// pid yet, which is nothing to say rather than something to guess at.
func holder(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if pid := strings.TrimSpace(string(data)); pid != "" {
		return " (pid " + pid + ")"
	}
	return ""
}

// serveCheck reads the file and says what it would serve, without touching
// a key, a relay or the network: it is what an owner runs after editing it.
func serveCheck(config string) error {
	s, err := openStore()
	if err != nil {
		return err
	}
	path := servePath(s, config)
	cfg, err := loadServeConfig(path)
	if err != nil {
		return err
	}
	if err := cfg.check(); err != nil {
		return err
	}
	for _, name := range cfg.names() {
		ch := cfg.Channels[name]
		fmt.Printf("%s: %s in %s\n", name, ch.Mode, ch.Dir)
		fmt.Printf("  exec:    %s\n", ch.Exec)
		if ch.Before != "" {
			fmt.Printf("  before:  %s\n", ch.Before)
		}
		if ch.After != "" {
			fmt.Printf("  after:   %s\n", ch.After)
		}
		fmt.Printf("  limits:  timeout %s, max_turns %d, retries %d, thread_ttl %s\n",
			ch.timeout, ch.MaxTurns, ch.Retries, ch.threadTTL)
	}
	switch {
	case cfg.Proxy == nil:
	case cfg.Proxy.Control != "":
		// The split proxy is asked whether it is there, and nothing more.
		if err := (&controlSource{path: cfg.Proxy.Control}).ping(); err != nil {
			fmt.Printf("\nproxy: control %s (nobody is listening; %s serve will fail each message until it is: %v)\n",
				cfg.Proxy.Control, prog, err)
		} else {
			fmt.Printf("\nproxy: control %s (answering)\n", cfg.Proxy.Control)
		}
	default:
		// The key is read for its size and nothing else is said of it.
		key, err := readKeyFile(cfg.Proxy.KeyFile)
		if err != nil {
			return err
		}
		fmt.Printf("\nproxy: key from %s (%d bytes), listen %s, upstream %s\n",
			cfg.Proxy.KeyFile, len(key), cfg.Proxy.Listen, cfg.Proxy.Upstream)
	}
	fmt.Printf("\n%s is good for %s\n", path, plural(len(cfg.Channels), "channel"))
	warnKept(s, cfg)
	warnCredentials(cfg)
	return nil
}

// warnCredentials says, with a proxy configured, which credential
// variables serve's own environment carries and that none is passed on: a
// unit still handing serve the real key is a mistake the proxy covers,
// and one its operator should hear about.
func warnCredentials(cfg *serveConfig) {
	if cfg.Proxy == nil {
		return
	}
	if found := credentialsInEnvironment(); len(found) > 0 {
		fmt.Fprintf(os.Stderr, "%s: %s %s set in serve's environment and %s not passed to the handler or the hooks; the proxy holds the key, and the line that sets %s can go\n",
			prog, plainList(found), isAre(len(found)), isAre(len(found)), itThem(len(found)))
	}
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func itThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
