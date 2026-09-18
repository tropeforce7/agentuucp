package auu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/message"
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
	// Speaking for this identity from here on: a home under a passphrase
	// says so now, at exit 4, rather than after a handler has run.
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
			if errors.Is(err, context.Canceled) {
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
	if _, _, err := fetchEvery(r.s, r.id, relays, len(relays) == 1); err != nil {
		if !longRun {
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
	pending, err := r.pending()
	if err != nil {
		return err
	}
	if !r.led.existed {
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
func (r *serveRun) hold(ctx context.Context) error {
	relays, err := selectedRelays(r.s, "")
	if err != nil {
		return err
	}
	_, err = awaitEvents(ctx, r.s, r.id, relays, watchOptions{messages: true, interval: serveInterval})
	return err
}

// pending is every message this run is to answer, oldest first: on a served
// channel, admitted by the rule that stops two experts talking for ever,
// and not settled in the ledger.
//
// Oldest is by when this machine received it, then by the relay's own
// counter, which is the only true order among messages that arrived in the
// same second, and then by id so that two runs agree.
func (r *serveRun) pending() ([]*store.Stored, error) {
	msgs, err := r.s.List(store.Inbox)
	if err != nil {
		return nil, err
	}
	var out []*store.Stored
	for _, m := range msgs {
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
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case !a.Received.Equal(b.Received):
			return a.Received.Before(b.Received)
		case a.RelayID != b.RelayID:
			return a.RelayID < b.RelayID
		default:
			return a.Inner.ID < b.Inner.ID
		}
	})
	return out, nil
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
// here, whoever it is from and whatever it is about.
func (r *serveRun) channelFor(m *store.Stored) *serveChannel {
	if m.Inner.Body.Type == message.TypeReply {
		if e := r.led.repliedWith(m.Inner.Body.InReplyTo); e != nil {
			return r.cfg.Channels[e.Channel]
		}
		return nil
	}
	return r.cfg.Channels[channelOf(m)]
}

// answerable is the rest of the rule: a question is answered and a
// statement is not, and a thread that has had its turns is done, so that
// two experts pointed at each other stop. Whether a reply is serve's to
// answer at all is channelFor's: it is the same lookup as the channel.
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
		if backlog && r.answerable(m) {
			continue
		}
		e := r.led.entry(m.Inner.ID, m.Inner.Body.Thread, channelOf(m))
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
// the run: it is this machine's own trouble — a disk, a lock, a key — and
// not the message's, which is what the ledger's failure count is for.
func (r *serveRun) handle(ctx context.Context, m *store.Stored) error {
	ch := r.channelFor(m)
	thread := m.Inner.Body.Thread
	short := shortID(thread)

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
	worktree, base, err := worktreeFor(r.root, ch, thread, stateDir, newThread)
	if err != nil {
		return err
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
	// A reply the handler has already written and serve could not send —
	// the relay was down, the mailbox full — is sent from the file, with
	// the patch that was made for it. The handler is not run twice for one
	// answer, and neither are the hooks.
	if text, ok := keptReply(replyPath); ok {
		return r.send(m, ch, text, keptPatch(threadDir, thread), facts)
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
	if err := os.WriteFile(stdinPath, []byte(m.Inner.Body.Text), 0o600); err != nil {
		return err
	}
	stdin, err := os.Open(stdinPath)
	if err != nil {
		return err
	}
	outPath := runFile(threadDir, "out", m.Inner.ID)
	errPath := runFile(threadDir, "err", m.Inner.ID)
	stdout, err := createTrunc(outPath)
	if err != nil {
		stdin.Close()
		return err
	}
	stderr, err := createTrunc(errPath)
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
	text, has := output(outPath)
	if !has {
		// Nothing to say is an answer: the message is settled, and no
		// reply goes out. In a side copy that means the change stays in
		// the worktree and travels nowhere, since a patch goes with an
		// answer and is not one by itself.
		return r.settle(m, ch, "")
	}
	if err := os.Rename(outPath, replyPath); err != nil {
		return err
	}
	// After the hooks, so that an after that refuses a red side copy has
	// already refused it.
	patch, err := patchFor(ch, worktree, base, threadDir, thread)
	if err != nil {
		r.failed(m, ch, err.Error())
		return nil
	}
	return r.send(m, ch, text, patch, facts)
}

// runOne runs a hook: no standard input, its two streams in one file, and
// that file printed prefixed afterwards.
func (r *serveRun) runOne(ctx context.Context, line, outPath string, env []string, stdin *os.File, ch *serveChannel, facts runFacts, short string) (programRun, error) {
	f, err := createTrunc(outPath)
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
	out, _, err := sendSealed(r.s, r.id, relay, recipient, body, attach, sendMode{})
	if err != nil {
		if isLocked(err) {
			// The keys went away under a running service. Nothing is
			// recorded against the message, the reply is on disk, and the
			// next serve sends it without running the handler again.
			return err
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
	e := r.led.entry(m.Inner.ID, m.Inner.Body.Thread, ch.name)
	e.Handled = time.Now().UTC().Truncate(time.Second)
	e.Tried = e.Handled
	e.Reply = replyID
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
			fmt.Printf("%s: %s from %s had nothing to say\n", ch.name, shortID(m.Inner.ID), orNone(m.SenderName))
		default:
			fmt.Printf("%s: answered %s from %s (reply %s)\n",
				ch.name, shortID(m.Inner.ID), orNone(m.SenderName), shortID(replyID))
		}
	}
	return nil
}

// failed counts one attempt against a message, gives up when the count has
// run out, and says why on standard error. The message stays unread, so the
// owner's inbox shows it for what it is.
func (r *serveRun) failed(m *store.Stored, ch *serveChannel, why string) {
	e := r.led.entry(m.Inner.ID, m.Inner.Body.Thread, ch.name)
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
	fmt.Fprintf(os.Stderr, "%s: %s from %s was not answered: %s (%s)\n",
		ch.name, shortID(m.Inner.ID), orNone(m.SenderName), why, tail)
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
func output(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	text := strings.TrimRight(string(data), " \t\r\n")
	return text, strings.TrimSpace(text) != ""
}

// keptReply is a reply written by an earlier round whose send did not get
// through.
func keptReply(path string) (string, bool) {
	return output(path)
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
