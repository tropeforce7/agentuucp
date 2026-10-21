package auu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// auu handle run: the host's scripts, run on the asks to their routes.
//
// A round is a fetch, then each route's first round where it is due, then
// the admission of every ask on a route's channel that has no job, in the
// inbox's order, and then the jobs run until none is runnable now. Every
// step a job takes is written in the ledger before it is taken and after,
// so that a run stopped anywhere leaves the next one a job it can say
// where it stood.

// handleLockName is the one-handle-run-per-home lock, under handle/.
const handleLockName = "lock"

// handleNow is the clock the ledger's times are read from, to the second,
// as serve's are. A test moves it to reach a retry that is due.
var handleNow = func() time.Time { return time.Now().UTC().Truncate(time.Second) }

// handleRun is one run of the command.
type handleRun struct {
	s   *store.Store
	id  *identity.Identity
	cfg *handleConfig
	led *handleLedger
	// root is the handle directory in the home.
	root   string
	asJSON bool
	out    handleRoundJSON
	// failed says a job failed in this round, which is the exit code of
	// --once, as serve's is.
	failed bool
	// said is the messages already said to be left in the inbox, so that
	// each is said once per run.
	said map[string]bool
	// event is the round's report of the job last reported, which the
	// reply's send fills in.
	event *handleJobEvent
	// resumed is the jobs the ledger had as preparing when this run read
	// it: a run that stopped part way through unpacking, which the next
	// prepare starts afresh (A7).
	resumed map[string]bool
}

// handleRoundJSON is one round as --json gives it.
type handleRoundJSON struct {
	// Skipped is how many asks first rounds left in the inbox.
	Skipped int              `json:"skipped"`
	Jobs    []handleJobEvent `json:"jobs"`
}

// handleJobEvent is one job as a round leaves it.
type handleJobEvent struct {
	ID      string `json:"id"`
	Route   string `json:"route"`
	State   string `json:"state"`
	Attempt int    `json:"attempt"`
	Reason  string `json:"reason"`
	// Reply is the id of the reply sent for it in this round, empty when
	// none went.
	Reply string `json:"reply"`
}

// handleRunCmd is 'auu handle run --once'.
func handleRunCmd(config string, backlog, asJSON bool) error {
	s, err := openStore()
	if err != nil {
		return err
	}
	cfg, err := loadHandle(s, config)
	if err != nil {
		return err
	}
	// Speaking for this identity, and in send scope for the whole run: every
	// reply originates. A home under a passphrase is refused at exit 4 now,
	// before a key is asked for, rather than a person at a terminal being
	// prompted into a service's run: a service has no terminal.
	if enc, err := s.Encrypted(); err != nil {
		return err
	} else if enc {
		if err := needsSend(s, "auu handle run"); err != nil {
			return err
		}
	}
	s, id, err := loadIdentity()
	if err != nil {
		return err
	}
	root := s.HandleDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	lock, err := takeHandleLock(root)
	if err != nil {
		return err
	}
	defer lock.Release()
	led, err := loadHandleLedger(filepath.Join(root, handleLedgerFile))
	if err != nil {
		return err
	}
	r := &handleRun{s: s, id: id, cfg: cfg, led: led, root: root, asJSON: asJSON,
		said: map[string]bool{}, resumed: map[string]bool{}}
	for id, job := range led.Jobs {
		if job.State == jobPreparing {
			r.resumed[id] = true
		}
	}
	// A job the load found running is interrupted, and that is written
	// before any round.
	if len(led.interrupted) > 0 {
		if err := led.save(); err != nil {
			return err
		}
	}
	if backlog && !r.anyFirstRound() {
		return usageErrf("--backlog runs the asks already in the inbox for a route at its first round, "+
			"and every route in %s has had one; there is no backlog to run", cfg.path)
	}
	warnKept(s, cfg.channels())
	cfg.warnDefault()
	if found := credentialsInEnvironment(); len(found) > 0 {
		fmt.Fprintf(os.Stderr, "%s: %s %s set in handle's environment and %s not passed to the scripts\n",
			prog, plainList(found), isAre(len(found)), isAre(len(found)))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := r.round(ctx, backlog); err != nil {
		return err
	}
	if r.asJSON {
		if err := printJSON(r.out); err != nil {
			return err
		}
	} else if len(r.out.Jobs) == 0 && r.out.Skipped == 0 {
		if _, err := fmt.Println("nothing to run"); err != nil {
			return err
		}
	}
	if r.failed {
		return usageErrf("a job failed in this round; the failures are above")
	}
	return nil
}

// takeHandleLock is one handle run per home, as takeServeLock is one serve.
func takeHandleLock(root string) (*lockfile.Lock, error) {
	path := filepath.Join(root, handleLockName)
	lock, err := lockfile.Try(path)
	if errors.Is(err, lockfile.ErrHeld) {
		return nil, transportErr(fmt.Errorf("another %s handle run is running in this home%s; stop it first",
			prog, holder(path)))
	}
	if err != nil {
		return nil, fmt.Errorf("taking the handle lock: %w", err)
	}
	os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	return lock, nil
}

// anyFirstRound says some route in the file has had no first round on its
// channel yet, which is what --backlog is for.
func (r *handleRun) anyFirstRound() bool {
	for _, name := range r.cfg.names() {
		if r.atFirstRound(name) {
			return true
		}
	}
	return false
}

// atFirstRound says a route has had no first round on the channel it now
// names: none at all, or one on another channel, which is a new baseline
// (A3), since the asks waiting on the new channel were never its work.
func (r *handleRun) atFirstRound(name string) bool {
	mark := r.led.Routes[name]
	return mark == nil || mark.Channel != r.cfg.Routes[name].Channel
}

// round is a fetch, the first rounds, admission, and the jobs that are
// runnable now, each to the end of its attempt.
func (r *handleRun) round(ctx context.Context, backlog bool) error {
	relays, err := selectedRelays(r.s, "")
	if err != nil {
		return err
	}
	if _, _, err := fetchEvery(ctx, r.s, r.id, relays, len(relays) == 1); err != nil {
		return err
	}
	msgs, err := r.s.List(store.Inbox)
	if err != nil {
		return err
	}
	slices.SortStableFunc(msgs, store.ArrivalOrder)
	for _, name := range r.cfg.names() {
		if r.atFirstRound(name) {
			if err := r.baseline(name, msgs, backlog); err != nil {
				return err
			}
		}
	}
	for _, m := range msgs {
		name := r.routeFor(m)
		if name == "" {
			continue
		}
		if _, err := r.admit(m, name, jobQueued, ""); err != nil {
			return err
		}
	}
	// Replies due from earlier rounds go first, then the jobs, each of
	// which sends its own as it ends.
	if err := r.replies(); err != nil {
		return escaped(err)
	}
	return r.dispatch(ctx)
}

// routeFor is the route whose work a message is, or "" for one that is
// nobody's: an ask, on a route's channel, with no job yet, delivered whole
// and with ids of the shape a job's are. Every reply, note,
// acknowledgement and vouch is left alone, so that no loop can form
// between a handle and a serve, or two handles; a quarantined message is
// never in the inbox at all.
func (r *handleRun) routeFor(m *store.Stored) string {
	if m.Inner.Body.Type != message.TypeAsk {
		return ""
	}
	name := ""
	for _, candidate := range r.cfg.names() {
		if r.cfg.Routes[candidate].Channel == channelOf(m) {
			name = candidate
		}
	}
	if name == "" {
		return ""
	}
	if _, ok := r.led.Jobs[m.Inner.ID]; ok {
		return ""
	}
	// A stream that waits on the relay for a newer auu is not here yet: it
	// is neither admitted nor skipped by a first round, and the round after
	// the upgrade delivers it and admits it (A2).
	if m.Newer != "" {
		r.sayOnce(m.Inner.ID, "%s: %s from %s waits on the relay for a newer auu (section %q); left pending",
			name, shortID(m.Inner.ID), orNone(identity.Printable(m.SenderName)), m.Newer)
		return ""
	}
	// Every record in the inbox has been held to these at Load; one written
	// by hand that is not is left where it is, since its ids become a job's
	// key and its directories.
	if message.ValidID(m.Inner.ID) != nil || message.ValidID(m.Inner.Body.Thread) != nil ||
		!identity.ValidFingerprint(m.Inner.From) || m.RelayID < 0 {
		r.sayOnce(m.Inner.ID, "%s: %s is not a record handle can take, and is left in the inbox", name, shortID(m.Inner.ID))
		return ""
	}
	return name
}

// sayOnce says a sentence about a message on standard error, once per run.
func (r *handleRun) sayOnce(id, format string, a ...any) {
	if r.said[id] {
		return
	}
	r.said[id] = true
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

// baseline is a route's first round on its channel: every ask waiting
// there is its backlog, written down as skipped by the first start so that
// a route set up today does not run a year of mail at once, or with
// --backlog admitted as any other ask is. It is said in one sentence, and
// the route's mark is written with the channel it was taken on.
func (r *handleRun) baseline(name string, msgs []*store.Stored, backlog bool) error {
	route := r.cfg.Routes[name]
	if mark := r.led.Routes[name]; mark != nil {
		fmt.Fprintf(os.Stderr, "%s: route %q moved from channel %q to %q, and takes a new baseline there\n",
			prog, name, mark.Channel, route.Channel)
	}
	skipped := 0
	for _, m := range msgs {
		if r.routeFor(m) != name {
			continue
		}
		if backlog {
			if _, err := r.admit(m, name, jobQueued, ""); err != nil {
				return err
			}
			continue
		}
		job, err := r.admit(m, name, jobSkipped, skippedAtFirstStart)
		if err != nil {
			return err
		}
		skipped++
		r.out.Skipped++
		_ = job
	}
	r.led.Routes[name] = &handleRouteMark{FirstRound: handleNow(), Channel: route.Channel}
	if err := r.led.save(); err != nil {
		return err
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "%s: route %q: %s already in the inbox, left alone; '%s handle run --once --backlog' at a route's first round runs them instead\n",
			prog, name, plural(skipped, "ask"), prog)
	}
	return nil
}

// admit writes a message's job, under the next admission number, in the
// state given, and saves the ledger with it. The number is spent once and
// never reused, and one that would pass the type's maximum is the host's
// fault, not the message's.
func (r *handleRun) admit(m *store.Stored, name, state, by string) (*handleJob, error) {
	if r.led.NextSeq == math.MaxInt64 {
		return nil, fmt.Errorf("%s has spent every admission number it has; move it aside knowing what that costs", r.led.path)
	}
	route := r.cfg.Routes[name]
	job := &handleJob{
		Route: name, Revision: route.revision(), Channel: route.Channel,
		Thread: m.Inner.Body.Thread, From: m.Inner.From, Arrived: m.Arrived.UTC(), RelayID: m.RelayID,
		Seq: r.led.NextSeq, State: state, By: by,
	}
	r.led.NextSeq++
	r.led.Jobs[m.Inner.ID] = job
	if state == jobQueued {
		if err := r.led.save(); err != nil {
			return nil, err
		}
	}
	return job, nil
}

// revision is the route's revision: the first sixteen hex characters of
// the SHA-256 of its object as this build marshals it, compact, with its
// defaults filled in, so that an edit to any field is a new revision and a
// reformat is not.
func (route *handleRoute) revision() string {
	data, err := json.Marshal(route)
	if err != nil {
		// A struct of strings, numbers and bools always marshals.
		panic(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:16]
}

// terminal says a job is where it ends: succeeded, failed for review,
// skipped or removed.
func (job *handleJob) terminal() bool {
	switch job.State {
	case jobSucceeded, jobSkipped, jobRemoved:
		return true
	case jobFailed:
		return job.Review
	}
	return false
}

// runnable says a job may start its next step now: queued, or preparing
// when the run that began it stopped, and not before its retry is due.
func (job *handleJob) runnable(now time.Time) bool {
	switch job.State {
	case jobQueued, jobPreparing:
		return job.RetryAt.IsZero() || !job.RetryAt.After(now)
	}
	return false
}

// next is the job of a route to run now, or "": a sequential route's head,
// the lowest seq that has not succeeded, been skipped or been removed, only
// when it is runnable, so that a job in review holds the jobs behind it; a
// parallel route's lowest runnable job, since its jobs do not wait on each
// other.
func (r *handleRun) next(name string) string {
	parallel := r.cfg.Routes[name].Execution == executionParallel
	now := handleNow()
	best := ""
	var bestJob *handleJob
	for id, job := range r.led.Jobs {
		if job.Route != name {
			continue
		}
		// A job that ended is behind the head; one in review is the head,
		// and holds a sequential route until the operator moves it.
		if job.State == jobSucceeded || job.State == jobSkipped || job.State == jobRemoved {
			continue
		}
		if parallel && !job.runnable(now) {
			continue
		}
		if bestJob == nil || job.Seq < bestJob.Seq {
			best, bestJob = id, job
		}
	}
	if bestJob == nil || !bestJob.runnable(now) {
		return ""
	}
	return best
}

// dispatch runs jobs, a route at a time in the file's order, until none is
// runnable now. Each job run ends terminal, or not runnable until a retry
// that is not yet due, so the loop ends.
func (r *handleRun) dispatch(ctx context.Context) error {
	for {
		ran := false
		for _, name := range r.cfg.names() {
			id := r.next(name)
			if id == "" {
				continue
			}
			ran = true
			if err := r.runJob(ctx, id); err != nil {
				return escaped(err)
			}
		}
		if !ran {
			return nil
		}
	}
}
