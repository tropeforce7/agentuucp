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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
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
	// unreachable says the last fetch of the long run reached no relay, so
	// that it is said once per run of failures.
	unreachable bool
	// mu is the one lock over the ledger and the round's report while jobs
	// run at once: a worker holds it for every step a job takes but the
	// script's own run, so that each transition is saved whole and two
	// completions in one instant write one ledger after the other.
	mu sync.Mutex
	// inFlight is the jobs a worker has in hand this dispatch.
	inFlight map[string]bool
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

// handleRunCmd is 'auu handle run --once'. A signal is how a run is
// stopped: it ends the script that is running with everything it started,
// and the job is written interrupted, killed by the service's own stop,
// before the process exits; a stopped run is not a failure.
func handleRunCmd(config string, once, backlog, asJSON bool) error {
	r, release, err := openHandleRun(config, backlog, asJSON)
	if err != nil {
		return err
	}
	defer release()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if once {
		return r.once(ctx, backlog)
	}
	return r.long(ctx, backlog)
}

// openHandleRun is everything a run does before its first round: the file,
// the scope, the keys, the lock and the ledger. release gives the lock
// back.
func openHandleRun(config string, backlog, asJSON bool) (*handleRun, func(), error) {
	r, lock, err := openHandleRunLocked(config, backlog, asJSON)
	if err != nil {
		if lock != nil {
			lock.Release()
		}
		return nil, nil, err
	}
	return r, func() { lock.Release() }, nil
}

func openHandleRunLocked(config string, backlog, asJSON bool) (*handleRun, *lockfile.Lock, error) {
	s, err := openStore()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := loadHandle(s, config)
	if err != nil {
		return nil, nil, err
	}
	// Speaking for this identity, and in send scope for the whole run: every
	// reply originates. A home under a passphrase is refused at exit 4 now,
	// before a key is asked for, rather than a person at a terminal being
	// prompted into a service's run: a service has no terminal.
	if enc, err := s.Encrypted(); err != nil {
		return nil, nil, err
	} else if enc {
		if err := needsSend(s, "auu handle run"); err != nil {
			return nil, nil, err
		}
	}
	s, id, err := loadIdentity()
	if err != nil {
		return nil, nil, err
	}
	root := s.HandleDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, nil, err
	}
	lock, err := takeHandleLock(root)
	if err != nil {
		return nil, nil, err
	}
	led, err := loadHandleLedger(filepath.Join(root, handleLedgerFile))
	if err != nil {
		return nil, lock, err
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
			return nil, lock, err
		}
	}
	if backlog && !r.anyFirstRound() {
		return nil, lock, usageErrf("--backlog runs the asks already in the inbox for a route at its first round, "+
			"and every route in %s has had one; there is no backlog to run", cfg.path)
	}
	warnKept(s, cfg.channels())
	cfg.warnDefault()
	if found := credentialsInEnvironment(); len(found) > 0 {
		fmt.Fprintf(os.Stderr, "%s: %s %s set in handle's environment and %s not passed to the scripts\n",
			prog, plainList(found), isAre(len(found)), isAre(len(found)))
	}
	return r, lock, nil
}

// once is one round and the exit code that says how it went.
func (r *handleRun) once(ctx context.Context, backlog bool) error {
	if err := r.round(ctx, backlog, false); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
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
//
// In the long run a fetch that reached no relay is not the end of the
// service: the hold that follows has its own patience with a relay that is
// down, and it is said once per run of failures. Under --once it is this
// run's failure, as serve's is.
func (r *handleRun) round(ctx context.Context, backlog, longRun bool) error {
	r.out, r.failed, r.event = handleRoundJSON{}, false, nil
	// The operator's requests first, so that a retry, a skip or a pause
	// made while the service held is this round's (A6).
	if err := r.applyOps(); err != nil {
		return escaped(err)
	}
	relays, err := selectedRelays(r.s, "")
	if err != nil {
		return err
	}
	if _, _, err := fetchEvery(ctx, r.s, r.id, relays, len(relays) == 1); err != nil {
		if !longRun || ctx.Err() != nil {
			return err
		}
		if !r.unreachable {
			r.unreachable = true
			fmt.Fprintf(os.Stderr, "%s: no relay could be reached; waiting for one to come back\n", prog)
		}
	} else {
		r.unreachable = false
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
	// A job interrupted by a stop, or found running at the load, is
	// settled before anything else runs: queued again where that is safe,
	// in review otherwise.
	if err := r.settleInterrupted(); err != nil {
		return escaped(err)
	}
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

// runnable says a job may start its next step now: queued, preparing
// when the run that began it stopped, or failed without review on an
// idempotent route with attempts left, and not before its retry is due.
func (job *handleJob) runnable(now time.Time) bool {
	switch job.State {
	case jobQueued, jobPreparing:
	case jobFailed:
		if job.Review {
			return false
		}
	default:
		return false
	}
	return job.RetryAt.IsZero() || !job.RetryAt.After(now)
}

// settleInterrupted decides every interrupted job of a route in the file.
// A started attempt's effect may have been committed (point 7), so it is
// run again only on an idempotent route with attempts left, and then only
// when the process is known gone: killed by the service's own stop, which
// waited for it, or supervisor_reaps set, the host's word that the service
// manager ends the whole group with the service (D6). Every other is
// failed for review, saying why, and gets its reply.
func (r *handleRun) settleInterrupted() error {
	for _, id := range r.led.bySeq() {
		job := r.led.Jobs[id]
		route := r.cfg.Routes[job.Route]
		if job.State != jobInterrupted || route == nil {
			continue
		}
		gone := job.Killed || r.cfg.SupervisorReap
		switch {
		case route.Idempotent && job.Attempt < route.Retries && gone:
			job.State, job.Review, job.RetryAt = jobQueued, false, time.Time{}
			if err := r.led.save(); err != nil {
				return err
			}
			continue
		case !route.Idempotent:
			job.Reason = "interrupted on a route that is not idempotent, so it is not run again"
		case !gone:
			job.Reason = "interrupted, and nothing says its script is gone: the service did not stop it and supervisor_reaps is not set"
		default:
			job.Reason = "interrupted, and its attempts are spent"
		}
		job.State, job.Review = jobFailed, true
		if err := r.led.save(); err != nil {
			return err
		}
		r.report(id, job, nil)
		if err := r.compose(id, job, nil); err != nil {
			return err
		}
		if err := r.answer(id); err != nil {
			return err
		}
	}
	return nil
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
		// A job a worker has in hand is not offered again; on a sequential
		// route it is the head, and holds the route.
		if r.inFlight[id] {
			if !parallel {
				return ""
			}
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

// paused says the operator has paused a route: it takes its asks and
// launches none.
func (r *handleRun) paused(name string) bool {
	mark := r.led.Routes[name]
	return mark != nil && mark.Paused
}

// dispatch runs jobs until none is runnable now, a worker each, at most
// workers_total at once and a route's max_parallel of its own. Routes are
// offered a worker round-robin in the file's order, one job at a time, so
// that a busy route does not take every worker from the others. Each job
// run ends terminal, or not runnable until a retry that is not yet due, so
// the loop ends; a job whose retry is not yet due holds no worker. A fault
// of the host's in one worker starts nothing more, and the run ends with it
// once the workers running have finished.
func (r *handleRun) dispatch(ctx context.Context) error {
	type finished struct {
		route, id string
		err       error
	}
	done := make(chan finished)
	names := r.cfg.names()
	perRoute := map[string]int{}
	running, turn := 0, 0
	var fault error
	r.mu.Lock()
	r.inFlight = map[string]bool{}
	for {
		// A stop that came during the replies or the settling, or one
		// since, starts nothing more.
		for fault == nil && ctx.Err() == nil && running < r.cfg.WorkersTotal {
			started := false
			for i := range names {
				name := names[(turn+i)%len(names)]
				if perRoute[name] >= r.cfg.Routes[name].MaxParallel || r.paused(name) {
					continue
				}
				id := r.next(name)
				if id == "" {
					continue
				}
				r.inFlight[id] = true
				perRoute[name]++
				running++
				turn = (turn + i + 1) % len(names)
				started = true
				go func() { done <- finished{name, id, r.runJob(ctx, id)} }()
				break
			}
			if !started {
				break
			}
		}
		if running == 0 {
			r.inFlight = nil
			r.mu.Unlock()
			if fault != nil {
				return escaped(fault)
			}
			return ctx.Err()
		}
		r.mu.Unlock()
		f := <-done
		r.mu.Lock()
		running--
		perRoute[f.route]--
		delete(r.inFlight, f.id)
		if f.err != nil && fault == nil && !errors.Is(f.err, context.Canceled) {
			fault = f.err
		}
	}
}

// handleOpsPoll is how often the long run's hold looks in handle/ops/ for
// an operator's request, which ends the hold so the next round applies it.
var handleOpsPoll = 2 * time.Second

// afterRound, when a test sets it, is told each time the long run has
// finished a round, with how many it has done.
var afterRound func(n int)

// long is the service: rounds, with a hold between them on the relays for
// mail on the routes' channels, ended early by a job's retry or reply
// falling due or an operator's request landing. It ends when it is stopped,
// which is not a failure, or when the hold ends for a reason no wait will
// change, which is.
func (r *handleRun) long(ctx context.Context, backlog bool) error {
	for n := 1; ; n++ {
		if err := r.round(ctx, backlog, true); err != nil {
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		backlog = false
		if r.asJSON && (len(r.out.Jobs) > 0 || r.out.Skipped > 0) {
			// One object per round that did something, one to a line.
			if err := printJSONLine(r.out); err != nil {
				return err
			}
		}
		if afterRound != nil {
			afterRound(n)
		}
		if err := r.hold(ctx); err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return err
		}
	}
}

// hold waits until the next round is due: mail on a route's channel, the
// earliest retry or reply falling due, or an operator's request in
// handle/ops/. A watch that ends at its own deadline, or one cut by a
// request, is the cue for the next round, and is no error.
func (r *handleRun) hold(ctx context.Context) error {
	relays, err := selectedRelays(r.s, "")
	if err != nil {
		return err
	}
	watched := map[string]bool{}
	for _, name := range r.cfg.names() {
		channel := r.cfg.Routes[name].Channel
		watched[channel] = true
		if channel == channels.Default {
			// A listing names the default channel by no name at all.
			watched[""] = true
		}
	}
	held, cancel := context.WithCancel(ctx)
	defer cancel()
	var woken atomic.Bool
	ops := filepath.Join(r.root, "ops")
	// What is there as the hold begins is what the round has seen; only a
	// request that lands after wakes it, so that one nothing has yet taken
	// away, or a file a desktop leaves, does not end every hold.
	seen := requests(ops)
	// Read here, not in the goroutine, which may outlive the hold's return
	// by a moment.
	every := handleOpsPoll
	go func() {
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-held.Done():
				return
			case <-tick.C:
				for name := range requests(ops) {
					if !seen[name] {
						woken.Store(true)
						cancel()
						return
					}
				}
			}
		}
	}()
	_, err = awaitEvents(held, r.s, r.id, relays,
		watchOptions{messages: true, channels: watched, interval: serveInterval, deadline: r.nextDue()})
	switch {
	case err == nil, woken.Load(), errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
		return nil
	}
	return err
}

// requests is the names in the ops directory that have a request's shape:
// a JSON name that does not begin with a dot and is not a directory. A
// link or anything else that is not a regular file is listed too, so that
// the round that reads it moves it aside and says so rather than leaving
// it unsaid. A directory that is not there holds none.
func requests(ops string) map[string]bool {
	out := map[string]bool{}
	entries, err := os.ReadDir(ops)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if name := e.Name(); !e.IsDir() && strings.HasSuffix(name, ".json") && !strings.HasPrefix(name, ".") {
			out[name] = true
		}
	}
	return out
}

// nextDue is when the earliest job of a route in the file is next due
// without new mail: a retry, a failure before launch, or a reply whose send
// failed. A job counts only where the route would run it: on a sequential
// route, its head alone, so that a head in review does not wake the service
// for the jobs it holds. Zero when nothing is; never sooner than one
// serveInterval from now, so that the long run does not spin on a job that
// is due at once.
func (r *handleRun) nextDue() time.Time {
	var at time.Time
	earliest := func(t time.Time) {
		if !t.IsZero() && (at.IsZero() || t.Before(at)) {
			at = t
		}
	}
	heads := map[string]*handleJob{}
	for _, job := range r.led.Jobs {
		if job.State == jobSucceeded || job.State == jobSkipped || job.State == jobRemoved {
			continue
		}
		if head := heads[job.Route]; head == nil || job.Seq < head.Seq {
			heads[job.Route] = job
		}
	}
	for _, job := range r.led.Jobs {
		route := r.cfg.Routes[job.Route]
		if route == nil {
			continue
		}
		waits := route.Execution == executionSequential && heads[job.Route] != job || r.paused(job.Route)
		if !waits && (job.State == jobQueued || (job.State == jobFailed && !job.Review)) && !job.RetryAt.IsZero() {
			earliest(job.RetryAt)
		}
		if job.awaitsReply() && job.ReplyFailures > 0 && job.ReplyFailures < route.Retries {
			earliest(job.ReplyTried.Add(retryBackoff(job.ReplyFailures)))
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
