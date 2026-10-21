package auu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// The operator's commands.
//
// status, jobs and inspect read the file and the ledger and nothing else,
// without the lock, so that they answer while a service runs. retry, skip,
// pause and resume change a job or a route: with no service holding
// handle/lock the command takes the lock and changes the ledger itself;
// with one, it writes the change as a request under handle/ops/, which the
// service applies at the start of its next round, within a few seconds,
// since the request ends the service's hold. One writer of the ledger at a
// time, either way.

// The operator's changes, as a request names them.
const (
	opRetry  = "retry"
	opSkip   = "skip"
	opPause  = "pause"
	opResume = "resume"
)

// handleRequest is one request under handle/ops/, read strictly.
type handleRequest struct {
	V      int    `json:"v"`
	Op     string `json:"op"`
	Target string `json:"target"`
}

// openHandleRead is the file and the ledger as they are, for a command that
// only looks.
func openHandleRead(config string) (*store.Store, *handleConfig, *handleLedger, error) {
	s, err := openStore()
	if err != nil {
		return nil, nil, nil, err
	}
	cfg, err := loadHandle(s, config)
	if err != nil {
		return nil, nil, nil, err
	}
	led, err := readHandleLedger(filepath.Join(s.HandleDir(), handleLedgerFile))
	if err != nil {
		return nil, nil, nil, err
	}
	return s, cfg, led, nil
}

// findJob is the job an id or a prefix of one names, at least four
// characters, as every other command takes a message id.
func findJob(led *handleLedger, idOrPrefix string) (string, error) {
	if len(idOrPrefix) < 4 {
		return "", usageErrf("a job's id prefix must be at least 4 characters")
	}
	lower := strings.ToLower(idOrPrefix)
	if _, ok := led.Jobs[lower]; ok {
		return lower, nil
	}
	var hits []string
	for id := range led.Jobs {
		if strings.HasPrefix(id, lower) {
			hits = append(hits, id)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return "", usageErrf("no job %q in the ledger", idOrPrefix)
	default:
		return "", usageErrf("%q begins %d jobs; give more of the id", idOrPrefix, len(hits))
	}
}

// handleOperate is retry, skip, pause or resume: applied to the ledger under
// the lock when no service runs, queued for the service when one does.
func handleOperate(config, op, target string) error {
	s, cfg, led, err := openHandleRead(config)
	if err != nil {
		return err
	}
	// The target is held to its shape and found before anything is
	// written, so that a request is never queued for nothing.
	if op == opPause || op == opResume {
		if _, ok := cfg.Routes[target]; !ok {
			return usageErrf("no route %q in %s", target, cfg.path)
		}
	} else if target, err = findJob(led, target); err != nil {
		return err
	}
	root := s.HandleDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	lock, err := lockfile.Try(filepath.Join(root, handleLockName))
	if errors.Is(err, lockfile.ErrHeld) {
		name, err := queueRequest(root, op, target)
		if err != nil {
			return err
		}
		_, err = fmt.Printf("%s %s: queued for the running service as %s\n", op, target, name)
		return err
	}
	if err != nil {
		return fmt.Errorf("taking the handle lock: %w", err)
	}
	defer lock.Release()
	// Read again under the lock: the ledger read before it may have moved.
	led, err = loadHandleLedger(filepath.Join(root, handleLedgerFile))
	if err != nil {
		return err
	}
	r := &handleRun{s: s, cfg: cfg, led: led, root: root}
	said, err := r.applyRequest(op, target)
	if err != nil {
		return err
	}
	if err := led.save(); err != nil {
		return err
	}
	_, err = fmt.Println(said)
	return err
}

// queueRequest writes a request for the running service under handle/ops/,
// through a temporary file renamed into place, so that the service reads
// it whole or not at all. Its name orders requests in the order they were
// made.
func queueRequest(root, op, target string) (string, error) {
	ops := filepath.Join(root, "ops")
	if err := os.MkdirAll(ops, 0o700); err != nil {
		return "", err
	}
	data, err := json.Marshal(handleRequest{V: 1, Op: op, Target: target})
	if err != nil {
		return "", err
	}
	name := strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + op + "-" + target + ".json"
	tmp, err := os.CreateTemp(ops, ".request-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	return name, os.Rename(tmp.Name(), filepath.Join(ops, name))
}

// applyRequest changes the ledger as an operator's request says, or refuses
// it in a sentence naming why, and says what it did. It sends nothing: a
// reply it makes owed goes at the next round, which has the keys.
func (r *handleRun) applyRequest(op, target string) (string, error) {
	cfg, led := r.cfg, r.led
	switch op {
	case opPause, opResume:
		route := cfg.Routes[target]
		if route == nil {
			return "", usageErrf("no route %q in %s", target, cfg.path)
		}
		mark := led.Routes[target]
		if mark == nil || mark.Channel != route.Channel {
			return "", usageErrf("route %q has not had its first round on channel %q; run the service once first", target, route.Channel)
		}
		mark.Paused = op == opPause
		if mark.Paused {
			return fmt.Sprintf("route %s paused: it takes its asks and runs none until it is resumed", target), nil
		}
		return fmt.Sprintf("route %s resumed", target), nil
	}
	job := led.Jobs[target]
	if job == nil {
		return "", usageErrf("no job %s in the ledger", target)
	}
	route := cfg.Routes[job.Route]
	switch op {
	case opRetry:
		// A reply that could not be sent, its sends spent: sent again,
		// without the script run again (A4).
		if route != nil && job.awaitsReply() && job.ReplyFailures >= route.Retries {
			job.ReplyFailures, job.ReplyTried = 0, time.Time{}
			return fmt.Sprintf("retry %s: its reply is sent again at the next round, and its script is not run again", target), nil
		}
		if job.State != jobFailed && job.State != jobInterrupted {
			return "", usageErrf("retry %s: it is %s; only a failed or interrupted job is run again", target, job.State)
		}
		// The reply kept for the attempt before is not the next one's: it is
		// removed so that the next is composed afresh, even by a run that
		// stops between the job's end and its composing. One whose envelope
		// may be on the relay already, unrecorded, is sent first, so that
		// the asker is never told twice of one failure.
		paths, err := r.pathsFor(job.Route, target)
		if err != nil {
			return "", err
		}
		posted := postedFile(paths.kept, target)
		if _, err := os.Lstat(posted); err == nil && job.Reply == "" {
			return "", usageErrf("retry %s: its reply may be on the relay already; let the next round send it, then retry", target)
		}
		for _, kept := range []string{replyText(paths.kept), sealedFile(paths.kept, target), posted} {
			if err := os.Remove(kept); err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
		}
		job.State, job.Review, job.RetryAt, job.Failures = jobQueued, false, time.Time{}, 0
		job.OperatorRetry = true
		job.SecondOwed = job.Reply != ""
		job.ReplyFailures, job.ReplyTried = 0, time.Time{}
		return fmt.Sprintf("retry %s: queued to run again, attempt %d next", target, job.Attempt+1), nil
	case opSkip:
		switch job.State {
		case jobSucceeded, jobSkipped, jobRemoved:
			return "", usageErrf("skip %s: it is %s already", target, job.State)
		case jobRunning:
			return "", usageErrf("skip %s: its script is running; skip it once it has ended", target)
		}
		job.State, job.By, job.Review, job.RetryAt = jobSkipped, skippedByOperator, false, time.Time{}
		if job.Reply != "" {
			return fmt.Sprintf("skip %s: skipped; its reply went already, and nothing more is sent", target), nil
		}
		// A reply composed for the failure and not yet sent is composed
		// again as the skip's, unless its envelope may already be on the
		// relay, which only its own send may record.
		paths, err := r.pathsFor(job.Route, target)
		if err != nil {
			return "", err
		}
		if _, err := os.Lstat(postedFile(paths.kept, target)); errors.Is(err, os.ErrNotExist) {
			if err := os.Remove(replyText(paths.kept)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
		}
		job.ReplyFailures, job.ReplyTried = 0, time.Time{}
		return fmt.Sprintf("skip %s: skipped, and its reply goes at the next round", target), nil
	}
	return "", usageErrf("%q is not an operator's request", op)
}

// applyOps applies every request under handle/ops/, in the order they were
// made, at the start of a round, and removes each: a request is said and
// gone whether it was applied or refused, and one that will not read, or
// that is not a request's shape, is moved to ops/damaged/ and said.
func (r *handleRun) applyOps() error {
	ops := filepath.Join(r.root, "ops")
	names := make([]string, 0)
	for name := range requests(ops) {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		path := filepath.Join(ops, name)
		req, why := readRequest(path)
		if why != "" {
			damaged := filepath.Join(ops, "damaged")
			if err := os.MkdirAll(damaged, 0o700); err != nil {
				return err
			}
			if err := os.Rename(path, filepath.Join(damaged, name)); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s: the request %s %s, and is moved to %s\n", prog, identity.PrintableText(name), why, damaged)
			continue
		}
		said, err := r.applyRequest(req.Op, req.Target)
		if err != nil {
			var exit *exitError
			if !errors.As(err, &exit) {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s: the request %s was not applied: %s\n", prog, identity.PrintableText(name), identity.PrintableText(err.Error()))
		} else {
			if err := r.led.save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s: %s\n", prog, said)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// readRequest is one request file held to its shape: read through a handle
// as a regular file, decoded strictly, v 1, an op of the four, and a target
// that is a message id for a job's and a route's name for a route's. The
// reason is why it is not one.
func readRequest(path string) (handleRequest, string) {
	var req handleRequest
	data, err := regular.ReadFile(path)
	if err != nil {
		return req, "could not be read"
	}
	if err := wire.Decode(data, &req); err != nil {
		return req, "will not read as a request"
	}
	switch {
	case req.V != 1:
		return req, "is not version 1"
	case req.Op == opRetry || req.Op == opSkip:
		if message.ValidID(req.Target) != nil {
			return req, "does not name a job by its id"
		}
	case req.Op == opPause || req.Op == opResume:
		if validRouteName(req.Target) != nil {
			return req, "does not name a route"
		}
	default:
		return req, "names no operator's request"
	}
	return req, ""
}

// jobStateOrder is the order status counts states in.
var jobStateOrder = []string{jobQueued, jobPreparing, jobRunning, jobFailed, jobInterrupted, jobSucceeded, jobSkipped, jobRemoved}

// handleRouteStatus is one route as status says it.
type handleRouteStatus struct {
	Route     string         `json:"route"`
	Channel   string         `json:"channel"`
	Execution string         `json:"execution"`
	Paused    bool           `json:"paused"`
	Started   bool           `json:"started"`
	Counts    map[string]int `json:"counts"`
	// OldestQueued is when the first queued job by seq arrived here.
	OldestQueued time.Time       `json:"oldest_queued,omitzero"`
	Running      []handleRunning `json:"running"`
	NextRetry    time.Time       `json:"next_retry,omitzero"`
	// BlockedBy is the sequential route's head in review, and Blocked its
	// reason.
	BlockedBy string `json:"blocked_by,omitempty"`
	Blocked   string `json:"blocked,omitempty"`
	// Unsent counts the replies whose sends are spent.
	Unsent int `json:"unsent_replies"`
}

// handleRunning is an attempt running, as status says it.
type handleRunning struct {
	ID      string    `json:"id"`
	Attempt int       `json:"attempt"`
	Started time.Time `json:"started"`
}

// serviceRunning says a handle run holds the lock in this home. It is
// looked for by taking the lock and giving it back at once, and only where
// a run has made the file.
func serviceRunning(root string) (bool, error) {
	path := filepath.Join(root, handleLockName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	lock, err := lockfile.Try(path)
	if errors.Is(err, lockfile.ErrHeld) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, lock.Release()
}

// handleStatus is 'auu handle status': each route of the file, as the
// ledger has it, and whether a service runs.
func handleStatus(config string, asJSON bool) error {
	s, cfg, led, err := openHandleRead(config)
	if err != nil {
		return err
	}
	running, err := serviceRunning(s.HandleDir())
	if err != nil {
		return err
	}
	var out struct {
		Service bool                `json:"service_running"`
		Routes  []handleRouteStatus `json:"routes"`
	}
	out.Service = running
	for _, name := range cfg.names() {
		route := cfg.Routes[name]
		st := handleRouteStatus{Route: name, Channel: route.Channel, Execution: route.Execution, Counts: map[string]int{}}
		if mark := led.Routes[name]; mark != nil && mark.Channel == route.Channel {
			st.Started, st.Paused = true, mark.Paused
		}
		st.Running = []handleRunning{}
		var head *handleJob
		var headID string
		for _, id := range led.bySeq() {
			job := led.Jobs[id]
			if job.Route != name {
				continue
			}
			st.Counts[job.State]++
			// The oldest queued is the first by seq: admission's order, and
			// no clock's.
			if job.State == jobQueued && st.Counts[jobQueued] == 1 {
				st.OldestQueued = job.Arrived
			}
			if job.State == jobRunning {
				st.Running = append(st.Running, handleRunning{id, job.Attempt, job.Started})
			}
			if (job.State == jobQueued || job.State == jobFailed && !job.Review) && !job.RetryAt.IsZero() &&
				(st.NextRetry.IsZero() || job.RetryAt.Before(st.NextRetry)) {
				st.NextRetry = job.RetryAt
			}
			if job.awaitsReply() && job.ReplyFailures >= route.Retries {
				st.Unsent++
			}
			if head == nil && job.State != jobSucceeded && job.State != jobSkipped && job.State != jobRemoved {
				head, headID = job, id
			}
		}
		if route.Execution == executionSequential && head != nil && head.State == jobFailed && head.Review {
			st.BlockedBy, st.Blocked = headID, head.Reason
		}
		out.Routes = append(out.Routes, st)
	}
	if asJSON {
		return printJSON(out)
	}
	if out.Service {
		fmt.Println("a handle run is running in this home")
	} else {
		fmt.Println("no handle run is running in this home")
	}
	for _, st := range out.Routes {
		fmt.Printf("\n%s: channel %q, %s", st.Route, st.Channel, st.Execution)
		switch {
		case !st.Started:
			fmt.Print(", not yet had its first round")
		case st.Paused:
			fmt.Print(", paused")
		}
		fmt.Println()
		var counts []string
		for _, state := range jobStateOrder {
			if n := st.Counts[state]; n > 0 {
				counts = append(counts, fmt.Sprintf("%d %s", n, state))
			}
		}
		if len(counts) == 0 {
			counts = []string{"no jobs"}
		}
		fmt.Printf("  jobs:     %s\n", strings.Join(counts, ", "))
		if !st.OldestQueued.IsZero() {
			fmt.Printf("  oldest queued: arrived %s\n", st.OldestQueued.Local().Format(time.DateTime))
		}
		for _, run := range st.Running {
			fmt.Printf("  running:  %s, attempt %d, since %s\n", shortID(run.ID), run.Attempt, run.Started.Local().Format(time.DateTime))
		}
		if !st.NextRetry.IsZero() {
			fmt.Printf("  next retry: %s\n", st.NextRetry.Local().Format(time.DateTime))
		}
		if st.BlockedBy != "" {
			fmt.Printf("  blocked:  %s is in review, and holds the route until it is retried or skipped: %s\n",
				shortID(st.BlockedBy), identity.PrintableText(st.Blocked))
		}
		if st.Unsent > 0 {
			fmt.Printf("  %s could not be sent; %s handle retry JOB sends one again\n", plural(st.Unsent, "reply"), prog)
		}
	}
	return nil
}

// handleJobsCmd is 'auu handle jobs': one line per job by seq, those of one
// route or in one state when asked.
func handleJobsCmd(config, route, state string, asJSON bool) error {
	_, cfg, led, err := openHandleRead(config)
	if err != nil {
		return err
	}
	if route != "" {
		if _, ok := cfg.Routes[route]; !ok {
			if _, had := led.Routes[route]; !had {
				return usageErrf("no route %q in %s or the ledger", route, cfg.path)
			}
		}
	}
	if state != "" && !jobStates[state] {
		return usageErrf("--state is one of %s", strings.Join(jobStateOrder, ", "))
	}
	type line struct {
		ID string `json:"id"`
		*handleJob
	}
	out := make([]line, 0)
	for _, id := range led.bySeq() {
		job := led.Jobs[id]
		if (route == "" || job.Route == route) && (state == "" || job.State == state) {
			out = append(out, line{id, job})
		}
	}
	if asJSON {
		return printJSON(out)
	}
	if len(out) == 0 {
		_, err := fmt.Println("no jobs")
		return err
	}
	for _, l := range out {
		what := l.State
		if l.State == jobFailed && l.Review {
			what = "failed, in review"
		}
		reason := ""
		if l.Reason != "" {
			reason = ": " + identity.PrintableText(l.Reason)
		}
		fmt.Printf("%d %s %s %s, attempt %d%s\n", l.Seq, shortID(l.ID), l.Route, what, l.Attempt, reason)
	}
	return nil
}

// handleLog is one attempt's log file and its first line.
type handleLog struct {
	Path  string `json:"path"`
	First string `json:"first_line"`
}

// handleInspect is 'auu handle inspect JOB': the entry whole, the attempt
// directories still there, each attempt's two logs with their first line,
// and the replies.
func handleInspect(config, target string, asJSON bool) error {
	s, _, led, err := openHandleRead(config)
	if err != nil {
		return err
	}
	id, err := findJob(led, target)
	if err != nil {
		return err
	}
	job := led.Jobs[id]
	r := &handleRun{s: s, led: led, root: s.HandleDir()}
	paths, err := r.pathsFor(job.Route, id)
	if err != nil {
		return err
	}
	var out struct {
		ID       string      `json:"id"`
		Job      *handleJob  `json:"job"`
		Attempts []string    `json:"attempts"`
		Logs     []handleLog `json:"logs"`
	}
	out.ID, out.Job, out.Attempts, out.Logs = id, job, []string{}, []handleLog{}
	for n := 1; n <= job.Attempt; n++ {
		dir := filepath.Join(paths.job, "attempt-"+strconv.Itoa(n))
		if info, err := os.Lstat(dir); err == nil && info.IsDir() {
			out.Attempts = append(out.Attempts, dir)
		}
		for _, stream := range []string{"stdout", "stderr"} {
			path := filepath.Join(paths.kept, stream+"-"+strconv.Itoa(n)+".txt")
			if first, ok := logFirstLine(path); ok {
				out.Logs = append(out.Logs, handleLog{Path: path, First: first})
			}
		}
	}
	if asJSON {
		return printJSON(out)
	}
	fmt.Printf("job %s, route %s, seq %d\n", id, job.Route, job.Seq)
	what := job.State
	if job.State == jobFailed && job.Review {
		what = "failed, in review"
	}
	if job.State == jobSkipped {
		what = "skipped by " + job.By
	}
	fmt.Printf("  state:    %s, attempt %d\n", what, job.Attempt)
	fmt.Printf("  revision: %s\n", identity.PrintableText(job.Revision))
	fmt.Printf("  from:     %s, on channel %q, arrived %s\n", job.From[:16], job.Channel, job.Arrived.Local().Format(time.DateTime))
	if job.Reason != "" {
		fmt.Printf("  reason:   %s\n", identity.PrintableText(job.Reason))
	}
	if job.Attempt > 0 {
		fmt.Printf("  last run: exit %d, started %s", job.Exit, job.Started.Local().Format(time.DateTime))
		if !job.Ended.IsZero() {
			fmt.Printf(", ended %s", job.Ended.Local().Format(time.DateTime))
		}
		fmt.Println()
	}
	for _, dir := range out.Attempts {
		fmt.Printf("  attempt:  %s\n", dir)
	}
	for _, l := range out.Logs {
		fmt.Printf("  log:      %s\n            %s\n", l.Path, orNone(identity.PrintableText(l.First)))
	}
	switch {
	case job.Reply == "":
		fmt.Println("  reply:    none sent")
	case job.SecondReply != "":
		fmt.Printf("  reply:    %s, and %s after the operator's retry\n", job.Reply, job.SecondReply)
	default:
		fmt.Printf("  reply:    %s\n", job.Reply)
	}
	return nil
}

// logFirstLine is a log's first line, read no further than maxReason bytes,
// cut on a rune: the log is the script's, and shown escaped.
func logFirstLine(path string) (string, bool) {
	f, err := regular.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	buf := make([]byte, maxReason+1)
	n, _ := io.ReadFull(f, buf)
	return cutReason(string(buf[:n])), true
}
