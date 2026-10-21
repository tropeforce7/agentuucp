package auu

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// The handle ledger is handle's record of every job it has taken.
//
// As serve's is, it is the only thing that says an ask is work: a message
// on a route's channel with no job here has not been taken, and one with a
// job is wherever the job's state says, however it got there. It is
// written before each step a job takes and after, so that a run that stops
// at any point finds, at its next load, either the step not begun or the
// step done, and a job that was running as an interrupted one.

// handleLedgerFile is the ledger's name under the handle directory.
const handleLedgerFile = "ledger.json"

const handleLedgerV = 1

// A job's states. queued, preparing and running are a job on its way;
// failed without review and interrupted are work the next round takes up;
// succeeded, failed with review, skipped and removed are where a job ends.
const (
	jobQueued      = "queued"
	jobPreparing   = "preparing"
	jobRunning     = "running"
	jobSucceeded   = "succeeded"
	jobFailed      = "failed"
	jobInterrupted = "interrupted"
	jobSkipped     = "skipped"
	jobRemoved     = "removed"
)

// Who skipped a skipped job: the first start, which leaves the mail
// already in the inbox, or the operator.
const (
	skippedAtFirstStart = "first-start"
	skippedByOperator   = "operator"
)

// jobStates is the set a job's state is held to at load.
var jobStates = map[string]bool{
	jobQueued: true, jobPreparing: true, jobRunning: true, jobSucceeded: true,
	jobFailed: true, jobInterrupted: true, jobSkipped: true, jobRemoved: true,
}

// handleLedger is the file.
type handleLedger struct {
	V int `json:"v"`
	// NextSeq is the next admission's number, written with the job it was
	// spent on; it is above every job's Seq.
	NextSeq int64                       `json:"next_seq"`
	Routes  map[string]*handleRouteMark `json:"routes"`
	Jobs    map[string]*handleJob       `json:"jobs"`

	path string
	// existed says the file was there when this run started.
	existed bool
	// interrupted is the jobs the load found running and made interrupted,
	// which the run saves before any round.
	interrupted []string
}

// handleRouteMark is a route's own record: that it has had its first
// round, which is its baseline, the channel it was taken on, since a route
// moved to another channel is at its first round there (A3), and whether
// the operator has paused it.
type handleRouteMark struct {
	FirstRound time.Time `json:"first_round"`
	Channel    string    `json:"channel"`
	Paused     bool      `json:"paused"`
}

// handleJob is one ask's job, keyed in the ledger by the message's id.
type handleJob struct {
	// Route and Revision are the route that took the ask and its revision
	// then. Channel, Thread, From, Arrived and RelayID are the message's,
	// written once at admission, so that a message removed since is still
	// accounted for.
	Route    string    `json:"route"`
	Revision string    `json:"revision"`
	Channel  string    `json:"channel"`
	Thread   string    `json:"thread"`
	From     string    `json:"from"`
	Arrived  time.Time `json:"arrived"`
	RelayID  int64     `json:"relay_id"`
	// Seq is the admission's number, frozen at admission: the order every
	// queue is read in.
	Seq   int64  `json:"seq"`
	State string `json:"state"`
	// Attempt is the number of the attempt the state is about, 0 while
	// the job has not been run. Started is written before the program
	// starts and Ended after it is waited for; Exit, TimedOut and Killed
	// are the last attempt's, Killed saying the service's own stop killed
	// it.
	Attempt  int       `json:"attempt"`
	Started  time.Time `json:"started"`
	Ended    time.Time `json:"ended"`
	Exit     int       `json:"exit"`
	TimedOut bool      `json:"timed_out"`
	Killed   bool      `json:"killed"`
	// Review says no automatic retry follows: the operator's retry or skip
	// is what moves the job.
	Review bool `json:"review"`
	// Failures counts failures before launch, and RetryAt is when the next
	// automatic attempt is due.
	Failures int       `json:"failures"`
	RetryAt  time.Time `json:"retry_at"`
	Reason   string    `json:"reason"`
	// By is who skipped a skipped job: first-start or operator.
	By string `json:"by"`
	// Reply is the acknowledgement's id once sent; ReplyFailures and
	// ReplyTried are its sends that did not get through, and ReplySent is
	// when it went.
	Reply         string    `json:"reply"`
	ReplyFailures int       `json:"reply_failures"`
	ReplyTried    time.Time `json:"reply_tried"`
	ReplySent     time.Time `json:"reply_sent"`
}

// handleLedgerRefusal is the end of every sentence that refuses the file:
// what it is, and what moving it aside costs.
const handleLedgerRefusal = "it is the record of every job handle has taken, so fix it or move it aside knowing " +
	"that the asks in the inbox are then met as at a first start: skipped, or run again with --backlog"

// loadHandleLedger reads the ledger, or gives an empty one that knows it is
// new. A file that is there and will not read is refused rather than
// replaced, as serve's is: a fresh start would take every ask again. A job
// found running is interrupted, since nothing runs it now: the run that
// started it is gone. The caller saves that before any round.
func loadHandleLedger(path string) (*handleLedger, error) {
	l := &handleLedger{V: handleLedgerV, Routes: map[string]*handleRouteMark{}, Jobs: map[string]*handleJob{}, path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	l.existed = true
	refuse := func(format string, a ...any) error {
		return fmt.Errorf("%s %s; %s", path, fmt.Sprintf(format, a...), handleLedgerRefusal)
	}
	// Strictly, as serve's: a misspelt key would read as absent, and a
	// job that ended as one never taken.
	if err := wire.Decode(data, l); err != nil {
		return nil, fmt.Errorf("%s will not read (%v); %s", path, err, handleLedgerRefusal)
	}
	if l.V != handleLedgerV {
		return nil, fmt.Errorf("%s is version %d; this %s writes version %d", path, l.V, prog, handleLedgerV)
	}
	l.path = path
	if l.Routes == nil {
		l.Routes = map[string]*handleRouteMark{}
	}
	if l.Jobs == nil {
		l.Jobs = map[string]*handleJob{}
	}
	if l.NextSeq < 0 {
		return nil, refuse("has next_seq %d, which is not a count", l.NextSeq)
	}
	for name, mark := range l.Routes {
		if mark == nil {
			return nil, refuse("has no entry under route %q", name)
		}
		// A route's name is a directory under jobs/ and kept/, held to the
		// rules handle.json's route ids are.
		if err := validRouteName(name); err != nil {
			return nil, refuse("names a route %q, which is not a route's name: %v", name, err)
		}
		if err := channels.ValidName(mark.Channel); err != nil {
			return nil, refuse("names the channel of route %q as %q, which is not a channel's name: %v", name, mark.Channel, err)
		}
	}
	seqs := map[int64]string{}
	for id, job := range l.Jobs {
		if job == nil {
			return nil, refuse("has no entry under %q", id)
		}
		// A job's id is a message's and its route a route's: each is a
		// directory under jobs/ and kept/.
		if message.ValidID(id) != nil {
			return nil, refuse("has a job under %q, which is not a message id", id)
		}
		if err := validRouteName(job.Route); err != nil {
			return nil, refuse("names the route of %s as %q, which is not a route's name: %v", id, job.Route, err)
		}
		if err := channels.ValidName(job.Channel); err != nil {
			return nil, refuse("names the channel of %s as %q, which is not a channel's name: %v", id, job.Channel, err)
		}
		if message.ValidID(job.Thread) != nil {
			return nil, refuse("names the thread of %s as %q, which is not a message id", id, job.Thread)
		}
		if job.Reply != "" && message.ValidID(job.Reply) != nil {
			return nil, refuse("names the reply to %s as %q, which is not a message id", id, job.Reply)
		}
		if !jobStates[job.State] {
			return nil, refuse("has %s in state %q, which is not a job's state", id, job.State)
		}
		// Only a skipped job was skipped by somebody. The state is one of
		// the set by now, and by one of the two once the first case passes.
		switch {
		case job.By != "" && job.By != skippedAtFirstStart && job.By != skippedByOperator:
			return nil, refuse("says %s was skipped by %q, which is neither %s nor %s", id, job.By, skippedAtFirstStart, skippedByOperator)
		case job.By != "" && job.State != jobSkipped:
			return nil, refuse("says %s, in state %s, was skipped by %s", id, job.State, job.By)
		}
		if !identity.ValidFingerprint(job.From) {
			return nil, refuse("names %q as the sender of %s, which is not a fingerprint", job.From, id)
		}
		if job.RelayID < 0 {
			return nil, refuse("has relay id %d for %s, which is not a relay's counter", job.RelayID, id)
		}
		for _, count := range []struct {
			name string
			n    int64
		}{
			{"seq", job.Seq}, {"attempt", int64(job.Attempt)}, {"failures", int64(job.Failures)},
			{"reply_failures", int64(job.ReplyFailures)},
		} {
			if count.n < 0 {
				return nil, refuse("has %s %d for %s, which is not a count", count.name, count.n, id)
			}
		}
		if other, ok := seqs[job.Seq]; ok {
			first, second := other, id
			if second < first {
				first, second = second, first
			}
			return nil, refuse("has seq %d for both %s and %s; an admission's number is spent once", job.Seq, first, second)
		}
		seqs[job.Seq] = id
		if job.Seq >= l.NextSeq {
			return nil, refuse("has seq %d for %s and next_seq %d, which must be above every seq", job.Seq, id, l.NextSeq)
		}
		// An attempt is written with its start before the program runs, so
		// one counted with no start was never begun here.
		if job.Attempt > 0 && job.Started.IsZero() {
			return nil, refuse("counts attempt %d for %s with no start", job.Attempt, id)
		}
	}
	for id, job := range l.Jobs {
		if job.State == jobRunning {
			job.State = jobInterrupted
			job.Killed = false
			l.interrupted = append(l.interrupted, id)
		}
	}
	return l, nil
}

// validRouteName is the rule a route's name is held to in the ledger, as
// in handle.json: a channel's name, and not shaped like a message id.
func validRouteName(name string) error {
	if err := channels.ValidName(name); err != nil {
		return err
	}
	if threadShaped(name) {
		return errors.New("a name of 32 hex characters is the shape of a message id")
	}
	return nil
}

// save writes the ledger as serve's is written: through a temporary file
// in the same directory, synced, then renamed over the old one.
func (l *handleLedger) save() error {
	if err := saveThrough(l.path, l); err != nil {
		return err
	}
	l.existed = true
	return nil
}
