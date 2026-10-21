package auu

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/regular"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A route's limits, and the cleanup of what its jobs leave.
//
// A route takes no more asks than its max_queued and max_queued_bytes,
// counted over the jobs that are queued, preparing or running: the rest
// wait in the inbox, said once a round, and are taken in their order when
// the queue has room. A script's two logs are cut to max_log_bytes after
// its run. A job's directories go when it has nothing more to do with
// them: a succeeded job's once its reply is saved, a removed job's at once,
// and a failed or skipped job's keep_failed after it ended. The sweep
// that removes them runs at the start and after every round, and removes
// only the directories of the jobs the ledger names; anything else under
// handle/jobs/ or handle/kept/ is said by name and left.

// askBytes is an ask's size against max_queued_bytes: the size the relay
// listed it at, or, for a record with none, its text and the sizes its
// files claim, which the message's rule held to zero or more. The sum is
// held at the type's maximum rather than wrapping.
func askBytes(m *store.Stored) int64 {
	if m.RelaySize > 0 {
		return m.RelaySize
	}
	n := int64(len(m.Inner.Body.Text))
	for _, a := range m.Inner.Body.Attachments {
		if a.Size > math.MaxInt64-n {
			return math.MaxInt64
		}
		n += max(a.Size, 0)
	}
	return n
}

// queued is a route's load against its caps: how many of its jobs are
// queued, preparing or running, and their bytes, held at the type's
// maximum. It is the one count admission and status both read.
func (r *handleRun) queued(name string) (int, int64) {
	jobs, bytes := 0, int64(0)
	for _, job := range r.led.Jobs {
		if job.Route != name || !(job.State == jobQueued || job.State == jobPreparing || job.State == jobRunning) {
			continue
		}
		jobs++
		if job.Bytes > math.MaxInt64-bytes {
			bytes = math.MaxInt64
		} else {
			bytes += job.Bytes
		}
	}
	return jobs, bytes
}

// fits says one more ask of size bytes is within a route's caps. Both
// sides of the subtraction are zero or more, so it cannot wrap; a load
// already over a cap lowered since leaves no room.
func (r *handleRun) fits(name string, size int64) bool {
	route := r.cfg.Routes[name]
	jobs, bytes := r.queued(name)
	return jobs < route.MaxQueued && size <= route.MaxQueuedBytes-bytes
}

// atCap says, once a round, that a route's asks wait in the inbox, and
// when the first of them is larger than the route's max_queued_bytes by
// itself, that it waits until the cap is raised, since no room the queue
// makes will take it.
func (r *handleRun) atCap(name string, n int, first *store.Stored) {
	route := r.cfg.Routes[name]
	if size := askBytes(first); size > route.MaxQueuedBytes {
		fmt.Fprintf(os.Stderr, "%s: route %s is at its cap; %s in the inbox, the first, %s, larger than its max_queued_bytes of %d by itself, so it waits until the cap is raised\n",
			prog, name, waitIn(n), shortID(first.Inner.ID), route.MaxQueuedBytes)
		return
	}
	fmt.Fprintf(os.Stderr, "%s: route %s is at its cap; %s in the inbox\n", prog, name, waitIn(n))
}

// waitIn is "1 ask waits" or "N asks wait".
func waitIn(n int) string {
	if n == 1 {
		return "1 ask waits"
	}
	return plural(n, "ask") + " wait"
}

// logCutMark is what ends a log cut at max_log_bytes.
const logCutMark = "\n[handle: the log is cut here at max_log_bytes of %d; the script wrote %d bytes]\n"

// cutLog cuts a log longer than max to max bytes, the end replaced by a
// mark saying so, so that its first line stays, and gives how many bytes
// the script wrote, or 0 when nothing was cut. The log is handle's own,
// opened as a regular file and never through a link.
func cutLog(path string, maxBytes int64) (int64, error) {
	f, err := regular.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := info.Size()
	if size <= maxBytes {
		return 0, nil
	}
	mark := fmt.Sprintf(logCutMark, maxBytes, size)
	// max_log_bytes is at least 4096 at check, far more than the mark.
	keep := maxBytes - int64(len(mark))
	if err := f.Truncate(keep); err != nil {
		return 0, err
	}
	if _, err := f.WriteAt([]byte(mark), keep); err != nil {
		return 0, err
	}
	return size, f.Close()
}

// sweepable says a job's directories have done their work: no reply is
// owed from them, and it succeeded or was removed, or it failed for review
// or was skipped and keep_failed has passed since it ended. A job whose
// route is out of the file keeps its directories, since nothing says how
// long.
func sweepable(job *handleJob, route *handleRoute, now time.Time) bool {
	if job.awaitsReply() {
		return false
	}
	switch {
	case job.State == jobSucceeded, job.State == jobRemoved:
		return true
	case job.State == jobSkipped, job.State == jobFailed && job.Review:
		return route != nil && !job.Ended.IsZero() && !now.Before(job.Ended.Add(route.keepFailed))
	}
	return false
}

// sweep removes the directories of every job sweepable now, by the route
// id and message id the ledger holds, and says once a run each entry under
// handle/jobs/ or handle/kept/ that is no job's. What will not go is said,
// and never ends the run.
func (r *handleRun) sweep() {
	now := handleNow()
	for _, id := range r.led.bySeq() {
		job := r.led.Jobs[id]
		if sweepable(job, r.cfg.Routes[job.Route], now) {
			r.cleanOrSay(id)
		}
	}
	for _, under := range []string{"jobs", "kept"} {
		r.strays(filepath.Join(r.root, under))
	}
}

// strays says each entry under one of handle's two job directories that
// the ledger does not name: a route directory with no job of that route,
// or anything in it that is not a directory named by a job of that route.
// Nothing is removed: a name from a listing alone is never what handle
// removes by.
func (r *handleRun) strays(dir string) {
	routes, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	jobsOf := map[string]map[string]bool{}
	for id, job := range r.led.Jobs {
		if jobsOf[job.Route] == nil {
			jobsOf[job.Route] = map[string]bool{}
		}
		jobsOf[job.Route][id] = true
	}
	for _, route := range routes {
		path := filepath.Join(dir, route.Name())
		if !route.IsDir() || jobsOf[route.Name()] == nil {
			r.stray(path)
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || !jobsOf[route.Name()][e.Name()] {
				r.stray(filepath.Join(path, e.Name()))
			}
		}
	}
}

// cleanOrSay is clean, a directory that will not go, what a script left
// that the account cannot remove, said once a run and tried again at the
// next sweep. It never ends a run: the next start would meet it too.
func (r *handleRun) cleanOrSay(id string) {
	if err := r.clean(id); err != nil {
		job := r.led.Jobs[id]
		r.sayOnce("unswept "+id, "%s: %s's directories could not all be removed, and are tried again at the next sweep: %s",
			job.Route, shortID(id), identity.PrintableText(err.Error()))
	}
}

// removeTree removes a job's directory. A script may leave a directory its
// account cannot write, which RemoveAll does not change, so a removal that
// fails makes every directory under dir, found by a walk that follows no
// link, the owner's to write, and tries again.
func removeTree(dir string) error {
	err := os.RemoveAll(dir)
	if err == nil {
		return nil
	}
	filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr == nil && d.IsDir() {
			os.Chmod(path, 0o700)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

// stray says one entry no job names, once a run.
func (r *handleRun) stray(path string) {
	r.sayOnce("stray "+path, "%s: %s is no job's in the ledger, and is left alone", prog, identity.PrintableText(path))
}
