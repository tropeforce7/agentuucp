package auu

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A parallel route runs up to its max_parallel jobs at once, each in a
// working directory of its own: three scripts that each wait until three
// have started all finish, and the same file name written by each stands
// in its own work/ alone.
func TestAParallelRouteRunsUpToMaxParallelWithPrivateDirectories(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Execution = executionParallel
	bob.routes["import"].MaxParallel = 3
	bob.workers = 3
	bob.write(t)
	barrier := t.TempDir()
	// The scripts fail, so that their directories stay to be looked in.
	t.Setenv(handlerScript, "barrier:"+barrier+"=3;into:AUU_WORK_DIR/same.txt=mine;exit:3")
	var sent []sentJSON
	for i := range 3 {
		sent = append(sent, alice.sendTo(t, "documents", fmt.Sprintf("ask %d", i), "at once"))
	}
	bob.handleRound(t)
	l := bob.ledger(t)
	for _, s := range sent {
		job := l.Jobs[s.ID]
		if job.Exit != 3 {
			t.Fatalf("a job ended %+v: the three did not run at once", job)
		}
		work := filepath.Join(bob.jobDir("import", s.ID), "attempt-1", "work")
		entries, err := os.ReadDir(work)
		if err != nil || len(entries) != 1 || entries[0].Name() != "same.txt" {
			t.Fatalf("%s's work/ holds %v (%v)", s.ID, entries, err)
		}
	}
}

// workers_total bounds every route together: two parallel routes of two
// each, under a total of two, never run more than two scripts at once.
func TestWorkersTotalBoundsEveryRoute(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Execution = executionParallel
	bob.routes["convert"] = &handleRoute{Channel: "images", Command: helperCommand(t), Execution: executionParallel}
	bob.workers = 2
	bob.write(t)
	bob.handleRound(t)
	spans := filepath.Join(t.TempDir(), "spans")
	t.Setenv(handlerScript, "span:"+spans)
	for i := range 2 {
		alice.sendTo(t, "documents", fmt.Sprintf("doc %d", i), "a document")
		alice.sendTo(t, "images", fmt.Sprintf("img %d", i), "an image")
	}
	bob.handleRound(t)
	if most := mostAtOnce(t, spans); most != 2 {
		t.Fatalf("%d scripts ran at once under a workers_total of 2, want 2: no more, and the two at once", most)
	}
}

// mostAtOnce is the most runs a span file shows overlapping.
func mostAtOnce(t *testing.T, path string) int {
	t.Helper()
	type edge struct {
		at    int64
		start bool
	}
	var edges []edge
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, path)), "\n") {
		var kind string
		var at int64
		fmt.Sscanf(line, "%s %d", &kind, &at)
		edges = append(edges, edge{at, kind == "S"})
	}
	for i := 1; i < len(edges); i++ {
		for j := i; j > 0 && edges[j].at < edges[j-1].at; j-- {
			edges[j], edges[j-1] = edges[j-1], edges[j]
		}
	}
	now, most := 0, 0
	for _, e := range edges {
		if e.start {
			now++
		} else {
			now--
		}
		most = max(most, now)
	}
	return most
}

// Routes are offered the workers round-robin in the file's order: with one
// worker and two routes of two waiting jobs each, the jobs run one of each
// route in turn.
func TestRoutesAreServedRoundRobin(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["convert"] = &handleRoute{Channel: "images", Command: helperCommand(t)}
	bob.workers = 1
	bob.write(t)
	bob.handleRound(t)
	order := filepath.Join(t.TempDir(), "order")
	t.Setenv(handlerScript, "append:"+order)
	route := map[string]string{}
	for i := range 2 {
		route[alice.sendTo(t, "documents", fmt.Sprintf("doc %d", i), "a document").ID] = "import"
	}
	for i := range 2 {
		route[alice.sendTo(t, "images", fmt.Sprintf("img %d", i), "an image").ID] = "convert"
	}
	bob.handleRound(t)
	var ran []string
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, order)), "\n") {
		ran = append(ran, route[strings.Fields(line)[1]])
	}
	// convert sorts before import, so it is offered the worker first.
	if strings.Join(ran, " ") != "convert import convert import" {
		t.Fatalf("the routes ran in the order %v", ran)
	}
}

// Two jobs that end in the same instant write one ledger, one after the
// other, each of them whole: both succeeded and replied. Under make race.
func TestTwoCompletionsInOneInstantWriteOneLedger(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Execution = executionParallel
	// Idempotent, so that a job offered to two workers would really run
	// twice rather than be stopped by the rule that a started job on any
	// other route is not run again.
	bob.routes["import"].Idempotent = true
	bob.write(t)
	barrier := t.TempDir()
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";barrier:"+barrier+"=2")
	first := alice.sendTo(t, "documents", "first", "together")
	second := alice.sendTo(t, "documents", "second", "together")
	bob.handleRound(t)
	// Each job ran once: a job a worker has in hand is not offered again.
	runs := readFile(t, marker)
	for _, s := range []sentJSON{first, second} {
		if n := strings.Count(runs, " "+s.ID+" "); n != 1 {
			t.Fatalf("%s ran %d times", s.ID, n)
		}
	}
	l := bob.ledger(t)
	for _, s := range []sentJSON{first, second} {
		if job := l.Jobs[s.ID]; job.State != jobSucceeded || job.Reply == "" {
			t.Fatalf("a job is %+v", job)
		}
	}
	if len(repliesOn(t, alice, first.Thread)) != 1 || len(repliesOn(t, alice, second.Thread)) != 1 {
		t.Fatal("each ask did not get its one reply")
	}
}

// A job whose retry is not yet due holds no worker: with one worker on a
// parallel idempotent route, the first job's failure leaves its retry
// waiting and the second job runs in the same round.
func TestARetryDelayFreesTheWorker(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Execution = executionParallel
	bob.routes["import"].MaxParallel = 1
	bob.routes["import"].Idempotent = true
	bob.workers = 1
	bob.write(t)
	t.Setenv(handlerScript, "failsubject:first")
	first := alice.sendTo(t, "documents", "first", "fails once")
	second := alice.sendTo(t, "documents", "second", "runs meanwhile")
	bob.handleRound(t)
	l := bob.ledger(t)
	if job := l.Jobs[first.ID]; job.State != jobFailed || job.Review || job.RetryAt.IsZero() {
		t.Fatalf("the first job is %+v", job)
	}
	if job := l.Jobs[second.ID]; job.State != jobSucceeded {
		t.Fatalf("the second job did not run while the first waited: %+v", job)
	}
}

// A route's max_parallel bounds it below workers_total: a parallel route of
// two, under a total of three, runs two of its three jobs at once and not
// three.
func TestMaxParallelBoundsItsRouteBelowWorkersTotal(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Execution = executionParallel
	bob.routes["import"].MaxParallel = 2
	bob.workers = 3
	bob.write(t)
	spans := filepath.Join(t.TempDir(), "spans")
	t.Setenv(handlerScript, "span:"+spans)
	for i := range 3 {
		alice.sendTo(t, "documents", fmt.Sprintf("doc %d", i), "a document")
	}
	bob.handleRound(t)
	if most := mostAtOnce(t, spans); most != 2 {
		t.Fatalf("%d of the route's scripts ran at once under its max_parallel of 2", most)
	}
}
