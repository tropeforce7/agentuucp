package auu

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The operator's commands: status, jobs and inspect, which only look, and
// retry, skip, pause and resume, which move a job or a route, applied to
// the ledger at once with no service running and queued for the service
// when one is.

// failInReview has one ask fail for review on bob's route, which is not
// idempotent, with a first line of the script's own, and returns it.
func failInReview(t *testing.T, alice *user, bob *handlerHost, subject, said string) sentJSON {
	t.Helper()
	t.Setenv(handlerScript, "say:"+said+";exit:3")
	sent := alice.sendTo(t, "documents", subject, "the ask")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job == nil || job.State != jobFailed || !job.Review {
		t.Fatalf("the job is %+v; want it failed for review", job)
	}
	return sent
}

// status says, per route, the counts by state, the head that blocks a
// sequential route by its id with its reason escaped, the replies that
// could not be sent, and whether a service holds the lock.
func TestHandleStatusSaysTheBlockedHead(t *testing.T) {
	alice, bob := newHandler(t)
	head := failInReview(t, alice, bob, "the head", "no such table \x1b[2J")
	alice.sendTo(t, "documents", "behind it", "waits")
	bob.handleRound(t)
	out := bob.run("handle", "status")
	for _, want := range []string{
		"no handle run is running in this home",
		`import: channel "documents", sequential`,
		"jobs:     1 queued, 1 failed",
		"blocked:  " + head.ID[:12] + " is in review, and holds the route until it is retried or skipped: exited 3: no such table \\x1b[2J",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status said\n%s\nwant %q", out, want)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("status printed the reason's escape raw:\n%q", out)
	}
	lock, err := takeHandleLock(filepath.Join(bob.home, "handle"))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Service bool                `json:"service_running"`
		Routes  []handleRouteStatus `json:"routes"`
	}
	if err := json.Unmarshal([]byte(bob.run("handle", "status", "--json")), &st); err != nil {
		t.Fatal(err)
	}
	lock.Release()
	if !st.Service || len(st.Routes) != 1 || st.Routes[0].BlockedBy != head.ID || st.Routes[0].Counts[jobQueued] != 1 {
		t.Fatalf("status --json under a held lock: %+v", st)
	}
}

// jobs is one line per job in admission order, those of one route or one
// state when asked, its flags after the positional as every command takes
// them; a state outside the set is refused by name.
func TestHandleJobsListsBySeq(t *testing.T) {
	alice, bob := newHandler(t)
	first := failInReview(t, alice, bob, "first", "no such table")
	second := alice.sendTo(t, "documents", "second", "waits")
	third := alice.sendTo(t, "documents", "third", "waits")
	bob.handleRound(t)
	lines := strings.Split(strings.TrimSpace(bob.run("handle", "jobs")), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "0 "+first.ID[:12]+" import failed, in review, attempt 1: exited 3") ||
		!strings.HasPrefix(lines[1], "1 "+second.ID[:12]+" import queued") || !strings.HasPrefix(lines[2], "2 "+third.ID[:12]) {
		t.Fatalf("jobs printed\n%s", strings.Join(lines, "\n"))
	}
	if out := strings.TrimSpace(bob.run("handle", "jobs", "--state", "queued")); strings.Count(out, "\n") != 1 || strings.Contains(out, first.ID[:12]) {
		t.Fatalf("jobs --state queued printed\n%s", out)
	}
	if out := strings.TrimSpace(bob.run("handle", "jobs", "--route", "import", "--state", "succeeded")); out != "no jobs" {
		t.Fatalf("jobs of a state no job is in printed %q", out)
	}
	if _, err := bob.tryRun("handle", "jobs", "--state", "done"); err == nil || !strings.Contains(err.Error(), "--state is one of queued, preparing") {
		t.Fatalf("a state outside the set: %v", err)
	}
	if _, err := bob.tryRun("handle", "jobs", "--route", "exports"); err == nil || !strings.Contains(err.Error(), `no route "exports"`) {
		t.Fatalf("a route nobody has: %v", err)
	}
}

// inspect names the job's attempt directory and its two logs with their
// first lines, escaped, and its reply; a prefix of the id finds it, and
// one of fewer than four characters is refused.
func TestHandleInspectNamesTheLogs(t *testing.T) {
	alice, bob := newHandler(t)
	// The helper's steps are split at a semicolon, so the line has none.
	sent := failInReview(t, alice, bob, "inspected", "no such table \x1b[2J\x07")
	out := bob.run("handle", "inspect", sent.ID[:12])
	job := bob.ledger(t).Jobs[sent.ID]
	kept := bob.keptDir("import", sent.ID)
	for _, want := range []string{
		"job " + sent.ID + ", route import, seq 0",
		"state:    failed, in review, attempt 1",
		"revision: " + job.Revision,
		"attempt:  " + filepath.Join(bob.jobDir("import", sent.ID), "attempt-1"),
		"log:      " + filepath.Join(kept, "stderr-1.txt") + "\n            no such table \\x1b[2J\\a",
		"reply:    " + job.Reply,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect said\n%s\nwant %q", out, want)
		}
	}
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("inspect printed the log's escape raw:\n%q", out)
	}
	var doc struct {
		ID   string      `json:"id"`
		Job  *handleJob  `json:"job"`
		Logs []handleLog `json:"logs"`
	}
	if err := json.Unmarshal([]byte(bob.run("handle", "inspect", sent.ID, "--json")), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID != sent.ID || doc.Job.Reply != job.Reply || len(doc.Logs) != 2 {
		t.Fatalf("inspect --json: %+v", doc)
	}
	if _, err := bob.tryRun("handle", "inspect", sent.ID[:3]); err == nil || !strings.Contains(err.Error(), "at least 4 characters") {
		t.Fatalf("a prefix of three: %v", err)
	}
}

// With no service running, retry and skip take the lock and move the job
// in the ledger at once, saying so: a failed job queued to run again, the
// operator's word letting a route that is not idempotent run it once more,
// and a queued one skipped. A retry of a job that has not failed and a
// skip of one already skipped are refused by name.
func TestRetryAndSkipMoveAJobWithNoServiceRunning(t *testing.T) {
	alice, bob := newHandler(t)
	marker := filepath.Join(t.TempDir(), "runs")
	failed := failInReview(t, alice, bob, "retried", "no such table")
	queued := alice.sendTo(t, "documents", "skipped", "behind it")
	bob.handleRound(t)
	if out := bob.run("handle", "retry", failed.ID[:12]); !strings.Contains(out, "retry "+failed.ID+": queued to run again, attempt 2 next") {
		t.Fatalf("retry said %q", out)
	}
	if job := bob.ledger(t).Jobs[failed.ID]; job.State != jobQueued || job.Review || !job.OperatorRetry {
		t.Fatalf("the retried job is %+v", job)
	}
	if out := bob.run("handle", "skip", queued.ID); !strings.Contains(out, "skip "+queued.ID+": skipped, and its reply goes at the next round") {
		t.Fatalf("skip said %q", out)
	}
	if job := bob.ledger(t).Jobs[queued.ID]; job.State != jobSkipped || job.By != skippedByOperator {
		t.Fatalf("the skipped job is %+v", job)
	}
	t.Setenv(handlerScript, "append:"+marker+";echo:done")
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[failed.ID]
	if job.State != jobSucceeded || job.Attempt != 2 || job.OperatorRetry {
		t.Fatalf("the retried job ran to %+v", job)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times; want the retry alone, the skipped job not run", runs)
	}
	if _, err := bob.tryRun("handle", "retry", failed.ID); err == nil || !strings.Contains(err.Error(), "it is succeeded; only a failed or interrupted job is run again") {
		t.Fatalf("a retry of a succeeded job: %v", err)
	}
	if _, err := bob.tryRun("handle", "skip", queued.ID); err == nil || !strings.Contains(err.Error(), "it is skipped already") {
		t.Fatalf("a second skip: %v", err)
	}
	if _, err := bob.tryRun("handle", "retry", strings.Repeat("0", 32)); err == nil || !strings.Contains(err.Error(), "no job") {
		t.Fatalf("a retry of no job: %v", err)
	}
}

// With a service running, retry and skip are written under handle/ops/ and
// said to be queued; the service applies them at its next round, which the
// request's landing brings within a poll, and the files are gone.
func TestRetryAndSkipAreQueuedForARunningService(t *testing.T) {
	alice, bob := newHandler(t)
	failed := failInReview(t, alice, bob, "retried", "no such table")
	was := handleOpsPoll
	handleOpsPoll = 10 * time.Millisecond
	t.Cleanup(func() { handleOpsPoll = was })
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:done")
	ops := filepath.Join(bob.home, "handle", "ops")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var said string
	quickWatch(t, func(poll int) {
		switch {
		case poll == 3 && said == "":
			out, stderr, code := bob.inAnotherProcess("handle", "retry", failed.ID[:12])
			if code != 0 {
				t.Errorf("retry under a service: exit %d\n%s%s", code, out, stderr)
				cancel()
			}
			said = out
			if names := requests(ops); len(names) != 1 {
				t.Errorf("the request under ops/ is %v", names)
			}
		case said != "":
			if data, err := os.ReadFile(marker); err == nil && strings.Count(string(data), "\n") == 1 {
				cancel()
			}
		}
		if poll >= 3000 {
			cancel()
		}
	})
	if err := longHandle(t, bob, ctx); err != nil {
		t.Fatalf("the long run ended %v", err)
	}
	if !strings.Contains(said, "retry "+failed.ID+": queued for the running service as ") {
		t.Fatalf("retry under a service said %q", said)
	}
	if job := bob.ledger(t).Jobs[failed.ID]; job.State != jobSucceeded || job.Attempt != 2 {
		t.Fatalf("the queued retry ran to %+v", job)
	}
	if names := requests(ops); len(names) != 0 {
		t.Fatalf("the applied request is still there: %v", names)
	}
}

// A request a round cannot read as one is moved to ops/damaged/ and said,
// its name escaped; one of the right shape that is refused, a retry of a
// job that has not failed, is said and removed; and the round goes on.
func TestAMalformedRequestIsMovedAsideAndSaid(t *testing.T) {
	alice, bob := newHandler(t)
	t.Setenv(handlerScript, "echo:done")
	done := alice.sendTo(t, "documents", "done", "the ask")
	bob.handleRound(t)
	ops := filepath.Join(bob.home, "handle", "ops")
	if err := os.MkdirAll(ops, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"1-version.json": `{"v":2,"op":"retry","target":"` + done.ID + `"}`,
		"2-op.json":      `{"v":1,"op":"delete","target":"` + done.ID + `"}`,
		"3-target.json":  `{"v":1,"op":"retry","target":"../x"}`,
		"4-route.json":   `{"v":1,"op":"pause","target":"a/b"}`,
		"5-extra.json":   `{"v":1,"op":"skip","target":"` + done.ID + `","force":true}`,
		"6-cut.json":     `{"v":1,"op":"sk`,
	}
	wants := []string{
		"the request 1-version.json is not version 1",
		"the request 2-op.json names no operator's request",
		"the request 3-target.json does not name a job by its id",
		"the request 4-route.json does not name a route",
		"the request 5-extra.json will not read as a request",
		"the request 6-cut.json will not read as a request",
	}
	// Windows will not create a name with an escape in it, so there the
	// escaped name is not tried and the refused request goes under a plain
	// one; the link below is left out too.
	refused, said := "8-retry-"+done.ID+".json", "8-retry-"+done.ID+".json"
	if runtime.GOOS != "windows" {
		bad["7-\x1b[2J-x.json"] = `{}`
		wants = append(wants, `the request 7-\x1b[2J-x.json is not version 1`)
		refused, said = "8-retry-\x1b[2J"+done.ID+".json", "8-retry-\\x1b[2J"+done.ID+".json"
	}
	wants = append(wants, "the request "+said+" was not applied: retry "+done.ID+": it is succeeded")
	if err := os.WriteFile(filepath.Join(ops, refused), []byte(`{"v":1,"op":"retry","target":"`+done.ID+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, data := range bad {
		if err := os.WriteFile(filepath.Join(ops, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		os.WriteFile(target, []byte(`{"v":1,"op":"pause","target":"import"}`), 0o600)
		if err := os.Symlink(target, filepath.Join(ops, "9-link.json")); err != nil {
			t.Fatal(err)
		}
		bad["9-link.json"] = ""
	}
	_, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("the round ended %v\n%s", err, stderr)
	}
	for name := range bad {
		if _, err := os.Lstat(filepath.Join(ops, "damaged", name)); err != nil {
			t.Errorf("%q was not moved aside: %v", name, err)
		}
	}
	for _, want := range wants {
		if !strings.Contains(stderr, want) {
			t.Errorf("the round said\n%s\nwant %q", stderr, want)
		}
	}
	if runtime.GOOS != "windows" && !strings.Contains(stderr, "the request 9-link.json could not be read") {
		t.Errorf("the round said\n%s\nwant the link refused", stderr)
	}
	if strings.Contains(stderr, "\x1b") {
		t.Errorf("a request's name was printed raw:\n%q", stderr)
	}
	if names := requests(ops); len(names) != 0 {
		t.Fatalf("requests are left under ops/: %v", names)
	}
	if bob.ledger(t).Routes["import"].Paused {
		t.Fatal("the request through a link was applied")
	}
}

// A paused route admits its asks and launches none, and status says it is
// paused; resumed, the next round runs them. A route that has had no first
// round has nothing to pause, and says so.
func TestPauseHoldsLaunchesAndResumeReleasesThem(t *testing.T) {
	_, cold := newHandlerCold(t)
	if _, err := cold.tryRun("handle", "pause", "import"); err == nil || !strings.Contains(err.Error(), `route "import" has not had its first round`) {
		t.Fatalf("a pause before the first round: %v", err)
	}
	alice, bob := newHandler(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:done")
	if out := bob.run("handle", "pause", "import"); !strings.Contains(out, "route import paused") {
		t.Fatalf("pause said %q", out)
	}
	sent := alice.sendTo(t, "documents", "held", "the ask")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job == nil || job.State != jobQueued {
		t.Fatalf("the ask on a paused route is %+v; want it admitted and queued", job)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a paused route launched its script")
	}
	if out := bob.run("handle", "status"); !strings.Contains(out, `import: channel "documents", sequential, paused`) {
		t.Fatalf("status said\n%s", out)
	}
	if _, err := bob.tryRun("handle", "pause", "exports"); err == nil || !strings.Contains(err.Error(), `no route "exports"`) {
		t.Fatalf("a pause of a route nobody has: %v", err)
	}
	if out := bob.run("handle", "resume", "import"); !strings.Contains(out, "route import resumed") {
		t.Fatalf("resume said %q", out)
	}
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobSucceeded {
		t.Fatalf("the resumed route's job is %+v", job)
	}
	// A route moved to another channel is at its first round there (A3),
	// and has nothing there to pause until it has had it.
	bob.routes["import"].Channel = "images"
	bob.write(t)
	if _, err := bob.tryRun("handle", "pause", "import"); err == nil ||
		!strings.Contains(err.Error(), `route "import" has not had its first round on channel "images"`) {
		t.Fatalf("a pause of a route moved to another channel: %v", err)
	}
}

// A skip sends the skipped reply at the next round: after a failure whose
// retry was still to come, it says how the last attempt ended; on a job
// never run, that it was not run. A skip of a job whose reply went sends
// nothing more.
func TestASkipAfterAFailureSendsTheSkippedReply(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Execution = executionParallel
	bob.routes["import"].Idempotent = true
	bob.routes["import"].Retries = 3
	bob.write(t)
	t.Setenv(handlerScript, "say:no such table;exit:3")
	retrying := alice.sendTo(t, "documents", "retrying", "the ask")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[retrying.ID]; job.State != jobFailed || job.Review || job.Reply != "" {
		t.Fatalf("the job is %+v; want it waiting on its retry, no reply sent", job)
	}
	bob.run("handle", "pause", "import")
	never := alice.sendTo(t, "documents", "never run", "the ask")
	bob.handleRound(t)
	bob.run("handle", "skip", retrying.ID)
	bob.run("handle", "skip", never.ID)
	bob.handleRound(t)
	for _, c := range []struct {
		sent sentJSON
		want string
	}{
		{retrying, "handle: skipped by the operator (exit 3, attempt 1 of 3)"},
		{never, "handle: skipped by the operator (not run)"},
	} {
		replies := repliesOn(t, alice, c.sent.Thread)
		if len(replies) != 1 || replies[0].Text != c.want {
			t.Fatalf("the replies to %s: %+v; want one, %q", c.sent.ID, replies, c.want)
		}
	}

	// A job in review has had its reply: a skip moves it on and says so.
	bob.run("handle", "resume", "import")
	bob.routes["import"].Idempotent = false
	bob.routes["import"].Execution = executionSequential
	bob.write(t)
	reviewed := failInReview(t, alice, bob, "reviewed", "no such table")
	if out := bob.run("handle", "skip", reviewed.ID); !strings.Contains(out, "its reply went already, and nothing more is sent") {
		t.Fatalf("a skip after the reply said %q", out)
	}
	bob.handleRound(t)
	if replies := repliesOn(t, alice, reviewed.Thread); len(replies) != 1 {
		t.Fatalf("a skip after the reply sent another: %d replies", len(replies))
	}
}

// An operator's retry of a job whose reply went sends nothing more while
// it fails, and exactly one more reply when it then succeeds (D162),
// saying the attempt was the operator's; the asker holds two replies, and
// a later round sends no third.
func TestARetryAfterTheReplyWentSendsOneMoreOnlyOnSuccess(t *testing.T) {
	alice, bob := newHandler(t)
	sent := failInReview(t, alice, bob, "retried", "no such table")
	bob.run("handle", "retry", sent.ID)
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobFailed || job.Attempt != 2 || job.SecondReply != "" {
		t.Fatalf("the retry that failed again is %+v", job)
	}
	if n := len(repliesOn(t, alice, sent.Thread)); n != 1 {
		t.Fatalf("a retry that failed again sent a reply: %d replies", n)
	}
	t.Setenv(handlerScript, "reply:imported after all")
	bob.run("handle", "retry", sent.ID)
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobSucceeded || job.SecondReply == "" || job.SecondReply == job.Reply {
		t.Fatalf("the retry that succeeded is %+v", job)
	}
	replies := repliesOn(t, alice, sent.Thread)
	if len(replies) != 2 {
		t.Fatalf("alice holds %d replies; want the failure's and the success's", len(replies))
	}
	var second messageJSON
	for _, r := range replies {
		if r.ID == job.SecondReply {
			second = r
		}
	}
	if second.Text != "handle: succeeded (exit 0, attempt 3, run again by the operator)\n\nimported after all" || second.InReplyTo != sent.ID {
		t.Fatalf("the second reply is %+v", second)
	}
	bob.handleRound(t)
	if n := len(repliesOn(t, alice, sent.Thread)); n != 2 {
		t.Fatalf("a later round sent a third: %d replies", n)
	}
}

// A reply whose sends are spent is said by status, and the operator's
// retry sends it again without running the script again (A4).
func TestARetryResendsAReplyGivenUpWithoutRunningAgain(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Retries = 1
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:done")
	sent := alice.sendTo(t, "documents", "a question", "the ask")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")
	bob.handleRound(t)
	if out := bob.run("handle", "status"); !strings.Contains(out, "1 reply could not be sent; auu handle retry JOB sends one again") {
		t.Fatalf("status said\n%s", out)
	}
	bob.run("peers", "add", alice.exportLine())
	if out := bob.run("handle", "retry", sent.ID); !strings.Contains(out, "its reply is sent again at the next round, and its script is not run again") {
		t.Fatalf("retry said %q", out)
	}
	bob.handleRound(t)
	if replies := repliesOn(t, alice, sent.Thread); len(replies) != 1 {
		t.Fatalf("alice holds %d replies", len(replies))
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times", runs)
	}
}

// A failure before launch is said to the asker without this machine's
// paths: an error from the filesystem names the file it failed on, and the
// home is said by its name, never where it is (S81). The copy of the
// asker's files for a second attempt is made to fail on a file it may not
// read.
func TestAPrepareFailureNamesNoPathOfTheHosts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a file's mode does not stop its owner reading it on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of any mode")
	}
	freezeClock(t)
	alice, bob := newHandler(t)
	bob.routes["import"].Idempotent = true
	bob.routes["import"].Retries = 2
	bob.write(t)
	t.Setenv(handlerScript, "exit:3")
	file := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(file, []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sent := alice.sendTo(t, "documents", "unreadable", "the ask", file)
	bob.handleRound(t)
	original := filepath.Join(bob.jobDir("import", sent.ID), "original", "data.csv")
	if err := os.Chmod(original, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(original, 0o600) })
	for range 2 {
		moveClock(t, retryBackoff(2))
		bob.handleRound(t)
	}
	replies := repliesOn(t, alice, sent.Thread)
	if len(replies) != 1 || !strings.HasPrefix(replies[0].Text, "handle: failed (could not prepare: the files it sent could not be copied for attempt 2: ") {
		t.Fatalf("alice holds %+v", replies)
	}
	homes := []string{bob.home}
	if real, err := filepath.EvalSymlinks(bob.home); err == nil {
		homes = append(homes, real)
	}
	for _, home := range homes {
		if strings.Contains(replies[0].Text, home) {
			t.Fatalf("the reply names the home's path %s:\n%s", home, replies[0].Text)
		}
	}
	if !strings.Contains(replies[0].Text, filepath.Join("AUU_HOME", "handle", "jobs", "import", sent.ID, "original", "data.csv")) {
		t.Fatalf("the reply %q does not say where in the home it failed", replies[0].Text)
	}
}

// An operator's request names a job or a route and never a path: a
// target that is not a job in the ledger or a route in the file is refused
// before anything is written, with or without a service, and a request
// file whose target is not the shape of one is moved aside under ops/
// with nothing made anywhere else.
func TestLimitAnOperatorsRequestIsNeverAPath(t *testing.T) {
	_, bob := newHandler(t)
	ops := filepath.Join(bob.home, "handle", "ops")
	escapes := []string{"../../../x", "..", "a/b", `a\b`, strings.Repeat("0", 31) + "/"}
	try := func() {
		for _, target := range escapes {
			for _, op := range []string{opRetry, opSkip} {
				if _, err := bob.tryRun("handle", op, target); err == nil ||
					!strings.Contains(err.Error(), "no job") && !strings.Contains(err.Error(), "at least 4 characters") {
					t.Errorf("%s %q: %v", op, target, err)
				}
			}
			for _, op := range []string{opPause, opResume} {
				if _, err := bob.tryRun("handle", op, target); err == nil || !strings.Contains(err.Error(), "no route") {
					t.Errorf("%s %q: %v", op, target, err)
				}
			}
		}
		if names := requests(ops); len(names) != 0 {
			t.Errorf("a refused request was queued: %v", names)
		}
	}
	try()
	lock, err := takeHandleLock(filepath.Join(bob.home, "handle"))
	if err != nil {
		t.Fatal(err)
	}
	try()
	lock.Release()
	if err := os.MkdirAll(ops, 0o700); err != nil {
		t.Fatal(err)
	}
	for i, target := range escapes {
		data := `{"v":1,"op":"retry","target":` + strconvQuote(target) + `}`
		if err := os.WriteFile(filepath.Join(ops, string(rune('a'+i))+".json"), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := listTree(t, bob.home)
	bob.handleRound(t)
	after := listTree(t, bob.home)
	for path := range after {
		if !before[path] && !strings.HasPrefix(path, filepath.Join(ops, "damaged")) {
			t.Errorf("the requests made %s", path)
		}
	}
	for i := range escapes {
		if _, err := os.Lstat(filepath.Join(ops, "damaged", string(rune('a'+i))+".json")); err != nil {
			t.Errorf("request %d was not moved aside: %v", i, err)
		}
	}
}

// strconvQuote is a JSON string for a target.
func strconvQuote(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

// listTree is every path under a directory but the ones a round writes
// whatever it is asked: the ledger, the inbox and the store's own files.
func listTree(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.HasPrefix(filepath.Base(path), ".") {
			out[path] = true
		}
		return nil
	})
	return out
}

// A job in review whose reply was composed and could not be sent yet is
// skipped with its reply composed again as the skip's: the asker is told
// it was skipped, once, and not the failure that came before.
func TestASkipRecomposesAReplyNotYetSent(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Retries = 3
	bob.write(t)
	t.Setenv(handlerScript, "say:no such table;exit:3")
	sent := alice.sendTo(t, "documents", "unsent", "the ask")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobFailed || !job.Review || job.Reply != "" || job.ReplyFailures != 1 {
		t.Fatalf("the job is %+v; want it in review with its reply unsent", job)
	}
	bob.run("peers", "add", alice.exportLine())
	bob.run("handle", "skip", sent.ID)
	bob.handleRound(t)
	replies := repliesOn(t, alice, sent.Thread)
	if len(replies) != 1 || replies[0].Text != "handle: skipped by the operator (exit 3, attempt 1 of 1)" {
		t.Fatalf("alice holds %+v; want the skip's reply alone", replies)
	}
}

// An operator's retry removes the reply kept for the attempt before, so a
// run that stops between the retried job's success and the composing of
// its reply sends the success at the next round, composed afresh, and
// never the failure kept from before (the reader's finding 1).
func TestARetrysReplyIsComposedAfreshAfterAStop(t *testing.T) {
	alice, bob := newHandler(t)
	sent := failInReview(t, alice, bob, "retried", "no such table")
	t.Setenv(handlerScript, "echo:done")
	bob.run("handle", "retry", sent.ID)
	kept := bob.keptDir("import", sent.ID)
	for _, gone := range []string{replyText(kept), sealedFile(kept, sent.ID)} {
		if _, err := os.Lstat(gone); err == nil {
			t.Fatalf("the retry left %s", gone)
		}
	}
	stopped := errors.New("stopped")
	beforeCompose = func() error { return stopped }
	_, err, _ := bob.handleRound(t)
	beforeCompose = nil
	if !errors.Is(err, stopped) {
		t.Fatalf("the planted stop: %v", err)
	}
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	var second messageJSON
	for _, r := range repliesOn(t, alice, sent.Thread) {
		if r.ID == job.SecondReply {
			second = r
		}
	}
	if job.SecondReply == "" || job.SecondReply == job.Reply ||
		!strings.HasPrefix(second.Text, "handle: succeeded (exit 0, attempt 2, run again by the operator)") {
		t.Fatalf("the job is %+v and its second reply %+v", job, second)
	}
}

// A retry of a job whose reply may be on the relay already, its envelope
// posted and its answer lost, is refused until that reply is sent, so the
// asker is never told twice of one failure (the reader's finding 2).
func TestARetryWaitsForAReplyThatMayBeOnTheRelay(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Retries = 3
	bob.write(t)
	t.Setenv(handlerScript, "say:no such table;exit:3")
	sent := alice.sendTo(t, "documents", "posted", "the ask")
	bob.run("inbox")
	bob.run("peers", "rm", "alice")
	bob.handleRound(t)
	kept := bob.keptDir("import", sent.ID)
	if err := os.WriteFile(postedFile(kept, sent.ID), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.tryRun("handle", "retry", sent.ID); err == nil || !strings.Contains(err.Error(), "its reply may be on the relay already") {
		t.Fatalf("a retry with a posted reply: %v", err)
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobFailed || !job.Review {
		t.Fatalf("the refused retry moved the job: %+v", job)
	}
}

// A second reply whose sends are spent is said by status, and the
// operator's retry sends it again without running the script (the
// reader's finding 3).
func TestARetryResendsASecondReplyGivenUp(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Retries = 1
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	sent := failInReview(t, alice, bob, "retried", "no such table")
	bob.run("handle", "retry", sent.ID)
	t.Setenv(handlerScript, "append:"+marker+";echo:done")
	bob.run("peers", "rm", "alice")
	bob.handleRound(t)
	if out := bob.run("handle", "status"); !strings.Contains(out, "1 reply could not be sent") {
		t.Fatalf("status said\n%s", out)
	}
	bob.run("peers", "add", alice.exportLine())
	if out := bob.run("handle", "retry", sent.ID); !strings.Contains(out, "its reply is sent again at the next round") {
		t.Fatalf("retry said %q", out)
	}
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.SecondReply == "" {
		t.Fatalf("the second reply did not go: %+v", job)
	}
	if n := len(repliesOn(t, alice, sent.Thread)); n != 2 {
		t.Fatalf("alice holds %d replies", n)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times", runs)
	}
}
