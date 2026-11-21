package auu

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/store"
)

// withdrawAsk has alice withdraw a message she sent, end to end through the
// relay, and checks that it was replaced there.
func withdrawAsk(t *testing.T, alice *user, id string) {
	t.Helper()
	if out := alice.run("withdraw", id[:12], "--reason", "asked the wrong thing", "--yes"); !strings.Contains(out, "replaced on the relay") {
		t.Fatalf("withdraw said %q", out)
	}
}

// A queued job whose message its sender withdraws ends as removed at the
// round that fetches the note: the script is not run, no reply goes, its
// directories are cleaned, and the note itself is no job.
func TestHandleEndsAWithdrawnQueuedJobAsRemoved(t *testing.T) {
	alice, bob := newHandler(t)
	t.Setenv(handlerScript, "exit:3")
	alice.sendTo(t, "documents", "first", "holds the route")
	bob.handleRound(t)
	queued := alice.sendTo(t, "documents", "second", "withdrawn")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[queued.ID]; job == nil || job.State != jobQueued {
		t.Fatalf("the second ask's job is %+v", job)
	}
	withdrawAsk(t, alice, queued.ID)
	l := bob.ledger(t)
	for id, job := range l.Jobs {
		if id != queued.ID && job.State == jobFailed {
			job.State, job.By = jobSkipped, skippedByOperator
		}
	}
	if err := l.save(); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv(handlerScript, "append:"+marker)
	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	if len(report.Jobs) != 1 || report.Jobs[0].ID != queued.ID || report.Jobs[0].State != jobRemoved ||
		report.Jobs[0].Reason != withdrawnJob {
		t.Fatalf("the round reported %+v", report.Jobs)
	}
	l = bob.ledger(t)
	if job := l.Jobs[queued.ID]; job.State != jobRemoved || job.Reason != "its message was withdrawn by its sender" ||
		job.Attempt != 0 || job.Reply != "" {
		t.Fatalf("the withdrawn job is %+v", job)
	}
	if len(l.Jobs) != 2 {
		t.Fatalf("the ledger holds %d jobs, want the two asks and no job for the note", len(l.Jobs))
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the script ran for a withdrawn message")
	}
	for _, dir := range []string{bob.jobDir("import", queued.ID), bob.keptDir("import", queued.ID)} {
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a withdrawn job's directory %s is still there (%v)", dir, err)
		}
	}
	if r := repliesOn(t, alice, queued.Thread); len(r) != 0 {
		t.Fatalf("a reply went for a withdrawn ask: %+v", r)
	}
}

// A job a crash left preparing whose message is then withdrawn ends as
// removed, and is not prepared again.
func TestHandleEndsAWithdrawnPreparingJobAsRemoved(t *testing.T) {
	alice, bob := newHandler(t)
	t.Setenv(handlerScript, "exit:3")
	alice.sendTo(t, "documents", "first", "holds the route")
	bob.handleRound(t)
	sent := alice.sendTo(t, "documents", "second", "left preparing")
	bob.handleRound(t)
	l := bob.ledger(t)
	for id, job := range l.Jobs {
		if id == sent.ID {
			job.State = jobPreparing
		} else if job.State == jobFailed {
			job.State, job.By = jobSkipped, skippedByOperator
		}
	}
	if err := l.save(); err != nil {
		t.Fatal(err)
	}
	withdrawAsk(t, alice, sent.ID)
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv(handlerScript, "append:"+marker)
	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	if len(report.Jobs) != 1 || report.Jobs[0].State != jobRemoved || report.Jobs[0].Reason != withdrawnJob {
		t.Fatalf("the round reported %+v", report.Jobs)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the script ran for a withdrawn message")
	}
	for _, dir := range []string{bob.jobDir("import", sent.ID), bob.keptDir("import", sent.ID)} {
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a withdrawn job's directory %s is still there (%v)", dir, err)
		}
	}
}

// A job that failed, whose route has since been made one it is not run
// again on, and whose message is then withdrawn, ends as removed with no
// reply, rather than in review with one: the withdrawal is looked at
// before the job's attempts (P13).
func TestHandleEndsAWithdrawnFailedJobAsRemovedBeforeItsAttempts(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Idempotent = true
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";exit:3")
	sent := alice.sendTo(t, "documents", "failed", "then withdrawn")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobFailed || job.Review || job.Attempt != 1 {
		t.Fatalf("after one failure the job is %+v", job)
	}
	bob.routes["import"].Idempotent = false
	bob.write(t)
	withdrawAsk(t, alice, sent.ID)
	moveClock(t, retryBackoff(1))
	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	if len(report.Jobs) != 1 || report.Jobs[0].State != jobRemoved || report.Jobs[0].Reason != withdrawnJob {
		t.Fatalf("the round reported %+v", report.Jobs)
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobRemoved || job.Review || job.Redecided || job.Attempt != 1 {
		t.Fatalf("the job is %+v", job)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times", runs)
	}
	if r := repliesOn(t, alice, sent.Thread); len(r) != 0 {
		t.Fatalf("a reply went for a withdrawn ask: %+v", r)
	}
}

// A job interrupted on a route that is not idempotent, whose message is
// then withdrawn, ends as removed with no reply, rather than in review
// with one (P13).
func TestHandleEndsAWithdrawnInterruptedJobAsRemoved(t *testing.T) {
	alice, bob := newHandler(t)
	started := filepath.Join(t.TempDir(), "started")
	t.Setenv(handlerScript, "append:"+started+";sleep:60s")
	sent := alice.sendTo(t, "documents", "interrupted", "then withdrawn")
	stopWhenStarted(t, bob, started)
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobInterrupted {
		t.Fatalf("after the stop the job is %+v", job)
	}
	withdrawAsk(t, alice, sent.ID)
	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	if len(report.Jobs) != 1 || report.Jobs[0].State != jobRemoved || report.Jobs[0].Reason != withdrawnJob {
		t.Fatalf("the round reported %+v", report.Jobs)
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobRemoved || job.Review || job.Ended.IsZero() {
		t.Fatalf("the job is %+v", job)
	}
	if r := repliesOn(t, alice, sent.Thread); len(r) != 0 {
		t.Fatalf("a reply went for a withdrawn ask: %+v", r)
	}
	for _, dir := range []string{bob.jobDir("import", sent.ID), bob.keptDir("import", sent.ID)} {
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a withdrawn job's directory %s is still there (%v)", dir, err)
		}
	}
}

// A job whose message is withdrawn while its script runs finishes, and its
// reply goes; a job that has ended is left as it ended.
func TestHandleFinishesAJobWithdrawnWhileRunningAndLeavesOneEnded(t *testing.T) {
	alice, bob := newHandler(t)
	running := alice.sendTo(t, "documents", "running", "withdrawn while it runs")
	t.Setenv(handlerScript, "markwithdrawn:"+bob.inboxRecord(running.ID)+";echo:done")
	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	if len(report.Jobs) != 1 || report.Jobs[0].State != jobSucceeded {
		t.Fatalf("the round reported %+v", report.Jobs)
	}
	if r := repliesOn(t, alice, running.Thread); len(r) != 1 {
		t.Fatalf("the replies are %+v, want the one the run made", r)
	}

	t.Setenv(handlerScript, "echo:done")
	ended := alice.sendTo(t, "documents", "ended", "answered, then withdrawn")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[ended.ID]; job.State != jobSucceeded {
		t.Fatalf("the job is %+v", job)
	}
	withdrawAsk(t, alice, ended.ID)
	report, err, stderr = bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	if len(report.Jobs) != 0 {
		t.Fatalf("the round reported %+v for a job that had ended", report.Jobs)
	}
	if job := bob.ledger(t).Jobs[ended.ID]; job.State != jobSucceeded || job.Reason == withdrawnJob {
		t.Fatalf("the ended job is %+v", job)
	}
}

// A pending ask serve has tried, whose sender then withdraws it, is
// settled with no reply, said once on the console and listed under
// skipped in --json, and never handed to the handler again; it is written
// down as given up, so its thread stays its opener's, and another peer
// who names the thread id is left alone, given no worktree and none of
// the opener's directories (R155).
func TestServeSettlesATriedAskThatWasWithdrawnAsGivenUp(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeSideCopy)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";write:secret.txt=alice's private work;exit:3")
	failed := alice.ask(t, "jostle", "failed once", "question")
	if _, err := bob.tryRun("serve", "--once"); err == nil {
		t.Fatal("the first round did not fail")
	}
	threadDir := filepath.Join(bob.home, "serve", "threads", failed.Thread)
	before := tree(t, threadDir)
	withdrawAsk(t, alice, failed.ID)
	out := bob.serve(t)
	want := "jostle: " + shortID(failed.ID) + " from alice was withdrawn by its sender; skipped"
	if strings.Count(out, "withdrawn") != 1 || !strings.Contains(out, want) {
		t.Fatalf("the round said %q; want %q once", out, want)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times", runs)
	}
	if e := bob.ledgerOf(t).Messages[failed.ID]; e == nil || e.Skipped || !e.GaveUp || !e.Handled.IsZero() || e.Failures != 1 {
		t.Fatalf("the entry is %+v; want it given up, not skipped", e)
	}
	nothingFromBob(t, alice, bob)

	t.Setenv(handlerScript, "append:"+marker+";env")
	hijack := carol.askOn(t, "jostle", failed.Thread, "carol's question", "what is in this thread?")
	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Fatalf("the round after reported %+v", report)
	}
	if line := leftAlone(hijack, "carol", alice.fingerprint()); !strings.Contains(stderr, line) {
		t.Fatalf("the round said:\n%s\nwant %q", stderr, line)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times; carol's message was handed to it", runs)
	}
	if after := tree(t, threadDir); !reflect.DeepEqual(after, before) {
		t.Fatalf("alice's thread directory changed: %v, was %v", after, before)
	}
	nothingFromBob(t, carol, bob)
	if e, ok := bob.ledgerOf(t).Messages[hijack.ID]; ok {
		t.Fatalf("carol's message was written into the ledger: %+v", e)
	}
}

// A pending ask serve never tried, whose sender withdraws it, is settled
// as skipped: listed under skipped in --json, never answered and left
// unread. A skipped opening ask opens no thread, so the next ask on its
// thread id, whoever sends it, opens it and is answered on turn one (P14).
func TestServeSkipsAnUntriedAskThatWasWithdrawn(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	// One never tried, fetched by the owner before serve's round, and
	// withdrawn: skipped under --json, and its thread opened afresh by
	// the next ask on it, carol's, which a thread alice opened would leave
	// alone.
	t.Setenv(handlerScript, "append:"+marker+";echo:the expert has spoken")
	opener := alice.ask(t, "jostle", "never tried", "question")
	bob.run("inbox")
	withdrawAsk(t, alice, opener.ID)
	report := bob.round(t)
	if len(report.Skipped) != 1 || report.Skipped[0].ID != opener.ID || report.Skipped[0].Channel != "jostle" ||
		len(report.Answered)+len(report.Failed) != 0 {
		t.Fatalf("the round reported %+v", report)
	}
	if r := repliesOn(t, alice, opener.Thread); len(r) != 0 {
		t.Fatalf("a reply went for a withdrawn ask: %+v", r)
	}
	if again := bob.round(t); len(again.Skipped)+len(again.Failed)+len(again.Answered) != 0 {
		t.Fatalf("the round after reported %+v", again)
	}
	if e := bob.ledgerOf(t).Messages[opener.ID]; e == nil || !e.Skipped || e.GaveUp {
		t.Fatalf("the entry is %+v; want it skipped", e)
	}
	s, _, _ := bob.opened()
	if m, err := s.Load(store.Inbox, opener.ID); err != nil || m.Read || m.Withdrawn.IsZero() {
		t.Fatalf("the skipped ask's record is %+v, %v; want it marked withdrawn and unread", m, err)
	}
	next := carol.askOn(t, "jostle", opener.Thread, "asked again", "the right question")
	report = bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != next.ID {
		t.Fatalf("the round reported %+v", report)
	}
	if got := readFile(t, marker); !strings.HasSuffix(got, "handler "+next.ID+" 1\n") {
		t.Fatalf("the handler's runs are %q; want the next ask on turn one", got)
	}
}

// A mark made while the round answers the messages before it, by another
// process fetching the withdrawal note, is read before the ask is handed
// to the handler: the ask is skipped in that round.
func TestServeReadsAMarkMadeDuringTheRound(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	first := alice.ask(t, "jostle", "first", "question")
	second := alice.ask(t, "jostle", "second", "withdrawn during the round")
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";markwithdrawn:"+filepath.Join(bob.home, string(store.Inbox), second.ID+".json")+";echo:done")
	report := bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != first.ID || len(report.Skipped) != 1 || report.Skipped[0].ID != second.ID {
		t.Fatalf("the round reported %+v", report)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the handler ran %d times", runs)
	}
}

// An ask answered and then withdrawn is left as it was: still answered,
// and its thread's turns are not given back.
func TestServeLeavesAnAnsweredAskThatWasWithdrawn(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	sent := alice.ask(t, "jostle", "answered", "question")
	if out := bob.round(t); len(out.Answered) != 1 {
		t.Fatalf("the first round reported %+v", out)
	}
	before := bob.ledgerOf(t).Messages[sent.ID]
	withdrawAsk(t, alice, sent.ID)
	if out := bob.round(t); len(out.Skipped)+len(out.Failed)+len(out.Answered) != 0 {
		t.Fatalf("the round after reported %+v", out)
	}
	l := bob.ledgerOf(t)
	if e := l.Messages[sent.ID]; e.Skipped || !e.Handled.Equal(before.Handled) || e.Reply != before.Reply {
		t.Fatalf("the entry is %+v, was %+v", e, before)
	}
	if n := l.answered(sent.Thread); n != 1 {
		t.Fatalf("the thread counts %d turns, want 1", n)
	}
}

// The operator's skip of a job whose message was withdrawn removes it, as
// a round would, and sends nothing: a job queued behind a head in review,
// which no round reaches, and the head itself, whose failure's reply went
// already. Its directories go at the next round's sweep.
func TestHandleSkipOfAWithdrawnJobRemovesIt(t *testing.T) {
	alice, bob := newHandler(t)
	head := failInReview(t, alice, bob, "the head", "no such table")
	queued := alice.sendTo(t, "documents", "behind it", "withdrawn while it waits")
	bob.handleRound(t)
	withdrawAsk(t, alice, queued.ID)
	withdrawAsk(t, alice, head.ID)
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[queued.ID]; job.State != jobQueued {
		t.Fatalf("behind the head the withdrawn job is %+v", job)
	}
	for _, id := range []string{queued.ID, head.ID} {
		want := "skip " + id + ": its message was withdrawn by its sender, so it is removed and nothing is sent"
		if out := bob.run("handle", "skip", id); !strings.Contains(out, want) {
			t.Fatalf("skip said %q; want %q", out, want)
		}
		if job := bob.ledger(t).Jobs[id]; job.State != jobRemoved || job.Reason != withdrawnJob || job.By != "" || job.Ended.IsZero() {
			t.Fatalf("the skipped job is %+v", job)
		}
	}
	t.Setenv(handlerScript, "echo:done")
	bob.handleRound(t)
	if r := repliesOn(t, alice, queued.Thread); len(r) != 0 {
		t.Fatalf("a reply went for the withdrawn queued ask: %+v", r)
	}
	if r := repliesOn(t, alice, head.Thread); len(r) != 1 {
		t.Fatalf("the head's replies are %+v; want its failure's alone", r)
	}
	for _, id := range []string{queued.ID, head.ID} {
		for _, dir := range []string{bob.jobDir("import", id), bob.keptDir("import", id)} {
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a removed job's directory %s is still there (%v)", dir, err)
			}
		}
	}
}

// attemptLeft joins no thread id that is not a message id's shape: each of
// the traversal set, with the serve directory's three directories and
// their parent there to be found, is said to have left nothing. A thread
// id of the shape is found by any one of its three, each alone, since a
// handler or the owner may remove the others.
func TestLimitThreadIDIsNotAPathAtWithdrawnSkip(t *testing.T) {
	root := filepath.Join(t.TempDir(), "serve")
	for _, under := range []string{"threads", "kept", "worktrees"} {
		if err := os.MkdirAll(filepath.Join(root, under), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range pathSet() {
		if attemptLeft(root, v) {
			t.Errorf("attemptLeft took the thread id %q", v)
		}
	}
	thread := strings.Repeat("a", 32)
	if attemptLeft(root, thread) {
		t.Fatal("a thread with no directory was said to have one")
	}
	for _, under := range []string{"threads", "kept", "worktrees"} {
		dir := filepath.Join(root, under, thread)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if !attemptLeft(root, thread) {
			t.Fatalf("the thread's %s directory was not found", under)
		}
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}
	}
}

// An attempt cut off before serve wrote it down, by a stop, keys locked
// before the send or a crash, left the thread's directory and no time in
// the ledger: the withdrawn ask is written down as given up and tried
// now, and the thread stays its opener's (R155).
func TestServeSettlesAnAttemptCutOffAsGivenUp(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeSideCopy)
	sent := alice.ask(t, "jostle", "cut off", "question")
	bob.run("inbox")
	// What the attempt left of its own is the side copy's worktree, the
	// thread's directory having been removed by its handler.
	worktree := filepath.Join(bob.home, "serve", "worktrees", sent.Thread)
	if err := os.MkdirAll(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree, "left.txt"), []byte("alice's attempt"), 0o600); err != nil {
		t.Fatal(err)
	}
	withdrawAsk(t, alice, sent.ID)
	if report := bob.round(t); len(report.Skipped) != 1 || report.Skipped[0].ID != sent.ID {
		t.Fatalf("the round reported %+v", report)
	}
	if e := bob.ledgerOf(t).Messages[sent.ID]; e == nil || e.Skipped || !e.GaveUp || e.Tried.IsZero() {
		t.Fatalf("the entry is %+v; want it given up and tried", e)
	}
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";env")
	hijack := carol.askOn(t, "jostle", sent.Thread, "carol's question", "what is in this thread?")
	report, stderr := bob.roundSaid(t)
	if len(report.Answered)+len(report.Failed)+len(report.Skipped) != 0 {
		t.Fatalf("the round after reported %+v", report)
	}
	if line := leftAlone(hijack, "carol", alice.fingerprint()); !strings.Contains(stderr, line) {
		t.Fatalf("the round said:\n%s\nwant %q", stderr, line)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("carol's message was handed to the handler")
	}
	nothingFromBob(t, carol, bob)
}

// A withdrawn ask that loses its turn in the round, to an ask before it on
// its thread answered with the last one, is left as serve leaves any such
// ask: not settled, not reported.
func TestServeLeavesAWithdrawnAskThatLostItsTurn(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.MaxTurns = 1
	bob.write(t)
	first := alice.ask(t, "jostle", "first", "question")
	second := alice.askOn(t, "jostle", first.Thread, "second", "and another")
	bob.run("inbox")
	withdrawAsk(t, alice, second.ID)
	report := bob.round(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != first.ID || len(report.Skipped) != 0 {
		t.Fatalf("the round reported %+v", report)
	}
	if e, ok := bob.ledgerOf(t).Messages[second.ID]; ok {
		t.Fatalf("the ask that lost its turn was written down: %+v", e)
	}
}

// A skip of a withdrawn job whose reply's envelope may be on the relay
// already, its send not having recorded it, is an ordinary skip: that send
// alone may record the reply. One whose reply is recorded is removed, a
// mark that it was posted left behind or not.
func TestHandleSkipOfAWithdrawnJobLeavesAPostedReplyToItsSend(t *testing.T) {
	alice, bob := newHandler(t)
	head := failInReview(t, alice, bob, "the head", "no such table")
	queued := alice.sendTo(t, "documents", "behind it", "its reply recorded")
	bob.handleRound(t)
	l := bob.ledger(t)
	l.Jobs[head.ID].Reply = ""
	l.Jobs[queued.ID].Reply = strings.Repeat("e", 32)
	if err := l.save(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{head.ID, queued.ID} {
		kept := bob.keptDir("import", id)
		if err := os.MkdirAll(kept, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(postedFile(kept, id), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	withdrawAsk(t, alice, head.ID)
	withdrawAsk(t, alice, queued.ID)
	bob.run("inbox")
	if out := bob.run("handle", "skip", queued.ID); !strings.Contains(out, "skip "+queued.ID+": its message was withdrawn by its sender, so it is removed and nothing is sent") {
		t.Fatalf("skip of the job with its reply recorded said %q", out)
	}
	if out := bob.run("handle", "skip", head.ID); !strings.Contains(out, "skip "+head.ID+": skipped, and its reply goes at the next round") {
		t.Fatalf("skip said %q", out)
	}
	if job := bob.ledger(t).Jobs[head.ID]; job.State != jobSkipped || job.By != skippedByOperator {
		t.Fatalf("the skipped job is %+v", job)
	}
}
