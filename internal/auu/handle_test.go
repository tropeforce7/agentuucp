package auu

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/store"
)

// auu handle run, from the ask to the end of its job.
//
// Every script in these tests is this test binary, run again as serve's
// handler is, with -test.run=TestServeHelperProcess and its steps in
// AUU_TEST_HANDLER; the command is the program and its arguments, so no
// shell is in between on any platform.

// handlerHost is bob, with a route "import" on his channel "documents"
// run by this binary, and alice to ask him.
type handlerHost struct {
	*user
	path   string
	routes map[string]*handleRoute
	top    string
	// reaps is the file's supervisor_reaps, and workers its workers_total,
	// 0 for the default.
	reaps   bool
	workers int
}

// helperCommand is the command that runs this binary as a script.
func helperCommand(t *testing.T) []string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{exe, "-test.run=TestServeHelperProcess", "handler"}
}

// newHandlerCold is alice, and bob with one route on "documents", whose
// handle has never run.
func newHandlerCold(t *testing.T) (alice *user, bob *handlerHost) {
	t.Helper()
	relayURL := startRelay(t)
	alice = newUser(t, "alice", relayURL)
	b := newUser(t, "bob", relayURL)
	alice.run("peers", "add", b.exportLine())
	b.run("peers", "add", alice.exportLine())
	b.run("channel", "create", "documents")
	b.run("channel", "create", "images")
	t.Setenv(handlerScript, "echo:handled")
	bob = &handlerHost{user: b, path: filepath.Join(b.home, handleFile),
		routes: map[string]*handleRoute{"import": {Channel: "documents", Command: helperCommand(t)}}}
	bob.write(t)
	return alice, bob
}

// newHandler is the same with handle having run once, so that every ask
// after it is the ordinary case.
func newHandler(t *testing.T) (alice *user, bob *handlerHost) {
	t.Helper()
	alice, bob = newHandlerCold(t)
	captureStderr(t, func() { bob.run("handle", "run", "--once") })
	return alice, bob
}

// write puts handle.json in bob's home as it stands.
func (h *handlerHost) write(t *testing.T) {
	t.Helper()
	file := map[string]any{"v": 1, "routes": h.routes}
	if h.reaps {
		file["supervisor_reaps"] = true
	}
	if h.workers > 0 {
		file["workers_total"] = h.workers
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// handleRound runs one round and gives its report, the error the run
// ended with, and what it said on standard error.
func (h *handlerHost) handleRound(t *testing.T, args ...string) (handleRoundJSON, error, string) {
	t.Helper()
	var out string
	var err error
	stderr := captureStderr(t, func() {
		out, err = h.tryRun(append([]string{"handle", "run", "--once", "--json"}, args...)...)
	})
	var report handleRoundJSON
	if strings.TrimSpace(out) != "" {
		if jerr := json.Unmarshal([]byte(out), &report); jerr != nil {
			t.Fatalf("handle run printed %q: %v\nstderr:\n%s", out, jerr, stderr)
		}
	}
	return report, err, stderr
}

// ledger is what handle wrote down.
func (h *handlerHost) ledger(t *testing.T) *handleLedger {
	t.Helper()
	l, err := loadHandleLedger(filepath.Join(h.home, "handle", handleLedgerFile))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// jobDir and keptDir are a job's two directories.
func (h *handlerHost) jobDir(route, id string) string {
	return filepath.Join(h.home, "handle", "jobs", route, id)
}

func (h *handlerHost) keptDir(route, id string) string {
	return filepath.Join(h.home, "handle", "kept", route, id)
}

// inboxRecord is the path of a message's record in bob's inbox.
func (h *handlerHost) inboxRecord(id string) string {
	return filepath.Join(h.home, string(store.Inbox), id+".json")
}

// sendTo sends one message from u to bob on a channel, with files, and
// returns it.
func (u *user) sendTo(t *testing.T, channel, subject, text string, files ...string) sentJSON {
	t.Helper()
	args := []string{"send", "--to", "bob", "--channel", channel, "--subject", subject, "--json"}
	for _, f := range files {
		args = append(args, "--attach", f)
	}
	var sent sentJSON
	if err := json.Unmarshal([]byte(u.run(append(args, text)...)), &sent); err != nil {
		t.Fatal(err)
	}
	return sent
}

// readMessageJSON is an attempt's message.json, read as a script would.
func readMessageJSON(t *testing.T, path string) handleMessage {
	t.Helper()
	var doc handleMessage
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// An ask on a route's channel runs the route's script once, in an empty
// work/ of its attempt's own, with the body on standard input, every
// variable the plan names, and a message.json that says the ask field by
// field, its files by the sender's name and the name each was written
// under, each copy byte for byte what was sent.
func TestAnAskOnARouteRunsTheScriptWithItsInput(t *testing.T) {
	alice, bob := newHandler(t)
	dir := t.TempDir()
	invoice := filepath.Join(dir, "March.pdf")
	notes := filepath.Join(dir, "notes.txt")
	for path, text := range map[string]string{invoice: "%PDF the invoices\n", notes: "two of them\n"} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	environ := filepath.Join(t.TempDir(), "environ")
	// The script fails, so that the job's files stay to be read: a
	// succeeded job's go with its reply.
	t.Setenv(handlerScript, "cat;environ:"+environ+";exit:3")
	// A credential in handle's own environment is never handed on, and an
	// inherited value of one of handle's names is replaced.
	t.Setenv("ANTHROPIC_API_KEY", "sk-not-for-the-script")
	t.Setenv("AUU_TURN", "inherited")
	t.Setenv("AUU_SUBJECT", "inherited")
	sent := alice.sendTo(t, "documents", "the invoices for March", "please import these", invoice, notes)
	sentAsk := sent

	report, _, stderr := bob.handleRound(t)
	if len(report.Jobs) != 1 || report.Jobs[0].ID != sent.ID || report.Jobs[0].State != jobFailed || report.Jobs[0].Attempt != 1 {
		t.Fatalf("the round reported %+v\n%s", report, stderr)
	}
	job := bob.ledger(t).Jobs[sent.ID]
	if job == nil || job.State != jobFailed || job.Exit != 3 || job.Started.IsZero() || job.Ended.IsZero() || job.Seq < 0 {
		t.Fatalf("the ledger has %+v", job)
	}

	kept := bob.keptDir("import", sent.ID)
	if got := readFile(t, filepath.Join(kept, "stdout-1.txt")); got != "please import these" {
		t.Errorf("the script read %q on standard input", got)
	}
	attempt := filepath.Join(bob.jobDir("import", sent.ID), "attempt-1")
	work := filepath.Join(attempt, "work")
	vars := map[string]string{}
	for _, kv := range strings.Split(readFile(t, environ), "\n") {
		if name, value, ok := strings.Cut(kv, "="); ok {
			vars[name] = value
		}
	}
	temps, _ := filepath.Glob(filepath.Join(attempt, "tmp-*"))
	if len(temps) != 1 {
		t.Fatalf("the attempt has %v for its temporary directory", temps)
	}
	temp := temps[0]
	want := map[string]string{
		"AUU_MESSAGE_ID":         sent.ID,
		"AUU_THREAD_ID":          sent.Thread,
		"AUU_IN_REPLY_TO":        "",
		"AUU_TYPE":               "ask",
		"AUU_FROM":               alice.fingerprint(),
		"AUU_FROM_NAME":          "alice",
		"AUU_RECIPIENTS":         "",
		"AUU_CHANNEL":            "documents",
		"AUU_SUBJECT":            "the invoices for March",
		"AUU_ATTACHMENTS":        filepath.Join(attempt, "input", "attachments"),
		"AUU_JOB_ID":             "import/" + sent.ID,
		"AUU_ATTEMPT":            "1",
		"AUU_WORK_DIR":           work,
		"AUU_OUTPUT_DIR":         filepath.Join(temp, "output"),
		"AUU_OUTPUT_ATTACHMENTS": filepath.Join(temp, "output", "attachments"),
		"AUU_TEMP_DIR":           temp,
		"AUU_MESSAGE_JSON":       filepath.Join(attempt, "input", "message.json"),
		"TMPDIR":                 temp,
	}
	for name, value := range want {
		if got, ok := vars[name]; !ok || got != value {
			t.Errorf("%s is %q (set %v), want %q", name, got, ok, value)
		}
	}
	if vars["AUU_RELAY"] == "" {
		t.Error("AUU_RELAY is empty")
	}
	for _, name := range append(append([]string{}, worktreeNames...), credentialVars...) {
		if _, ok := vars[name]; ok {
			t.Errorf("the script was given %s", name)
		}
	}
	if !strings.Contains(stderr, "ANTHROPIC_API_KEY is set in handle's environment and is not passed to the scripts") {
		t.Errorf("handle did not say it holds a credential it does not pass on:\n%s", stderr)
	}
	if pwd := vars["PWD"]; pwd != "" && pwd != work {
		// PWD is the shell's; with no shell it is the parent's, left as it was.
		t.Logf("PWD is %q, the parent's, since no shell set it", pwd)
	}

	doc := readMessageJSON(t, want["AUU_MESSAGE_JSON"])
	if doc.V != 1 || doc.JobID != "import/"+sent.ID || doc.Route != "import" || doc.Attempt != 1 ||
		doc.MessageID != sent.ID || doc.Thread != sent.Thread || doc.InReplyTo != "" || doc.Type != "ask" ||
		doc.From != alice.fingerprint() || doc.FromName != "alice" || doc.To != bob.fingerprint() ||
		len(doc.Recipients) != 0 || doc.Recipients == nil || doc.Channel != "documents" || doc.Relay != vars["AUU_RELAY"] ||
		doc.Subject != "the invoices for March" || doc.Time.IsZero() || !doc.Arrived.Equal(job.Arrived) ||
		doc.Seq != job.Seq || doc.Revision != job.Revision || doc.BodyFile != filepath.Join(attempt, "input", "body.txt") ||
		doc.AttachmentsDir != want["AUU_ATTACHMENTS"] {
		t.Errorf("message.json is %+v", doc)
	}
	if got := readFile(t, doc.BodyFile); got != "please import these" {
		t.Errorf("body.txt holds %q", got)
	}
	if len(doc.Attachments) != 2 {
		t.Fatalf("message.json names %d attachments", len(doc.Attachments))
	}
	for i, path := range []string{invoice, notes} {
		a := doc.Attachments[i]
		sent, _ := os.ReadFile(path)
		sum := sha256.Sum256(sent)
		if a.Name != filepath.Base(path) || a.File != filepath.Base(path) || a.Path != filepath.Join(doc.AttachmentsDir, a.File) ||
			a.Size != int64(len(sent)) || a.SHA256 != hex.EncodeToString(sum[:]) || a.Media == "" {
			t.Errorf("attachment %d is %+v", i, a)
		}
		copied, err := os.ReadFile(a.Path)
		if err != nil || string(copied) != string(sent) {
			t.Errorf("the copy of %s holds %q (%v)", a.Name, copied, err)
		}
		// A copy, not the original under another name: what the script
		// does to it does not reach the next attempt's.
		mine, err1 := os.Stat(a.Path)
		theirs, err2 := os.Stat(filepath.Join(bob.jobDir("import", sentAsk.ID), "original", a.File))
		if err1 != nil || err2 != nil || os.SameFile(mine, theirs) {
			t.Errorf("the attempt's %s is original/'s own file (%v, %v)", a.Name, err1, err2)
		}
	}
	entries, _ := os.ReadDir(work)
	if len(entries) != 0 {
		t.Errorf("work/ holds %v before the script wrote anything in it", entries)
	}
	// The script is told nothing of kept/, and the job's own message.json
	// is attempt 0's.
	for name, value := range vars {
		if strings.HasPrefix(value, filepath.Join(bob.home, "handle", "kept")) {
			t.Errorf("%s names handle's kept directory: %s", name, value)
		}
	}
	if job0 := readMessageJSON(t, filepath.Join(bob.jobDir("import", sent.ID), "message.json")); job0.Attempt != 0 ||
		job0.AttachmentsDir != filepath.Join(bob.jobDir("import", sent.ID), "original") {
		t.Errorf("the job's own message.json is %+v", job0)
	}
}

// The script is a program and its arguments, with no shell between: a
// subject full of a shell's syntax and an argument that names a Windows
// variable reach the script as they are, the subject in the environment
// alone and the argument as the file wrote it, on every platform.
func TestNothingFromTheMessageReachesTheCommandLine(t *testing.T) {
	alice, bob := newHandler(t)
	args := filepath.Join(t.TempDir(), "args")
	environ := filepath.Join(t.TempDir(), "environ")
	bob.routes["import"].Command = append(helperCommand(t)[:2], "%AUU_SUBJECT%", "$AUU_SUBJECT", "handler")
	bob.write(t)
	t.Setenv(handlerScript, "args:"+args+";environ:"+environ+";exit:3")
	subject := "a & b | c ^ d $(touch x) `y` %PATH%"
	sent := alice.sendTo(t, "documents", subject, "the body")
	bob.handleRound(t)
	got := strings.Split(strings.TrimSpace(readFile(t, args)), "\n")
	want := []string{"-test.run=TestServeHelperProcess", "%AUU_SUBJECT%", "$AUU_SUBJECT", "handler"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("the script's arguments are %q, want %q", got, want)
	}
	if !strings.Contains(readFile(t, environ), "AUU_SUBJECT="+subject+"\n") {
		t.Fatal("the subject is not in the script's environment as it was sent")
	}
	work := filepath.Join(bob.jobDir("import", sent.ID), "attempt-1", "work")
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatalf("something ran the subject: work/ holds %v (%v)", entries, err)
	}
}

// Only asks on a route's channel are a route's work: a note, a reply, an
// ask on another channel and a stranger's ask, which is quarantined and
// never in the inbox, are each left alone, and nothing is written for them.
func TestOnlyAsksFromTheRoutesChannelAreAdmitted(t *testing.T) {
	alice, bob := newHandler(t)
	carol := newUser(t, "carol", alice.relayURL())
	carol.run("peers", "add", bob.exportLine())
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv(handlerScript, "append:"+marker)

	note := alice.run("send", "--to", "bob", "--channel", "documents", "--type", "note", "--subject", "fyi", "--json", "a note")
	other := alice.sendTo(t, "images", "a picture", "not for the route")
	stranger := ""
	if out, err := carol.tryRun("send", "--to", "bob", "--channel", "documents", "--subject", "hello", "--json", "a stranger's ask"); err == nil {
		var s sentJSON
		json.Unmarshal([]byte(out), &s)
		stranger = s.ID
	}
	ask := alice.sendTo(t, "documents", "the one", "the one that is")
	// A reply on the route's channel is a reply and nobody's work: bob asks
	// alice something, and she answers on documents.
	var asked sentJSON
	json.Unmarshal([]byte(bob.run("send", "--to", "alice", "--subject", "a question of bob's", "--json", "well?")), &asked)
	alice.run("inbox")
	alice.run("reply", asked.ID, "--channel", "documents", "--json", "an answer on documents")

	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	if len(report.Jobs) != 1 || report.Jobs[0].ID != ask.ID {
		t.Fatalf("the round ran %+v, want the one ask", report.Jobs)
	}
	l := bob.ledger(t)
	if len(l.Jobs) != 1 || l.Jobs[ask.ID] == nil {
		t.Fatalf("the ledger has %d jobs: %v", len(l.Jobs), l.Jobs)
	}
	var noteSent sentJSON
	json.Unmarshal([]byte(note), &noteSent)
	for _, id := range []string{noteSent.ID, other.ID, stranger} {
		if id != "" && l.Jobs[id] != nil {
			t.Errorf("%s was taken", id)
		}
	}
	if got := strings.Count(readFile(t, marker), "\n"); got != 1 {
		t.Fatalf("the script ran %d times", got)
	}
}

// A route's first round leaves the asks already in the inbox, those a
// fetch brings at that round among them, as skipped by the first start,
// and says how many; --backlog runs them instead, and is refused once
// every route has had its first round; a route added later takes its own.
func TestTheFirstRoundSkipsTheInboxAndBacklogRunsIt(t *testing.T) {
	alice, bob := newHandlerCold(t)
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv(handlerScript, "append:"+marker)
	old := alice.sendTo(t, "documents", "old", "sent before handle ever ran")

	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("the first round: %v\n%s", err, stderr)
	}
	if report.Skipped != 1 || len(report.Jobs) != 0 {
		t.Fatalf("the first round reported %+v", report)
	}
	if !strings.Contains(stderr, `route "import": 1 ask already in the inbox, left alone; 'auu handle run --once --backlog' at a route's first round runs them instead`) {
		t.Fatalf("the first round said:\n%s", stderr)
	}
	job := bob.ledger(t).Jobs[old.ID]
	if job == nil || job.State != jobSkipped || job.By != skippedAtFirstStart {
		t.Fatalf("the waiting ask's job is %+v", job)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the script ran on the backlog")
	}
	// Every route has had its first round, so there is no backlog to run.
	if _, err, _ := bob.handleRound(t, "--backlog"); err == nil || !strings.Contains(err.Error(), "every route in "+bob.path+" has had one; there is no backlog to run") {
		t.Fatalf("--backlog after the first round: %v", err)
	}

	// A route added later, on a channel with mail waiting, takes its own
	// baseline, and with --backlog runs it.
	waiting := alice.sendTo(t, "images", "a picture", "waiting for the new route")
	bob.routes["convert"] = &handleRoute{Channel: "images", Command: helperCommand(t)}
	bob.write(t)
	report, err, stderr = bob.handleRound(t, "--backlog")
	if err != nil {
		t.Fatalf("the new route's first round: %v\n%s", err, stderr)
	}
	if len(report.Jobs) != 1 || report.Jobs[0].ID != waiting.ID || report.Jobs[0].State != jobSucceeded {
		t.Fatalf("the new route's backlog ran %+v", report)
	}
	if bob.ledger(t).Jobs[old.ID].State != jobSkipped {
		t.Fatal("--backlog for a new route ran the old route's skipped ask")
	}
}

// A cold home whose first round fetches an ask that was waiting on the
// relay leaves that one too: the fetch comes before the baseline.
func TestTheFirstRoundsFetchIsPartOfItsBaseline(t *testing.T) {
	alice, bob := newHandlerCold(t)
	waiting := alice.sendTo(t, "documents", "waiting", "on the relay, not yet fetched")
	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	if report.Skipped != 1 || bob.ledger(t).Jobs[waiting.ID].State != jobSkipped {
		t.Fatalf("the ask fetched at the first round: %+v", report)
	}
}

// A route moved to another channel is at its first round again there: the
// asks waiting on the new channel are its backlog, said, and an ask after
// that is run (A3).
func TestARouteMovedToAnotherChannelTakesANewBaseline(t *testing.T) {
	alice, bob := newHandler(t)
	waiting := alice.sendTo(t, "images", "a picture", "waiting on images")
	bob.routes["import"].Channel = "images"
	bob.write(t)
	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, `route "import" moved from channel "documents" to "images", and takes a new baseline there`) {
		t.Fatalf("the round said:\n%s", stderr)
	}
	if report.Skipped != 1 || bob.ledger(t).Jobs[waiting.ID].State != jobSkipped {
		t.Fatalf("the waiting ask on the new channel: %+v", report)
	}
	if mark := bob.ledger(t).Routes["import"]; mark.Channel != "images" {
		t.Fatalf("the route's mark is %+v", mark)
	}
	next := alice.sendTo(t, "images", "another", "after the move")
	report, err, _ = bob.handleRound(t)
	if err != nil || len(report.Jobs) != 1 || report.Jobs[0].ID != next.ID || report.Jobs[0].State != jobSucceeded {
		t.Fatalf("the ask after the move: %+v, %v", report, err)
	}
}

// Jobs on a sequential route run in the order they were admitted, which is
// the inbox's order frozen at admission: a record's arrival rewritten
// after its admission does not reorder it.
func TestAdmissionOrderIsFrozenAtSeq(t *testing.T) {
	alice, bob := newHandler(t)
	order := filepath.Join(t.TempDir(), "order")
	// A script that fails holds the route at its head, so the three are
	// admitted in one round and run in the next.
	t.Setenv(handlerScript, "exit:3")
	blocker := alice.sendTo(t, "documents", "first", "fails and holds the route")
	bob.handleRound(t)
	var sent []sentJSON
	for _, s := range []string{"second", "third", "fourth"} {
		sent = append(sent, alice.sendTo(t, "documents", s, s))
	}
	bob.handleRound(t)
	l := bob.ledger(t)
	for i := 1; i < len(sent); i++ {
		if l.Jobs[sent[i].ID].Seq <= l.Jobs[sent[i-1].ID].Seq {
			t.Fatalf("seq %d then %d", l.Jobs[sent[i-1].ID].Seq, l.Jobs[sent[i].ID].Seq)
		}
	}
	// The last one's record is rewritten to have arrived first of all.
	s := storeOf(t, bob.user)
	rec, err := s.Load(store.Inbox, sent[2].ID)
	if err != nil {
		t.Fatal(err)
	}
	rec.Arrived = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	data, _ := json.Marshal(rec)
	if err := os.WriteFile(bob.inboxRecord(sent[2].ID), data, 0o600); err != nil {
		t.Fatal(err)
	}
	// And the ledger's own copy of when it arrived, so that nothing but
	// the admission number says which comes first.
	l.Jobs[sent[2].ID].Arrived = rec.Arrived
	// The blocker is set aside by hand, and the three run.
	l.Jobs[blocker.ID].State = jobSkipped
	l.Jobs[blocker.ID].By = skippedByOperator
	if err := l.save(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(handlerScript, "append:"+order)
	if _, err, stderr := bob.handleRound(t); err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	var ran []string
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, order)), "\n") {
		ran = append(ran, strings.Fields(line)[1])
	}
	want := []string{sent[0].ID, sent[1].ID, sent[2].ID}
	if strings.Join(ran, " ") != strings.Join(want, " ") {
		t.Fatalf("the jobs ran in the order %v, want %v", ran, want)
	}
}

// A sequential route runs one job at a time in its order, and a job that
// fails for review holds the jobs behind it, which wait in the queue; a
// parallel route's failure holds nothing.
func TestAJobRunsInOrderAndAFailureBlocksASequentialRoute(t *testing.T) {
	alice, bob := newHandler(t)
	t.Setenv(handlerScript, "say:no such table;exit:3")
	first := alice.sendTo(t, "documents", "first", "fails")
	second := alice.sendTo(t, "documents", "second", "waits")
	report, err, stderr := bob.handleRound(t)
	if err == nil {
		t.Fatal("a round with a failed job ended well")
	}
	if len(report.Jobs) != 1 || report.Jobs[0].ID != first.ID || report.Jobs[0].State != jobFailed {
		t.Fatalf("the round ran %+v", report.Jobs)
	}
	l := bob.ledger(t)
	if job := l.Jobs[first.ID]; !job.Review || job.Exit != 3 || job.Reason != "exited 3: no such table" {
		t.Fatalf("the failed job is %+v", job)
	}
	if l.Jobs[second.ID].State != jobQueued || l.Jobs[second.ID].Attempt != 0 {
		t.Fatalf("the job behind it is %+v", l.Jobs[second.ID])
	}
	if !strings.Contains(stderr, "no such table") {
		t.Fatalf("the script's standard error was not shown:\n%s", stderr)
	}
	// Another round leaves both as they are.
	if report, _, _ := bob.handleRound(t); len(report.Jobs) != 0 {
		t.Fatalf("the blocked route ran %+v", report.Jobs)
	}

	// On a parallel route the job behind a failure runs.
	bob.routes["import"].Execution = executionParallel
	bob.write(t)
	t.Setenv(handlerScript, "echo:ok")
	report, _, _ = bob.handleRound(t)
	if len(report.Jobs) != 1 || report.Jobs[0].ID != second.ID || report.Jobs[0].State != jobSucceeded {
		t.Fatalf("the parallel route ran %+v", report.Jobs)
	}
}

// A message the owner removes while its job waits is removed, and nothing
// is run for it.
func TestAMessageTheOwnerRemovedWhileQueuedIsRecordedAsRemoved(t *testing.T) {
	alice, bob := newHandler(t)
	t.Setenv(handlerScript, "exit:3")
	alice.sendTo(t, "documents", "first", "holds the route")
	bob.handleRound(t)
	queued := alice.sendTo(t, "documents", "second", "taken back")
	bob.handleRound(t)
	if job := bob.ledger(t).Jobs[queued.ID]; job == nil || job.State != jobQueued {
		t.Fatalf("the second ask's job is %+v", job)
	}
	bob.run("rm", queued.ID)
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
	if len(report.Jobs) != 1 || report.Jobs[0].State != jobRemoved {
		t.Fatalf("the round reported %+v", report.Jobs)
	}
	if job := bob.ledger(t).Jobs[queued.ID]; job.State != jobRemoved || job.Attempt != 0 {
		t.Fatalf("the removed job is %+v", job)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the script ran for a removed message")
	}
}

// A message removed while its script runs is removed: the attempt finishes
// on its own copy, and the ledger says so.
func TestAMessageTheOwnerRemovedWhileRunningIsRecordedAsRemoved(t *testing.T) {
	alice, bob := newHandler(t)
	sent := alice.sendTo(t, "documents", "taken back", "while it runs")
	read := filepath.Join(t.TempDir(), "read")
	t.Setenv(handlerScript, "remove:"+bob.inboxRecord(sent.ID)+";stdin:"+read)
	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	if len(report.Jobs) != 1 || report.Jobs[0].State != jobRemoved {
		t.Fatalf("the round reported %+v", report.Jobs)
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobRemoved || job.Attempt != 1 || job.Ended.IsZero() {
		t.Fatalf("the job is %+v", job)
	}
	if got := readFile(t, read); got != "while it runs" {
		t.Fatalf("the attempt read %q from its own copy", got)
	}
	// A removed job's files go at once, and no reply is sent for it.
	if _, err := os.Stat(bob.jobDir("import", sent.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a removed job's directory is still there (%v)", err)
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.Reply != "" {
		t.Fatalf("a reply went for a removed ask: %s", job.Reply)
	}
}

// The files a message sent that will not unpack are the attempt's failure
// before launch: no script starts and no attempt directory is made; the
// job is queued again at serve's backoff, and failed for review when the
// route's retries are spent.
func TestNoScriptStartsOnAnUnpackThatFails(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Retries = 2
	bob.write(t)
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv(handlerScript, "append:"+marker)
	file := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(file, []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sent := alice.sendTo(t, "documents", "data", "import it", file)
	bob.run("inbox")
	plantBadDigest(t, bob, sent.ID)

	report, err, stderr := bob.handleRound(t)
	if err == nil {
		t.Fatalf("a round whose job could not be prepared ended well\n%s", stderr)
	}
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobQueued || job.Failures != 1 || job.Attempt != 0 || job.RetryAt.IsZero() ||
		!strings.Contains(job.Reason, "could not be unpacked") {
		t.Fatalf("after one failure the job is %+v (%+v)", job, report)
	}
	if _, err := os.Stat(filepath.Join(bob.jobDir("import", sent.ID), "attempt-1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an attempt directory was made")
	}
	if _, err := os.Stat(filepath.Join(bob.jobDir("import", sent.ID), "original.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the failed unpack left original.tmp")
	}
	// Not before the retry is due.
	if report, _, _ := bob.handleRound(t); len(report.Jobs) != 0 {
		t.Fatalf("a job not yet due ran: %+v", report.Jobs)
	}
	moveClock(t, retryBackoff(1))
	bob.handleRound(t)
	job = bob.ledger(t).Jobs[sent.ID]
	if job.State != jobFailed || !job.Review || job.Failures != 2 || job.Attempt != 0 {
		t.Fatalf("after the retries the job is %+v", job)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the script ran")
	}
}

// moveClock puts handle's clock ahead by d for the rest of the test.
func moveClock(t *testing.T, d time.Duration) {
	t.Helper()
	was := handleNow
	handleNow = func() time.Time { return was().Add(d) }
	t.Cleanup(func() { handleNow = was })
}

// plantBadDigest rewrites a received message's first attachment's digest,
// so that its bytes no longer match what the record says they are.
func plantBadDigest(t *testing.T, bob *handlerHost, id string) {
	t.Helper()
	rec, err := storeOf(t, bob.user).Load(store.Inbox, id)
	if err != nil {
		t.Fatal(err)
	}
	rec.Inner.Body.Attachments[0].SHA256 = strings.Repeat("0", 64)
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bob.inboxRecord(id), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// An error reading the job's original/ — its permissions taken away — is
// the attempt's failure before launch, and never taken for a removal.
func TestAnIOErrorReadingTheOriginalIsTheAttemptsFailureNotARemoval(t *testing.T) {
	skipUnlessPermissionsHold(t)
	alice, bob := newHandler(t)
	file := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(file, []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(handlerScript, "exit:3")
	alice.sendTo(t, "documents", "first", "holds the route")
	bob.handleRound(t)
	sent := alice.sendTo(t, "documents", "data", "import it", file)
	// The job is prepared once by hand, as far as its original/.
	bob.handleRound(t)
	original := filepath.Join(bob.jobDir("import", sent.ID), "original")
	if err := os.MkdirAll(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "data.csv"), []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(original, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(original, 0o700) })
	l := bob.ledger(t)
	for id, job := range l.Jobs {
		if id != sent.ID && job.State == jobFailed {
			job.State, job.By = jobSkipped, skippedByOperator
		}
	}
	if err := l.save(); err != nil {
		t.Fatal(err)
	}
	bob.handleRound(t)
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State == jobRemoved || job.State != jobQueued || job.Failures != 1 || !strings.Contains(job.Reason, "could not be listed") {
		t.Fatalf("the job is %+v", job)
	}
}

// A fault of the host's ends the run, with the job left where it was; a
// fault of a message's is that job's, and the run goes on to the next.
func TestAHostFaultEndsTheRunAndAMessageFaultDoesNot(t *testing.T) {
	alice, bob := newHandler(t)
	bob.routes["import"].Execution = executionParallel
	bob.write(t)
	file := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(file, []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := alice.sendTo(t, "documents", "bad", "will not unpack", file)
	good := alice.sendTo(t, "documents", "good", "runs")
	bob.run("inbox")
	plantBadDigest(t, bob, bad.ID)
	report, _, stderr := bob.handleRound(t)
	l := bob.ledger(t)
	if l.Jobs[bad.ID].Failures != 1 || l.Jobs[good.ID].State != jobSucceeded {
		t.Fatalf("the message's fault stopped the round: %+v\n%s", report, stderr)
	}

	// The host's: a job's directory that is not a directory, which handle
	// refuses to follow or write through.
	if runtime.GOOS == "windows" {
		t.Skip("the planted file stands in for a link, which Windows makes only with a privilege")
	}
	third := alice.sendTo(t, "documents", "third", "its directory is planted")
	bob.run("inbox")
	if err := os.MkdirAll(filepath.Dir(bob.jobDir("import", third.ID)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), bob.jobDir("import", third.ID)); err != nil {
		t.Fatal(err)
	}
	_, err, _ := bob.handleRound(t)
	if err == nil || !strings.Contains(err.Error(), "is not a directory of handle's; move it aside") {
		t.Fatalf("a planted directory: %v", err)
	}
	if job := bob.ledger(t).Jobs[third.ID]; job.State != jobPreparing || job.Failures != 0 {
		t.Fatalf("the host's fault was counted against the job: %+v", job)
	}
}

// A stream that waits on the relay for a newer auu is not admitted, not
// skipped by a first round, and said once a run (A2).
func TestAStreamWaitingForANewerAuuIsNotAdmitted(t *testing.T) {
	alice, bob := newHandlerCold(t)
	streamSectionsTo(t, alice, bob.user, "documents", "a newer stream", critical("must-know"))
	report, err, stderr := bob.handleRound(t)
	if err != nil {
		t.Fatalf("handle run: %v\n%s", err, stderr)
	}
	var waiting *store.Stored
	msgs, _ := storeOf(t, bob.user).List(store.Inbox)
	for _, m := range msgs {
		if m.Newer != "" {
			waiting = m
		}
	}
	if waiting == nil {
		t.Fatal("the stream is not in the inbox as waiting for a newer auu")
	}
	if report.Skipped != 0 || bob.ledger(t).Jobs[waiting.Inner.ID] != nil {
		t.Fatalf("a stream waiting for a newer auu was taken: %+v", report)
	}
	if strings.Count(stderr, "waits on the relay for a newer auu") != 1 {
		t.Fatalf("the round said:\n%s", stderr)
	}
}

// A job a run left preparing is prepared afresh at the next round: the
// unpack that stopped part way is removed, and the attempt's input is
// whole (A7).
func TestAJobLeftPreparingIsPreparedAfresh(t *testing.T) {
	alice, bob := newHandler(t)
	file := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(file, []byte("a,b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sent := alice.sendTo(t, "documents", "data", "import it", file)
	given := filepath.Join(t.TempDir(), "given")
	t.Setenv(handlerScript, "snapshot:AUU_ATTACHMENTS="+given)
	// The run stops between the preparing write and the rename of the
	// unpacked directory, with half a file in it.
	stopped := errors.New("stopped")
	beforeOriginalRename = func(tmp string) error {
		os.WriteFile(filepath.Join(tmp, "data.csv"), []byte("half"), 0o600)
		os.WriteFile(filepath.Join(tmp, "stray"), []byte("left by the crash"), 0o600)
		return stopped
	}
	_, err, _ := bob.handleRound(t)
	beforeOriginalRename = nil
	if !errors.Is(err, stopped) {
		t.Fatalf("the planted stop: %v", err)
	}
	if job := bob.ledger(t).Jobs[sent.ID]; job.State != jobPreparing {
		t.Fatalf("after the stop the job is %+v", job)
	}
	if _, err := os.Stat(filepath.Join(bob.jobDir("import", sent.ID), "original.tmp", "stray")); err != nil {
		t.Fatalf("the stop left no partial unpack to clean: %v", err)
	}
	// And an original/ with something in it that is not the asker's, which
	// a stop the ledger cannot place could leave: it goes too.
	stray := filepath.Join(bob.jobDir("import", sent.ID), "original")
	if err := os.Mkdir(stray, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stray, "stray"), []byte("not the asker's"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err, stderr := bob.handleRound(t)
	if err != nil || len(report.Jobs) != 1 || report.Jobs[0].State != jobSucceeded {
		t.Fatalf("the next round: %+v, %v\n%s", report, err, stderr)
	}
	// The script was given the one file, whole: not the half, and not the
	// stray of either directory.
	entries, _ := os.ReadDir(given)
	if len(entries) != 1 || readFile(t, filepath.Join(given, "data.csv")) != "a,b\n" {
		t.Fatalf("the attempt was given %v", entries)
	}
}

// Each attempt has a temporary directory of its own, which TMPDIR names,
// under the attempt and nowhere else.
func TestTheScriptsTemporaryDirectoryIsItsOwn(t *testing.T) {
	alice, bob := newHandler(t)
	environ := filepath.Join(t.TempDir(), "environ")
	bob.routes["import"].Execution = executionParallel
	bob.write(t)
	// The scripts fail, so that their directories stay to be compared.
	t.Setenv(handlerScript, "environ:"+environ+";exit:3")
	sent := alice.sendTo(t, "documents", "one", "one")
	bob.handleRound(t)
	vars := readFile(t, environ)
	attempt := filepath.Join(bob.jobDir("import", sent.ID), "attempt-1")
	temps, _ := filepath.Glob(filepath.Join(attempt, "tmp-*"))
	if len(temps) != 1 || !strings.Contains(vars, "TMPDIR="+temps[0]+"\n") || !strings.Contains(vars, "AUU_TEMP_DIR="+temps[0]+"\n") {
		t.Fatalf("the attempt's temporary directories are %v, and the script was given:\n%s", temps, vars)
	}
	if runtime.GOOS == "windows" && (!strings.Contains(vars, "TMP="+temps[0]+"\n") || !strings.Contains(vars, "TEMP="+temps[0]+"\n")) {
		t.Fatal("TMP and TEMP do not name the attempt's temporary directory")
	}
	second := alice.sendTo(t, "documents", "two", "two")
	bob.handleRound(t)
	others, _ := filepath.Glob(filepath.Join(bob.jobDir("import", second.ID), "attempt-1", "tmp-*"))
	if len(others) != 1 || others[0] == temps[0] {
		t.Fatalf("two attempts' temporary directories: %v and %v", temps, others)
	}
	// A succeeded job's temporary directory goes with the rest of its
	// files once its reply is saved, whatever the script left in it.
	t.Setenv(handlerScript, "environ:"+environ)
	third := alice.sendTo(t, "documents", "three", "three")
	bob.handleRound(t)
	if _, err := os.Stat(bob.jobDir("import", third.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a succeeded job's directory is still there (%v)", err)
	}
	if job := bob.ledger(t).Jobs[third.ID]; job.State != jobSucceeded || job.Reply == "" {
		t.Fatalf("the third job is %+v", job)
	}
}

// A script past its route's timeout is killed with everything it started,
// through the runner serve's handler uses, and the job fails for review,
// saying so. Unix only: the group is a Unix idea, and the shell here is the
// route's own program, named in the file.
func TestAScriptsChildrenAreKilledWithItAtTheTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no process group to kill")
	}
	alice, bob := newHandler(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	bob.routes["import"].Command = []string{"/bin/sh", "-c", "sleep 60 & echo $! > " + pidFile + "; sleep 60"}
	bob.routes["import"].Timeout = "2s"
	bob.write(t)
	sent := alice.sendTo(t, "documents", "slow", "takes too long")

	began := time.Now()
	report, _, _ := bob.handleRound(t)
	if took := time.Since(began); took > 20*time.Second {
		t.Fatalf("the round took %s: the kill did not end the wait", took)
	}
	job := bob.ledger(t).Jobs[sent.ID]
	if job.State != jobFailed || !job.Review || !job.TimedOut || job.Reason != "was killed at the timeout" {
		t.Fatalf("the job is %+v (%+v)", job, report)
	}
	pid := 0
	fmt.Sscanf(strings.TrimSpace(readFile(t, pidFile)), "%d", &pid)
	if pid == 0 {
		t.Fatal("the script never started its child")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := syscallKill(pid); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the script's child (pid %d) outlived the kill", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
