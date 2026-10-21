package auu

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
)

// handleJobID and handleSender are a message id and a fingerprint, the
// shapes a job's key and its from are held to.
var (
	handleJobID  = strings.Repeat("a", 32)
	handleSender = strings.Repeat("b", 64)
)

// handleJobJSON is a job as admission writes it, with the fields given
// after its own; a later key is a second key, which the strict decode
// refuses, so a field given here is one the job does not have.
func handleJobJSON(fields string) string {
	return `{"route":"import","channel":"documents","thread":"` + handleJobID + `","from":"` + handleSender +
		`","seq":0,"state":"queued"` + fields + `}`
}

// writeHandleLedger puts a ledger in a directory of its own and returns its
// path.
func writeHandleLedger(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), handleLedgerFile)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// oneJob is a ledger holding one job under handleJobID, with next_seq 1.
func oneJob(job string) string {
	return `{"v":1,"next_seq":1,"routes":{},"jobs":{"` + handleJobID + `":` + job + `}}`
}

// A ledger that is there and will not read is refused, naming the file and
// what moving it aside costs, and never taken as a fresh start: the file is
// left byte for byte, nothing is written beside it, and no ledger comes
// back for a round to admit asks into. Each rule a job is held to at load
// is refused the same way, by its whole sentence.
func TestAHandleLedgerThatWillNotParseIsAnErrorNotAFreshStart(t *testing.T) {
	refusal := "; " + handleLedgerRefusal
	bad := strings.Repeat("c", 31)
	for _, row := range []struct {
		name, file string
		// want is the sentence after the path; empty for the decode's,
		// whose words are the decoder's.
		want string
	}{
		{"cut short", `{"v":1,"next_seq":1,"jobs":{`, ""},
		{"a misspelt key", `{"v":1,"next_seq":0,"routes":{},"job":{}}`, ""},
		{"a key by case", `{"v":1,"Next_Seq":0,"routes":{},"jobs":{}}`, ""},
		{"a key twice", oneJob(handleJobJSON(`,"state":"running"`)), ""},
		{"trailing data", `{"v":1,"next_seq":0,"routes":{},"jobs":{}}{}`, ""},
		{"a null job", oneJob(`null`), ` has no entry under "` + handleJobID + `"`},
		{"a null route", `{"v":1,"next_seq":0,"routes":{"import":null},"jobs":{}}`, ` has no entry under route "import"`},
		{"a route that is not a name", `{"v":1,"next_seq":0,"routes":{"a/b":{"first_round":"2026-10-21T05:00:00Z","paused":false}},"jobs":{}}`,
			` names a route "a/b", which is not a route's name: ` + channels.ValidName("a/b").Error()},
		{"a job that is not a message id", `{"v":1,"next_seq":1,"routes":{},"jobs":{"` + bad + `":` + handleJobJSON(``) + `}}`,
			` has a job under "` + bad + `", which is not a message id`},
		{"a job's route that is not a name", oneJob(strings.Replace(handleJobJSON(``), `"route":"import"`, `"route":".."`, 1)),
			` names the route of ` + handleJobID + ` as "..", which is not a route's name: ` + channels.ValidName("..").Error()},
		{"a state not in the set", oneJob(strings.Replace(handleJobJSON(``), `"state":"queued"`, `"state":"done"`, 1)),
			` has ` + handleJobID + ` in state "done", which is not a job's state`},
		{"no state", oneJob(strings.Replace(handleJobJSON(``), `,"state":"queued"`, ``, 1)),
			` has ` + handleJobID + ` in state "", which is not a job's state`},
		{"a sender that is not a fingerprint", oneJob(strings.Replace(handleJobJSON(``), handleSender, strings.ToUpper(handleSender), 1)),
			` names "` + strings.ToUpper(handleSender) + `" as the sender of ` + handleJobID + `, which is not a fingerprint`},
		{"no sender", oneJob(strings.Replace(handleJobJSON(``), `"from":"`+handleSender+`",`, ``, 1)),
			` names "" as the sender of ` + handleJobID + `, which is not a fingerprint`},
		{"a route shaped like a message id", `{"v":1,"next_seq":0,"routes":{"` + strings.Repeat("f", 32) + `":{"first_round":"2026-10-21T05:00:00Z","paused":false}},"jobs":{}}`,
			` names a route "` + strings.Repeat("f", 32) + `", which is not a route's name: a name of 32 hex characters is the shape of a message id`},
		{"a job's route shaped like a message id", oneJob(strings.Replace(handleJobJSON(``), `"route":"import"`, `"route":"`+strings.Repeat("F", 32)+`"`, 1)),
			` names the route of ` + handleJobID + ` as "` + strings.Repeat("F", 32) + `", which is not a route's name: a name of 32 hex characters is the shape of a message id`},
		{"a channel that is not a name", oneJob(strings.Replace(handleJobJSON(``), `"channel":"documents"`, `"channel":"x:y"`, 1)),
			` names the channel of ` + handleJobID + ` as "x:y", which is not a channel's name: ` + channels.ValidName("x:y").Error()},
		{"a thread that is not a message id", oneJob(strings.Replace(handleJobJSON(``), `"thread":"`+handleJobID+`"`, `"thread":"../x"`, 1)),
			` names the thread of ` + handleJobID + ` as "../x", which is not a message id`},
		{"a reply that is not a message id", oneJob(handleJobJSON(`,"reply":"` + bad + `"`)),
			` names the reply to ` + handleJobID + ` as "` + bad + `", which is not a message id`},
		{"a skipper outside the set", oneJob(strings.Replace(handleJobJSON(`,"by":"cron"`), `"state":"queued"`, `"state":"skipped"`, 1)),
			` says ` + handleJobID + ` was skipped by "cron", which is neither first-start nor operator`},
		{"a skipper on a job not skipped", oneJob(handleJobJSON(`,"by":"operator"`)),
			` says ` + handleJobID + `, in state queued, was skipped by operator`},
		// The state's rule runs before the skipper's, which prints it.
		{"a skipper on a state not in the set", oneJob(strings.Replace(handleJobJSON(`,"by":"operator"`), `"state":"queued"`, `"state":"\u001b[2J"`, 1)),
			` has ` + handleJobID + ` in state "\x1b[2J", which is not a job's state`},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := writeHandleLedger(t, row.file)
			l, err := loadHandleLedger(path)
			if err == nil || l != nil {
				t.Fatalf("the ledger loaded as %+v, %v", l, err)
			}
			if row.want == "" {
				if !strings.HasPrefix(err.Error(), path+" will not read (") || !strings.HasSuffix(err.Error(), ")"+refusal) {
					t.Fatalf("the refusal is\n%s\nwant %s will not read (...)%s", err, path, refusal)
				}
			} else if err.Error() != path+row.want+refusal {
				t.Fatalf("the refusal is\n%s\nwant\n%s", err, path+row.want+refusal)
			}
			if data, _ := os.ReadFile(path); string(data) != row.file {
				t.Fatalf("the refused file was changed to %q", data)
			}
			if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
				t.Fatalf("a refused load left %v beside the ledger", entries)
			}
		})
	}
	// The same fields as handle writes them are read: a reply's id, and a
	// skipped job's skipper, each of the two.
	// A skipped job with no skipper is read too: by is set by what skips,
	// and its absence is not refused.
	reply := strings.Repeat("9", 32)
	for _, c := range []struct{ job, reply, by string }{
		{handleJobJSON(`,"reply":"` + reply + `"`), reply, ""},
		{strings.Replace(handleJobJSON(`,"by":"first-start"`), `"state":"queued"`, `"state":"skipped"`, 1), "", skippedAtFirstStart},
		{strings.Replace(handleJobJSON(`,"by":"operator"`), `"state":"queued"`, `"state":"skipped"`, 1), "", skippedByOperator},
		{strings.Replace(handleJobJSON(``), `"state":"queued"`, `"state":"skipped"`, 1), "", ""},
	} {
		l, err := loadHandleLedger(writeHandleLedger(t, oneJob(c.job)))
		if err != nil {
			t.Errorf("%s: %v; want it read", c.job, err)
			continue
		}
		if job := l.Jobs[handleJobID]; job.Reply != c.reply || job.By != c.by {
			t.Errorf("%s: read reply %q and by %q", c.job, job.Reply, job.By)
		}
	}
	// No file is a fresh ledger, and knows it is new.
	l, err := loadHandleLedger(filepath.Join(t.TempDir(), handleLedgerFile))
	if err != nil || l.existed || len(l.Jobs) != 0 || len(l.Routes) != 0 || l.NextSeq != 0 {
		t.Fatalf("no file: %+v, %v; want an empty ledger that did not exist", l, err)
	}
}

// TestLimitHandleLedgerIntegers: the ledger's v is 1; next_seq, and each
// job's seq, attempt, failures, reply_failures and relay_id, are zero or
// more; a seq is spent once and is below next_seq; an attempt counted has a
// start. A negative and the type's minimum are refused naming the field and
// the job, as is a seq repeated, a seq at next_seq, and an attempt with no
// start, and the text one past the type's maximum by the decode; zero, one
// and the type's maximum are read. exit is a process's, any int, and is
// read at both extremes.
func TestLimitHandleLedgerIntegers(t *testing.T) {
	refusal := "; " + handleLedgerRefusal
	started := `,"started":"2026-10-21T05:02:00Z"`
	minInt, maxInt := strconv.Itoa(math.MinInt), strconv.Itoa(math.MaxInt)
	minInt64, maxInt64 := strconv.FormatInt(math.MinInt64, 10), strconv.FormatInt(math.MaxInt64, 10)
	refused := func(t *testing.T, file, want string) {
		t.Helper()
		path := writeHandleLedger(t, file)
		_, err := loadHandleLedger(path)
		if err == nil || err.Error() != path+want+refusal {
			t.Errorf("%s:\n%v\nwant\n%s", file, err, path+want+refusal)
		}
	}
	// The text one past the type's maximum is the decode's to refuse.
	decodeRefused := func(t *testing.T, file string) {
		t.Helper()
		path := writeHandleLedger(t, file)
		_, err := loadHandleLedger(path)
		if err == nil || !strings.HasPrefix(err.Error(), path+" will not read (") || !strings.HasSuffix(err.Error(), refusal) {
			t.Errorf("%s:\n%v\nwant the decode's refusal", file, err)
		}
	}
	read := func(t *testing.T, file string) *handleLedger {
		t.Helper()
		l, err := loadHandleLedger(writeHandleLedger(t, file))
		if err != nil {
			t.Errorf("%s: %v; want it read", file, err)
			return nil
		}
		return l
	}

	for _, v := range []int{0, 2, -1, math.MinInt, math.MaxInt} {
		path := writeHandleLedger(t, `{"v":`+strconv.Itoa(v)+`,"next_seq":0,"routes":{},"jobs":{}}`)
		_, err := loadHandleLedger(path)
		if err == nil || err.Error() != path+" is version "+strconv.Itoa(v)+"; this auu writes version 1" {
			t.Errorf("v %d: %v; want the refusal naming both versions", v, err)
		}
	}

	for _, n := range []string{"-1", minInt64} {
		refused(t, `{"v":1,"next_seq":`+n+`,"routes":{},"jobs":{}}`, " has next_seq "+n+", which is not a count")
	}
	for _, n := range []string{"0", "1", maxInt64} {
		read(t, `{"v":1,"next_seq":`+n+`,"routes":{},"jobs":{}}`)
	}

	job := func(fields string) string { return oneJob(strings.Replace(handleJobJSON(fields), `,"seq":0`, ``, 1)) }
	for _, c := range []struct{ field, values string }{
		{"attempt", "-1 " + minInt},
		{"failures", "-1 " + minInt},
		{"reply_failures", "-1 " + minInt},
	} {
		for _, n := range strings.Fields(c.values) {
			refused(t, job(`,"seq":0,"`+c.field+`":`+n), " has "+c.field+" "+n+" for "+handleJobID+", which is not a count")
		}
		for _, n := range []string{"0", "1", maxInt} {
			if l := read(t, job(`,"seq":0,"`+c.field+`":`+n+started)); l != nil {
				job := l.Jobs[handleJobID]
				got := map[string]int{"attempt": job.Attempt, "failures": job.Failures, "reply_failures": job.ReplyFailures}[c.field]
				if strconv.Itoa(got) != n {
					t.Errorf("%s %s read as %d", c.field, n, got)
				}
			}
		}
		decodeRefused(t, job(`,"seq":0,"`+c.field+`":9223372036854775808`))
	}
	for _, field := range []string{"next_seq", "seq", "relay_id", "exit"} {
		file := job(`,"seq":0`)
		if field == "next_seq" {
			file = strings.Replace(file, `"next_seq":1`, `"next_seq":9223372036854775808`, 1)
		} else if field == "seq" {
			file = job(`,"seq":9223372036854775808`)
		} else {
			file = job(`,"seq":0,"` + field + `":9223372036854775808`)
		}
		decodeRefused(t, file)
	}
	for _, n := range []string{"-1", minInt64} {
		refused(t, job(`,"seq":`+n), " has seq "+n+" for "+handleJobID+", which is not a count")
	}
	// seq is below next_seq: at it, and the type's maximum, which no
	// next_seq can be above, are refused; one below is read.
	refused(t, job(`,"seq":1`), " has seq 1 for "+handleJobID+" and next_seq 1, which must be above every seq")
	refused(t, strings.Replace(job(`,"seq":`+maxInt64), `"next_seq":1`, `"next_seq":`+maxInt64, 1),
		" has seq "+maxInt64+" for "+handleJobID+" and next_seq "+maxInt64+", which must be above every seq")
	if l := read(t, strings.Replace(job(`,"seq":`+strconv.FormatInt(math.MaxInt64-1, 10)), `"next_seq":1`, `"next_seq":`+maxInt64, 1)); l != nil &&
		l.Jobs[handleJobID].Seq != math.MaxInt64-1 {
		t.Errorf("seq one below the type's maximum read as %d", l.Jobs[handleJobID].Seq)
	}
	// A seq spent twice.
	other := strings.Repeat("d", 32)
	twice := `{"v":1,"next_seq":5,"routes":{},"jobs":{"` + other + `":` + handleJobJSON(``) + `,"` + handleJobID + `":` + handleJobJSON(``) + `}}`
	refused(t, strings.ReplaceAll(twice, `"seq":0`, `"seq":3`), " has seq 3 for both "+handleJobID+" and "+other+"; an admission's number is spent once")

	// An attempt counted with no start was never begun here.
	refused(t, job(`,"seq":0,"attempt":1`), " counts attempt 1 for "+handleJobID+" with no start")
	refused(t, job(`,"seq":0,"attempt":1,"started":"0001-01-01T00:00:00Z"`), " counts attempt 1 for "+handleJobID+" with no start")

	for _, n := range []string{"-1", minInt64} {
		refused(t, job(`,"seq":0,"relay_id":`+n), " has relay id "+n+" for "+handleJobID+", which is not a relay's counter")
	}
	for _, n := range []string{"0", "1", maxInt64} {
		if l := read(t, job(`,"seq":0,"relay_id":`+n)); l != nil && strconv.FormatInt(l.Jobs[handleJobID].RelayID, 10) != n {
			t.Errorf("relay_id %s read as %d", n, l.Jobs[handleJobID].RelayID)
		}
	}
	for _, n := range []string{minInt, "-1", "0", "3", maxInt} {
		if l := read(t, job(`,"seq":0,"exit":`+n)); l != nil && strconv.Itoa(l.Jobs[handleJobID].Exit) != n {
			t.Errorf("exit %s read as %d", n, l.Jobs[handleJobID].Exit)
		}
	}
}

// A job a run left running is interrupted at the next load, before any
// round, since the run that started it is gone and nothing runs it now: its
// killed is false, since this run did not kill it, and every other field
// and every other job is as the file had it. The load writes nothing; a
// save then makes it so on disk.
func TestARunningJobIsInterruptedAtTheNextLoad(t *testing.T) {
	queued := strings.Repeat("e", 32)
	file := `{"v":1,"next_seq":2,"routes":{"import":{"first_round":"2026-10-21T05:00:00Z","paused":false}},"jobs":{` +
		`"` + handleJobID + `":` + strings.Replace(handleJobJSON(`,"attempt":2,"started":"2026-10-21T05:02:00Z","killed":true,"exit":3`), `"state":"queued"`, `"state":"running"`, 1) + `,` +
		`"` + queued + `":` + strings.Replace(handleJobJSON(``), `"seq":0`, `"seq":1`, 1) + `}}`
	path := writeHandleLedger(t, file)
	l, err := loadHandleLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	job := l.Jobs[handleJobID]
	if job.State != jobInterrupted || job.Killed {
		t.Fatalf("the running job loaded as %s, killed %v; want interrupted, not killed", job.State, job.Killed)
	}
	if job.Attempt != 2 || job.Exit != 3 || !job.Started.Equal(time.Date(2026, 10, 21, 5, 2, 0, 0, time.UTC)) || job.Seq != 0 {
		t.Fatalf("the interrupted job's other fields changed: %+v", job)
	}
	if l.Jobs[queued].State != jobQueued {
		t.Fatalf("the queued job loaded as %s", l.Jobs[queued].State)
	}
	if data, _ := os.ReadFile(path); string(data) != file {
		t.Fatal("the load wrote the file")
	}
	if err := l.save(); err != nil {
		t.Fatal(err)
	}
	again, err := loadHandleLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Jobs[handleJobID].State != jobInterrupted || again.Jobs[queued].State != jobQueued {
		t.Fatalf("after the save: %s and %s", again.Jobs[handleJobID].State, again.Jobs[queued].State)
	}
}

// save writes the ledger through a temporary file in the same directory,
// synced and renamed, so the file on disk is always one whole ledger: what
// it wrote reads back as it was, private to its owner, with nothing left
// beside it; and a save that cannot write leaves the last ledger as it was.
func TestTheLedgerIsSavedThroughATemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, handleLedgerFile)
	l, err := loadHandleLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.NextSeq = 1
	l.Routes["import"] = &handleRouteMark{FirstRound: time.Date(2026, 10, 21, 5, 0, 0, 0, time.UTC)}
	l.Jobs[handleJobID] = &handleJob{Route: "import", Channel: "documents", Thread: handleJobID, From: handleSender,
		State: jobFailed, Attempt: 1, Started: time.Date(2026, 10, 21, 5, 2, 0, 0, time.UTC), Exit: 3, Review: true,
		Reason: "exited 3: no such table"}
	if err := l.save(); err != nil {
		t.Fatal(err)
	}
	if !l.existed {
		t.Error("a saved ledger does not know it exists")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != handleLedgerFile {
		t.Fatalf("the save left %v", entries)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("the ledger's mode is %v (%v), want 0600", info.Mode().Perm(), err)
		}
	}
	back, err := loadHandleLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if !back.existed || back.NextSeq != 1 || back.Routes["import"] == nil || !back.Routes["import"].FirstRound.Equal(l.Routes["import"].FirstRound) {
		t.Fatalf("the ledger read back as %+v", back)
	}
	if got, want := *back.Jobs[handleJobID], *l.Jobs[handleJobID]; got != want {
		t.Fatalf("the job read back as\n%+v\nwant\n%+v", got, want)
	}

	// A save that cannot make its temporary file leaves the ledger whole.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a directory's write bit is Unix's, and root ignores it")
	}
	before, _ := os.ReadFile(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	back.NextSeq = 2
	if err := back.save(); err == nil {
		t.Fatal("a save into a directory it cannot write to succeeded")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a failed save changed the ledger")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("a failed save left %v", entries)
	}
}
