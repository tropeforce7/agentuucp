package auu

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/testutil"
)

// TestLimitAJobsIDIsNotAPathAtHandle: a job's directories are joined from
// its route id and its message id under handle/ and nowhere else, and
// pathsFor runs each one's rule again at the join, whatever held it
// before: every value of the traversal set is refused as a route id unless
// it is a route's name, and as a message id unless it is a message id, and
// a pair it takes is under the directory. makeDirs makes nothing outside
// handle/ and refuses what stands at a name and is not a directory; and
// a name in original/ that is not its own SafeName, which extractInto never
// writes, is not taken for an attachment's file.
func TestLimitAJobsIDIsNotAPathAtHandle(t *testing.T) {
	scratch := t.TempDir()
	root := filepath.Join(scratch, "handle")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	r := &handleRun{root: root}
	for _, v := range pathSet() {
		for _, c := range []struct{ route, id string }{{v, handleJobID}, {"import", v}} {
			paths, err := r.pathsFor(c.route, c.id)
			valid := validRouteName(c.route) == nil && message.ValidID(c.id) == nil
			if valid != (err == nil) {
				t.Errorf("pathsFor(%q, %q): %v; want taken %v", c.route, c.id, err, valid)
				continue
			}
			if err != nil {
				continue
			}
			for _, p := range []string{paths.job, paths.kept, paths.original} {
				if rel, err := filepath.Rel(root, p); err != nil || strings.HasPrefix(rel, "..") {
					t.Errorf("pathsFor(%q, %q) made %s, outside %s", c.route, c.id, p, root)
				}
			}
			if err := r.makeDirs(paths.job); err != nil {
				t.Errorf("makeDirs of %s: %v", paths.job, err)
			}
		}
	}
	if entries, _ := os.ReadDir(scratch); len(entries) != 1 || entries[0].Name() != "handle" {
		t.Fatalf("the joins made %v beside handle/", entries)
	}
	if err := r.makeDirs(filepath.Join(scratch, "elsewhere")); err == nil {
		t.Fatal("makeDirs made a directory outside handle/")
	}
	if err := os.WriteFile(filepath.Join(root, "jobs", "planted"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.makeDirs(filepath.Join(root, "jobs", "planted", handleJobID)); err == nil ||
		!strings.Contains(err.Error(), "is not a directory of handle's") {
		t.Fatalf("makeDirs through a file: %v", err)
	}

	original := filepath.Join(scratch, "original")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	m := &store.Stored{Inner: &envelope.Inner{Body: message.Body{Attachments: []message.Attachment{{Name: "a\tb.txt"}}}}}
	safe := message.SafeName("a\tb.txt")
	if safe == "a\tb.txt" {
		t.Fatal("the planted name is its own SafeName; the test needs one that is not")
	}
	if err := os.WriteFile(filepath.Join(original, "a\tb.txt"), []byte("planted"), 0o600); err != nil {
		t.Skipf("this filesystem refuses the name: %v", err)
	}
	if _, why := originalFiles(m, original); !strings.Contains(why, "are not all in") {
		t.Fatalf("a name that is not its own SafeName was taken: %q", why)
	}
	if err := os.WriteFile(filepath.Join(original, safe), []byte("written"), 0o600); err != nil {
		t.Fatal(err)
	}
	if files, why := originalFiles(m, original); why != "" || len(files) != 1 || files[0] != safe {
		t.Fatalf("the SafeName file: %v, %q", files, why)
	}
}

// TestLimitARetryAtAtTheExtremes: a job queued again after a failure
// before launch is runnable when its retry_at is now or past, and not
// before, at every value the grammar names, the earliest and latest
// instants among them; a job with none is runnable at once.
func TestLimitARetryAtAtTheExtremes(t *testing.T) {
	now := handleNow()
	for _, e := range testutil.TimeEdges(now) {
		var want bool
		switch e.Name {
		case testutil.AtTheEdge, testutil.ASecondBefore, testutil.AYearPast, testutil.TheEarliest:
			want = true
		case testutil.ASecondPast, testutil.ADayAhead, testutil.AYearAhead, testutil.OnePastYear9999, testutil.TheLatest:
			want = false
		default:
			t.Fatalf("no answer for %q", e.Name)
		}
		job := &handleJob{State: jobQueued, Failures: 1, RetryAt: e.At}
		if got := job.runnable(now); got != want {
			t.Errorf("retry_at %s (%v): runnable %v, want %v", e.Name, e.At, got, want)
		}
	}
	if job := (&handleJob{State: jobQueued}); !job.runnable(now) {
		t.Error("a job with no retry_at is not runnable")
	}
}

// TestLimitAReplyTriedAtTheExtremes: a reply whose send failed is due
// again when its last try plus serve's backoff is now or past, and not
// before, at every value the grammar names; one never tried is due at once,
// and one whose sends are spent is never due.
func TestLimitAReplyTriedAtTheExtremes(t *testing.T) {
	route := &handleRoute{Retries: 3}
	now := handleNow()
	backoff := retryBackoff(1)
	for _, e := range testutil.TimeEdges(now.Add(-backoff)) {
		var want bool
		switch e.Name {
		case testutil.AtTheEdge, testutil.ASecondBefore, testutil.AYearPast, testutil.TheEarliest:
			want = true
		case testutil.ASecondPast, testutil.ADayAhead, testutil.AYearAhead, testutil.OnePastYear9999, testutil.TheLatest:
			want = false
		default:
			t.Fatalf("no answer for %q", e.Name)
		}
		job := &handleJob{State: jobSucceeded, ReplyFailures: 1, ReplyTried: e.At}
		if got := job.owesReply(route, now); got != want {
			t.Errorf("reply_tried %s (%v): due %v, want %v", e.Name, e.At, got, want)
		}
	}
	if job := (&handleJob{State: jobSucceeded}); !job.owesReply(route, now) {
		t.Error("a reply never tried is not due")
	}
	if job := (&handleJob{State: jobSucceeded, ReplyFailures: 3, ReplyTried: testutil.EarliestInstant()}); job.owesReply(route, now) {
		t.Error("a reply whose sends are spent is due")
	}
}

// TestLimitAScriptsReplyIsReadUnderMaxReplyBytes: a script's reply.txt is
// read through a reader that stops one byte past the route's
// max_reply_bytes: a file at the cap is the reply, one byte over is left
// out and said, and 0, no cap, and the type's maximum, where there is no
// byte past to stop at, take a file of any size whole.
func TestLimitAScriptsReplyIsReadUnderMaxReplyBytes(t *testing.T) {
	output := t.TempDir()
	write := func(n int) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(output, "reply.txt"), []byte(strings.Repeat("x", n)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		max   int64
		size  int
		taken bool
	}{
		{1, 1, true}, {1, 2, false}, {4096, 4096, true}, {4096, 4097, false},
		{0, 70000, true}, {math.MaxInt64, 70000, true}, {math.MaxInt64 - 1, 70000, true},
	} {
		write(c.size)
		root, err := os.OpenRoot(output)
		if err != nil {
			t.Fatal(err)
		}
		text, why := scriptReply(root, &handleRoute{MaxReplyBytes: c.max})
		root.Close()
		if c.taken && (why != "" || len(text) != c.size) {
			t.Errorf("max %d, %d bytes: %d read, %q; want it whole", c.max, c.size, len(text), why)
		}
		if !c.taken && (text != "" || why != "it is over the route's max_reply_bytes of "+strconv.FormatInt(c.max, 10)) {
			t.Errorf("max %d, %d bytes: %q; want it left out", c.max, c.size, why)
		}
	}
}
