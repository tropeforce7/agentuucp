package auu

import (
	"os"
	"path/filepath"
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
