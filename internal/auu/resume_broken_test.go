package auu

import (
	"os"
	"strings"
	"testing"
)

// A resume that finds unfinished work it cannot finish says so in its
// exit, not only in a warning (G44, R60): records whose sealed files are
// gone were warned of, left out of the count of failures, and the run
// exited 0 with "nothing to resume" beside them.
func TestAResumeWithBrokenRecordsIsNotASuccess(t *testing.T) {
	alice, _, _ := threePeers(t)
	_, copies := sealCopies(t, alice, "bob", "carol")
	s, _, _ := alice.opened()
	for _, p := range copies {
		if err := os.Remove(p.sealedPath(s)); err != nil {
			t.Fatal(err)
		}
	}
	var out string
	var runErr error
	said := captureStderr(t, func() { out, runErr = alice.tryRun("send", "--resume") })
	if runErr == nil {
		t.Fatalf("the resume exited 0 with two records it could not resume\nstdout: %s\nstderr: %s", out, said)
	}
	if !strings.Contains(runErr.Error(), "2 of 2 unfinished messages did not finish") {
		t.Fatalf("the resume's error: %v", runErr)
	}
	if strings.Contains(out, "nothing to resume") {
		t.Fatalf("the resume said there was nothing to resume:\n%s", out)
	}
	// Each broken record is named by its file, with what to do: auu outbox
	// drop does not list it.
	for _, p := range copies {
		if !strings.Contains(said, pendingPath(s, p.name())+" has no sealed file") || !strings.Contains(said, "remove it by hand") {
			t.Fatalf("the warning does not name %s and say to remove it:\n%s", pendingPath(s, p.name()), said)
		}
	}
	// Removed, the next resume has nothing to resume and succeeds.
	for _, p := range copies {
		if err := os.Remove(pendingPath(s, p.name())); err != nil {
			t.Fatal(err)
		}
	}
	if out := alice.run("send", "--resume"); !strings.Contains(out, "nothing to resume") {
		t.Fatalf("after the broken records were removed the resume said:\n%s", out)
	}
}

// Whole copies beside a broken one are still resumed, and the run still
// fails for the broken one (G44, R60).
func TestAResumeSendsTheWholeCopiesBesideABrokenOne(t *testing.T) {
	alice, bob, _ := threePeers(t)
	id, copies := sealCopies(t, alice, "bob", "carol")
	s, _, _ := alice.opened()
	// carol's copy loses its sealed file; bob's stays whole.
	for _, p := range copies {
		if p.ToName == "carol" {
			if err := os.Remove(p.sealedPath(s)); err != nil {
				t.Fatal(err)
			}
		}
	}
	var runErr error
	captureStderr(t, func() { _, runErr = alice.tryRun("send", "--resume") })
	if runErr == nil || !strings.Contains(runErr.Error(), "1 of 2 unfinished messages did not finish") {
		t.Fatalf("the resume's error: %v", runErr)
	}
	delivered := false
	for _, m := range bob.inboxJSON().Messages {
		delivered = delivered || m.ID == id
	}
	if !delivered {
		t.Fatal("the whole copy beside the broken one was not sent")
	}
}
