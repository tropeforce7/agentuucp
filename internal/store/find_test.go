package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
)

func twoBoxed(t *testing.T, id *identity.Identity, msgID string) *Stored {
	t.Helper()
	return &Stored{
		Inner: &envelope.Inner{
			ID: msgID, From: id.Fingerprint(), FromBundle: id.Public().Bundle(), To: id.Fingerprint(),
			Body: message.Body{Type: message.TypeAsk, Thread: strings.Repeat("t", 32), Text: "x"},
		},
	}
}

// One id in two boxes is one message: found by prefix, inbox copy first.
// Two ids sharing a prefix are two messages, and the error says so.
func TestFindPrefixAcrossBoxesAndClashes(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("me")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	self := "abcd" + strings.Repeat("1", 28)
	for _, box := range []Box{Sent, Inbox} {
		if err := s.Save(box, twoBoxed(t, id, self)); err != nil {
			t.Fatal(err)
		}
	}
	box, m, err := s.Find("abcd1")
	if err != nil || box != Inbox || m.Inner.ID != self {
		t.Fatalf("one message in two boxes: %v, %v, %v", box, err, m)
	}

	other := "abcd" + strings.Repeat("2", 28)
	if err := s.Save(Inbox, twoBoxed(t, id, other)); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Find("abcd")
	var amb *ErrAmbiguous
	if !errors.As(err, &amb) {
		t.Fatalf("two messages on one prefix: %v", err)
	}
	if amb.What != "messages" || len(amb.Candidates) != 2 || !strings.Contains(err.Error(), "2 messages") {
		t.Fatalf("ambiguity described as: %v", err)
	}
	// The duplicated self copy is listed once.
	if amb.Candidates[0] == amb.Candidates[1] {
		t.Fatalf("a message was listed twice: %v", amb.Candidates)
	}
	// And a prefix that only the second matches is not ambiguous at all.
	if _, m, err := s.Find("abcd2"); err != nil || m.Inner.ID != other {
		t.Fatalf("unique prefix: %v", err)
	}
}

// A thread is found by prefix, its latest message wins, sent/ counts, and two
// threads on one prefix are reported as threads.
func TestFindThread(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("me")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	relayID := int64(0)
	on := func(box Box, msgID, thread string, when time.Time) {
		relayID++
		m := twoBoxed(t, id, msgID)
		m.Inner.Body.Thread = thread
		m.Inner.Time = when
		m.Received = when
		m.RelayID = relayID
		if err := s.Save(box, m); err != nil {
			t.Fatal(err)
		}
	}
	t0 := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	threadA := "aaaa" + strings.Repeat("1", 28)
	on(Inbox, strings.Repeat("1", 32), threadA, t0)
	on(Sent, strings.Repeat("2", 32), threadA, t0.Add(time.Minute)) // my own, and the latest
	on(Inbox, strings.Repeat("3", 32), threadA, t0.Add(-time.Minute))

	box, m, err := s.FindThread("aaaa")
	if err != nil || box != Sent || m.Inner.ID != strings.Repeat("2", 32) {
		t.Fatalf("latest on the thread: %v %v %v", box, err, m)
	}
	// Two in the same second: the relay's id decides, not the file order.
	on(Inbox, strings.Repeat("8", 32), threadA, t0.Add(time.Hour)) // relay id 4
	on(Inbox, strings.Repeat("0", 32), threadA, t0.Add(time.Hour)) // relay id 5, sorts first by name
	if _, m, err := s.FindThread("aaaa"); err != nil || m.Inner.ID != strings.Repeat("0", 32) {
		t.Fatalf("same-second tie: %v, got %s", err, m.Inner.ID[:4])
	}
	if _, _, err := s.FindThread("aaa"); err == nil {
		t.Fatal("a 3-character prefix was accepted")
	}
	if _, _, err := s.FindThread("bbbb"); err == nil || !strings.Contains(err.Error(), "no thread") {
		t.Fatalf("missing thread: %v", err)
	}

	// Quarantine is not a place to reply from.
	threadQ := "qqqq" + strings.Repeat("1", 28)
	on(Quarantine, strings.Repeat("4", 32), threadQ, t0)
	if _, _, err := s.FindThread("qqqq"); err == nil {
		t.Fatal("a quarantined thread was found")
	}

	// Two threads on one prefix.
	threadB := "aaaa" + strings.Repeat("2", 28)
	on(Inbox, strings.Repeat("5", 32), threadB, t0)
	_, _, err = s.FindThread("aaaa")
	var amb *ErrAmbiguous
	if !errors.As(err, &amb) || amb.What != "threads" || len(amb.Candidates) != 2 {
		t.Fatalf("two threads: %v", err)
	}
	if _, m, err := s.FindThread("aaaa2"); err != nil || m.Inner.Body.Thread != threadB {
		t.Fatalf("the longer prefix: %v", err)
	}
}

// The first message on a thread is the one it was opened with: the one that
// answers nothing, whatever the clocks say, from inbox/ or sent/ and never
// from quarantine/. It is what the thread's subject is read from, so being
// wrong about it would put a reply's own subject where the thread's belongs.
func TestFirstOnThread(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("me")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	relayID := int64(0)
	on := func(box Box, msgID, thread, subject, inReplyTo string, when time.Time) {
		relayID++
		m := twoBoxed(t, id, msgID)
		m.Inner.Body.Thread = thread
		m.Inner.Body.Subject = subject
		m.Inner.Body.InReplyTo = inReplyTo
		m.Inner.Time = when
		m.Received = when
		m.RelayID = relayID
		if err := s.Save(box, m); err != nil {
			t.Fatal(err)
		}
	}
	t0 := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	thread := "aaaa" + strings.Repeat("1", 28)
	opener := strings.Repeat("1", 32)
	// The reply's sender has a clock an hour behind, so by time alone it
	// would be the first thing on the thread.
	on(Inbox, strings.Repeat("2", 32), thread, "A bit odd", opener, t0.Add(-time.Hour))
	on(Sent, opener, thread, "Foo Gap", "", t0)
	box, m, err := s.FirstOnThread(thread)
	if err != nil || box != Sent || m.Inner.Body.Subject != "Foo Gap" {
		t.Fatalf("the message that opened the thread: %v %v %+v", box, err, m)
	}

	// Two that answer nothing — a second message sent on the same thread —
	// and the earlier of them opens it.
	on(Sent, strings.Repeat("3", 32), thread, "later, and on the same thread", "", t0.Add(time.Hour))
	if _, m, err := s.FirstOnThread(thread); err != nil || m.Inner.Body.Subject != "Foo Gap" {
		t.Fatalf("two that answer nothing: %v %+v", err, m)
	}

	// With the opener gone, the earliest of what is left that answers
	// nothing is the best there is; with none of those left either, the
	// earliest of all, reply or not.
	if err := s.Remove(Sent, opener); err != nil {
		t.Fatal(err)
	}
	if _, m, err := s.FirstOnThread(thread); err != nil || m.Inner.Body.Subject != "later, and on the same thread" {
		t.Fatalf("the opener removed: %v %+v", err, m)
	}
	if err := s.Remove(Sent, strings.Repeat("3", 32)); err != nil {
		t.Fatal(err)
	}
	if _, m, err := s.FirstOnThread(thread); err != nil || m.Inner.Body.Subject != "A bit odd" {
		t.Fatalf("nothing left but a reply: %v %+v", err, m)
	}

	// Quarantine is not searched, so a stranger on the thread cannot say
	// what it is about, and a thread with nothing else on it is not found.
	threadQ := "qqqq" + strings.Repeat("1", 28)
	on(Quarantine, strings.Repeat("4", 32), threadQ, "not yours to name", "", t0)
	if _, _, err := s.FirstOnThread(threadQ); err == nil {
		t.Fatal("a quarantined message opened a thread")
	}
	if _, _, err := s.FirstOnThread("bbbb" + strings.Repeat("1", 28)); err == nil ||
		!strings.Contains(err.Error(), "no message on thread") {
		t.Fatalf("a thread with nothing on it: %v", err)
	}
}
