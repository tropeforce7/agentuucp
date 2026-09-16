package auu

import (
	"encoding/json"
	"strings"
	"testing"
)

// The subject a person types in the editor is the message's subject, and a
// template line that came back without its '#' is still the comment it was.
// A reply of 2026-09-07 went out with the thread's subject on the record
// and the subject its writer had typed — "A bit odd" — sitting at the top
// of the body, under two more lines of template, because the editor
// returned the three comment lines with the '#' taken off.

// replied sends a message from alice to bob and has bob reply to it,
// returning bob's reply as alice received it.
func replied(t *testing.T, alice, bob *user, replyArgs ...string) messageJSON {
	t.Helper()
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--subject", "Foo Gap", "--json", "the question")), &sent); err != nil {
		t.Fatal(err)
	}
	bob.run("inbox")
	bob.run(append([]string{"reply", sent.ID[:12]}, replyArgs...)...)
	var in inboxJSON
	if err := json.Unmarshal([]byte(alice.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	for _, m := range in.Messages {
		if m.Type != "reply" {
			continue
		}
		// The listing carries no text; the message itself does.
		var full messageJSON
		if err := json.Unmarshal([]byte(alice.run("read", m.ID, "--json")), &full); err != nil {
			t.Fatal(err)
		}
		return full
	}
	t.Fatalf("no reply in alice's inbox: %+v", in.Messages)
	return messageJSON{}
}

// The Subject line of the template is edited in place, and what is typed
// there is the subject the message goes out with.
func TestTheSubjectLineIsEditedInPlace(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `grep -q '^# Subject: Foo Gap   (edit the subject here; keep the #)$' "$1" || exit 13
sed -i.bak 's/^# Subject: .*/# Subject: A bit odd   (edit the subject here; keep the #)/' "$1"
printf 'This is very different\n' >> "$1"`)
	reply := replied(t, alice, bob, "--edit")
	if reply.Subject != "A bit odd" {
		t.Fatalf("the reply's subject is %q, want the one typed in the editor", reply.Subject)
	}
	if strings.Contains(reply.Text, "Subject:") || strings.Contains(reply.Text, "Reply to") {
		t.Fatalf("the template is in the body:\n%s", reply.Text)
	}
}

// Her editor's own behaviour: the three comment lines come back with the
// '#' replaced by a space. They are comments still — the Subject one sets
// the subject, the other two are dropped — and none of them is body.
func TestATemplateLineWithoutItsHashIsStillAComment(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `sed -i.bak 's/^#//' "$1"
sed -i.bak 's/^ Subject: .*/ Subject: A bit odd/' "$1"
printf 'This is very different\n' >> "$1"`)
	reply := replied(t, alice, bob, "--edit")
	if reply.Subject != "A bit odd" {
		t.Fatalf("the reply's subject is %q, want the one typed where the '#' had gone", reply.Subject)
	}
	if reply.Text != "This is very different" {
		t.Fatalf("the body is:\n%s\nwant the typed line alone", reply.Text)
	}
}

// A template left alone says nothing: the reply keeps the thread's subject,
// as it always did, and the hint is not mistaken for one.
func TestAnUneditedTemplateLeavesTheSubjectAlone(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `printf 'the same subject as before\n' >> "$1"`)
	reply := replied(t, alice, bob, "--edit")
	if reply.Subject != "Foo Gap" {
		t.Fatalf("the reply's subject is %q, want the thread's", reply.Subject)
	}
	if reply.Text != "the same subject as before" {
		t.Fatalf("the body is:\n%s", reply.Text)
	}
}

// --subject on a reply is the same thing by another road, and needs no
// editor.
func TestAReplyTakesItsOwnSubjectFromTheFlag(t *testing.T) {
	alice, bob := twoPeers(t)
	reply := replied(t, alice, bob, "--subject", "A bit odd", "this one differs")
	if reply.Subject != "A bit odd" {
		t.Fatalf("the reply's subject is %q", reply.Subject)
	}
	// And without one, the thread's.
	var sent sentJSON
	json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--subject", "Second thread", "--json", "another question")), &sent)
	bob.run("inbox")
	bob.run("reply", sent.ID[:12], "no subject of its own")
	var in inboxJSON
	json.Unmarshal([]byte(alice.run("inbox", "--json")), &in)
	for _, m := range in.Messages {
		if m.Thread == sent.Thread && m.Type == "reply" && m.Subject != "Second thread" {
			t.Fatalf("a reply with no subject of its own has %q", m.Subject)
		}
	}
}

// A fresh message's Subject line is editable too: the flag opens the
// template, and what comes back wins.
func TestAFreshMessagesSubjectCanBeEditedToo(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `sed -i.bak 's/^# Subject: .*/# Subject: changed my mind/' "$1"
printf 'the body\n' >> "$1"`)
	alice.run("send", "--to", "bob", "--subject", "as typed on the command line", "--edit")
	subject, text := firstMessage(t, bob)
	if subject != "changed my mind" {
		t.Fatalf("the subject is %q, want the one from the editor", subject)
	}
	if text != "the body" {
		t.Fatalf("the body is %q", text)
	}
}

// And with no --subject there is no Subject line, so the first line is the
// subject, as it always was.
func TestWithNoSubjectTheFirstLineIsStillTheSubject(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `printf 'a subject line\n\nand the body\n' >> "$1"`)
	alice.run("send", "--to", "bob", "--edit")
	subject, text := firstMessage(t, bob)
	if subject != "a subject line" || text != "and the body" {
		t.Fatalf("subject %q, text %q", subject, text)
	}
}

// An untouched template says nothing at all, rather than reading its own
// line back: a subject given on the command line goes out as it was given,
// spaces and all.
func TestAnUntouchedSubjectLineIsNotReadBack(t *testing.T) {
	alice, bob := twoPeers(t)
	editor(t, `printf 'the body\n' >> "$1"`)
	alice.run("send", "--to", "bob", "--subject", "  spaced  ", "--edit")
	subject, _ := firstMessage(t, bob)
	if subject != "  spaced  " {
		t.Fatalf("the subject is %q, want it as it was given", subject)
	}
}

// read shows the thread's subject, and under it the reply's own when the
// reply was given one. --json carries both: subject is the message's, as it
// is everywhere, and thread_subject is the thread's.
func TestReadShowsTheThreadsSubjectAndTheReplysOwn(t *testing.T) {
	alice, bob := twoPeers(t)
	reply := replied(t, alice, bob, "--subject", "A bit odd", "this one differs")
	if reply.Subject != "A bit odd" || reply.ThreadSubject != "Foo Gap" {
		t.Fatalf("read --json: subject %q, thread_subject %q", reply.Subject, reply.ThreadSubject)
	}
	text := alice.run("read", reply.ID)
	if !strings.Contains(text, "subject: Foo Gap\n  reply: A bit odd\n") {
		t.Fatalf("read:\n%s", text)
	}
	// The listing is unchanged: one line for each message, each with its
	// own subject and no thread_subject in it.
	listing := alice.run("inbox", "--json")
	if strings.Contains(listing, "thread_subject") {
		t.Fatalf("the listing carries thread_subject:\n%s", listing)
	}
	if lines := alice.run("inbox"); !strings.Contains(lines, "A bit odd") {
		t.Fatalf("inbox:\n%s", lines)
	}
}

// A reply that kept the thread's subject prints one subject line, exactly
// as it always did, and says the same thing twice in --json.
func TestReadOfAReplyWithNoSubjectOfItsOwnIsUnchanged(t *testing.T) {
	alice, bob := twoPeers(t)
	reply := replied(t, alice, bob, "the usual answer")
	if reply.Subject != "Foo Gap" || reply.ThreadSubject != "Foo Gap" {
		t.Fatalf("read --json: subject %q, thread_subject %q", reply.Subject, reply.ThreadSubject)
	}
	text := alice.run("read", reply.ID)
	if strings.Contains(text, "  reply:") {
		t.Fatalf("a second subject line where there is nothing to say:\n%s", text)
	}
	if !strings.Contains(text, "subject: Foo Gap\n") {
		t.Fatalf("read:\n%s", text)
	}
}

// The message that opened the thread is where its subject comes from, so a
// thread whose first message has been removed here falls back to the
// message's own subject rather than inventing one.
func TestTheThreadsSubjectFallsBackWhenItsFirstMessageIsGone(t *testing.T) {
	alice, bob := twoPeers(t)
	var sent sentJSON
	if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--subject", "Foo Gap", "--json", "the question")), &sent); err != nil {
		t.Fatal(err)
	}
	bob.run("inbox")
	bob.run("reply", sent.ID[:12], "--subject", "A bit odd", "this one differs")
	var in inboxJSON
	if err := json.Unmarshal([]byte(alice.run("inbox", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	var replyID string
	for _, m := range in.Messages {
		if m.Type == "reply" {
			replyID = m.ID
		}
	}
	alice.run("rm", sent.ID, "--local-only")
	var got messageJSON
	if err := json.Unmarshal([]byte(alice.run("read", replyID, "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if got.ThreadSubject != "A bit odd" {
		t.Fatalf("thread_subject with the thread's first message gone: %q", got.ThreadSubject)
	}
	if text := alice.run("read", replyID); !strings.Contains(text, "subject: A bit odd\n") || strings.Contains(text, "  reply:") {
		t.Fatalf("read:\n%s", text)
	}
}
