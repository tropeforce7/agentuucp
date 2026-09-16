package auu

import (
	"encoding/json"
	"strings"
	"testing"
)

func sentOf(t *testing.T, out string) sentJSON {
	t.Helper()
	var s sentJSON
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("send --json: %v\n%s", err, out)
	}
	return s
}

func inboxOf(t *testing.T, u *user) inboxJSON {
	t.Helper()
	var got inboxJSON
	if err := json.Unmarshal([]byte(u.run("inbox", "--json")), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func onThread(msgs []messageJSON, thread string) []messageJSON {
	var out []messageJSON
	for _, m := range msgs {
		if m.Thread == thread {
			out = append(out, m)
		}
	}
	return out
}

// Replying to a thread answers its latest message, whoever wrote it — and
// when that was you, it is a follow-up to the person you wrote to.
func TestReplyToThread(t *testing.T) {
	alice, bob := twoPeers(t)
	first := sentOf(t, alice.run("send", "--to", "bob", "--subject", "q", "--json", "one"))
	thread := first.Thread

	// Bob has not answered. Alice replies to the thread anyway: the latest
	// message is her own, so this goes to bob, answering it.
	out := alice.run("reply", thread[:12], "two")
	if !strings.Contains(out, "from you") {
		t.Fatalf("a follow-up to my own message should say so:\n%s", out)
	}
	got := inboxOf(t, bob)
	msgs := onThread(got.Messages, thread)
	if len(msgs) != 2 {
		t.Fatalf("bob has %d messages on the thread", len(msgs))
	}
	var followUp *messageJSON
	for i := range msgs {
		if msgs[i].Type == "reply" {
			followUp = &msgs[i]
		}
	}
	if followUp == nil || followUp.InReplyTo != first.ID {
		t.Fatalf("follow-up %+v does not answer %s", followUp, first.ID[:12])
	}

	// Bob replies to the thread: its latest message is alice's follow-up.
	out = bob.run("reply", thread[:12], "three")
	if !strings.Contains(out, "from alice") {
		t.Fatalf("bob's reply should name alice:\n%s", out)
	}
	got = inboxOf(t, alice)
	msgs = onThread(got.Messages, thread)
	if len(msgs) != 1 || msgs[0].InReplyTo != followUp.ID || msgs[0].FromName != "bob" {
		t.Fatalf("alice got %+v", msgs)
	}

	// And now alice replies to the thread: latest is bob's, received.
	alice.run("reply", thread[:12], "four")
	got = inboxOf(t, bob)
	msgs = onThread(got.Messages, thread)
	if len(msgs) != 3 {
		t.Fatalf("bob has %d messages on the thread", len(msgs))
	}
}

// The full thread id works as well as a prefix, and --json is quiet.
func TestReplyToThreadByFullIDAndJSON(t *testing.T) {
	alice, bob := twoPeers(t)
	first := sentOf(t, alice.run("send", "--to", "bob", "--subject", "q", "--json", "one"))
	out := alice.run("reply", first.Thread, "--json", "two")
	if strings.Contains(out, "replying to its latest") {
		t.Fatalf("--json output has prose in it:\n%s", out)
	}
	reply := sentOf(t, out)
	if reply.Thread != first.Thread || reply.InReplyTo != first.ID {
		t.Fatalf("reply %+v", reply)
	}
	inboxOf(t, bob)
}

// A message id is still a message id: one you sent is refused, with the
// thread as the way to follow it up.
func TestReplyToASentMessageIdPointsAtTheThread(t *testing.T) {
	alice, _ := twoPeers(t)
	first := sentOf(t, alice.run("send", "--to", "bob", "--subject", "q", "--json", "one"))
	_, err := alice.tryRun("reply", first.ID[:12], "two")
	if err == nil || !strings.Contains(err.Error(), "or to its thread "+first.Thread[:12]) {
		t.Fatalf("err %v", err)
	}
}

// An id that is neither says so.
func TestReplyToNothing(t *testing.T) {
	alice, _ := twoPeers(t)
	_, err := alice.tryRun("reply", "ffffffffffff", "x")
	if err == nil || !strings.Contains(err.Error(), "no message or thread matches") {
		t.Fatalf("err %v", err)
	}
}
