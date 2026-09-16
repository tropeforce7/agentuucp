package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A message to yourself needs no peer entry.
func TestSendToSelf(t *testing.T) {
	relayURL := startRelay(t)
	me := newUser(t, "me", relayURL)
	me.run("send", "--to", "self", "--subject", "note", "milk")
	var got inboxJSON
	if err := json.Unmarshal([]byte(me.run("inbox", "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if got.Fetch.Delivered != 1 || got.Fetch.Quarantined != 0 || len(got.Messages) != 1 {
		t.Fatalf("%+v, %d messages", got.Fetch, len(got.Messages))
	}
	// The sender is shown by name, and the name is mine.
	if m := got.Messages[0]; m.FromName != "me" || m.Subject != "note" {
		t.Fatalf("the message shows as from %q, subject %q", m.FromName, m.Subject)
	}
	// Only the word: a shell's idea of a home directory is a path, not me.
	if _, err := me.tryRun("send", "--to", "/Users/me", "x"); err == nil {
		t.Fatal("a path was taken for self")
	}
	// And nothing was added to the peer list to make it work.
	if _, err := os.Stat(filepath.Join(me.home, "authorized_peers")); err == nil {
		data, _ := os.ReadFile(filepath.Join(me.home, "authorized_peers"))
		if strings.TrimSpace(string(data)) != "" {
			t.Fatalf("a self-send wrote to the peer list:\n%s", data)
		}
	}
}

// The relay lets an owner write to their own mailbox whatever the allow list
// says; the list is about other people.
func TestSelfSurvivesARestrictedMailbox(t *testing.T) {
	relayURL := startRelay(t)
	me := newUser(t, "me", relayURL)
	other := newUser(t, "other", relayURL)
	me.run("peers", "add", other.exportLine())
	me.run("allow", "push") // the list is: other, and nobody else
	me.run("send", "--to", "self", "--subject", "still works", "yes")
	var got inboxJSON
	json.Unmarshal([]byte(me.run("inbox", "--json")), &got)
	if got.Fetch.Delivered != 1 {
		t.Fatalf("with a restricted mailbox: %+v", got.Fetch)
	}
}

// A large note to yourself takes the stream path, which has its own
// unknown-sender check.
func TestStreamToSelf(t *testing.T) {
	relayURL := startRelay(t)
	me := newUser(t, "me", relayURL)
	file := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(file, make([]byte, 200<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	out := me.run("send", "--to", "self", "--subject", "big", "--attach", file, "--json", "x")
	var sent sentJSON
	json.Unmarshal([]byte(out), &sent)
	if sent.Kind != "stream" {
		t.Fatalf("sent as %q", sent.Kind)
	}
	var got inboxJSON
	json.Unmarshal([]byte(me.run("inbox", "--json")), &got)
	if got.Fetch.Delivered != 1 || got.Fetch.Quarantined != 0 {
		t.Fatalf("stream to self: %+v", got.Fetch)
	}
}

// Replying to your own note is replying to yourself.
func TestReplyToSelf(t *testing.T) {
	relayURL := startRelay(t)
	me := newUser(t, "me", relayURL)
	me.run("send", "--to", "self", "--subject", "q", "question")
	var got inboxJSON
	json.Unmarshal([]byte(me.run("inbox", "--json")), &got)
	me.run("reply", got.Messages[0].ID, "answer")
	json.Unmarshal([]byte(me.run("inbox", "--json")), &got)
	if got.Fetch.Delivered != 1 || len(got.Messages) != 2 {
		t.Fatalf("reply to self: %+v, %d messages", got.Fetch, len(got.Messages))
	}
	var reply, question *messageJSON
	for i := range got.Messages {
		switch got.Messages[i].Type {
		case "reply":
			reply = &got.Messages[i]
		case "ask":
			question = &got.Messages[i]
		}
	}
	if reply == nil || question == nil {
		t.Fatalf("messages: %+v", got.Messages)
	}
	if reply.InReplyTo != question.ID || reply.Thread != question.Thread || reply.FromName != "me" {
		t.Fatalf("reply %+v does not answer question %+v", *reply, *question)
	}
}

// Adding your own line to the peer list is refused with the alternative.
func TestPeersAddSelfIsRefused(t *testing.T) {
	relayURL := startRelay(t)
	me := newUser(t, "me", relayURL)
	_, err := me.tryRun("peers", "add", me.exportLine())
	if err == nil || !strings.Contains(err.Error(), "--to self") {
		t.Fatalf("err %v", err)
	}
	if out := me.run("peers", "ls"); !strings.Contains(out, "no peers") {
		t.Fatalf("a self entry was made:\n%s", out)
	}
}

// "self" is a word that means you, so nobody may be called it.
func TestSelfIsAReservedName(t *testing.T) {
	relayURL := startRelay(t)
	for _, name := range []string{"self", "Self", "SELF"} {
		u := &user{t: t, home: t.TempDir()}
		if out, err := u.tryRun("init", "--name", name, "--relay", relayURL); err == nil {
			t.Fatalf("--name %s was accepted:\n%s", name, out)
		} else if !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("--name %s: %v", name, err)
		}
	}
}

// A note to yourself is one message in two boxes, sent/ and inbox/, under one
// id. A prefix must find it, not call it ambiguous.
func TestSelfMessageFoundByPrefix(t *testing.T) {
	relayURL := startRelay(t)
	me := newUser(t, "me", relayURL)
	me.run("send", "--to", "self", "--subject", "Foo Gap", "is it?")
	var got inboxJSON
	json.Unmarshal([]byte(me.run("inbox", "--json")), &got)
	id := got.Messages[0].ID

	out := me.run("read", id[:12])
	if !strings.Contains(out, "Foo Gap") {
		t.Fatalf("read by prefix:\n%s", out)
	}
	// And the copy found is the received one, so it can be replied to.
	me.run("reply", id[:12], "yes")

}
