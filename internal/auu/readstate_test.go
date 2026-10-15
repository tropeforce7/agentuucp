package auu

import (
	"encoding/json"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/store"
)

// What read and wait print about a message's read state is what they saved
// (G42, R58): each marked the message read in the store and printed the
// copy it had loaded before, so `auu read --json` and `auu wait --json`
// said read false of a message the store held as read.
func TestReadAndWaitSayTheReadStateTheySaved(t *testing.T) {
	for _, command := range []string{"read", "wait"} {
		t.Run(command, func(t *testing.T) {
			alice, bob, _ := peered(t)
			var sent sentJSON
			if err := json.Unmarshal([]byte(alice.run("send", "--to", "bob", "--subject", "read state", "--json", "hello")), &sent); err != nil {
				t.Fatal(err)
			}
			var got messageJSON
			if command == "read" {
				bob.run("inbox", "--json")
				if err := json.Unmarshal([]byte(bob.run("read", sent.ID, "--json")), &got); err != nil {
					t.Fatal(err)
				}
			} else {
				var waited waitJSON
				if err := json.Unmarshal([]byte(bob.run("wait", "--thread", sent.Thread, "--timeout", "5s", "--json")), &waited); err != nil {
					t.Fatal(err)
				}
				if !waited.Found || waited.Message == nil {
					t.Fatal("wait did not return the message")
				}
				got = *waited.Message
			}
			persisted := bob.stored(store.Inbox, sent.ID)
			if !persisted.Read {
				t.Fatalf("%s did not mark the stored message read", command)
			}
			if !got.Read {
				t.Fatalf("%s --json says read false of a message the store holds as read", command)
			}
			// A second read, of a message already read, says so as it did.
			var again messageJSON
			if err := json.Unmarshal([]byte(bob.run("read", sent.ID, "--json")), &again); err != nil {
				t.Fatal(err)
			}
			if !again.Read {
				t.Fatal("a second read says read false")
			}
		})
	}
}
