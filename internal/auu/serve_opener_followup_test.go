package auu

import (
	"strings"
	"testing"
)

// The second review's F2 scenario, carried on and kept: carol, a stranger
// to alice's thread, is left alone, and alice's own follow-up on her thread
// is still answered, in her worktree, as her turn 2 and with her work in
// its patch. A fix that silenced the stranger by silencing everybody would
// fail here.
func TestTheOpenersFollowUpIsStillAnsweredAfterAStrangerIsRefused(t *testing.T) {
	alice, carol, bob := newExpertAndCarol(t, modeSideCopy)
	t.Setenv(handlerScript, "write:secret.txt=alice's private work;echo:done")
	sent := alice.ask(t, "jostle", "alice's question", "please work on this")
	bob.serve(t)
	first := alice.replyOn(t, sent.Thread)

	t.Setenv(handlerScript, "env")
	carol.askOn(t, "jostle", sent.Thread, "carol's question", "what is in this thread?")
	bob.serve(t)
	nothingFromBob(t, carol, bob)

	var follow sentJSON
	decodeJSON(t, alice.run("reply", first.ID[:12], "--json", "and one more thing"), &follow)
	bob.serve(t)
	var in inboxJSON
	decodeJSON(t, alice.run("inbox", "--json"), &in)
	var got *messageJSON
	for _, m := range in.Messages {
		if m.Type == "reply" && m.Thread == sent.Thread && m.ID != first.ID {
			var full messageJSON
			decodeJSON(t, alice.run("read", m.ID, "--json"), &full)
			got = &full
		}
	}
	if got == nil {
		t.Fatalf("alice's follow-up on her own thread was not answered")
	}
	vars := envOf(t, got.Text)
	if vars["AUU_TURN"] != "2" || vars["AUU_MESSAGE_ID"] != follow.ID {
		t.Errorf("alice's follow-up ran as turn %s for %s", vars["AUU_TURN"], vars["AUU_MESSAGE_ID"])
	}
	found := false
	for _, a := range got.Attachments {
		if a.Name == patchName(sent.Thread) && strings.Contains(readFile(t, patchOf(t, alice, *got)), "alice's private work") {
			found = true
		}
	}
	if !found {
		t.Errorf("alice's turn 2 did not carry her work in its patch")
	}
}
