package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// TestLimitAKeptPatchIsNotReadThroughALink: a side copy's reply that could
// not be sent is kept with its patch, and the retry attaches the patch
// without running the handler again. A link put in place of the patch was
// followed, and the file it named went to the asker as the patch (F1,
// tracer A's TestProbeAKeptPatchFollowsLink, B's link probe). Now the
// retry refuses the link by name, the message fails for it, and nothing of
// the file it names leaves: inline, and as a stream, which a file over the
// threshold makes the reply.
//
// The patch is kept in serve's kept directory, which no program is told
// of (S56), so the link here stands for one an older serve's home holds,
// moved there as the link it is, and for a second line of defence.
//
// On Windows a symbolic link needs the privilege or developer mode, and
// the test skips where it cannot make one; a junction names a directory,
// never the patch file. A hard link is not refused by any open, since it
// is the file, and is TestServeKeepsItsAnswerWhereTheHandlerIsNotGiven's.
func TestLimitAKeptPatchIsNotReadThroughALink(t *testing.T) {
	for _, size := range []struct {
		name  string
		bytes int
	}{{"inline", 64}, {"stream", 200 << 10}} {
		t.Run(size.name, func(t *testing.T) {
			alice, bob := newExpert(t, modeSideCopy)
			const secret = "TOP SECRET KEY MATERIAL"
			target := filepath.Join(t.TempDir(), "id_secret")
			text := secret + strings.Repeat("x", size.bytes) + "\n"
			if err := os.WriteFile(target, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(t.TempDir(), "runs")
			t.Setenv(handlerScript, "append:"+marker+";write:one.txt=the only change;echo:an answer worth keeping")
			sent := alice.ask(t, "jostle", "a question", "the first")
			bob.run("inbox")
			// The send fails with the peer gone, and the reply is kept
			// with its patch.
			bob.run("peers", "rm", "alice")
			captureStderr(t, func() { bob.tryRun("serve", "--once") })
			patch := filepath.Join(bob.home, "serve", "kept", sent.Thread, "patch-"+sent.ID, patchName(sent.Thread))
			if !strings.Contains(readFile(t, patch), "one.txt") {
				t.Fatal("no patch was kept, so the test proves nothing")
			}
			// What a handler, or a child it left running, can do between
			// the two rounds.
			if err := os.Remove(patch); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, patch); err != nil {
				t.Skipf("no symbolic link can be made here: %v", err)
			}
			bob.run("peers", "add", alice.exportLine())
			var out string
			said := captureStderr(t, func() { out, _ = bob.tryRun("serve", "--once", "--json") })
			var report roundJSON
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if len(report.Failed) != 1 || len(report.Answered) != 0 {
				t.Fatalf("the retry: %+v\n%s", report, said)
			}
			if !strings.Contains(said, "is a symbolic link, which is not followed") || !strings.Contains(said, patchName(sent.Thread)) {
				t.Fatalf("the failure does not name the link:\n%s", said)
			}
			if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
				t.Fatalf("the handler ran %d times", runs)
			}
			if out := alice.run("inbox", "--json"); strings.Contains(out, `"type": "reply"`) || strings.Contains(out, secret) {
				t.Fatalf("something reached the asker:\n%s", out)
			}
			s, _, _ := bob.opened()
			kept, err := s.List(store.Sent)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range kept {
				for _, a := range m.Inner.Body.Attachments {
					if strings.Contains(string(a.Data), secret) {
						t.Fatalf("the link's target was sent as %s", a.Name)
					}
				}
			}
			if waiting, _ := outboxOf(t, bob.user); len(waiting) != 0 {
				t.Fatalf("the outbox holds %d copies of a send that was refused", len(waiting))
			}
		})
	}
}

// TestLimitAnAttachmentThroughALinkIsRefused: every read of an attachment
// asks the entry itself, so a link is refused by estimateSize,
// loadAttachments and sourcesFor alike, as keptFiles already refused it,
// and the file the link names is never read. The file itself is taken.
func TestLimitAnAttachmentThroughALinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("PRIVATE KEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "0123456789ab.patch")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symbolic link can be made here: %v", err)
	}
	const refusal = "is a symbolic link, which is not followed; attach the file it points at"
	reads := map[string]func(string) error{
		"estimateSize":    func(p string) error { _, err := estimateSize(message.Body{}, []string{p}); return err },
		"loadAttachments": func(p string) error { _, err := loadAttachments([]string{p}); return err },
		"sourcesFor":      func(p string) error { _, err := sourcesFor([]string{p}); return err },
		"keptFiles":       func(p string) error { _, err := keptFiles([]string{p}); return err },
	}
	for name, read := range reads {
		err := read(link)
		if err == nil {
			t.Errorf("%s took the link", name)
			continue
		}
		if name != "keptFiles" && !strings.Contains(err.Error(), refusal) {
			t.Errorf("%s: %v; want the link named", name, err)
		}
		if err := read(target); err != nil {
			t.Errorf("%s refused the file itself: %v", name, err)
		}
	}
	if hint := largestAttachmentHint([]string{link}); hint != "" {
		t.Errorf("the size hint read through the link: %q", hint)
	}
	// A link put in place after the look is refused at the open: the
	// stream's sources open the file twice, and each open asks the handle.
	sources, err := sourcesFor([]string{target})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("ANOTHER SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, target); err != nil {
		t.Fatal(err)
	}
	if f, err := sources[0].Open(); err == nil {
		f.Close()
		t.Fatal("a source opened through a link put in place after the look")
	}
}
