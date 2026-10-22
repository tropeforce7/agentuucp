package auu

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Serve and handle together: a channel belongs to one service, held at
// both checks and at both starts, and a reply is nobody's work.

// TestServeCheckRefusesAChannelHandleHandles: serve check and serve itself
// read handle.json from its place in the home and refuse a channel a route
// takes, naming both files; a handle.json that will not read is refused
// naming both; a route on another channel, and no handle.json at all, are
// taken.
func TestServeCheckRefusesAChannelHandleHandles(t *testing.T) {
	_, bob := newExpertCold(t, "read-only")
	handled := filepath.Join(bob.home, handleFile)
	command, err := json.Marshal(helperCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	route := func(channel string) {
		t.Helper()
		data := `{"v":1,"routes":{"work":{"channel":"` + channel + `","command":` + string(command) + `}}}`
		if err := os.WriteFile(handled, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	try := func(args ...string) error {
		t.Helper()
		var err error
		captureStderr(t, func() { _, err = bob.tryRun(args...) })
		return err
	}
	if err := try("serve", "check"); err != nil {
		t.Fatalf("serve check with no handle.json: %v", err)
	}
	route("jostle")
	want := bob.path + `: channel "jostle": route "work" of ` + handled + ` takes it; a channel belongs to one service, serve's or handle's`
	for _, args := range [][]string{{"serve", "check"}, {"serve", "--once"}} {
		err := try(args...)
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != exitUsage || err.Error() != want {
			t.Fatalf("%s with a route on its channel: %v\nwant %s", strings.Join(args, " "), err, want)
		}
	}
	// Refused before the lock is taken, as before a key or a relay.
	if _, err := os.Stat(filepath.Join(bob.home, "serve", serveLockName)); err == nil {
		t.Fatal("the refused serve took the lock")
	}
	route("documents")
	if err := try("serve", "check"); err != nil {
		t.Fatalf("serve check with a route on another channel: %v", err)
	}
	if err := os.WriteFile(handled, []byte(`{"v":1,"routes":{`), 0o600); err != nil {
		t.Fatal(err)
	}
	prefix := bob.path + ": its channels are checked against " + handled + ", which will not read: "
	if err := try("serve", "check"); err == nil || !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("a handle.json that will not read: %v\nwant it to begin %s", err, prefix)
	}
}

// TestHandleRunRefusesAChannelServeServes: the run reads serve.json as
// check does, and refuses to start on a route whose channel serve serves,
// before it takes the lock or a key.
func TestHandleRunRefusesAChannelServeServes(t *testing.T) {
	_, bob := newHandlerCold(t)
	served := filepath.Join(bob.home, serveFile)
	if err := os.WriteFile(served, []byte(`{"v":1,"channels":{"documents":{"dir":"`+jsonPath(t.TempDir())+`","exec":"cat"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	want := bob.path + `: route "import": channel "documents" is served by ` + served + `; a channel belongs to one service, serve's or handle's`
	_, err, _ := bob.handleRound(t)
	if err == nil || err.Error() != want {
		t.Fatalf("handle run with its route's channel served: %v\nwant %s", err, want)
	}
	if _, err := os.Stat(filepath.Join(bob.home, "handle", handleLockName)); err == nil {
		t.Fatal("the refused run took the lock")
	}
}

// TestAReplyToAnAcknowledgementIsNobodysWork: a route on the default
// channel says at start that a reply to one of its acknowledgements is left
// unhandled, and it is: the asker's reply to handle's reply makes no job
// and runs nothing, and serve, answering another channel in the same home,
// has no record of it either.
func TestAReplyToAnAcknowledgementIsNobodysWork(t *testing.T) {
	alice, bob := newExpert(t, "read-only")
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:handled")
	host := &handlerHost{user: bob.user, path: filepath.Join(bob.home, handleFile),
		routes: map[string]*handleRoute{"inbox": {Channel: "default", Command: helperCommand(t)}}}
	host.write(t)
	_, _, stderr := host.handleRound(t)
	if !strings.Contains(stderr, `route "inbox" handles the default channel: a reply to one of its acknowledgements arrives there and is left unhandled`) {
		t.Fatalf("the first round said:\n%s", stderr)
	}
	sent := alice.sendTo(t, "default", "an ask", "please")
	host.handleRound(t)
	job := host.ledger(t).Jobs[sent.ID]
	if job == nil || job.Reply == "" {
		t.Fatalf("the ask's job is %+v", job)
	}
	alice.run("inbox")
	var reply sentJSON
	if err := json.Unmarshal([]byte(alice.run("reply", job.Reply, "--json", "thank you")), &reply); err != nil {
		t.Fatal(err)
	}
	host.handleRound(t)
	bob.serve(t)
	if j := host.ledger(t).Jobs[reply.ID]; j != nil {
		t.Fatalf("the reply to the acknowledgement was taken as a job: %+v", j)
	}
	if runs := strings.Count(readFile(t, marker), "\n"); runs != 1 {
		t.Fatalf("the script ran %d times; want the ask's alone", runs)
	}
	if e := bob.ledgerOf(t).Messages[reply.ID]; e != nil {
		t.Fatalf("serve recorded the reply: %+v", e)
	}
	if rec, err := storeOf(t, bob.user).Load("inbox", reply.ID); err != nil || rec == nil {
		t.Fatalf("the reply is not in the inbox: %v", err)
	}
}
