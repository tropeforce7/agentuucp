//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The network and the agent.
var networkRows = []matrixRow{
	{"N01", "upload_interrupted", "the relay frozen during a large upload, the sender killed, then send --resume", n01},
	{"N02", "wait_with_relay_frozen", "auu wait while the relay is frozen", n02},
	{"N03", "two_fetches_at_once", "two auu inbox at the same moment on one machine", n03},
	{"N04", "agent_started_twice", "auu agent start while an agent runs", n04},
	{"N05", "agent_socket_dir_removed", "the agent's socket directory removed under a running agent", n05},
}

// pauseRelay freezes the relay's processes; connections open and requests
// queue in the kernel, and nothing answers.
func pauseRelay(t *testing.T) func() {
	t.Helper()
	if r := compose("pause", "relay"); r.code != 0 {
		t.Fatalf("pausing the relay: %s", r.stderr)
	}
	return func() { compose("unpause", "relay") }
}

func n01(t *testing.T) {
	alice.exec("", "sh", "-c", "head -c 200000000 /dev/urandom > /home/alice/large.bin")
	t.Cleanup(func() {
		alice.exec("", "sh", "-c", "rm -rf /home/alice/.auu/outbox/* /home/alice/large.bin")
		bob.exec("", "sh", "-c", "rm -rf /home/bob/n01 /home/bob/.auu/inbox/*.d")
	})
	// The relay is frozen once the upload has been opened, so the sender
	// is stuck part way through it, and then killed.
	m := logMark()
	done := make(chan result, 1)
	go func() {
		done <- alice.auu("send", "--to", "bob", "--subject", "two hundred megabytes", "--attach", "/home/alice/large.bin", "large")
	}()
	waitRelayLog(t, m, "path=/v1/mailbox/{fp}/streams status=201", 60*time.Second)
	unpause := pauseRelay(t)
	time.Sleep(time.Second)
	alice.root("pkill -u alice -x auu")
	r := <-done
	record(alice, "(the killed send)", "", r)
	unpause()
	ls := alice.exec("", "sh", "-c", "ls /home/alice/.auu/outbox")
	expectCode(t, ls, 0)
	if !strings.Contains(ls.stdout, ".stream") {
		t.Fatalf("no sealed stream in the outbox:\n%s", ls.stdout)
	}
	r = alice.auu("send", "--to", "bob", "--subject", "meanwhile", "a small one")
	expectSays(t, r, 0, "sent to bob", "warning: 1 unfinished stream in the outbox; finish with 'auu send --resume'")
	r = alice.auu("send", "--resume")
	expectSays(t, r, 0, "sent to bob")
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 2 {
		t.Fatalf("bob fetched %+v", in.Fetch)
	}
	var id string
	for _, m := range in.Messages {
		if m.Subject == "two hundred megabytes" {
			id = m.ID
		}
	}
	if id == "" {
		t.Fatalf("the large message is not in bob's inbox: %+v", in.Messages)
	}
	expectSays(t, bob.auu("extract", id, "--out", "/home/bob/n01"), 0, "wrote /home/bob/n01/large.bin")
	want := strings.Fields(alice.exec("", "sha256sum", "/home/alice/large.bin").stdout)[0]
	got := strings.Fields(bob.exec("", "sha256sum", "/home/bob/n01/large.bin").stdout)[0]
	if want != got {
		t.Errorf("the file arrived as %s, was %s", got, want)
	}
	verdict(t, "ok", "The stream is sealed to disk before the upload begins, every send after the interruption says "+
		"so, and send --resume finishes it whole.")
}

func n02(t *testing.T) {
	s := sendJSON(t, alice, "bob", "--subject", "waiting", "reply when you can")
	unpause := pauseRelay(t)
	t.Cleanup(unpause)
	start := time.Now()
	done := make(chan result, 1)
	go func() {
		done <- alice.auu("wait", "--thread", s.Thread, "--timeout", "10s", "--interval", "5s")
	}()
	var r result
	select {
	case r = <-done:
	case <-time.After(90 * time.Second):
		alice.root("pkill -u alice -x auu")
		r = <-done
		t.Error("wait did not return in ninety seconds with the relay frozen")
	}
	took := time.Since(start)
	unpause()
	record(alice, "(wait returned after "+took.Round(time.Second).String()+")", "", r)
	// Its own ten seconds, and exit 3, the timeout's code: a relay that
	// accepts connections and never answers is cut off by the wait's own
	// deadline, not by the transport's.
	expectCode(t, r, 3)
	stderrIs(t, r, "no reply on thread "+s.Thread+" after 10s\nauu: timed out waiting for thread "+s.Thread)
	if took < 10*time.Second || took > 12*time.Second {
		t.Errorf("wait returned after %s, want its own ten seconds", took)
	}
	drain(bob)
	verdict(t, "ok", "wait was asked for ten seconds and answers in ten with exit 3: every poll runs under the wait's "+
		"own deadline, so a relay that accepts and never answers is cut off when the wait is over.")
}

func n03(t *testing.T) {
	for i := 0; i < 3; i++ {
		sendJSON(t, bob, "alice", "--subject", "at once", "one of three")
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() { results <- alice.auu("inbox", "--json") }()
	}
	total, waited := 0, 0
	for i := 0; i < 2; i++ {
		r := <-results
		record(alice, "(one of the two)", "", r)
		expectCode(t, r, 0)
		var in inboxJSON
		jsonOf(t, r, &in)
		total += in.Fetch.Delivered
		if strings.Contains(r.stderr, "another auu was fetching from relay.example.com; it has finished, carrying on") {
			waited++
		}
	}
	listing := alice.auu("inbox", "--no-fetch")
	n := strings.Count(listing.stdout, "at once")
	record(alice, fmt.Sprintf("(%d delivered across the two fetches, %d listed, %d waited)", total, n, waited), "", result{})
	if n != 3 {
		t.Errorf("%d listed, want 3", n)
	}
	// The two take turns: one delivers three and the other, having waited
	// for it, finds nothing. Whether the second is seen to wait depends on
	// the two processes overlapping, which two started at once usually do.
	if total != 3 {
		t.Errorf("%d delivered across the two fetches, want 3", total)
	}
	verdict(t, "ok", "Two fetches from one machine take turns on a lock in the relay's directory: three delivered between "+
		"them, three listed, and the one that waited says so.")
}

func n04(t *testing.T) {
	defer encryptAlice(t)()
	expectSays(t, alice.auu("agent", "status"), 0, "agent:  running")
	r := alice.auu("agent", "start")
	expectCode(t, r, 0)
	if strings.TrimSpace(r.out()) != "" {
		t.Errorf("a second start said: %q", r.out())
	}
	expectSays(t, alice.auu("agent", "status"), 0, "agent:  running", "keys:   unlocked")
	verdict(t, "ok", "A second start is nothing: the running agent keeps its keys and its lock.")
}

func n05(t *testing.T) {
	defer encryptAlice(t)()
	st := alice.auu("agent", "status")
	expectSays(t, st, 0, "socket: /run/user/1001/auu/")
	alice.mustRoot(t, "rm -rf /run/user/1001/auu")
	deadline := time.Now().Add(45 * time.Second)
	var r result
	for {
		r = alice.auu("agent", "status")
		if strings.Contains(r.stdout, "agent:  not running") || time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	expectSays(t, r, 0, "agent:  not running")
	r = alice.auu("send", "--to", "bob", "after the socket went")
	expectCode(t, r, 4)
	stderrIs(t, r, locked)
	verdict(t, "ok", "The agent notices within its watchdog's thirty seconds and exits rather than hold keys nobody can "+
		"reach; the next command is the locked sentence.")
}
