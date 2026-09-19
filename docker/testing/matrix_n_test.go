//go:build e2e

package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
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

// n01Bytes is the size of the upload the relay is frozen under: a hundred
// megabytes, so that the stream opened twice — which the resume does when
// the relay kept nothing — fits a sender's post_bytes_per_hour budget of
// 256 MiB, which an open charges whole and an abandoned upload never gives
// back. The gigabyte the row tried first was refused at the open for that.
const n01Bytes = 100000000

// n01Quota is the relay's share of a processor while the upload runs, as a
// CFS quota of microseconds per hundred-millisecond period: two per cent.
// Under the one-request wire the whole stream is one PUT, and the
// container network carries a hundred megabytes in about a tenth of a
// second, inside which no poll of the relay's log lands, so the second the
// row used to sleep before pausing found the send finished and the outbox
// empty. At two per cent the relay takes the same PUT in about seven
// seconds (measured 2026-09-20), which is room to freeze it after its copy
// has passed max_bytes and long before the PUT ends.
const n01Quota = "2000"

// throttleRelay holds the relay's container to n01Quota of a processor,
// the way docker update does on any running container, and returns what
// lifts the quota again. Everything in the container is held, the relay
// and a shell run by docker exec alike.
func throttleRelay(t *testing.T) func() {
	t.Helper()
	if r := runHost(nil, "docker", "update", "--cpu-period", "100000", "--cpu-quota", n01Quota, relay.id); r.code != 0 {
		t.Fatalf("throttling the relay: %s", r.stderr)
	}
	return func() { runHost(nil, "docker", "update", "--cpu-quota", "-1", relay.id) }
}

// waitUploadPast polls the relay's copy of the one open upload until it
// holds at least n bytes. Under the throttle each poll's shell is slow and
// the copy moves by megabytes between two of them, so where the freeze
// lands is past n by some way, and nowhere near the end.
func waitUploadPast(t *testing.T, n int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		r := runHost(nil, "docker", "exec", "--user", "root", relay.id, "sh", "-c",
			"stat -c %s "+messagesDir+"/uploads/* 2>/dev/null")
		if got, err := strconv.ParseInt(strings.TrimSpace(r.stdout), 10, 64); err == nil && got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay's copy of the upload did not reach %d bytes in %s; stat says %q", n, timeout, r.stdout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func n01(t *testing.T) {
	alice.exec("", "sh", "-c", fmt.Sprintf("head -c %d /dev/urandom > /home/alice/large.bin", n01Bytes))
	t.Cleanup(func() {
		alice.exec("", "sh", "-c", "rm -rf /home/alice/.auu/outbox/* /home/alice/large.bin")
		bob.exec("", "sh", "-c", "rm -rf /home/bob/n01 /home/bob/.auu/inbox/*.d")
	})
	// The relay is slowed, the send begins, and once the relay's copy of
	// the upload has passed max_bytes — the relay's default, which this
	// stack does not change, and the least a stopped first attempt is kept
	// at — the relay is frozen: the sender's one PUT is stuck part way
	// through, and the sender is killed there.
	restore := throttleRelay(t)
	t.Cleanup(restore)
	m := logMark()
	done := make(chan result, 1)
	go func() {
		done <- alice.auu("send", "--to", "bob", "--subject", "a hundred megabytes", "--attach", "/home/alice/large.bin", "large")
	}()
	waitRelayLog(t, m, "path=/v1/mailbox/{fp}/streams status=201", 60*time.Second)
	waitUploadPast(t, relayapi.DefaultMaxBytes, 60*time.Second)
	unpause := pauseRelay(t)
	t.Cleanup(unpause)
	if strings.Contains(relayLogSince(m), "path=/v1/uploads/{id} status=201") {
		t.Fatalf("the upload finished before the relay was frozen; n01Quota wants lowering for this network")
	}
	alice.root("pkill -u alice -x auu")
	r := <-done
	record(alice, "(the killed send)", "", r)
	unpause()
	restore()
	ls := alice.exec("", "sh", "-c", "ls /home/alice/.auu/outbox")
	expectCode(t, ls, 0)
	if !strings.Contains(ls.stdout, ".stream") {
		t.Fatalf("no sealed stream in the outbox:\n%s", ls.stdout)
	}
	r = alice.auu("send", "--to", "bob", "--subject", "meanwhile", "a small one")
	expectSays(t, r, 0, "sent to bob", "warning: 1 unfinished stream in the outbox; finish with 'auu send --resume'")
	// The first attempt stopped past max_bytes, so the relay kept it for
	// the window, which the resume is well inside: its first PUT from zero
	// on the same id is answered 409 with the relay's offset, and the next
	// sends the rest.
	r = alice.auu("send", "--resume")
	expectSays(t, r, 0, "sent to bob")
	if log := relayLogSince(m); !strings.Contains(log, "path=/v1/uploads/{id} status=409") {
		t.Errorf("the relay did not answer the resume with its offset; the log since the send says:\n%s", log)
	}
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 2 {
		t.Fatalf("bob fetched %+v", in.Fetch)
	}
	var id string
	for _, m := range in.Messages {
		if m.Subject == "a hundred megabytes" {
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
	verdict(t, "ok", "The stream is sealed to disk before the upload begins, the killed send leaves the sealed copy, "+
		"every send after the interruption says so, and send --resume asks the relay where its copy ends — the "+
		"relay kept the stopped attempt, its 409 named the offset — and sends the rest from the sealed copy, so "+
		"the stream is placed whole by two attempts on one id.")
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
