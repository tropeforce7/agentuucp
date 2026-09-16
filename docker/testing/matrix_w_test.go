//go:build e2e

package e2e

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// Watching: auu watch, which holds a listing open on the relay and returns
// when something happens. The cycle left bob's directory holding default
// and bug reports; every row leaves the relay and the spools as it found
// them.
var watchRows = []matrixRow{
	{"W01", "already_queued", "mail already waiting: the watch returns at once and moves nothing", w01},
	{"W02", "arrives_during_hold", "a message posted while the relay holds bob's listing open", w02},
	{"W03", "channel_filter", "a watch of one channel while mail arrives for another", w03},
	{"W04", "fetch", "a watch that fetches what it reports", w04},
	{"W05", "directory_added", "alice watches bob's channels and bob adds one", w05},
	{"W06", "relay_restarts", "the relay restarted under a running watch", w06},
	{"W07", "self_elsewhere", "bob's other machine changes his channels under his watch", w07},
}

// watchJSON is auu watch --json as the suite reads it.
type watchJSON struct {
	Events []struct {
		Type     string `json:"type"`
		Relay    string `json:"relay"`
		Channel  string `json:"channel"`
		Kind     string `json:"kind"`
		Size     int64  `json:"size"`
		ID       int64  `json:"id"`
		Peer     string `json:"peer"`
		Issued   string `json:"issued"`
		Added    []string
		Removed  []string
		Updated  []string
		Messages []struct {
			ID      string `json:"id"`
			Subject string `json:"subject"`
			Channel string `json:"channel"`
		} `json:"messages"`
		Channels []struct {
			Name string `json:"name"`
		} `json:"channels"`
	} `json:"events"`
	Waited string `json:"waited"`
}

// waitedUnder asserts a watch reported it waited less than a bound.
func waitedUnder(t *testing.T, w watchJSON, bound time.Duration) {
	t.Helper()
	d, err := time.ParseDuration(w.Waited)
	if err != nil || d >= bound {
		t.Errorf("waited %q, want under %s", w.Waited, bound)
	}
}

// bobCursor reads bob's cursor for the relay.
func bobCursor(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(bob.read(t, bobRelayDir+"/cursor"))
}

func w01(t *testing.T) {
	before := fetchJSON(t, bob, "--no-fetch")
	id, _ := queueOne(t, "--channel", bugChannel, "--subject", "already waiting", "a bug")
	cursor := bobCursor(t)
	r := bob.auu("watch", "--json", "--timeout", "30s")
	var w watchJSON
	jsonOf(t, r, &w)
	expectCode(t, r, 0)
	waitedUnder(t, w, 2*time.Second)
	if len(w.Events) != 1 || w.Events[0].Type != "message" || w.Events[0].Channel != bugChannel ||
		w.Events[0].Relay != relayName || w.Events[0].ID != id || w.Events[0].Kind != "envelope" || w.Events[0].Size == 0 {
		t.Errorf("events: %+v", w.Events)
	}
	// Nothing moved: the spool, the cursor, the relay.
	if after := fetchJSON(t, bob, "--no-fetch"); len(after.Messages) != len(before.Messages) {
		t.Errorf("the spool changed: %d messages before, %d after", len(before.Messages), len(after.Messages))
	}
	if bobCursor(t) != cursor {
		t.Errorf("the cursor moved from %s to %s", cursor, bobCursor(t))
	}
	if left := queued(t, state.bobFP); len(left) != 1 || left[0] != id {
		t.Errorf("the relay holds %v after the watch, want %d still queued", left, id)
	}
	// Plain: one line, the relay, the count, the channel, the size.
	r = bob.auu("watch", "--timeout", "30s")
	expectSays(t, r, 0, relayName+": 1 message in \""+bugChannel+"\" (")
	drain(bob)
	verdict(t, "ok", "")
}

// heldListings are the access log's lines for bob's listing route held
// past a bound, as (status, dur) pairs.
var reListing = regexp.MustCompile(`method=GET path=/v1/mailbox/\{fp\} status=(\d+)(?: limit=\S+)? dur=(\S+)`)

func heldListings(log string, over time.Duration) (held int, statuses []string) {
	for _, m := range reListing.FindAllStringSubmatch(log, -1) {
		if d, err := time.ParseDuration(m[2]); err == nil && d > over {
			held++
			statuses = append(statuses, m[1])
		}
	}
	return held, statuses
}

func w02(t *testing.T) {
	mark := logMark()
	watch := bob.startAuu("watch", "--json", "--timeout", "1m")
	time.Sleep(3 * time.Second)
	if watch.finished() {
		r, _ := watch.wait(t, time.Second)
		t.Fatalf("the watch returned before anything was sent:\n%s%s", r.stdout, r.stderr)
	}
	sentAt := time.Now()
	id, _ := queueOne(t, "--subject", "during the hold", "now")
	r, _ := watch.wait(t, 30*time.Second)
	sinceSend := time.Since(sentAt)
	var w watchJSON
	jsonOf(t, r, &w)
	expectCode(t, r, 0)
	if len(w.Events) != 1 || w.Events[0].ID != id || w.Events[0].Channel != "default" {
		t.Errorf("events: %+v", w.Events)
	}
	if sinceSend > 2*time.Second {
		t.Errorf("the watch returned %s after the send, want within 2s", sinceSend)
	}
	// The relay's side: one listing held for the three seconds and more,
	// answered 200, and not a stall.
	if held, statuses := heldListings(relayLogSince(mark), 3*time.Second); held != 1 || statuses[0] != "200" {
		t.Errorf("held listings in the relay's log: %d %v, want one at 200:\n%s", held, statuses, relayLogSince(mark))
	}
	drain(bob)
	verdict(t, "ok", "")
}

func w03(t *testing.T) {
	watch := bob.startAuu("watch", "--json", "--channel", bugChannel, "--timeout", "10s")
	time.Sleep(2 * time.Second)
	queueOne(t, "--subject", "elsewhere", "to default")
	r, took := watch.wait(t, 30*time.Second)
	expectCode(t, r, 3)
	stderrIs(t, r, "auu: nothing happened in 10s")
	if r.stdout != "{\n  \"events\": [],\n  \"waited\": \"10s\"\n}\n" {
		t.Errorf("the shape at the timeout:\n%s", r.stdout)
	}
	if took < 10*time.Second || took > 20*time.Second {
		t.Errorf("the watch took %s, want its own 10s", took)
	}
	// Then to bugs, and only bugs is reported beside the default one.
	id, _ := queueOne(t, "--channel", bugChannel, "--subject", "a bug", "here")
	r = bob.auu("watch", "--json", "--channel", bugChannel, "--timeout", "30s")
	var w watchJSON
	jsonOf(t, r, &w)
	expectCode(t, r, 0)
	if len(w.Events) != 1 || w.Events[0].ID != id || w.Events[0].Channel != bugChannel {
		t.Errorf("events under --channel: %+v", w.Events)
	}
	drain(bob)
	verdict(t, "ok", "")
}

func w04(t *testing.T) {
	s := sendJSON(t, alice, "bob", "--subject", "fetched by the watch", "here")
	before := bobCursor(t)
	r := bob.auu("watch", "--fetch", "--json", "--timeout", "30s")
	var w watchJSON
	jsonOf(t, r, &w)
	expectCode(t, r, 0)
	if len(w.Events) != 1 || len(w.Events[0].Messages) != 1 || w.Events[0].Messages[0].ID != s.ID ||
		w.Events[0].Messages[0].Subject != "fetched by the watch" {
		t.Errorf("the event with --fetch: %+v", w.Events)
	}
	if after := bobCursor(t); after == before {
		t.Errorf("the cursor did not advance from %s", before)
	}
	in := fetchJSON(t, bob, "--no-fetch")
	found := false
	for _, m := range in.Messages {
		if m.ID == s.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("the message is not in the inbox after --fetch: %+v", in.Messages)
	}
	// --fetch delivers; the channel keeps, so the message stays on the
	// relay and the row takes it away itself.
	if left := queued(t, state.bobFP); len(left) != 1 {
		t.Errorf("queued %v after --fetch, want the message delivered and kept", left)
	}
	drain(bob)
	if left := queued(t, state.bobFP); len(left) != 0 {
		t.Errorf("%v still queued after the row drained", left)
	}
	verdict(t, "ok", "")
}

func w05(t *testing.T) {
	watch := alice.startAuu("watch", "--json", "--event", "directory", "--peer", "bob", "--timeout", "1m")
	time.Sleep(2 * time.Second)
	defer bobChannel(t, "cfp", "--description", "talks, until the deadline")()
	r, _ := watch.wait(t, 30*time.Second)
	var w watchJSON
	jsonOf(t, r, &w)
	expectCode(t, r, 0)
	if len(w.Events) != 1 || w.Events[0].Type != "directory" || w.Events[0].Peer != "bob" || w.Events[0].Issued == "" ||
		strings.Join(w.Events[0].Added, ",") != "cfp" || len(w.Events[0].Removed) != 0 || len(w.Events[0].Updated) != 0 {
		t.Errorf("the directory event: %+v", w.Events)
	}
	names := []string{}
	for _, ch := range w.Events[0].Channels {
		names = append(names, ch.Name)
	}
	if strings.Join(names, ",") != "default,"+bugChannel+",cfp" {
		t.Errorf("channels on the event: %v", names)
	}
	// Plain, for the removal the undo makes.
	watch = alice.startAuu("watch", "--event", "directory", "--peer", "bob", "--timeout", "1m")
	time.Sleep(2 * time.Second)
	expectCode(t, bob.auu("channel", "delete", "cfp"), 0)
	r, _ = watch.wait(t, 30*time.Second)
	expectSays(t, r, 0, relayName+": bob removed \"cfp\"")
	// The deferred undo would delete it again; put it back for that.
	expectCode(t, bob.auu("channel", "create", "cfp", "--description", "talks, until the deadline"), 0)
	verdict(t, "ok", "")
}

// relayBounce stops the relay, leaves it down long enough for a held
// listing to fail, and starts it again: dbBackup's stop and start without
// the database. A fault, so the no-fault run leaves the relay running.
func relayBounce(t *testing.T) {
	t.Helper()
	if nofault {
		return
	}
	relayStop(t)
	time.Sleep(3 * time.Second)
	relayStart(t)
}

func w06(t *testing.T) {
	watch := bob.startAuu("watch", "--json", "--interval", "5s", "--timeout", "2m")
	time.Sleep(2 * time.Second)
	relayBounce(t)
	time.Sleep(2 * time.Second)
	id, _ := queueOne(t, "--subject", "after the restart", "still here")
	r, _ := watch.wait(t, 40*time.Second)
	var w watchJSON
	jsonOf(t, r, &w)
	expectCode(t, r, 0)
	if len(w.Events) != 1 || w.Events[0].ID != id {
		t.Errorf("events after the restart: %+v", w.Events)
	}
	// Said once, for the run of failures, and tried again.
	if n := strings.Count(r.stderr, relayName+": unreachable ("); n != 1 || !strings.Contains(r.stderr, "); trying again in 5s") {
		t.Errorf("stderr across the restart (%d unreachable lines):\n%s", n, r.stderr)
	}
	drain(bob)
	verdict(t, "ok", "")
}

func w07(t *testing.T) {
	desk := bob.at(bobDesktop)
	if !bob.exists(bobDesktop + "/channels.json") {
		verdict(t, "gap", "bob's second machine has no channels.json to change from")
		t.Skip("no second machine with a directory")
	}
	// The desktop's file is behind the relay by whatever the laptop has
	// pushed since the copy; it takes the relay's first, as a person
	// would be told to.
	expectCode(t, desk.auu("channel", "pull"), 0)
	watch := bob.startAuu("watch", "--json", "--event", "directory", "--peer", "self", "--timeout", "1m")
	time.Sleep(2 * time.Second)
	expectSays(t, desk.auu("channel", "create", "from-the-desktop"), 0, relayName+": directory pushed (3 channels)")
	r, _ := watch.wait(t, 30*time.Second)
	var w watchJSON
	jsonOf(t, r, &w)
	expectCode(t, r, 0)
	if len(w.Events) != 1 || w.Events[0].Type != "directory" || w.Events[0].Peer != "you" ||
		strings.Join(w.Events[0].Added, ",") != "from-the-desktop" {
		t.Errorf("the directory event from the other machine: %+v", w.Events)
	}
	// Plain, for the desktop taking it away again; the laptop's file is
	// behind the relay now, which is the last row's to leave.
	watch = bob.startAuu("watch", "--event", "directory", "--peer", "self", "--timeout", "1m")
	time.Sleep(2 * time.Second)
	expectCode(t, desk.auu("channel", "delete", "from-the-desktop"), 0)
	r, _ = watch.wait(t, 30*time.Second)
	expectSays(t, r, 0, relayName+": you changed your channels elsewhere (issued ")
	// The laptop takes the desktop's directory, so the family leaves bob
	// able to edit his channels from either.
	expectSays(t, bob.auu("channel", "pull"), 0)
	verdict(t, "ok", "")
}
