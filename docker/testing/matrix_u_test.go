//go:build e2e

package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// Mail from a build from the future: alice runs a newer auu than bob, and
// what she sends carries a section bob's build has never heard of. No
// command of this build writes one, so alice's machine seals it with
// 'forge seal', which is envelope.SealSections and
// stream.BuildManifestSections posted through her own home and relay, as
// internal/auu/sections_test.go does in process. Each row removes what it
// sent from the relay and from bob's machine.
var newerRows = []matrixRow{
	{"U01", "critical_message", "a message with a critical section bob's build does not know", u01},
	{"U02", "critical_stream", "a stream with a critical section bob's build does not know", u02},
	{"U03", "ignored_section", "a message with a section bob's build does not know and need not", u03},
}

// futureSection is the section a newer build would know, and this one
// does not.
const futureSection = "from-the-future"

// newerFetch is the part of inbox --json these rows read: the fetch's
// count of what waits for a newer auu, and on each message the section it
// waits for or the sections it came with that were ignored.
type newerFetch struct {
	Fetch struct {
		Delivered, Unreadable, Kept int
		Newer                       []string `json:"newer"`
	} `json:"fetch"`
	Messages []struct {
		ID              string   `json:"id"`
		Subject         string   `json:"subject"`
		Text            string   `json:"text"`
		Newer           string   `json:"newer"`
		PayloadOnRelay  bool     `json:"payload_on_relay"`
		IgnoredSections []string `json:"ignored_sections"`
		DroppedSections int      `json:"dropped_sections"`
	} `json:"messages"`
}

// forgeSeal has alice's machine send bob what a newer build would, and
// returns the relay's id for it.
func forgeSeal(t *testing.T, args ...string) int64 {
	t.Helper()
	r := alice.exec("", append([]string{"forge", "seal", "--home", alice.home, "--to", "bob"}, args...)...)
	if r.code != 0 {
		t.Fatalf("forge seal: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.stdout), 10, 64)
	if err != nil {
		t.Fatalf("forge seal printed %q: %v", r.stdout, err)
	}
	return id
}

// fetchNewer is bob's inbox --json, read for what these rows ask of it.
func fetchNewer(t *testing.T) (newerFetch, result) {
	t.Helper()
	var in newerFetch
	r := bob.auu("inbox", "--json")
	if r.code != 0 {
		t.Fatalf("inbox --json: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	jsonOf(t, r, &in)
	return in, r
}

func u01(t *testing.T) {
	defer bob.root("rm -rf " + bobDamaged)
	id := forgeSeal(t, "--section", futureSection, "--critical", "--subject", "a newer ask")
	if !holds(queued(t, state.bobFP), id) {
		t.Fatalf("the relay does not queue %d", id)
	}
	r := bob.auu("inbox")
	expectCode(t, r, 0)
	// The sender by name, the section by name, where it was kept, and that
	// the remedy is bob's, not alice's: damaged.go's keepNewer, and
	// skill/reference.md's sentence.
	stderrIs(t, r, fmt.Sprintf(`warning: relay message %d from alice needs a newer auu (section %q) and was kept as %s; `+
		"update auu to read it", id, futureSection, keptFile(id)))
	keptRecord(t, id, fmt.Sprintf(`newer: section \"%s\"`, futureSection))
	// Counted apart from damaged mail, which would tell bob to ask alice
	// to send it again.
	newer := "1 message(s) kept under " + bobDamaged + " need a newer auu; update auu to read them"
	expectSays(t, r, 0, newer)
	expectNot(t, r, "a newer ask", "ask their senders", "ask the sender")
	if holds(queued(t, state.bobFP), id) {
		t.Errorf("the relay still queues %d; the client was expected to acknowledge it away", id)
	}
	// Said again, every run, and never fetched again.
	again := bob.auu("inbox")
	expectSays(t, again, 0, newer)
	stderrIs(t, again, "")
	verdict(t, "ok", "Bob's build keeps the message under damaged/ with the cause newer and the section's name, "+
		"acknowledges it, and says in one warning who sent it, which section it needs, where it is and that the remedy "+
		"is to update auu; the inbox counts it apart from damaged mail every run, and nobody is told to send it again.")
}

func u02(t *testing.T) {
	id := forgeSeal(t, "--section", futureSection, "--critical", "--stream", "--subject", "a newer stream")
	in, fetched := fetchNewer(t)
	if in.Fetch.Unreadable != 0 || in.Fetch.Kept != 0 || len(in.Fetch.Newer) != 1 || in.Fetch.Newer[0] != futureSection {
		t.Fatalf("fetch: %+v, want the stream waiting for %q", in.Fetch, futureSection)
	}
	var mid string
	for _, m := range in.Messages {
		if m.Subject == "a newer stream" {
			if m.Newer != futureSection || !m.PayloadOnRelay || m.Text != "" {
				t.Errorf("the waiting record in --json: %+v", m)
			}
			mid = m.ID
		}
	}
	if mid == "" {
		t.Fatalf("no record of the waiting stream in --json:\n%s", fetched.stdout)
	}
	defer func() {
		if r := bob.auu("rm", mid); r.code != 0 {
			t.Errorf("rm: exit %d\n%s%s", r.code, r.stdout, r.stderr)
		}
	}()
	// It waits on the relay, unacknowledged, for a build that knows it.
	if !holds(queued(t, state.bobFP), id) {
		t.Errorf("the relay no longer queues %d; the stream was expected to wait there", id)
	}
	// The listing marks it and says how many wait, every run.
	r := bob.auu("inbox")
	expectSays(t, r, 0,
		fmt.Sprintf("  needs a newer auu (section %q)", futureSection),
		fmt.Sprintf("1 stream(s) wait on the relay for a newer auu (section %q); update auu to fetch them", futureSection))
	stderrIs(t, r, "")
	// Read and reply say the one sentence, and show nothing of it.
	sentence := fmt.Sprintf("message %s waits on the relay for a newer auu (section %q); update auu to fetch it", mid[:12], futureSection)
	read := bob.auu("read", mid)
	expectCode(t, read, 0)
	if got := strings.TrimSpace(read.stdout); got != sentence {
		t.Errorf("read is\n  %q\nwant\n  %q", got, sentence)
	}
	reply := bob.auu("reply", mid, "a reply to what I cannot read")
	expectCode(t, reply, 1)
	stderrIs(t, reply, "auu: "+sentence)
	verdict(t, "ok", "The stream waits on the relay unacknowledged, recorded in bob's inbox with the section it needs; "+
		"the listing marks it and counts what waits every run, and read and reply answer with one sentence that names "+
		"the section and says to update auu, showing nothing of what it carries.")
}

func u03(t *testing.T) {
	forgeSeal(t, "--section", futureSection, "--subject", "an ask with a section", "--text", "read as any other")
	in, r := fetchNewer(t)
	if in.Fetch.Delivered != 1 || in.Fetch.Unreadable != 0 || len(in.Fetch.Newer) != 0 {
		t.Fatalf("fetch: %+v, want it delivered", in.Fetch)
	}
	stderrIs(t, r, "")
	var mid string
	for _, m := range in.Messages {
		if m.Subject == "an ask with a section" {
			if strings.Join(m.IgnoredSections, ",") != futureSection || m.DroppedSections != 0 || m.Newer != "" {
				t.Errorf("--json: %+v; want %q named in ignored_sections", m, futureSection)
			}
			mid = m.ID
		}
	}
	if mid == "" {
		t.Fatal("the message is not in the inbox")
	}
	defer bob.auu("rm", mid)
	expectSays(t, bob.auu("read", mid), 0, "read as any other")
	verdict(t, "ok", "A section bob's build does not know and need not is no obstacle: the message is read as any other, "+
		"and --json names the section it came with in ignored_sections.")
}
