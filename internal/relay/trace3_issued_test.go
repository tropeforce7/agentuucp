package relay

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The third trace's adversarial tests, relay_issued_adv_test.go, kept
// under the decided design: the scenario and the inputs are the trace's,
// the owner's document signed a century ahead and then the owner's push
// issued now, but driven through the push route, where the check is, and
// asserting the decided outcome. The store orders by issue, except over a
// row held from beyond the skew, which it judges on the relay's clock
// (R23).

// century is the trace's: a document signed a hundred years ahead.
func century() time.Time { return time.Now().Add(100 * 365 * 24 * time.Hour).UTC() }

const byRelayClock = "by this relay's clock"

// taken is any status a push route answers when it stores the document.
func taken(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated || status == http.StatusNoContent
}

func TestAnAllowlistIssuedFromTheFutureIsRefusedByName(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}

	status, body, _ := h.pushAllow(alice, alice, century(), bob.Fingerprint())
	if status != http.StatusBadRequest || !strings.Contains(string(body), byRelayClock) ||
		!strings.Contains(string(body), "ahead of now") {
		t.Fatalf("a list issued a century ahead: %d %s", status, body)
	}
	if _, _, _, found, err := h.store.Allowlist(alice.Fingerprint()); err != nil || found {
		t.Fatalf("a list issued a century ahead was stored: found %v, %v", found, err)
	}
	// The owner, from a machine with the right clock, pushes as ever.
	if status, body, _ := h.pushAllow(alice, alice, time.Now().UTC()); !taken(status) {
		t.Fatalf("the owner's push issued now after the refusal: %d %s", status, body)
	}
	if _, _, _, found, err := h.store.Allowlist(alice.Fingerprint()); err != nil || !found {
		t.Fatalf("the owner's push issued now was not stored: found %v, %v", found, err)
	}
}

func TestACardIssuedFromTheFutureIsRefusedByName(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)

	status, body, _ := h.pushCard(alice, alice, century(), true, true)
	if status != http.StatusBadRequest || !strings.Contains(string(body), byRelayClock) ||
		!strings.Contains(string(body), "ahead of now") {
		t.Fatalf("a card issued a century ahead: %d %s", status, body)
	}
	if _, _, _, found, err := h.store.Card(alice.Fingerprint()); err != nil || found {
		t.Fatalf("a card issued a century ahead was stored: found %v, %v", found, err)
	}
	if status, body, _ := h.pushCard(alice, alice, time.Now().UTC(), false, false); !taken(status) {
		t.Fatalf("the owner's push issued now after the refusal: %d %s", status, body)
	}
	if _, _, _, found, err := h.store.Card(alice.Fingerprint()); err != nil || !found {
		t.Fatalf("the owner's push issued now was not stored: found %v, %v", found, err)
	}
}

func TestADirectoryIssuedFromTheFutureIsRefusedByName(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)
	fp := alice.Fingerprint()
	stored := func() bool {
		t.Helper()
		_, _, found, err := h.store.Directory(fp)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}

	status, body, _ := h.pushDirectory(alice, alice, century(), dflt, bugs)
	if status != http.StatusBadRequest || !strings.Contains(string(body), byRelayClock) ||
		!strings.Contains(string(body), "ahead of now") {
		t.Fatalf("a directory issued a century ahead: %d %s", status, body)
	}
	if stored() {
		t.Fatal("a directory issued a century ahead was stored")
	}

	// The year 0 at +14:00 is the year -1 in UTC: signed and sent as the
	// owner wrote it, it would have been stored in a form the relay's own
	// DirectoryIssued cannot parse back.
	yearMinusOne := time.Date(0, time.January, 1, 0, 0, 0, 0, time.FixedZone("", 14*3600))
	status, body, _ = h.pushDirectory(alice, alice, yearMinusOne, dflt, bugs)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "outside the years") {
		t.Fatalf("a directory issued in the year -1 UTC: %d %s", status, body)
	}
	if stored() {
		t.Fatal("a directory issued in the year -1 UTC was stored")
	}

	// A channel whose not_after is that same instant: refused naming the
	// channel and the field.
	closing := bugs
	closing.NotAfter = &yearMinusOne
	status, body, _ = h.pushDirectory(alice, alice, time.Now().UTC(), dflt, closing)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "channel bug reports: not_after") ||
		!strings.Contains(string(body), "outside the years") {
		t.Fatalf("a channel closing in the year -1 UTC: %d %s", status, body)
	}
	if stored() {
		t.Fatal("a directory with a channel closing in the year -1 UTC was stored")
	}

	// The owner's push issued now is taken, and a channel bound at the
	// writable edge with it.
	edge := bugs
	latest := relayapi.LatestWritable
	edge.NotAfter = &latest
	if status, body, _ := h.pushDirectory(alice, alice, time.Now().UTC(), dflt, edge); !taken(status) {
		t.Fatalf("the owner's push issued now after the refusals: %d %s", status, body)
	}
	if !stored() {
		t.Fatal("the owner's push issued now was not stored")
	}
	if _, found, err := h.store.DirectoryIssued(fp); err != nil || !found {
		t.Fatalf("the stored issue does not read back: found %v, %v", found, err)
	}
}

// The relay names its clock on the one refusal its clock decided: an issue
// too far ahead. A year outside what this program writes, the issue's or a
// channel's bound, is refused in the same words CheckIssued gives, with no
// clock in them.
func TestOnlyTheSkewRefusalNamesTheRelaysClock(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)
	yearMinusOne := time.Date(0, time.January, 1, 0, 0, 0, 0, time.FixedZone("", 14*3600))
	closing := bugs
	closing.NotAfter = &yearMinusOne

	for _, c := range []struct {
		name  string
		push  func() (int, []byte)
		says  string
		clock bool
	}{
		{"an allow list a day ahead", func() (int, []byte) {
			s, b, _ := h.pushAllow(alice, alice, time.Now().AddDate(0, 0, 1))
			return s, b
		}, "ahead of now", true},
		{"a card a day ahead", func() (int, []byte) {
			s, b, _ := h.pushCard(alice, alice, time.Now().AddDate(0, 0, 1), true, true)
			return s, b
		}, "ahead of now", true},
		{"a directory a day ahead", func() (int, []byte) {
			s, b, _ := h.pushDirectory(alice, alice, time.Now().AddDate(0, 0, 1), dflt)
			return s, b
		}, "ahead of now", true},
		{"an allow list issued in the year -1 UTC", func() (int, []byte) {
			s, b, _ := h.pushAllow(alice, alice, yearMinusOne)
			return s, b
		}, "outside the years 0000 to 9999", false},
		{"a card issued in the year -1 UTC", func() (int, []byte) {
			s, b, _ := h.pushCard(alice, alice, yearMinusOne, true, true)
			return s, b
		}, "outside the years 0000 to 9999", false},
		{"a directory issued in the year -1 UTC", func() (int, []byte) {
			s, b, _ := h.pushDirectory(alice, alice, yearMinusOne, dflt)
			return s, b
		}, "outside the years 0000 to 9999", false},
		{"a channel closing in the year -1 UTC", func() (int, []byte) {
			s, b, _ := h.pushDirectory(alice, alice, time.Now(), dflt, closing)
			return s, b
		}, "channel bug reports: not_after", false},
	} {
		status, body := c.push()
		text := errorText(t, body)
		if status != http.StatusBadRequest || !strings.Contains(text, c.says) {
			t.Errorf("%s: %d %q, want 400 saying %q", c.name, status, text, c.says)
			continue
		}
		if got := strings.HasPrefix(text, byRelayClock+", "); got != c.clock {
			t.Errorf("%s: %q names the relay's clock: %v, want %v", c.name, text, got, c.clock)
		}
	}
}

// held is one owner document type as these tests drive it: plant a row
// through the store as the trace did, push one through the route, and
// read the stored bytes.
type held struct {
	name  string
	plant func(t *testing.T, h *harness, owner *identity.Identity, at time.Time)
	push  func(h *harness, owner *identity.Identity, at time.Time) (int, []byte, []byte)
	read  func(t *testing.T, h *harness, fp string) []byte
}

func heldDocuments() []held {
	return []held{
		{"allow list",
			func(t *testing.T, h *harness, owner *identity.Identity, at time.Time) {
				d, doc, sig := signedList(t, owner, at)
				if stored, err := h.store.SetAllowlist(owner.Fingerprint(), d, doc, sig); err != nil || !stored {
					t.Fatalf("planting a list issued %s: stored %v, %v", at, stored, err)
				}
			},
			func(h *harness, owner *identity.Identity, at time.Time) (int, []byte, []byte) {
				status, body, req := h.pushAllow(owner, owner, at)
				return status, body, req.Document
			},
			func(t *testing.T, h *harness, fp string) []byte {
				doc, _, _, found, err := h.store.Allowlist(fp)
				if err != nil || !found {
					t.Fatalf("the stored list: found %v, %v", found, err)
				}
				return doc
			}},
		{"card",
			func(t *testing.T, h *harness, owner *identity.Identity, at time.Time) {
				d, doc, sig := signedCard(t, owner, at, true, true)
				if stored, err := h.store.SetCard(owner.Fingerprint(), d, doc, sig); err != nil || !stored {
					t.Fatalf("planting a card issued %s: stored %v, %v", at, stored, err)
				}
			},
			func(h *harness, owner *identity.Identity, at time.Time) (int, []byte, []byte) {
				status, body, req := h.pushCard(owner, owner, at, false, false)
				return status, body, req.Document
			},
			func(t *testing.T, h *harness, fp string) []byte {
				doc, _, _, found, err := h.store.Card(fp)
				if err != nil || !found {
					t.Fatalf("the stored card: found %v, %v", found, err)
				}
				return doc
			}},
		{"directory",
			func(t *testing.T, h *harness, owner *identity.Identity, at time.Time) {
				d, doc, sig := signedDirectory(t, owner, at, dflt, bugs)
				if stored, err := h.store.SetDirectory(owner.Fingerprint(), d, doc, sig); err != nil || !stored {
					t.Fatalf("planting a directory issued %s: stored %v, %v", at, stored, err)
				}
			},
			func(h *harness, owner *identity.Identity, at time.Time) (int, []byte, []byte) {
				status, body, req := h.pushDirectory(owner, owner, at, dflt)
				return status, body, req.Document
			},
			func(t *testing.T, h *harness, fp string) []byte {
				doc, _, found, err := h.store.Directory(fp)
				if err != nil || !found {
					t.Fatalf("the stored directory: found %v, %v", found, err)
				}
				return doc
			}},
	}
}

// The trace's own step: a row issued a century ahead, put in the store as
// a relay before CheckIssued took it, and the owner's push issued now
// after it. The row is no bar, and the push replaces it; a row just past
// the skew is no bar either.
func TestARowHeldFromTheFutureIsReplacedByTheOwnersPush(t *testing.T) {
	for _, doc := range heldDocuments() {
		for _, ahead := range []struct {
			name string
			at   func() time.Time
		}{
			{"a century ahead", century},
			{"a minute past the skew", func() time.Time { return time.Now().Add(relayapi.MaxSkew + time.Minute).UTC() }},
		} {
			t.Run(doc.name+", "+ahead.name, func(t *testing.T) {
				h := newHarness(t, Config{})
				alice := ids(t, "alice")[0]
				h.register(alice)
				doc.plant(t, h, alice, ahead.at())

				status, body, sent := doc.push(h, alice, time.Now().UTC())
				if status != http.StatusNoContent {
					t.Fatalf("the owner's push issued now over a row from the future: %d %s", status, body)
				}
				if got := doc.read(t, h, alice.Fingerprint()); string(got) != string(sent) {
					t.Fatalf("the store holds\n%s\nnot the push issued now\n%s", got, sent)
				}
			})
		}
	}
}

// The ratchet's ordinary guard is untouched within the skew: a held row
// issued now, or a little inside now+MaxSkew, still refuses an older push
// with 409, and the row stays.
func TestARowHeldWithinTheSkewStillRefusesAnOlderPush(t *testing.T) {
	for _, doc := range heldDocuments() {
		for _, c := range []struct {
			name   string
			held   func() time.Time
			pushed func() time.Time
		}{
			{"held now, pushed a minute earlier",
				func() time.Time { return time.Now().UTC() },
				func() time.Time { return time.Now().Add(-time.Minute).UTC() }},
			{"held thirty seconds inside the skew, pushed now",
				func() time.Time { return time.Now().Add(relayapi.MaxSkew - 30*time.Second).UTC() },
				func() time.Time { return time.Now().UTC() }},
		} {
			t.Run(doc.name+", "+c.name, func(t *testing.T) {
				h := newHarness(t, Config{})
				alice := ids(t, "alice")[0]
				h.register(alice)
				doc.plant(t, h, alice, c.held())
				before := doc.read(t, h, alice.Fingerprint())

				status, body, _ := doc.push(h, alice, c.pushed())
				if status != http.StatusConflict {
					t.Fatalf("an older push over a row within the skew: %d %s, want 409", status, body)
				}
				if got := doc.read(t, h, alice.Fingerprint()); string(got) != string(before) {
					t.Fatal("the held row was replaced by an older push")
				}
			})
		}
	}
}

// A row an earlier release stored with an issue it could write and not
// read back, the year -1 in UTC, as v0.17.0 took 0000-01-01T00:00:00+14:00:
// the relay holds the directory, reads the column as the zero time and
// says so in its log, a watch of the owner answers and is not woken by it,
// and the owner's next push replaces the row.
func TestADirectoryRowWhoseIssueDoesNotParseIsHeldAndReplaced(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	bobFP := bob.Fingerprint()

	// Planted as the earlier release would have: the store's own write of
	// a directory issued in the year 0 at +14:00, which CheckIssued now
	// refuses at the route.
	yearMinusOne := time.Date(0, time.January, 1, 0, 0, 0, 0, time.FixedZone("", 14*3600))
	d, doc, sig := signedDirectory(t, bob, yearMinusOne, dflt, bugs)
	if stored, err := h.store.SetDirectory(bobFP, d, doc, sig); err != nil || !stored {
		t.Fatalf("planting the row: stored %v, %v", stored, err)
	}
	var raw string
	if err := h.store.db.QueryRow(`SELECT issued FROM directories WHERE fp = ?`, bobFP).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != "-0001-12-31T10:00:00Z" {
		t.Fatalf("the planted column is %q, not the earlier release's form", raw)
	}

	// Held, and read as zero without an error.
	issued, found, err := h.store.DirectoryIssued(bobFP)
	if err != nil || !found || !issued.IsZero() {
		t.Fatalf("DirectoryIssued over the row: %s, found %v, %v", issued, found, err)
	}
	if _, _, found, err := h.store.Directory(bobFP); err != nil || !found {
		t.Fatalf("the directory itself: found %v, %v", found, err)
	}

	// A watch of bob answers, and the column read as zero wakes nobody,
	// whatever the watcher holds.
	for _, held := range []time.Time{{}, time.Now()} {
		status, resp, body := h.list(alice, peersQuery(at(bobFP, held))).answer(t)
		if status != http.StatusOK {
			t.Fatalf("a watch holding %s over the row: %d %s", held, status, body)
		}
		for _, fp := range resp.DirectoriesChanged {
			if fp == bobFP {
				t.Fatalf("a watch holding %s was woken by a column read as zero: %+v", held, resp)
			}
		}
	}

	// Said in the log, naming the mailbox and the column as stored.
	logs := h.logs.String()
	if !strings.Contains(logs, "channel directory for "+bobFP+" holds an issue time this relay cannot read") ||
		!strings.Contains(logs, raw) {
		t.Fatalf("the log does not name the mailbox and its column:\n%s", logs)
	}

	// The owner's push issued now replaces the row, and the column reads.
	now := time.Now().UTC()
	if status, body, _ := h.pushDirectory(bob, bob, now, dflt); status != http.StatusNoContent {
		t.Fatalf("the owner's push issued now over the row: %d %s", status, body)
	}
	issued, found, err = h.store.DirectoryIssued(bobFP)
	if err != nil || !found || !issued.Equal(now) {
		t.Fatalf("DirectoryIssued after the push: %s, found %v, %v; want %s", issued, found, err, now)
	}
	// And now it wakes a watcher that holds nothing.
	status, resp, body := h.list(alice, peersQuery(at(bobFP, time.Time{}))).answer(t)
	if status != http.StatusOK || len(resp.DirectoriesChanged) != 1 || resp.DirectoriesChanged[0] != bobFP {
		t.Fatalf("a watch after the push: %d %+v %s", status, resp, body)
	}
}
