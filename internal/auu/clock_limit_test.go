package auu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/store"
)

// The outbox's and serve's ledger's times are this machine's clock read
// back from this machine's own file. Their ledger rows say which function
// of the tree holds each, by writing it, and the limit walk holds each row
// to naming every function of the tree that writes the field, so no path
// the row does not name puts a value there. These tests show what the named
// writers put there, through the file and back.

// clockWindow is this machine's clock before and after a write, the earlier
// truncated to the second as the writers truncate theirs.
type clockWindow struct{ from, to time.Time }

func clockFrom() clockWindow { return clockWindow{from: time.Now().UTC().Truncate(time.Second)} }

func (w clockWindow) closed() clockWindow { w.to = time.Now().UTC(); return w }

func (w clockWindow) holds(at time.Time) bool { return !at.Before(w.from) && !at.After(w.to) }

// TestLimitTheOutboxStampsAreThisMachinesClock: an outbox record's Started
// and Time are held by the three functions that make one, sendStream for a
// stream to one, sealStreams for each copy of a stream to several and
// writeCopies for each copy of an envelope to several: Started is this
// machine's clock when the record is made and Time the stamp the seal just
// made, this machine's clock too, each to the second. Each is read back
// through listPending, which decodes the file, and is between the clock
// before the send and after it.
func TestLimitTheOutboxStampsAreThisMachinesClock(t *testing.T) {
	check := func(t *testing.T, who string, recs []*pending, w clockWindow, want int, kind string) {
		t.Helper()
		if len(recs) != want {
			t.Fatalf("%s: %d records in the outbox, want %d", who, len(recs), want)
		}
		for _, p := range recs {
			if p.kind != kind {
				t.Errorf("%s: a record of kind %s, want %s", who, p.kind, kind)
			}
			if !w.holds(p.Started) {
				t.Errorf("%s: started %v, not this machine's clock between %v and %v", who, p.Started, w.from, w.to)
			}
			if !w.holds(p.Time) {
				t.Errorf("%s: time %v, not this machine's clock between %v and %v", who, p.Time, w.from, w.to)
			}
			if !p.Started.Equal(p.Started.Truncate(time.Second)) || !p.Time.Equal(p.Time.Truncate(time.Second)) {
				t.Errorf("%s: started %v and time %v are not whole seconds", who, p.Started, p.Time)
			}
		}
	}

	t.Run("writeCopies", func(t *testing.T) {
		alice, _, _ := threePeers(t)
		w := clockFrom()
		sealCopies(t, alice, "bob", "carol")
		w = w.closed()
		recs, broken := outboxOf(t, alice)
		if len(broken) != 0 {
			t.Fatalf("broken records: %v", broken)
		}
		check(t, "writeCopies", recs, w, 2, kindEnvelope)
	})

	// A stream is left in the outbox by a relay that cuts its upload.
	attachment := func(t *testing.T) string {
		t.Helper()
		file := filepath.Join(t.TempDir(), "long.bin")
		if err := os.WriteFile(file, make([]byte, 300<<10), 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	knowing := func(t *testing.T, relayURL string, names ...string) []*user {
		t.Helper()
		var us []*user
		for _, n := range names {
			us = append(us, newUser(t, n, relayURL))
		}
		for _, u := range us {
			for _, v := range us {
				if u != v {
					u.run("peers", "add", v.exportLine())
				}
			}
			u.run("allow", "push")
		}
		return us
	}

	t.Run("sendStream", func(t *testing.T) {
		relayURL, _ := startInterruptibleRelay(t, 1, 64<<10)
		us := knowing(t, relayURL, "alice", "bob")
		file := attachment(t)
		w := clockFrom()
		if _, err := us[0].tryRun("send", "--to", "bob", "--attach", file, "x"); err == nil {
			t.Fatal("the send should have failed with the relay cut off part way")
		}
		w = w.closed()
		recs, _ := outboxOf(t, us[0])
		check(t, "sendStream", recs, w, 1, kindStream)
		if recs[0].stem != recs[0].MessageID {
			t.Fatalf("the record is named %s, not a stream to one", recs[0].stem)
		}
	})

	t.Run("sealStreams", func(t *testing.T) {
		relayURL, _ := startInterruptibleRelay(t, 1, 64<<10)
		us := knowing(t, relayURL, "alice", "bob", "carol")
		file := attachment(t)
		w := clockFrom()
		if _, err := us[0].tryRun("send", "--to", "bob,carol", "--attach", file, "x"); err == nil {
			t.Fatal("the send should have failed with the relay cut off part way")
		}
		w = w.closed()
		recs, _ := outboxOf(t, us[0])
		check(t, "sealStreams", recs, w, 2, kindStream)
		for _, p := range recs {
			if p.stem == p.MessageID {
				t.Fatalf("the record %s is a stream to one, not a copy", p.stem)
			}
		}
	})
}

// TestLimitTheServeLedgerTimesAreThisMachinesClock: a ledger entry's Tried
// is held by failed at a failed attempt and by settle at the answer, its
// Handled by settle, each this machine's clock to the second; its Arrived
// by setSender, which copies the message record's Arrived, itself this
// machine's clock at the record's first save (internal/store's
// TestLimitAStoredArrivalIsThisMachinesClock), and stays as it was. Each is read back
// through loadLedger, which decodes the file. fillSenders and fromSentCopy,
// the other two writers of Arrived the row names, are run on the answered
// entry as a v0.17.0 ledger kept it, with no sender and no arrival, once
// through the copy of the reply and once through an inbox record an
// earlier release kept; each writes the entry its own Handled.
func TestLimitTheServeLedgerTimesAreThisMachinesClock(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	bob.row.Retries = 3
	bob.write(t)
	t.Setenv(handlerScript, "say:the handler could not;exit:3")
	sent := alice.ask(t, "jostle", "a question", "the first")

	w := clockFrom()
	if _, err := bob.tryRun("serve", "--once", "--json"); err == nil {
		t.Fatal("a round whose handler failed ended well")
	}
	w = w.closed()
	e := bob.ledgerOf(t).Messages[sent.ID]
	if e == nil || e.Failures != 1 {
		t.Fatalf("the failed attempt wrote %+v", e)
	}
	if !w.holds(e.Tried) || !e.Handled.IsZero() {
		t.Fatalf("a failed attempt: tried %v, handled %v; want tried this machine's clock between %v and %v, handled none", e.Tried, e.Handled, w.from, w.to)
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.Load(store.Inbox, sent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Arrived.Equal(rec.Arrived.UTC()) || !w.holds(rec.Arrived.Truncate(time.Second)) {
		t.Fatalf("the entry arrived %v and its record %v; want the record's, this machine's clock between %v and %v", e.Arrived, rec.Arrived, w.from, w.to)
	}
	arrived := e.Arrived

	t.Setenv(handlerScript, "echo:answered")
	w = clockFrom()
	if report := bob.round(t); len(report.Answered) != 1 {
		t.Fatalf("the second round: %+v", report)
	}
	w = w.closed()
	e = bob.ledgerOf(t).Messages[sent.ID]
	if !w.holds(e.Handled) || !e.Tried.Equal(e.Handled) {
		t.Fatalf("the answer: handled %v, tried %v; want both this machine's clock between %v and %v", e.Handled, e.Tried, w.from, w.to)
	}
	if !e.Arrived.Equal(arrived) {
		t.Fatalf("the answer moved the arrival from %v to %v", arrived, e.Arrived)
	}

	// The same entry as a v0.17.0 ledger kept it, with no sender and no
	// arrival: fillSenders fills it from the copy of the reply serve sent
	// (fromSentCopy), and then, with that copy gone and the inbox record
	// one an earlier release kept, from the record (setSender, then its
	// own servedAt). Either way the arrival is the entry's own Handled,
	// this machine's clock at the answer.
	carry := func(t *testing.T, how string) {
		t.Helper()
		led := bob.ledgerOf(t)
		e := led.Messages[sent.ID]
		e.From, e.Arrived, e.Carried = "", time.Time{}, false
		if err := fillSenders(s, led); err != nil {
			t.Fatalf("%s: %v", how, err)
		}
		if err := led.save(); err != nil {
			t.Fatal(err)
		}
		e = bob.ledgerOf(t).Messages[sent.ID]
		if !e.Carried || e.From != alice.fingerprint() || !e.Arrived.Equal(e.Handled) || !w.holds(e.Arrived) {
			t.Fatalf("%s: carried %v, from %q, arrived %v; want carried from alice, arrived at the answer %v", how, e.Carried, e.From, e.Arrived, e.Handled)
		}
	}
	carry(t, "from the sent copy")

	reply := bob.ledgerOf(t).Messages[sent.ID].Reply
	if err := os.Remove(filepath.Join(bob.home, "sent", reply+".json")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(bob.home, "inbox", sent.ID+".json")
	var raw map[string]any
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &raw)
	}
	if err != nil {
		t.Fatal(err)
	}
	// An hour before the answer, so a record's received taken for the
	// arrival is told from the answer's time.
	delete(raw, "arrived")
	raw["received"] = bob.ledgerOf(t).Messages[sent.ID].Handled.Add(-time.Hour).Format(time.RFC3339)
	if data, err = json.Marshal(raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	carry(t, "from the inbox record")
}
