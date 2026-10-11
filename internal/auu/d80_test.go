package auu

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// A record v0.15.0 to v0.17.0 kept from a relay that listed it received at
// the third trace's stamp, UTC year 10000, has no arrived key. Before D80
// it loaded with that stamp as its arrival, serve wrote it into the ledger
// in UTC, and the ledger's save refused it at every start. Planted in
// bob's inbox in that shape, with its file's time set to a known instant,
// still on the relay: 'rm --local-only' refuses it by its id and leaves the
// record and the left-behind file as they were; the inbox lists it with
// the file's time as its arrival and its received as planted; serve
// answers it, saves its ledger and writes that arrival into the entry, and
// the record keeps its received as planted.
func TestARecordAStampedRelayLeftListsAndServesButIsNotLeftBehind(t *testing.T) {
	alice, bob := newExpert(t, modeReadOnly)
	marker := filepath.Join(t.TempDir(), "runs")
	t.Setenv(handlerScript, "append:"+marker+";echo:answered")
	// Not kept, so the relay holds no row the record's received would be
	// matched against; the record says it is still there, as the trace's
	// did, so that rm has a relay copy to remember.
	bob.run("channel", "keep", "jostle", "off")
	sent := alice.ask(t, "jostle", "a question", "the first")
	bob.run("inbox", "--json")

	// The record as v0.17.0 would have kept it from the stamped listing.
	path := filepath.Join(bob.home, "inbox", sent.ID+".json")
	var record map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, path)), &record); err != nil {
		t.Fatal(err)
	}
	delete(record, "arrived")
	record["received"] = json.RawMessage(`"` + receivedFromTheFuture + `"`)
	record["on_relay"] = json.RawMessage("true")
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	fileTime := time.Date(2026, time.March, 14, 15, 9, 26, 0, time.UTC)
	if err := os.Chtimes(path, fileTime, fileTime); err != nil {
		t.Fatal(err)
	}
	received, err := time.Parse(time.RFC3339, receivedFromTheFuture)
	if err != nil {
		t.Fatal(err)
	}

	s := storeOf(t, bob.user)
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	leftBehind := filepath.Join(s.RelayDir(r), "left-behind")
	// rm refuses it before the left-behind line is written.
	recordBefore := readFile(t, path)
	before, beforeErr := os.ReadFile(leftBehind)
	_, err = bob.tryRun("rm", "--local-only", sent.ID)
	if err == nil || !strings.Contains(err.Error(), "message "+sent.ID+" on the relay has a received time this program cannot write back") {
		t.Errorf("rm --local-only: %v; want it refused naming the message", err)
	}
	if recordAfter := readFile(t, path); recordAfter != recordBefore {
		t.Errorf("the record went from\n%s\nto\n%s", recordBefore, recordAfter)
	}
	after, afterErr := os.ReadFile(leftBehind)
	switch {
	case errors.Is(beforeErr, fs.ErrNotExist):
		if !errors.Is(afterErr, fs.ErrNotExist) {
			t.Errorf("the left-behind file was absent and is now there (%v): %q", afterErr, after)
		}
	case beforeErr != nil:
		t.Fatal(beforeErr)
	case afterErr != nil || !bytes.Equal(before, after):
		t.Errorf("the left-behind file went from %q to %q (%v)", before, after, afterErr)
	}

	var in inboxJSON
	if err := json.Unmarshal([]byte(bob.run("inbox", "--no-fetch", "--json")), &in); err != nil {
		t.Fatal(err)
	}
	if len(in.Messages) != 1 || in.Messages[0].ID != sent.ID || !in.Messages[0].Arrived.Equal(fileTime) || !in.Messages[0].Received.Equal(received) {
		t.Errorf("the inbox lists %+v; want the planted record, arrived %v and received %v", in.Messages, fileTime, received)
	}

	report, stderr := bob.roundSaid(t)
	if len(report.Answered) != 1 || report.Answered[0].ID != sent.ID || len(report.Failed) != 0 {
		t.Fatalf("want the planted ask answered and nothing else: %+v\nstderr:\n%s", report, stderr)
	}
	led := bob.ledgerOf(t)
	if e := led.Messages[sent.ID]; e == nil || e.From != alice.fingerprint() || !e.Arrived.Equal(fileTime) {
		t.Fatalf("the ledger entry is %+v; want alice's, arrived at the file's time %v", e, fileTime)
	}
	arrivalIs(t, bob, led, sent.ID)
	m, err := s.Load(store.Inbox, sent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Read || !m.Received.Equal(received) || !m.Arrived.Equal(fileTime) {
		t.Errorf("served: read %v, received %v, arrived %v; want read, the planted %v, and %v", m.Read, m.Received, m.Arrived, received, fileTime)
	}
	if runs := readFile(t, marker); strings.Count(runs, "\n") != 1 || !strings.Contains(runs, sent.ID) {
		t.Errorf("the handler ran other than once, for the planted ask:\n%s", runs)
	}
}

// A fresh fetch keeps this machine's clock at the save as the arrival,
// whatever the relay listed as received: four minutes ahead of this
// clock, within the skew, and a year back. The relay's received is kept
// as Received.
func TestAFreshFetchStampsThisClockAsArrived(t *testing.T) {
	for _, c := range []struct {
		name string
		off  time.Duration
	}{
		{"four minutes ahead", 4 * time.Minute},
		{"a year back", -365 * 24 * time.Hour},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, st, messages := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
			alice := newUser(t, "alice", srv.URL)
			bob := newUser(t, "bob", srv.URL)
			alice.run("peers", "add", bob.exportLine())
			bob.run("peers", "add", alice.exportLine())
			alice.run("send", "--to", "bob", "--subject", "arriving", "hello")
			rows, err := st.List(bob.exportFingerprint(), 0, 10)
			if err != nil || len(rows) != 1 {
				t.Fatalf("the relay holds %d rows for bob (%v); want one", len(rows), err)
			}
			received := time.Now().UTC().Add(c.off).Truncate(time.Second)
			setReceived(t, filepath.Join(filepath.Dir(messages), "relay.db"), rows[0].ID, received)

			before := time.Now().UTC()
			bob.run("inbox", "--json")
			after := time.Now().UTC()
			m := recordOf(t, bob, store.Inbox, "arriving")
			if m.Arrived.Before(before) || m.Arrived.After(after) {
				t.Errorf("the fetched record arrived %v; want this clock at the fetch, between %v and %v", m.Arrived, before, after)
			}
			if !m.Received.Equal(received) || m.Arrived.Equal(m.Received) {
				t.Errorf("the fetched record has received %v and arrived %v; want the relay's %v and an arrival of its own", m.Received, m.Arrived, received)
			}
		})
	}
}
