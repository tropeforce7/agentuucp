package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/testutil"
	"github.com/tropeforce7/agentuucp/internal/wire"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

// A release before v0.22.0 kept a section named withdrawal as one it did
// not know, whatever it said, so a record it saved may carry one that breaks
// the rule: on an ask, naming a message the note is not in reply to, marked
// critical, or with data that is not the section's at all. Each such record,
// in the inbox and in the quarantine, loads, keeps the section as its
// bytes, is listed, and is counted by LeftOn while it says it is on the
// relay (R150): mail the person already holds does not leave the listing
// because a later release gave the name a meaning. That nothing marks a
// message by such a section is the mark's to show, in the commit that adds
// it.
func TestARecordWithABrokenWithdrawalLoads(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	withdrawn := strings.Repeat("2", 32)
	for _, tc := range []struct {
		name   string
		mutate func(m *Stored)
	}{
		{"on an ask", func(m *Stored) { m.Inner.Body.Type = message.TypeAsk }},
		{"another message", func(m *Stored) { m.Inner.Body.InReplyTo = strings.Repeat("3", 32) }},
		{"marked critical", func(m *Stored) { m.Inner.Sections[0].Critical = true }},
		{"data that is not the section's", func(m *Stored) { m.Inner.Sections[0].Data = json.RawMessage(`{"x":1}`) }},
		{"a reason with ESC", func(m *Stored) {
			m.Inner.Sections[0].Data = json.RawMessage(`{"id":"` + withdrawn + `","reason":"a\u001bb"}`)
		}},
	} {
		for _, box := range []Box{Inbox, Quarantine} {
			t.Run(tc.name+" in "+string(box), func(t *testing.T) {
				s := newStore(t)
				id := strings.Repeat("1", 32)
				m := stored(id, now)
				m.OnRelay = true
				m.Inner.Body = withdraw.NoteBody(m.Inner.Body.Thread, withdrawn, "")
				m.Inner.Sections = []wire.Section{{Name: withdraw.SectionName, Data: json.RawMessage(`{"id":"` + withdrawn + `","reason":""}`)}}
				tc.mutate(m)
				data, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(s.msgPath(box, id)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(s.msgPath(box, id), data, 0o600); err != nil {
					t.Fatal(err)
				}
				got, err := s.Load(box, id)
				if err != nil {
					t.Fatalf("the record: %v; want it loaded", err)
				}
				if len(got.Inner.Sections) != 1 || string(got.Inner.Sections[0].Data) != string(m.Inner.Sections[0].Data) {
					t.Fatalf("the record's sections: %+v; want the one kept as its bytes", got.Inner.Sections)
				}
				listed, err := s.List(box)
				if err != nil || len(listed) != 1 || listed[0].Inner.ID != id {
					t.Fatalf("the listing: %d records, %v; want the one", len(listed), err)
				}
				if n, err := s.LeftOn(m.Relay); err != nil || n != 1 {
					t.Fatalf("LeftOn: %d, %v; want the record counted", n, err)
				}
				after, err := os.ReadFile(s.msgPath(box, id))
				if err != nil || string(after) != string(data) {
					t.Fatalf("the file after the load was rewritten: %v", err)
				}
			})
		}
	}
}

// The withdrawal mark at Load, as the mark writes it: none at all, which
// leaves the three keys out so the record is the one v0.21.1 wrote; or a
// time with the note's id and a reason that is the reason's rule's. Each
// other shape was not written by this program and is refused by name: an
// id or a reason with no time, a time with no id, an id that is not one, a
// reason with ESC, a bidi override, a newline or one byte over the cap.
func TestLoadHoldsAWithdrawalMark(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	id := strings.Repeat("1", 32)
	note := strings.Repeat("4", 32)
	if err := s.Save(Inbox, stored(id, now)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.msgPath(Inbox, id))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "withdrawn") {
		t.Fatalf("a record nobody withdrew carries a withdrawal key:\n%s", raw)
	}
	write := func(t *testing.T, mutate func(m *Stored)) error {
		t.Helper()
		m := stored(id, now)
		m.Withdrawn, m.WithdrawnBy, m.WithdrawnReason = now, note, "a mistake"
		mutate(m)
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.msgPath(Inbox, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = s.Load(Inbox, id)
		return err
	}
	if err := write(t, func(*Stored) {}); err != nil {
		t.Fatalf("a good mark: %v", err)
	}
	if err := write(t, func(m *Stored) { m.WithdrawnReason = "" }); err != nil {
		t.Fatalf("a mark with no reason: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(m *Stored)
		says   string
	}{
		{"an id with no time", func(m *Stored) { m.Withdrawn = time.Time{}; m.WithdrawnReason = "" }, "names a note or a reason but no time"},
		{"a reason with no time", func(m *Stored) { m.Withdrawn = time.Time{}; m.WithdrawnBy = "" }, "names a note or a reason but no time"},
		{"a time with no id", func(m *Stored) { m.WithdrawnBy = "" }, "the note that withdrew it is not a message id"},
		{"an id one short", func(m *Stored) { m.WithdrawnBy = note[:31] }, "the note that withdrew it is not a message id"},
		{"an id in uppercase", func(m *Stored) { m.WithdrawnBy = strings.Repeat("A", 32) }, "the note that withdrew it is not a message id"},
		{"a reason with ESC", func(m *Stored) { m.WithdrawnReason = "a\x1bb" }, "reason contains U+001B"},
		{"a reason with a bidi override", func(m *Stored) { m.WithdrawnReason = "a‮b" }, "reason contains U+202E"},
		{"a reason with a newline", func(m *Stored) { m.WithdrawnReason = "a\nb" }, "reason contains U+000A"},
		{"a reason one byte over", func(m *Stored) { m.WithdrawnReason = strings.Repeat("a", withdraw.MaxReasonBytes+1) }, "at most 4096"},
	} {
		err := write(t, tc.mutate)
		if err == nil || !strings.Contains(err.Error(), "the record's withdrawal: ") || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v; want the refusal saying %q", tc.name, err, tc.says)
		}
	}
}

// TestLimitAWithdrawalMarkIsAWritableTime: the mark's time is this
// machine's clock when it was made, shown and never ordered by, and the
// record's strict decode holds it to what RFC 3339 can write: the earliest
// and the latest writable times load, and every edge past the latest does
// not read at all, so no mark outside them reaches a print.
func TestLimitAWithdrawalMarkIsAWritableTime(t *testing.T) {
	s := newStore(t)
	id := strings.Repeat("1", 32)
	write := func(t *testing.T, at string) error {
		t.Helper()
		m := stored(id, time.Now().UTC().Truncate(time.Second))
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		fields["withdrawn"] = json.RawMessage(`"` + at + `"`)
		fields["withdrawn_by"] = json.RawMessage(`"` + strings.Repeat("4", 32) + `"`)
		data, err = json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.msgPath(Inbox, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = s.Load(Inbox, id)
		return err
	}
	if err := write(t, relayapi.EarliestWritable.Format(time.RFC3339Nano)); err != nil {
		t.Errorf("a mark at the earliest writable time: %v; want it loaded", err)
	}
	for _, e := range testutil.TimeEdges(relayapi.LatestWritable) {
		want := false
		switch e.Name {
		case testutil.AtTheEdge, testutil.ASecondBefore, testutil.AYearPast:
			want = true
		case testutil.ASecondPast, testutil.ADayAhead, testutil.AYearAhead, testutil.TheEarliest,
			testutil.OnePastYear9999, testutil.TheLatest:
		default:
			t.Fatalf("no answer for the edge %q", e.Name)
		}
		err := write(t, e.At.UTC().Format(time.RFC3339Nano))
		if (err == nil) != want {
			t.Errorf("a mark %s (%s): %v; want loaded %v", e.Name, e.At.UTC().Format(time.RFC3339Nano), err, want)
		}
	}
}

// TestLoadHoldsAWithdrawalKey: a sent record's key and its copies' keys
// and marks, as auu send and auu withdraw write them, load; a record
// nobody gave a key to carries no key; and each shape the sender never
// writes is refused by name: a key on a message this machine received, a
// key at the top of a message to several, a key that is not 64 lowercase
// hex characters at the top or on a copy, a copy withdrawn that was never
// placed, and a copy withdrawn on a record not marked withdrawn.
func TestLoadHoldsAWithdrawalKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := strings.Repeat("e", 64)
	to, third := strings.Repeat("b", 64), strings.Repeat("c", 64)
	one := func() *Stored {
		m := stored(strings.Repeat("1", 32), now)
		m.WithdrawKey = key
		return m
	}
	several := func() *Stored {
		m := stored(strings.Repeat("1", 32), now)
		m.Inner.Sections = []wire.Section{recipientsList(t, to, third)}
		m.Withdrawn, m.WithdrawnBy = now, strings.Repeat("4", 32)
		m.Copies = []SentCopy{
			{Fingerprint: to, Name: "bob", RelayID: 7, WithdrawKey: key, Withdrawn: now},
			{Fingerprint: third, Name: "carol", RelayID: 8, WithdrawKey: strings.Repeat("f", 64)},
		}
		return m
	}
	write := func(t *testing.T, box Box, m *Stored) error {
		t.Helper()
		s := newStore(t)
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(s.msgPath(box, m.Inner.ID)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.msgPath(box, m.Inner.ID), data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = s.Load(box, m.Inner.ID)
		return err
	}
	if err := write(t, Sent, one()); err != nil {
		t.Fatalf("a message to one with its key: %v", err)
	}
	if err := write(t, Sent, several()); err != nil {
		t.Fatalf("a message to two with a key per copy, one withdrawn: %v", err)
	}
	s := newStore(t)
	if err := s.Save(Sent, stored(strings.Repeat("1", 32), now)); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(s.msgPath(Sent, strings.Repeat("1", 32))); err != nil || strings.Contains(string(raw), "withdraw") {
		t.Fatalf("a record with no key carries one: %v\n%s", err, raw)
	}
	for _, tc := range []struct {
		name string
		box  Box
		m    func() *Stored
		says string
	}{
		{"a key on a received message", Inbox, one, "the record's withdrawal key: only a sent message has one"},
		{"a key on a quarantined message", Quarantine, one, "the record's withdrawal key: only a sent message has one"},
		{"a key at the top of a message to several", Sent, func() *Stored { m := several(); m.WithdrawKey = key; return m },
			"the record's withdrawal key: a message to several keeps its keys with its copies"},
		{"a key one short", Sent, func() *Stored { m := one(); m.WithdrawKey = key[:63]; return m },
			"the record's withdrawal key: it is not 64 lowercase hex characters"},
		{"a key in uppercase", Sent, func() *Stored { m := one(); m.WithdrawKey = strings.Repeat("E", 64); return m },
			"the record's withdrawal key: it is not 64 lowercase hex characters"},
		{"a copy's key one long", Sent, func() *Stored { m := several(); m.Copies[1].WithdrawKey = key + "e"; return m },
			"copy 2's withdrawal key is not 64 lowercase hex characters"},
		{"a copy's key not hex", Sent, func() *Stored { m := several(); m.Copies[1].WithdrawKey = strings.Repeat("g", 64); return m },
			"copy 2's withdrawal key is not 64 lowercase hex characters"},
		{"a copy withdrawn and never placed", Sent, func() *Stored { m := several(); m.Copies[0].RelayID = 0; return m },
			"copy 1 is withdrawn, but was never placed or the message is not marked withdrawn"},
		{"a copy withdrawn on a record not marked", Sent, func() *Stored {
			m := several()
			m.Withdrawn, m.WithdrawnBy = time.Time{}, ""
			return m
		}, "copy 1 is withdrawn, but was never placed or the message is not marked withdrawn"},
	} {
		err := write(t, tc.box, tc.m())
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v; want the refusal saying %q", tc.name, err, tc.says)
		}
	}
}

// FindIn looks in the boxes it is given alone: a message in the inbox is
// no match in the sent box, and one in the sent box is found there.
func TestFindInLooksInTheBoxesNamed(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	received, sent := strings.Repeat("1", 32), strings.Repeat("2", 32)
	if err := s.Save(Inbox, stored(received, now)); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(Sent, stored(sent, now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.FindIn(received[:8], Sent); !errors.Is(err, ErrNoMatch) {
		t.Errorf("a received message found in the sent box: %v", err)
	}
	if box, m, err := s.FindIn(sent[:8], Sent); err != nil || box != Sent || m.Inner.ID != sent {
		t.Errorf("the sent message: %v %v %v", box, m, err)
	}
	if box, _, err := s.Find(received[:8]); err != nil || box != Inbox {
		t.Errorf("Find still looks in the inbox: %v %v", box, err)
	}
}

// TestLimitACopysWithdrawalIsAWritableTime: a copy's withdrawal time is
// this machine's clock when auu withdraw sent its note, shown and never
// ordered by, and held as the record's own mark is, by the strict decode to
// what RFC 3339 can write: the earliest and the latest writable times load,
// and every edge past the latest does not read at all.
func TestLimitACopysWithdrawalIsAWritableTime(t *testing.T) {
	s := newStore(t)
	id := strings.Repeat("1", 32)
	to, third := strings.Repeat("b", 64), strings.Repeat("c", 64)
	write := func(t *testing.T, at string) error {
		t.Helper()
		m := stored(id, time.Now().UTC().Truncate(time.Second))
		m.Inner.Sections = []wire.Section{recipientsList(t, to, third)}
		m.Withdrawn, m.WithdrawnBy = time.Now().UTC().Truncate(time.Second), strings.Repeat("4", 32)
		m.Copies = []SentCopy{{Fingerprint: to, RelayID: 7}, {Fingerprint: third, RelayID: 8}}
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.Replace(string(data), `"relay_id":7`, `"relay_id":7,"withdrawn":"`+at+`"`, 1))
		if err := os.MkdirAll(filepath.Dir(s.msgPath(Sent, id)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.msgPath(Sent, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := s.Load(Sent, id)
		if err == nil && got.Copies[0].Withdrawn.IsZero() {
			t.Fatal("the copy's time was not read")
		}
		return err
	}
	if err := write(t, relayapi.EarliestWritable.Format(time.RFC3339Nano)); err != nil {
		t.Errorf("a copy withdrawn at the earliest writable time: %v; want it loaded", err)
	}
	for _, e := range testutil.TimeEdges(relayapi.LatestWritable) {
		want := false
		switch e.Name {
		case testutil.AtTheEdge, testutil.ASecondBefore, testutil.AYearPast:
			want = true
		case testutil.ASecondPast, testutil.ADayAhead, testutil.AYearAhead, testutil.TheEarliest,
			testutil.OnePastYear9999, testutil.TheLatest:
		default:
			t.Fatalf("no answer for the edge %q", e.Name)
		}
		err := write(t, e.At.UTC().Format(time.RFC3339Nano))
		if (err == nil) != want {
			t.Errorf("a copy withdrawn %s (%s): %v; want loaded %v", e.Name, e.At.UTC().Format(time.RFC3339Nano), err, want)
		}
	}
}
