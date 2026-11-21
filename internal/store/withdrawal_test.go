package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/message"
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
