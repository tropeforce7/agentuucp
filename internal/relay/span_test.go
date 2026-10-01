package relay

import (
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// A listing says the lowest and highest ids the mailbox holds, whatever the
// page: zero and zero empty, one row's id twice, the ends of three, and the
// ends again when the lowest and the highest are acknowledged. A stubs
// listing says them too, and a page after a cursor is the same page with
// the same count beside them. Another mailbox's rows are not in them.
func TestAListingSaysTheSpanOfIdsHeld(t *testing.T) {
	s, alice, bob := directoryStore(t)
	fp := bob.Fingerprint()
	span := func(after int64, stubs bool) Listing {
		t.Helper()
		l, err := s.ListingWithin(fp, after, 10, stubs, 0)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	put := func(to string) int64 {
		t.Helper()
		id, err := s.Put(to, "default", relayapi.KindEnvelope, "", sealed(t, alice, bob.Public(), "x"), Quotas{}, Forwarded{})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	if l := span(0, false); l.First != 0 || l.Last != 0 || l.Queued != 0 {
		t.Fatalf("empty: first %d last %d queued %d, want 0 0 0", l.First, l.Last, l.Queued)
	}
	// Alice's mail is numbered from the same counter and is not bob's.
	put(alice.Fingerprint())
	one := put(fp)
	if l := span(0, false); l.First != one || l.Last != one {
		t.Fatalf("one row %d: first %d last %d", one, l.First, l.Last)
	}
	two, three := put(fp), put(fp)
	whole := span(0, false)
	if whole.First != one || whole.Last != three || whole.Queued != 3 || len(whole.Rows) != 3 {
		t.Fatalf("three rows %d..%d: first %d last %d queued %d rows %d", one, three, whole.First, whole.Last, whole.Queued, len(whole.Rows))
	}
	if l := span(0, true); l.First != one || l.Last != three || len(l.Rows) != 3 || l.Rows[0].Envelope != nil {
		t.Fatalf("stubs: first %d last %d rows %d", l.First, l.Last, len(l.Rows))
	}
	after := span(one, false)
	if after.First != one || after.Last != three || after.Queued != 3 || len(after.Rows) != 2 ||
		after.Rows[0].ID != two || after.Rows[1].ID != three {
		t.Fatalf("after %d: first %d last %d queued %d rows %+v", one, after.First, after.Last, after.Queued, after.Rows)
	}
	for i := range after.Rows {
		if string(after.Rows[i].Envelope) != string(whole.Rows[i+1].Envelope) || after.Rows[i].Size != whole.Rows[i+1].Size {
			t.Fatalf("row %d after the cursor differs from the whole page's", after.Rows[i].ID)
		}
	}
	// Past the last: an empty page beside the span, which is what a
	// client reads as a cursor past everything held.
	if l := span(three+5, false); len(l.Rows) != 0 || l.First != one || l.Last != three {
		t.Fatalf("past the last: rows %d first %d last %d", len(l.Rows), l.First, l.Last)
	}
	for _, id := range []int64{one, three} {
		if gone, err := s.Delete(fp, id); err != nil || !gone {
			t.Fatalf("delete %d: %v %v", id, gone, err)
		}
	}
	if l := span(0, false); l.First != two || l.Last != two || l.Queued != 1 {
		t.Fatalf("the ends acknowledged: first %d last %d queued %d, want %d %d 1", l.First, l.Last, l.Queued, two, two)
	}
}
