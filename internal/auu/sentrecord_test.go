package auu

import (
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/store"
)

// Two changes of one sent record at once are both kept (G45, R61): each
// read the whole record, changed its own copy and saved the whole, so the
// second save took back the first's change, and a copy placed was shown
// waiting. Codex's review found it. The first change is held between its
// read and its save, and the second is begun while it is held: under the
// sent lock the second waits for the first's save, and without it the
// second reads the record the first is about to save over. The second is
// given a second to show that it ran; on a runner too slow to run it in
// that time the test passes whether or not it waits, and never fails a
// lock that holds.
func TestTwoChangesOfASentRecordAreBothKept(t *testing.T) {
	alice, _, _ := threePeers(t)
	sent := sentMany(t, alice.run("send", "--to", "bob,carol", "--json", "concurrent status"))
	s, _, _ := alice.opened()
	m := alice.stored(store.Sent, sent.ID)
	if len(m.Copies) != 2 {
		t.Fatalf("the sent record has %d copies, want 2", len(m.Copies))
	}
	for i := range m.Copies {
		m.Copies[i].RelayID = 0
	}
	if err := s.Save(store.Sent, m); err != nil {
		t.Fatal(err)
	}

	held, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{}, 2)
	go func() {
		updateSentCopy(s, sent.ID, m.Copies[0].Fingerprint, func(c *store.SentCopy) {
			close(held)
			<-release
			c.RelayID = 101
		})
		done <- struct{}{}
	}()
	<-held
	ran := make(chan struct{})
	go func() {
		updateSentCopy(s, sent.ID, m.Copies[1].Fingerprint, func(c *store.SentCopy) {
			close(ran)
			c.RelayID = 102
		})
		done <- struct{}{}
	}()
	select {
	case <-ran:
		t.Error("the second change read the sent record while the first was between its read and its save")
	case <-time.After(time.Second):
	}
	close(release)
	<-done
	<-done

	got, err := s.Load(store.Sent, sent.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range got.Copies {
		if want := int64(101 + i); c.RelayID != want {
			t.Errorf("the copy to %s kept relay id %d, want %d: one change saved over the other", c.Name, c.RelayID, want)
		}
	}
}
