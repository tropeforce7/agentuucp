package relay

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// signedList signs a list for owner, issued at, naming the senders.
func signedList(t *testing.T, owner *identity.Identity, at time.Time, senders ...string) (*allowlist.Document, []byte, []byte) {
	t.Helper()
	d := &allowlist.Document{Issued: at, Senders: senders}
	doc, sig, err := allowlist.Sign(owner, d)
	if err != nil {
		t.Fatal(err)
	}
	return d, doc, sig
}

// The store's own rules for a push: verified by the caller, ordered by
// issue between two rows that verify, the same bytes a no-op, a row that
// does not verify — no signature, a bit of it flipped, the document
// edited — replaced whatever its time.
func TestSetAllowlistOrdersByIssueAndReplacesAnUnsignedRow(t *testing.T) {
	s, alice, bob := directoryStore(t)
	at := time.Date(2026, 9, 17, 10, 4, 0, 0, time.UTC)

	// A row with its signature blanked and its issued moved into the
	// future, as an editor of the database could leave it: broken, and no
	// bar to a push.
	unsigned, _ := json.Marshal(&allowlist.Document{V: 1, Owner: alice.Fingerprint(), Issued: at.Add(time.Hour), Senders: []string{}})
	if _, err := s.db.Exec(`INSERT INTO allowlists (fp, doc, sig, issued, count) VALUES (?, ?, X'', ?, 0)`,
		alice.Fingerprint(), unsigned, at.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, _, state, _, _ := s.Allowlist(alice.Fingerprint()); state != relayapi.AllowBroken {
		t.Fatalf("state %q, want broken", state)
	}
	d, doc, sig := signedList(t, alice, at, bob.Fingerprint())
	if stored, err := s.SetAllowlist(alice.Fingerprint(), d, doc, sig); err != nil || !stored {
		t.Fatalf("a signed list over an unsigned row issued later: stored %v, %v", stored, err)
	}
	if _, _, state, _, _ := s.Allowlist(alice.Fingerprint()); state != relayapi.AllowSigned {
		t.Fatalf("state %q after the signed push, want signed", state)
	}

	// The same bytes again: nothing written, no error.
	if stored, err := s.SetAllowlist(alice.Fingerprint(), d, doc, sig); err != nil || stored {
		t.Fatalf("the same list again: stored %v, %v", stored, err)
	}
	// Issued earlier: refused, naming what is held.
	older, oldDoc, oldSig := signedList(t, alice, at.Add(-time.Second), bob.Fingerprint())
	_, err := s.SetAllowlist(alice.Fingerprint(), older, oldDoc, oldSig)
	var e *AllowlistOlderError
	if !errors.As(err, &e) || !e.Issued.Equal(at) {
		t.Fatalf("an older list: %v", err)
	}
	// The same instant, different bytes: refused too.
	same, sameDoc, sameSig := signedList(t, alice, at)
	if _, err := s.SetAllowlist(alice.Fingerprint(), same, sameDoc, sameSig); !errors.As(err, &e) {
		t.Fatalf("a different list at the same instant: %v", err)
	}
	// Issued later: replaces.
	newer, newDoc, newSig := signedList(t, alice, at.Add(time.Nanosecond))
	if stored, err := s.SetAllowlist(alice.Fingerprint(), newer, newDoc, newSig); err != nil || !stored {
		t.Fatalf("a newer list: stored %v, %v", stored, err)
	}
	got, _, _, _, _ := s.Allowlist(alice.Fingerprint())
	if string(got) != string(newDoc) {
		t.Fatal("the newer list was not stored")
	}
	// A row that no longer verifies, its issued moved an hour ahead by
	// the same editor: one bit of the signature flipped, then the
	// document edited under the intact signature. Each is broken, and no
	// bar to a push issued now, since the issued rule holds only between
	// two rows the owner signed; against the rule as it was, which read a
	// blank signature alone as no bar, the owner was refused for a time
	// an editor chose.
	ahead := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	flipped := append([]byte{}, newSig...)
	flipped[len(flipped)/2] ^= 0x01
	if _, err := s.db.Exec(`UPDATE allowlists SET sig = ?, issued = ? WHERE fp = ?`, flipped, ahead, alice.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, _, state, _, _ := s.Allowlist(alice.Fingerprint()); state != relayapi.AllowBroken {
		t.Fatalf("state %q with a flipped signature, want broken", state)
	}
	repair, repairDoc, repairSig := signedList(t, alice, time.Now(), bob.Fingerprint())
	if stored, err := s.SetAllowlist(alice.Fingerprint(), repair, repairDoc, repairSig); err != nil || !stored {
		t.Fatalf("a push over a flipped signature issued ahead: stored %v, %v", stored, err)
	}
	if _, _, state, _, _ := s.Allowlist(alice.Fingerprint()); state != relayapi.AllowSigned {
		t.Fatalf("state %q after the repair, want signed", state)
	}
	edited := strings.Replace(string(repairDoc), `"senders":[`, `"senders":["`+strings.Repeat("c", 64)+`",`, 1)
	if edited == string(repairDoc) {
		t.Fatal("the document has no senders array to edit")
	}
	if _, err := s.db.Exec(`UPDATE allowlists SET doc = ?, issued = ? WHERE fp = ?`, []byte(edited), ahead, alice.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, _, state, _, _ := s.Allowlist(alice.Fingerprint()); state != relayapi.AllowBroken {
		t.Fatalf("state %q with an edited document, want broken", state)
	}
	repair, repairDoc, repairSig = signedList(t, alice, time.Now(), bob.Fingerprint())
	if stored, err := s.SetAllowlist(alice.Fingerprint(), repair, repairDoc, repairSig); err != nil || !stored {
		t.Fatalf("a push over an edited document issued ahead: stored %v, %v", stored, err)
	}
	if got, _, state, _, _ := s.Allowlist(alice.Fingerprint()); state != relayapi.AllowSigned || string(got) != string(repairDoc) {
		t.Fatalf("after the repair: state %q, the bytes %v", state, string(got) == string(repairDoc))
	}
	// The issued column alone moved a century ahead, under a row that
	// still verifies: the column is not what the signature covers, and
	// the push is held to the time inside the document, so it is taken.
	// Against the rule as it was, the row read as signed and the column
	// barred every push with no broken state to name the repair.
	if _, err := s.db.Exec(`UPDATE allowlists SET issued = '2126-01-01T00:00:00Z' WHERE fp = ?`, alice.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, _, state, _, _ := s.Allowlist(alice.Fingerprint()); state != relayapi.AllowSigned {
		t.Fatalf("state %q with the column alone moved, want signed", state)
	}
	repair, repairDoc, repairSig = signedList(t, alice, time.Now(), bob.Fingerprint())
	if stored, err := s.SetAllowlist(alice.Fingerprint(), repair, repairDoc, repairSig); err != nil || !stored {
		t.Fatalf("a push over a verified row whose column alone was moved ahead: stored %v, %v", stored, err)
	}
	// And a column that is not a time at all is no failure either: the
	// column is never read to decide.
	if _, err := s.db.Exec(`UPDATE allowlists SET issued = 'yesterday' WHERE fp = ?`, alice.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	repair, repairDoc, repairSig = signedList(t, alice, time.Now(), bob.Fingerprint())
	if stored, err := s.SetAllowlist(alice.Fingerprint(), repair, repairDoc, repairSig); err != nil || !stored {
		t.Fatalf("a push over a verified row whose column is not a time: stored %v, %v", stored, err)
	}
	// No such mailbox.
	if _, err := s.SetAllowlist(strings.Repeat("0", 64), d, doc, sig); err != ErrNoMailbox {
		t.Fatalf("a push for no mailbox: %v", err)
	}
}
