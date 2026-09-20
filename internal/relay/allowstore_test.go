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
// issue, the same bytes a no-op, a row with no signature replaced whatever
// its time.
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
	// No such mailbox.
	if _, err := s.SetAllowlist(strings.Repeat("0", 64), d, doc, sig); err != ErrNoMailbox {
		t.Fatalf("a push for no mailbox: %v", err)
	}
}
