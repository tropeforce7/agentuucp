package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// signedCard signs a card for owner, issued at the given time.
func signedCard(t *testing.T, owner *identity.Identity, at time.Time, listed, knocks bool) (*card.Document, []byte, []byte) {
	t.Helper()
	d := &card.Document{Issued: at, Name: owner.Name, Listed: listed, Knocks: knocks}
	doc, sig, err := card.Sign(owner, d)
	if err != nil {
		t.Fatal(err)
	}
	return d, doc, sig
}

// pushCard signs a card for owner and PUTs it as the caller.
func (h *harness) pushCard(caller, owner *identity.Identity, at time.Time, listed, knocks bool) (int, []byte, relayapi.CardRequest) {
	h.t.Helper()
	_, doc, sig := signedCard(h.t, owner, at, listed, knocks)
	req := relayapi.CardRequest{Document: doc, Signature: sig}
	status, body := h.do(caller, "PUT", "/v1/mailbox/"+owner.Fingerprint()+"/card", req, nil)
	return status, body, req
}

// getCard fetches a mailbox's card as the caller.
func (h *harness) getCard(caller *identity.Identity, fp string) (int, []byte, relayapi.CardResponse) {
	h.t.Helper()
	status, body := h.do(caller, "GET", "/v1/mailbox/"+fp+"/card", nil, nil)
	var resp relayapi.CardResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &resp); err != nil {
			h.t.Fatalf("the card response is not JSON: %s", body)
		}
	}
	return status, body, resp
}

// signRawCard encodes and signs a card without checking it, for the
// documents Sign would refuse to make. The domain is the wire's literal,
// pinned from outside the package that defines it.
func signRawCard(t *testing.T, id *identity.Identity, d *card.Document) relayapi.CardRequest {
	t.Helper()
	doc, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return relayapi.CardRequest{Document: doc, Signature: mustSign(t, id, append([]byte("ccx-card-v1"), doc...))}
}

// cardListState is what the owner's own listing says the card is.
func (h *harness) cardListState(owner *identity.Identity) string {
	h.t.Helper()
	status, body := h.do(owner, "GET", "/v1/mailbox/"+owner.Fingerprint(), nil, nil)
	if status != http.StatusOK {
		h.t.Fatalf("listing: %d %s", status, body)
	}
	var resp relayapi.ListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		h.t.Fatal(err)
	}
	return resp.Card
}

// The store's own rules for a push: verified by the caller, ordered by
// issue between two rows that verify, the same bytes a no-op, a row that
// does not verify — no signature, a bit of it flipped, the document
// edited — replaced whatever its time, and the two words parsed into
// their columns.
func TestSetCardOrdersByIssueAndReplacesAnUnsignedRow(t *testing.T) {
	s, alice, bob := directoryStore(t)
	at := time.Date(2026, 9, 22, 10, 4, 0, 0, time.UTC)
	fp := alice.Fingerprint()

	// A row with its signature blanked and its issued moved into the
	// future, as an editor of the database could leave it: broken, and no
	// bar to a push.
	unsigned, _ := json.Marshal(&card.Document{V: 1, Owner: fp, Issued: at.Add(time.Hour), Name: "alice", Listed: true, Knocks: true})
	if _, err := s.db.Exec(`INSERT INTO cards (fp, doc, sig, issued, listed, knocks) VALUES (?, ?, X'', ?, 1, 1)`,
		fp, unsigned, at.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, _, state, found, _ := s.Card(fp); state != relayapi.CardBroken || !found {
		t.Fatalf("state %q found %v, want broken", state, found)
	}
	d, doc, sig := signedCard(t, alice, at, true, false)
	if stored, err := s.SetCard(fp, d, doc, sig); err != nil || !stored {
		t.Fatalf("a signed card over an unsigned row issued later: stored %v, %v", stored, err)
	}
	if _, _, state, _, _ := s.Card(fp); state != relayapi.CardSigned {
		t.Fatalf("state %q after the signed push, want signed", state)
	}
	// The columns are the relay's parse of the document.
	var listed, knocks int
	if err := s.db.QueryRow(`SELECT listed, knocks FROM cards WHERE fp = ?`, fp).Scan(&listed, &knocks); err != nil {
		t.Fatal(err)
	}
	if listed != 1 || knocks != 0 {
		t.Fatalf("the columns say listed %d knocks %d, want 1 0", listed, knocks)
	}

	// The same bytes again: nothing written, no error.
	if stored, err := s.SetCard(fp, d, doc, sig); err != nil || stored {
		t.Fatalf("the same card again: stored %v, %v", stored, err)
	}
	// Issued earlier: refused, naming what is held.
	older, oldDoc, oldSig := signedCard(t, alice, at.Add(-time.Second), true, false)
	_, err := s.SetCard(fp, older, oldDoc, oldSig)
	var e *CardOlderError
	if !errors.As(err, &e) || !e.Issued.Equal(at) || !errors.Is(err, ErrCardOlder) {
		t.Fatalf("an older card: %v", err)
	}
	// The same instant, different bytes: refused too.
	same, sameDoc, sameSig := signedCard(t, alice, at, false, false)
	if _, err := s.SetCard(fp, same, sameDoc, sameSig); !errors.As(err, &e) {
		t.Fatalf("a different card at the same instant: %v", err)
	}
	// Issued later: replaces, and the columns follow.
	newer, newDoc, newSig := signedCard(t, alice, at.Add(time.Nanosecond), false, true)
	if stored, err := s.SetCard(fp, newer, newDoc, newSig); err != nil || !stored {
		t.Fatalf("a newer card: stored %v, %v", stored, err)
	}
	got, _, _, _, _ := s.Card(fp)
	if string(got) != string(newDoc) {
		t.Fatal("the newer card was not stored")
	}
	if err := s.db.QueryRow(`SELECT listed, knocks FROM cards WHERE fp = ?`, fp).Scan(&listed, &knocks); err != nil {
		t.Fatal(err)
	}
	if listed != 0 || knocks != 1 {
		t.Fatalf("the columns say listed %d knocks %d after the newer card, want 0 1", listed, knocks)
	}
	// A row that no longer verifies, its issued moved an hour ahead by
	// the same editor: one bit of the signature flipped, then the
	// document edited under the intact signature. Each is broken, and no
	// bar to a push issued now, since the issued rule holds only between
	// two rows the owner signed; against the rule as it was, the owner
	// was refused for a time an editor chose.
	ahead := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	flipped := append([]byte{}, newSig...)
	flipped[len(flipped)/2] ^= 0x01
	if _, err := s.db.Exec(`UPDATE cards SET sig = ?, issued = ? WHERE fp = ?`, flipped, ahead, fp); err != nil {
		t.Fatal(err)
	}
	if _, _, state, _, _ := s.Card(fp); state != relayapi.CardBroken {
		t.Fatalf("state %q with a flipped signature, want broken", state)
	}
	repair, repairDoc, repairSig := signedCard(t, alice, time.Now(), true, true)
	if stored, err := s.SetCard(fp, repair, repairDoc, repairSig); err != nil || !stored {
		t.Fatalf("a push over a flipped signature issued ahead: stored %v, %v", stored, err)
	}
	if _, _, state, _, _ := s.Card(fp); state != relayapi.CardSigned {
		t.Fatalf("state %q after the repair, want signed", state)
	}
	edited := strings.Replace(string(repairDoc), `"name":"alice"`, `"name":"malice"`, 1)
	if edited == string(repairDoc) {
		t.Fatal("the document has no name to edit")
	}
	if _, err := s.db.Exec(`UPDATE cards SET doc = ?, issued = ? WHERE fp = ?`, []byte(edited), ahead, fp); err != nil {
		t.Fatal(err)
	}
	if _, _, state, _, _ := s.Card(fp); state != relayapi.CardBroken {
		t.Fatalf("state %q with an edited document, want broken", state)
	}
	repair, repairDoc, repairSig = signedCard(t, alice, time.Now(), true, true)
	if stored, err := s.SetCard(fp, repair, repairDoc, repairSig); err != nil || !stored {
		t.Fatalf("a push over an edited document issued ahead: stored %v, %v", stored, err)
	}
	if got, _, state, _, _ := s.Card(fp); state != relayapi.CardSigned || string(got) != string(repairDoc) {
		t.Fatalf("after the repair: state %q, the bytes %v", state, string(got) == string(repairDoc))
	}
	// The issued column alone moved a century ahead, under a row that
	// still verifies: the column is not what the signature covers, and
	// the push is held to the time inside the document, so it is taken;
	// a column that is not a time at all is no failure either, since the
	// column is never read to decide.
	if _, err := s.db.Exec(`UPDATE cards SET issued = '2126-01-01T00:00:00Z' WHERE fp = ?`, fp); err != nil {
		t.Fatal(err)
	}
	if _, _, state, _, _ := s.Card(fp); state != relayapi.CardSigned {
		t.Fatalf("state %q with the column alone moved, want signed", state)
	}
	repair, repairDoc, repairSig = signedCard(t, alice, time.Now(), true, true)
	if stored, err := s.SetCard(fp, repair, repairDoc, repairSig); err != nil || !stored {
		t.Fatalf("a push over a verified row whose column alone was moved ahead: stored %v, %v", stored, err)
	}
	if _, err := s.db.Exec(`UPDATE cards SET issued = 'yesterday' WHERE fp = ?`, fp); err != nil {
		t.Fatal(err)
	}
	repair, repairDoc, repairSig = signedCard(t, alice, time.Now(), true, true)
	if stored, err := s.SetCard(fp, repair, repairDoc, repairSig); err != nil || !stored {
		t.Fatalf("a push over a verified row whose column is not a time: stored %v, %v", stored, err)
	}
	// No such mailbox.
	if _, err := s.SetCard(strings.Repeat("0", 64), d, doc, sig); err != ErrNoMailbox {
		t.Fatalf("a push for no mailbox: %v", err)
	}
	if _, _, _, _, err := s.Card(strings.Repeat("0", 64)); err != ErrNoMailbox {
		t.Fatalf("a read for no mailbox: %v", err)
	}
	// A mailbox that has never pushed: none, not found.
	if _, _, state, found, err := s.Card(bob.Fingerprint()); err != nil || found || state != relayapi.CardNone {
		t.Fatalf("a mailbox with no card: %q found %v %v", state, found, err)
	}
}

// The push is the owner's alone, checked in the order the plan gives: the
// caller, the body, the signature, the rules, the owner, the store. A
// request with no document has no signature that verifies, and is
// refused as such.
func TestOnlyTheOwnerPushesACard(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	at := time.Date(2026, 9, 22, 10, 4, 0, 0, time.UTC)
	fp := bob.Fingerprint()
	stored := func() bool {
		_, _, _, found, err := h.store.Card(fp)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}

	// Another identity, with a card bob signed: refused before the body is
	// looked at.
	status, body, _ := h.pushCard(alice, bob, at, true, true)
	if status != http.StatusForbidden || errorText(t, body) != "not your mailbox" {
		t.Fatalf("another identity's push: %d %s", status, body)
	}
	if stored() {
		t.Fatal("a push by another identity was stored")
	}

	// A body that is not a card request.
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card", []byte(`[1,2]`), nil)
	if status != http.StatusBadRequest || errorText(t, body) != "malformed card request" {
		t.Fatalf("a malformed body: %d %s", status, body)
	}
	// A request with no document: an empty object, and one with a field
	// the request does not have. Each is refused as a signature that does
	// not verify, since there is none, and nothing is stored.
	for _, req := range []string{`{}`, `{"listed":true}`} {
		status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card", []byte(req), nil)
		if status != http.StatusUnauthorized || errorText(t, body) != "card signature does not verify" {
			t.Fatalf("a request with no document, %s: %d %s", req, status, body)
		}
		if stored() {
			t.Fatalf("a request with no document, %s, was stored", req)
		}
	}

	// Signed for bob's mailbox but under alice's key.
	doc, _ := json.Marshal(&card.Document{V: 1, Owner: fp, Issued: at, Name: "bob", Listed: true, Knocks: true})
	wrongKey := mustSign(t, alice, append([]byte("ccx-card-v1"), doc...))
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card",
		relayapi.CardRequest{Document: doc, Signature: wrongKey}, nil)
	if status != http.StatusUnauthorized || errorText(t, body) != "card signature does not verify" {
		t.Fatalf("a card under the wrong key: %d %s", status, body)
	}
	// A document with no signature at all.
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card", relayapi.CardRequest{Document: doc}, nil)
	if status != http.StatusUnauthorized || errorText(t, body) != "card signature does not verify" {
		t.Fatalf("a document with no signature: %d %s", status, body)
	}
	if stored() {
		t.Fatal("a card under the wrong key was stored")
	}

	// A rule broken under bob's own key: the validator's sentence. Sign
	// refuses to make it, so it is signed by hand.
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card",
		signRawCard(t, bob, &card.Document{V: 1, Owner: fp, Issued: at, Name: "", Listed: true}), nil)
	if status != http.StatusBadRequest || errorText(t, body) != "name is empty" {
		t.Fatalf("an invalid card: %d %s", status, body)
	}
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card",
		signRawCard(t, bob, &card.Document{V: 1, Owner: fp, Issued: at, Name: strings.Repeat("b", 65)}), nil)
	if status != http.StatusBadRequest || errorText(t, body) != "name is 65 bytes; at most 64" {
		t.Fatalf("a name over the cap: %d %s", status, body)
	}
	// And one the decoder refuses.
	with := strings.Replace(string(doc), `"v":1,`, `"v":1,"colour":"blue",`, 1)
	withSig := mustSign(t, bob, append([]byte("ccx-card-v1"), with...))
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card",
		relayapi.CardRequest{Document: []byte(with), Signature: withSig}, nil)
	if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), `unknown field "colour"`) {
		t.Fatalf("an unknown field: %d %s", status, body)
	}

	// Bob's key over a document naming alice as owner.
	forged, _ := json.Marshal(&card.Document{V: 1, Owner: alice.Fingerprint(), Issued: at, Name: "bob"})
	forgedSig := mustSign(t, bob, append([]byte("ccx-card-v1"), forged...))
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card",
		relayapi.CardRequest{Document: forged, Signature: forgedSig}, nil)
	if status != http.StatusBadRequest || errorText(t, body) != "card owner is not this mailbox" {
		t.Fatalf("a document naming another owner: %d %s", status, body)
	}
	if stored() {
		t.Fatal("a refused card was stored")
	}

	// A document padded past the card's cap, signed by bob: refused by
	// the length, before the signature, with the sentence naming the
	// bytes and the cap; at the cap it is taken. The route's body cap is
	// 64 KiB, and without this a padded card took every reader's page
	// over its hold.
	earlier, _ := json.Marshal(&card.Document{V: 1, Owner: fp, Issued: at.Add(-time.Second), Name: "bob", Listed: true, Knocks: true})
	pad := func(n int) []byte {
		out := append([]byte{}, earlier[:len(earlier)-1]...)
		out = append(out, strings.Repeat(" ", n-len(earlier))...)
		return append(out, '}')
	}
	over := pad(relayapi.MaxCardBytes + 1)
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card",
		relayapi.CardRequest{Document: over, Signature: mustSign(t, bob, append([]byte("ccx-card-v1"), over...))}, nil)
	if status != http.StatusBadRequest || errorText(t, body) != fmt.Sprintf("card is malformed: the card is %d bytes; at most %d, so send it compact", relayapi.MaxCardBytes+1, relayapi.MaxCardBytes) {
		t.Fatalf("a card one over its cap: %d %s", status, body)
	}
	if stored() {
		t.Fatal("a card over its cap was stored")
	}
	atCap := pad(relayapi.MaxCardBytes)
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card",
		relayapi.CardRequest{Document: atCap, Signature: mustSign(t, bob, append([]byte("ccx-card-v1"), atCap...))}, nil)
	if status != http.StatusNoContent {
		t.Fatalf("a card at its cap: %d %s", status, body)
	}
	if got, _, _, _, _ := h.store.Card(fp); string(got) != string(atCap) {
		t.Fatal("the padded card at the cap was not stored as signed")
	}

	// The good one, stored verbatim with the parsed columns.
	status, body, req := h.pushCard(bob, bob, at, true, false)
	if status != http.StatusNoContent {
		t.Fatalf("the owner's push: %d %s", status, body)
	}
	got, sig, state, found, err := h.store.Card(fp)
	if err != nil || !found || state != relayapi.CardSigned ||
		string(got) != string(req.Document) || string(sig) != string(req.Signature) {
		t.Fatalf("the pushed card is not what was stored: %q %v %v", state, found, err)
	}
	rec, err := h.store.MailboxRecord(fp)
	if err != nil || rec.Card != relayapi.CardSigned || !rec.CardListed || rec.CardKnocks {
		t.Fatalf("the administrator's record: %+v, %v", rec, err)
	}

	// Pushed again, the very same bytes: a no-op 204. Issued no later,
	// different bytes: 409 naming what is held.
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+fp+"/card", req, nil)
	if status != http.StatusNoContent {
		t.Fatalf("the same card again: %d %s", status, body)
	}
	status, body, _ = h.pushCard(bob, bob, at.Add(-time.Second), true, false)
	if status != http.StatusConflict || errorText(t, body) != "a newer card is already there (issued 2026-09-22T10:04:00Z)" {
		t.Fatalf("an older card: %d %s", status, body)
	}
	status, body, _ = h.pushCard(bob, bob, at, false, false)
	if status != http.StatusConflict {
		t.Fatalf("a different card at the same instant: %d %s", status, body)
	}
	if got, _, _, _, _ := h.store.Card(fp); string(got) != string(req.Document) {
		t.Fatal("a refused push replaced the stored card")
	}
}

// The fetch is the owner's alone and gives the pair back verbatim, with
// the state; a mailbox that has never pushed answers none; the owner's
// listing carries the state on every page.
func TestTheOwnerReadsTheirCardBack(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	status, body, resp := h.getCard(bob, bob.Fingerprint())
	if status != http.StatusOK || resp.State != relayapi.CardNone || len(resp.Document) != 0 {
		t.Fatalf("with no card: %d %s", status, body)
	}
	if !strings.Contains(string(body), `"state":"none"`) {
		t.Fatalf("the state is not always present: %s", body)
	}
	if got := h.cardListState(bob); got != relayapi.CardNone {
		t.Fatalf("the listing says %q with no card, want none", got)
	}
	status, body, _ = h.getCard(alice, bob.Fingerprint())
	if status != http.StatusForbidden || errorText(t, body) != "not your mailbox" {
		t.Fatalf("another identity's fetch: %d %s", status, body)
	}
	_, _, pushed := h.pushCard(bob, bob, time.Now(), true, true)
	status, body, resp = h.getCard(bob, bob.Fingerprint())
	if status != http.StatusOK || resp.State != relayapi.CardSigned ||
		string(resp.Document) != string(pushed.Document) || string(resp.Signature) != string(pushed.Signature) {
		t.Fatalf("the owner's fetch: %d %s", status, body)
	}
	// And the pair verifies with the owner's key, as the client checks.
	if _, err := card.Verify(bob.Public(), resp.Document, resp.Signature); err != nil {
		t.Fatalf("the served pair does not verify: %v", err)
	}
	if got := h.cardListState(bob); got != relayapi.CardSigned {
		t.Fatalf("the listing says %q after a push, want signed", got)
	}
	// The tag: the zero value names the field, so absence and none are
	// two things.
	if zero, _ := json.Marshal(relayapi.ListResponse{}); !strings.Contains(string(zero), `"card":""`) {
		t.Fatalf("the zero listing does not name card: %s", zero)
	}
	if zero, _ := json.Marshal(relayapi.CardResponse{}); !strings.Contains(string(zero), `"state":""`) {
		t.Fatalf("the zero card answer does not name state: %s", zero)
	}
}

// When the threat is the host: the row is edited through the store's own
// handle, and the relay reads it back broken — the owner's listing, the
// owner's fetch and the administrator's record all say so — until the
// owner pushes again. One byte of the signature, the signature blanked,
// and the document changed under an intact signature, each.
func TestAnEditedCardReadsBackBroken(t *testing.T) {
	h := newHarness(t, Config{})
	bob := ids(t, "bob")[0]
	h.register(bob)
	fp := bob.Fingerprint()
	push := func() {
		t.Helper()
		if status, body, _ := h.pushCard(bob, bob, time.Now(), true, true); status != http.StatusNoContent {
			t.Fatalf("card push: %d %s", status, body)
		}
	}
	broken := func(t *testing.T, edit string) {
		t.Helper()
		if got := h.cardListState(bob); got != relayapi.CardBroken {
			t.Fatalf("%s: the owner's listing says %q, want broken", edit, got)
		}
		if _, _, resp := h.getCard(bob, fp); resp.State != relayapi.CardBroken {
			t.Fatalf("%s: the owner's fetch says %q, want broken", edit, resp.State)
		}
		rec, err := h.store.MailboxRecord(fp)
		if err != nil || rec.Card != relayapi.CardBroken {
			t.Fatalf("%s: the administrator's record: %+v, %v", edit, rec, err)
		}
	}
	push()

	t.Run("one byte of the signature, issued moved ahead", func(t *testing.T) {
		// The editor moves issued a day ahead too: the push is taken all
		// the same, since the row does not verify, and the owner is not
		// answered 409 for a time an editor chose.
		_, sig, _, _, _ := h.store.Card(fp)
		changed := append([]byte{}, sig...)
		changed[len(changed)/2] ^= 0x01
		ahead := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
		if _, err := h.store.db.Exec(`UPDATE cards SET sig = ?, issued = ? WHERE fp = ?`, changed, ahead, fp); err != nil {
			t.Fatal(err)
		}
		broken(t, "one byte of the signature")
		push()
		if got := h.cardListState(bob); got != relayapi.CardSigned {
			t.Fatalf("after the repair the listing says %q, want signed", got)
		}
	})
	t.Run("the signature blanked", func(t *testing.T) {
		if _, err := h.store.db.Exec(`UPDATE cards SET sig = X'' WHERE fp = ?`, fp); err != nil {
			t.Fatal(err)
		}
		broken(t, "the signature blanked")
		push()
	})
	t.Run("the document changed", func(t *testing.T) {
		doc, _, _, _, _ := h.store.Card(fp)
		edited := strings.Replace(string(doc), `"name":"bob"`, `"name":"rob"`, 1)
		if edited == string(doc) {
			t.Fatal("the document has no name to edit")
		}
		if _, err := h.store.db.Exec(`UPDATE cards SET doc = ? WHERE fp = ?`, []byte(edited), fp); err != nil {
			t.Fatal(err)
		}
		broken(t, "the document changed")
		push()
	})
	t.Run("the columns edited under an intact document", func(t *testing.T) {
		// The columns decide nothing: the record's words follow them,
		// and the state follows the signature, which is intact.
		if _, err := h.store.db.Exec(`UPDATE cards SET listed = 0, knocks = 0 WHERE fp = ?`, fp); err != nil {
			t.Fatal(err)
		}
		if got := h.cardListState(bob); got != relayapi.CardSigned {
			t.Fatalf("the listing says %q with the columns edited, want signed", got)
		}
		rec, _ := h.store.MailboxRecord(fp)
		if rec.Card != relayapi.CardSigned || rec.CardListed || rec.CardKnocks {
			t.Fatalf("the administrator's record: %+v", rec)
		}
		push()
	})
}

// Deregistering a mailbox takes its card with it, by the cascade.
func TestDeregisteringAMailboxRemovesItsCard(t *testing.T) {
	h := newHarness(t, Config{})
	bob := ids(t, "bob")[0]
	h.register(bob)
	fp := bob.Fingerprint()
	if status, body, _ := h.pushCard(bob, bob, time.Now(), true, true); status != http.StatusNoContent {
		t.Fatalf("card push: %d %s", status, body)
	}
	if gone, err := h.store.Deregister(fp); err != nil || !gone {
		t.Fatalf("deregister: %v %v", gone, err)
	}
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM cards WHERE fp = ?`, fp).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d card rows left after deregistering", n)
	}
}

// The health answer carries the registration mode, always, as each mode
// the relay can be in; a health answer is unsigned, so the word is the
// relay's own and the client says so wherever it prints it.
func TestTheHealthAnswerCarriesTheRegistrationMode(t *testing.T) {
	for _, mode := range []string{"", relayapi.RegistrationOpen, relayapi.RegistrationToken, relayapi.RegistrationClosed} {
		cfg := Config{Registration: mode}
		if mode == relayapi.RegistrationToken {
			admin := ids(t, "admin")[0]
			path := adminFile(t, admin)
			loaded, err := LoadAdmins(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg.AdminFile, cfg.Admins = path, loaded
		}
		h := newHarness(t, cfg)
		status, body := h.do(nil, "GET", "/v1/health", nil, nil)
		if status != http.StatusOK {
			t.Fatalf("health: %d %s", status, body)
		}
		var resp relayapi.HealthResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
		want := mode
		if want == "" {
			want = relayapi.RegistrationOpen
		}
		if resp.Registration != want || !strings.Contains(string(body), `"registration":"`+want+`"`) {
			t.Fatalf("with registration %q the health answer says %q (%s); want %q, always present", mode, resp.Registration, body, want)
		}
	}
	// The tag: the zero value names the field.
	if zero, _ := json.Marshal(relayapi.HealthResponse{}); !strings.Contains(string(zero), `"registration":""`) {
		t.Fatalf("the zero health answer does not name registration: %s", zero)
	}
}

// listed fetches one page of the card listing as the caller.
func (h *harness) listed(caller *identity.Identity, query string) (int, []byte, relayapi.ListedResponse) {
	h.t.Helper()
	status, body := h.do(caller, "GET", "/v1/listed"+query, nil, nil)
	var resp relayapi.ListedResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &resp); err != nil {
			h.t.Fatalf("the listing is not JSON: %s", body)
		}
	}
	return status, body, resp
}

// The listing: every card that says listed, with its bundle, in
// fingerprint order, and none that says otherwise or has no card; the
// count of listed cards in all; after and limit paging through them; a
// blocked owner left out of the page and the count; the relay serving
// stored bytes without verifying, so an edited row goes out as stored for
// the reader to drop.
func TestTheListingServesEveryListedCardInFingerprintOrder(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "carol", "dave", "erin", "frank")
	for _, id := range people {
		h.register(id)
	}
	// alice, bob and carol listed; dave's card says no; erin has none;
	// frank listed and then blocked.
	listed := []*identity.Identity{people[0], people[1], people[2], people[5]}
	for _, id := range listed {
		if status, body, _ := h.pushCard(id, id, time.Now(), true, false); status != http.StatusNoContent {
			t.Fatalf("%s's push: %d %s", id.Name, status, body)
		}
	}
	if status, body, _ := h.pushCard(people[3], people[3], time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("dave's push: %d %s", status, body)
	}
	if err := h.store.SetBlock(people[5].Fingerprint(), "gone", people[0].Fingerprint(), time.Now()); err != nil {
		t.Fatal(err)
	}
	want := listed[:3]
	sort.Slice(want, func(i, j int) bool { return want[i].Fingerprint() < want[j].Fingerprint() })

	status, body, page := h.listed(people[4], "")
	if status != http.StatusOK {
		t.Fatalf("the listing: %d %s", status, body)
	}
	if page.Listed != 3 || len(page.Entries) != 3 {
		t.Fatalf("listed %d, %d entries; want 3 and 3", page.Listed, len(page.Entries))
	}
	for i, e := range page.Entries {
		pub, err := identity.ParseBundle(e.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		if pub.Fingerprint() != want[i].Fingerprint() {
			t.Fatalf("entry %d is %s, want %s: not in fingerprint order or not the listed set", i, pub.Short(), want[i].Public().Short())
		}
		d, err := card.Verify(pub, e.Document, e.Signature)
		if err != nil || !d.Listed || d.Name != want[i].Name {
			t.Fatalf("entry %d does not verify as its owner's listed card: %v", i, err)
		}
	}
	// The tags: entries and listed are always present, entries [] past
	// the end.
	if !strings.Contains(string(body), `"listed":3`) || !strings.Contains(string(body), `"entries":[`) {
		t.Fatalf("the answer lacks a field: %s", body)
	}
	status, body, page = h.listed(people[4], "?after="+want[2].Fingerprint())
	if status != http.StatusOK || len(page.Entries) != 0 || page.Listed != 3 || !strings.Contains(string(body), `"entries":[]`) {
		t.Fatalf("the page past the end: %d %s", status, body)
	}
	if zero, _ := json.Marshal(relayapi.ListedResponse{}); !strings.Contains(string(zero), `"entries":null`) || !strings.Contains(string(zero), `"listed":0`) {
		t.Fatalf("the zero answer does not name both fields: %s", zero)
	}

	// Paging: one at a time from each fingerprint, and the count the same
	// on every page.
	after := ""
	var got []string
	for {
		status, body, page := h.listed(people[4], "?limit=1&after="+after)
		if status != http.StatusOK {
			t.Fatalf("a page: %d %s", status, body)
		}
		if page.Listed != 3 {
			t.Fatalf("the count on a page is %d, want 3", page.Listed)
		}
		if len(page.Entries) == 0 {
			break
		}
		if len(page.Entries) != 1 {
			t.Fatalf("limit=1 gave %d entries", len(page.Entries))
		}
		pub, _ := identity.ParseBundle(page.Entries[0].Bundle)
		got = append(got, pub.Fingerprint())
		after = pub.Fingerprint()
	}
	if len(got) != 3 || got[0] != want[0].Fingerprint() || got[2] != want[2].Fingerprint() {
		t.Fatalf("paging one at a time gave %v", got)
	}

	// The blocked owner is left out; unblocked, in again, and the count
	// follows.
	if _, err := h.store.RemoveBlock(people[5].Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, _, page := h.listed(people[4], ""); page.Listed != 4 || len(page.Entries) != 4 {
		t.Fatalf("after the unblock: listed %d, %d entries; want 4 and 4", page.Listed, len(page.Entries))
	}

	// Served as stored: a row edited to say listed on a card that says
	// no goes out, and the reader is what drops it; and a signature
	// blanked is served blank. The relay verifies nothing here.
	if _, err := h.store.db.Exec(`UPDATE cards SET listed = 1 WHERE fp = ?`, people[3].Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.db.Exec(`UPDATE cards SET sig = X'' WHERE fp = ?`, people[0].Fingerprint()); err != nil {
		t.Fatal(err)
	}
	_, _, page = h.listed(people[4], "")
	if page.Listed != 5 || len(page.Entries) != 5 {
		t.Fatalf("with two edited rows: listed %d, %d entries; want 5 and 5, the relay serving as stored", page.Listed, len(page.Entries))
	}
	blank, unlisted := 0, 0
	for _, e := range page.Entries {
		if len(e.Signature) == 0 {
			blank++
		}
		pub, _ := identity.ParseBundle(e.Bundle)
		if d, err := card.Verify(pub, e.Document, e.Signature); err == nil && !d.Listed {
			unlisted++
		}
	}
	if blank != 1 || unlisted != 1 {
		t.Fatalf("the edited rows were not served as stored: %d blank, %d saying no", blank, unlisted)
	}
}

// The listing is for a registered, unblocked identity: a certificate
// alone, which the key lookup takes, is not enough, and a blocked
// caller is refused before the listing is read.
func TestTheListingIsForARegisteredUnblockedIdentity(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "stranger", "blocked")
	alice, stranger, blocked := people[0], people[1], people[2]
	h.register(alice)
	h.register(blocked)
	if status, body, _ := h.pushCard(alice, alice, time.Now(), true, false); status != http.StatusNoContent {
		t.Fatalf("alice's push: %d %s", status, body)
	}
	// An identity no mailbox has, signing a well-formed request: 401, the
	// one word every authentication failure gets.
	status, body, _ := h.listed(stranger, "")
	if status != http.StatusUnauthorized || errorText(t, body) != "unauthorized" {
		t.Fatalf("a stranger with no mailbox: %d %s", status, body)
	}
	// No signature at all.
	status, body, _ = h.listed(nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("no signature: %d %s", status, body)
	}
	if err := h.store.SetBlock(blocked.Fingerprint(), "gone", alice.Fingerprint(), time.Now()); err != nil {
		t.Fatal(err)
	}
	status, body, _ = h.listed(blocked, "")
	if status != http.StatusForbidden || errorText(t, body) != msgBlocked {
		t.Fatalf("a blocked caller: %d %s", status, body)
	}
	// And a registered one is answered.
	if status, body, page := h.listed(alice, ""); status != http.StatusOK || len(page.Entries) != 1 {
		t.Fatalf("the owner's own listing: %d %s", status, body)
	}
}

// TestLimitTheListingParameters: after is a fingerprint or absent, refused
// by name before it reaches SQL; limit is held to [1, MaxListedLimit] and
// refused by name outside it rather than served at the cap, since a
// client sizes what it holds of a page to the cap and would refuse more —
// 0, 101, -1, the type's extremes, and the text forms that bite.
func TestLimitTheListingParameters(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)
	for _, tc := range []struct{ param, value string }{
		{"after", "ab"}, {"after", strings.Repeat("a", 63)}, {"after", strings.Repeat("a", 65)},
		{"after", strings.Repeat("A", 64)}, {"after", "%20" + strings.Repeat("a", 63)}, {"after", "../x"},
		{"limit", "0"}, {"limit", strconv.Itoa(relayapi.MaxListedLimit + 1)}, {"limit", "-1"}, {"limit", "-0"},
		{"limit", strconv.FormatInt(math.MinInt64, 10)}, {"limit", strconv.FormatInt(math.MaxInt64, 10)},
		{"limit", "9223372036854775808"}, {"limit", "%201"}, {"limit", "١"}, {"limit", "1e2"}, {"limit", "0x10"},
	} {
		status, body, _ := h.listed(alice, "?"+tc.param+"="+tc.value)
		if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), "bad "+tc.param+" parameter") {
			t.Errorf("%s=%s: %d %s; want 400 naming the parameter", tc.param, tc.value, status, body)
		}
	}
	if status, body, _ := h.listed(alice, "?limit="+strconv.Itoa(relayapi.MaxListedLimit+1)); status != http.StatusBadRequest ||
		errorText(t, body) != fmt.Sprintf("bad limit parameter: from 1 to %d", relayapi.MaxListedLimit) {
		t.Errorf("one over the cap: %d %s; want the sentence naming the range", status, body)
	}
	for _, query := range []string{"", "?limit=1", "?limit=%2B1", "?limit=" + strconv.Itoa(relayapi.MaxListedLimit),
		"?after=" + strings.Repeat("a", 64), "?after=" + strings.Repeat("f", 64)} {
		if status, body, _ := h.listed(alice, query); status != http.StatusOK {
			t.Errorf("%q: %d %s; want 200", query, status, body)
		}
	}
}
