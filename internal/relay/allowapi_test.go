package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// allowReq is what a client sends: the signed document and its signature,
// issued now.
func (h *harness) allowReq(owner *identity.Identity, senders ...string) relayapi.AllowRequest {
	h.t.Helper()
	return h.allowReqAt(owner, time.Now(), senders...)
}

func (h *harness) allowReqAt(owner *identity.Identity, at time.Time, senders ...string) relayapi.AllowRequest {
	h.t.Helper()
	_, doc, sig := signedList(h.t, owner, at, senders...)
	return relayapi.AllowRequest{Document: doc, Signature: sig}
}

// pushAllow signs a list for owner and PUTs it as the caller.
func (h *harness) pushAllow(caller, owner *identity.Identity, at time.Time, senders ...string) (int, []byte, relayapi.AllowRequest) {
	h.t.Helper()
	req := h.allowReqAt(owner, at, senders...)
	status, body := h.do(caller, "PUT", "/v1/mailbox/"+owner.Fingerprint()+"/allow", req, nil)
	return status, body, req
}

// getAllow fetches a mailbox's list as the caller.
func (h *harness) getAllow(caller *identity.Identity, fp string) (int, []byte, relayapi.AllowResponse) {
	h.t.Helper()
	status, body := h.do(caller, "GET", "/v1/mailbox/"+fp+"/allow", nil, nil)
	var resp relayapi.AllowResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &resp); err != nil {
			h.t.Fatalf("the allow response is not JSON: %s", body)
		}
	}
	return status, body, resp
}

// signRawAllow encodes and signs a list without checking it, for the
// documents Sign would refuse to make.
func signRawAllow(t *testing.T, id *identity.Identity, d *allowlist.Document) relayapi.AllowRequest {
	t.Helper()
	doc, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return relayapi.AllowRequest{Document: doc, Signature: mustSign(t, id, append([]byte("ccx-allow-v1"), doc...))}
}

// listState is what the owner's own listing says the allow list is.
func (h *harness) listState(owner *identity.Identity) string {
	h.t.Helper()
	status, body := h.do(owner, "GET", "/v1/mailbox/"+owner.Fingerprint(), nil, nil)
	if status != http.StatusOK {
		h.t.Fatalf("listing: %d %s", status, body)
	}
	var resp relayapi.ListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		h.t.Fatal(err)
	}
	return resp.Allow
}

const refusedSender = "sender is not on the recipient's allow list"

// The rule the old table enforced, proved again against the new shape:
// with no list any registered sender may post, a list admits those it
// names, and a list of nobody reopens the mailbox.
func TestAllowlistBlocksUnlistedSender(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	for _, id := range people {
		h.register(id)
	}

	if status, body := h.do(carol, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, carol, bob.Public(), "hi"), nil); status != http.StatusOK {
		t.Fatalf("expected open mailbox to accept carol: %d %s", status, body)
	}
	if got := h.listState(bob); got != relayapi.AllowNone {
		t.Fatalf("the listing says %q with no list, want none", got)
	}

	// Bob restricts his mailbox to alice.
	status, body, _ := h.pushAllow(bob, bob, time.Now(), alice.Fingerprint())
	if status != http.StatusNoContent {
		t.Fatalf("allow push: %d %s", status, body)
	}
	if status, body := h.do(carol, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, carol, bob.Public(), "hi again"), nil); status != http.StatusForbidden || errorText(t, body) != refusedSender {
		t.Fatalf("expected 403 for unlisted sender, got %d %s", status, body)
	}
	if status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, alice, bob.Public(), "hello"), nil); status != http.StatusOK {
		t.Fatalf("expected listed sender to pass: %d %s", status, body)
	}
	// And bob himself, from any machine holding his key.
	if status, body := h.do(bob, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, bob, bob.Public(), "note to self"), nil); status != http.StatusOK {
		t.Fatalf("the owner's own post: %d %s", status, body)
	}
	if got := h.listState(bob); got != relayapi.AllowSigned {
		t.Fatalf("the listing says %q after a push, want signed", got)
	}

	// A list of nobody reopens the mailbox, and is signed all the same.
	status, body, _ = h.pushAllow(bob, bob, time.Now())
	if status != http.StatusNoContent {
		t.Fatalf("allow clear: %d %s", status, body)
	}
	if status, _ := h.do(carol, "POST", "/v1/mailbox/"+bob.Fingerprint(),
		sealed(t, carol, bob.Public(), "third"), nil); status != http.StatusOK {
		t.Fatal("expected cleared allowlist to reopen the mailbox")
	}
	if got := h.listState(bob); got != relayapi.AllowSigned {
		t.Fatalf("the listing says %q after a clear, want signed", got)
	}
	rec, err := h.store.MailboxRecord(bob.Fingerprint())
	if err != nil || rec.AllowlistSize != 0 || rec.Allow != relayapi.AllowSigned {
		t.Fatalf("bob's record after a clear: %+v, %v", rec, err)
	}
}

// The push is the owner's alone, checked in the order the plan gives: the
// caller, the body, the document's presence, the signature, the rules,
// the owner, the store.
func TestOnlyTheOwnerPushesAnAllowlist(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	at := time.Date(2026, 9, 17, 10, 4, 0, 0, time.UTC)
	stored := func() bool {
		_, _, _, found, err := h.store.Allowlist(bob.Fingerprint())
		if err != nil {
			t.Fatal(err)
		}
		return found
	}

	// Another identity, with a list bob signed: refused before the body is
	// looked at.
	status, body, _ := h.pushAllow(alice, bob, at, alice.Fingerprint())
	if status != http.StatusForbidden || errorText(t, body) != "not your mailbox" {
		t.Fatalf("another identity's push: %d %s", status, body)
	}
	if stored() {
		t.Fatal("a push by another identity was stored")
	}

	// A body that is not an allow request.
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow", []byte(`[1,2]`), nil)
	if status != http.StatusBadRequest || errorText(t, body) != "malformed allow request" {
		t.Fatalf("a malformed body: %d %s", status, body)
	}

	// A request with no document: a plain array of senders, which is not
	// a field the request has, an empty array, and an empty object — each
	// the sentence saying what was missing, and nothing stored, not the
	// array and not an empty list.
	// The sentence is pinned as a person reads it: it names no version.
	const noDocument = "this relay takes a signed allow list; the request carries no document"
	if relayapi.MsgNeedSignedAllowlist != noDocument {
		t.Fatalf("the no-document sentence is %q, want %q", relayapi.MsgNeedSignedAllowlist, noDocument)
	}
	for _, req := range []string{
		`{"allow":["` + alice.Fingerprint() + `"]}`,
		`{"allow":[]}`,
		`{}`,
	} {
		status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow", []byte(req), nil)
		if status != http.StatusBadRequest || errorText(t, body) != noDocument {
			t.Fatalf("a request with no document, %s: %d %s", req, status, body)
		}
		if stored() {
			t.Fatalf("a request with no document, %s, was stored", req)
		}
	}

	// Signed by bob's mailbox but under alice's key.
	doc, _ := json.Marshal(&allowlist.Document{V: 1, Owner: bob.Fingerprint(), Issued: at, Senders: []string{alice.Fingerprint()}})
	wrongKey := mustSign(t, alice, append([]byte("ccx-allow-v1"), doc...))
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow",
		relayapi.AllowRequest{Document: doc, Signature: wrongKey}, nil)
	if status != http.StatusUnauthorized || errorText(t, body) != "allow list signature does not verify" {
		t.Fatalf("a list under the wrong key: %d %s", status, body)
	}
	// A document with no signature at all: not the no-document sentence,
	// since a document was sent, and not stored.
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow",
		relayapi.AllowRequest{Document: doc}, nil)
	if status != http.StatusUnauthorized || errorText(t, body) != "allow list signature does not verify" {
		t.Fatalf("a document with no signature: %d %s", status, body)
	}
	if stored() {
		t.Fatal("a list under the wrong key was stored")
	}

	// A rule broken under bob's own key: the validator's sentence. Sign
	// refuses to make it, so it is signed by hand.
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow",
		signRawAllow(t, bob, &allowlist.Document{V: 1, Owner: bob.Fingerprint(), Issued: at,
			Senders: []string{alice.Fingerprint(), bob.Fingerprint()}}), nil)
	if status != http.StatusBadRequest {
		t.Fatalf("an invalid list: %d %s", status, body)
	}
	if got := errorText(t, body); got != `sender "`+bob.Fingerprint()+`": is the owner, who is always admitted` {
		t.Fatalf("the refusal is %q, not the validator's sentence", got)
	}
	// And one the decoder refuses.
	with := strings.Replace(string(doc), `"v":1,`, `"v":1,"colour":"blue",`, 1)
	withSig := mustSign(t, bob, append([]byte("ccx-allow-v1"), with...))
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow",
		relayapi.AllowRequest{Document: []byte(with), Signature: withSig}, nil)
	if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), `unknown field "colour"`) {
		t.Fatalf("an unknown field: %d %s", status, body)
	}

	// Bob's key over a document naming alice as owner.
	forged, _ := json.Marshal(&allowlist.Document{V: 1, Owner: alice.Fingerprint(), Issued: at, Senders: []string{}})
	forgedSig := mustSign(t, bob, append([]byte("ccx-allow-v1"), forged...))
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow",
		relayapi.AllowRequest{Document: forged, Signature: forgedSig}, nil)
	if status != http.StatusBadRequest || errorText(t, body) != "allow list owner is not this mailbox" {
		t.Fatalf("a document naming another owner: %d %s", status, body)
	}
	if stored() {
		t.Fatal("a refused list was stored")
	}

	// The good one, stored verbatim; a field the request does not have,
	// an array of senders beside the pair, is not read.
	req := h.allowReqAt(bob, at, alice.Fingerprint())
	withArray, err := json.Marshal(map[string]any{
		"allow": []string{strings.Repeat("f", 64)}, "document": req.Document, "signature": req.Signature})
	if err != nil {
		t.Fatal(err)
	}
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow", withArray, nil)
	if status != http.StatusNoContent {
		t.Fatalf("the owner's push: %d %s", status, body)
	}
	doc, sig, state, found, err := h.store.Allowlist(bob.Fingerprint())
	if err != nil || !found || state != relayapi.AllowSigned ||
		string(doc) != string(req.Document) || string(sig) != string(req.Signature) {
		t.Fatalf("the pushed list is not what was stored: %q %v %v", state, found, err)
	}
	if ok, _ := h.store.MayPost(bob.Fingerprint(), strings.Repeat("f", 64)); ok {
		t.Fatal("the array beside the document was read")
	}

	// Pushed again, the very same bytes: a no-op 204. Issued no later,
	// different bytes: 409 naming what is held.
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow", req, nil)
	if status != http.StatusNoContent {
		t.Fatalf("the same list again: %d %s", status, body)
	}
	status, body, _ = h.pushAllow(bob, bob, at.Add(-time.Second), alice.Fingerprint())
	if status != http.StatusConflict || errorText(t, body) != "a newer allow list is already there (issued 2026-09-17T10:04:00Z)" {
		t.Fatalf("an older list: %d %s", status, body)
	}
	status, body, _ = h.pushAllow(bob, bob, at)
	if status != http.StatusConflict {
		t.Fatalf("a different list at the same instant: %d %s", status, body)
	}
	if got, _, _, _, _ := h.store.Allowlist(bob.Fingerprint()); string(got) != string(req.Document) {
		t.Fatal("a refused push replaced the stored list")
	}
}

// The cap is enforced by the validator after the signature, at 1000 and
// 1001, and a refused list writes nothing.
func TestAllowlistCap(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)
	at := time.Date(2026, 9, 17, 10, 4, 0, 0, time.UTC)
	list := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = strings.Repeat("a", 60) + fmt.Sprintf("%04x", i)
		}
		return out
	}

	if status, body, _ := h.pushAllow(alice, alice, at, list(relayapi.MaxAllowlist)...); status != http.StatusNoContent {
		t.Fatalf("a list at the cap was refused: %d %s", status, body)
	}
	status, body := h.do(alice, "PUT", "/v1/mailbox/"+alice.Fingerprint()+"/allow",
		signRawAllow(t, alice, &allowlist.Document{V: 1, Owner: alice.Fingerprint(), Issued: at.Add(time.Second),
			Senders: list(relayapi.MaxAllowlist + 1)}), nil)
	if status != http.StatusBadRequest {
		t.Fatalf("a list one over the cap gave %d, want 400: %s", status, body)
	}
	if got := errorText(t, body); got != "the allow list has 1001 senders; at most 1000" {
		t.Fatalf("error %q does not give both numbers", got)
	}
	rec, err := h.store.MailboxRecord(alice.Fingerprint())
	if err != nil || rec.AllowlistSize != relayapi.MaxAllowlist {
		t.Fatalf("the refused list wrote to the database: %+v, %v", rec, err)
	}
}

// The fetch is the owner's alone and gives the pair back verbatim, with
// the state; a mailbox that has never pushed answers none.
func TestTheOwnerReadsTheirAllowlistBack(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	status, body, resp := h.getAllow(bob, bob.Fingerprint())
	if status != http.StatusOK || resp.State != relayapi.AllowNone || len(resp.Document) != 0 {
		t.Fatalf("with no list: %d %s", status, body)
	}
	status, body, _ = h.getAllow(alice, bob.Fingerprint())
	if status != http.StatusForbidden || errorText(t, body) != "not your mailbox" {
		t.Fatalf("another identity's fetch: %d %s", status, body)
	}
	_, _, pushed := h.pushAllow(bob, bob, time.Now(), alice.Fingerprint())
	status, body, resp = h.getAllow(bob, bob.Fingerprint())
	if status != http.StatusOK || resp.State != relayapi.AllowSigned ||
		string(resp.Document) != string(pushed.Document) || string(resp.Signature) != string(pushed.Signature) {
		t.Fatalf("the owner's fetch: %d %s", status, body)
	}
	// And the pair verifies with the owner's key, as the client checks.
	if _, err := allowlist.Verify(bob.Public(), resp.Document, resp.Signature); err != nil {
		t.Fatalf("the served pair does not verify: %v", err)
	}
}

// The test this plan exists for. The database is edited directly to admit
// a stranger, and the next post from that stranger is refused, because
// the relay verifies the list every time it enforces it; the owner's
// listing says broken, the log has the line once a minute, and a fresh
// push repairs it. The same for one byte of the signature, and for the
// mailbox's bundle, which locks the owner out too.
func TestAnEditedAllowlistRefusesRatherThanAdmits(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "mallory")
	alice, bob, mallory := people[0], people[1], people[2]
	for _, id := range people {
		h.register(id)
	}
	fp := bob.Fingerprint()
	const line = "allow list for " + "%s" + " does not verify; refusing every post to it until the owner pushes again"
	logged := func() int {
		return strings.Count(h.logs.String(), fmt.Sprintf(line, fp))
	}
	post := func(from *identity.Identity) (int, string) {
		status, body := h.do(from, "POST", "/v1/mailbox/"+fp, sealed(t, from, bob.Public(), "x"), nil)
		if status == http.StatusOK {
			return status, ""
		}
		return status, errorText(t, body)
	}
	push := func() {
		t.Helper()
		if status, body, _ := h.pushAllow(bob, bob, time.Now(), alice.Fingerprint()); status != http.StatusNoContent {
			t.Fatalf("allow push: %d %s", status, body)
		}
	}
	push()
	if status, _ := post(alice); status != http.StatusOK {
		t.Fatal("alice, admitted, was refused before any edit")
	}

	t.Run("a sender added to the document", func(t *testing.T) {
		doc, _, _, _, _ := h.store.Allowlist(fp)
		edited := strings.Replace(string(doc), `"senders":[`, `"senders":["`+mallory.Fingerprint()+`",`, 1)
		if edited == string(doc) {
			t.Fatal("the document has no senders array to edit")
		}
		if _, err := h.store.db.Exec(`UPDATE allowlists SET doc = ?, count = 2 WHERE fp = ?`, []byte(edited), fp); err != nil {
			t.Fatal(err)
		}
		before := logged()
		if status, msg := post(mallory); status != http.StatusForbidden || msg != refusedSender {
			t.Fatalf("the stranger the edit admitted: %d %q", status, msg)
		}
		// Alice, whom the owner did admit, is refused too: the list is
		// broken, and it fails closed.
		if status, msg := post(alice); status != http.StatusForbidden || msg != refusedSender {
			t.Fatalf("an admitted sender under a broken list: %d %q", status, msg)
		}
		// The owner's own note to self still goes through, before the list
		// is read.
		if status, _ := post(bob); status != http.StatusOK {
			t.Fatal("the owner's own post was refused under a broken list")
		}
		// One line for the burst, not one per refusal.
		if got := logged() - before; got != 1 {
			t.Fatalf("%d log lines for two refusals inside a minute, want 1", got)
		}
		h.clock.advance(2 * time.Minute)
		post(mallory)
		if got := logged() - before; got != 2 {
			t.Fatalf("%d log lines after a minute, want 2", got)
		}
		if got := h.listState(bob); got != relayapi.AllowBroken {
			t.Fatalf("the owner's listing says %q, want broken", got)
		}
		if _, _, resp := h.getAllow(bob, fp); resp.State != relayapi.AllowBroken {
			t.Fatalf("the owner's fetch says %q, want broken", resp.State)
		}
		rec, _ := h.store.MailboxRecord(fp)
		if rec.Allow != relayapi.AllowBroken || rec.AllowlistSize != 2 {
			t.Fatalf("the administrator's record: %+v", rec)
		}
		// A fresh push repairs it.
		push()
		if status, _ := post(alice); status != http.StatusOK {
			t.Fatal("alice was refused after the repair")
		}
		if status, _ := post(mallory); status != http.StatusForbidden {
			t.Fatal("mallory was admitted after the repair")
		}
		if got := h.listState(bob); got != relayapi.AllowSigned {
			t.Fatalf("the listing says %q after the repair, want signed", got)
		}
	})

	t.Run("the signature blanked", func(t *testing.T) {
		// The edit that once read as an unsigned list and was honoured:
		// it is refused at once on the relay, not found later on the
		// owner's machine.
		if _, err := h.store.db.Exec(`UPDATE allowlists SET sig = X'' WHERE fp = ?`, fp); err != nil {
			t.Fatal(err)
		}
		h.clock.advance(2 * time.Minute)
		before := logged()
		if status, msg := post(alice); status != http.StatusForbidden || msg != refusedSender {
			t.Fatalf("an admitted sender under a blanked signature: %d %q", status, msg)
		}
		if status, msg := post(mallory); status != http.StatusForbidden || msg != refusedSender {
			t.Fatalf("a stranger under a blanked signature: %d %q", status, msg)
		}
		if got := logged() - before; got != 1 {
			t.Fatalf("%d log lines, want 1", got)
		}
		if got := h.listState(bob); got != relayapi.AllowBroken {
			t.Fatalf("the owner's listing says %q, want broken", got)
		}
		push()
		if status, _ := post(alice); status != http.StatusOK {
			t.Fatal("alice was refused after the repair")
		}
	})

	t.Run("one byte of the signature", func(t *testing.T) {
		_, sig, _, _, _ := h.store.Allowlist(fp)
		changed := append([]byte{}, sig...)
		changed[len(changed)/2] ^= 0x01
		if _, err := h.store.db.Exec(`UPDATE allowlists SET sig = ? WHERE fp = ?`, changed, fp); err != nil {
			t.Fatal(err)
		}
		h.clock.advance(2 * time.Minute)
		before := logged()
		if status, msg := post(alice); status != http.StatusForbidden || msg != refusedSender {
			t.Fatalf("an admitted sender under an edited signature: %d %q", status, msg)
		}
		if got := logged() - before; got != 1 {
			t.Fatalf("%d log lines, want 1", got)
		}
		push()
		if status, _ := post(alice); status != http.StatusOK {
			t.Fatal("alice was refused after the repair")
		}
	})

	t.Run("the mailbox's bundle", func(t *testing.T) {
		// An attacker who replaces the bundle the list is verified against
		// has locked the owner out: every request the owner signs stops
		// verifying, which is loud, and the list is broken for everyone.
		var bundle []byte
		if err := h.store.db.QueryRow(`SELECT bundle FROM mailboxes WHERE fp = ?`, fp).Scan(&bundle); err != nil {
			t.Fatal(err)
		}
		if _, err := h.store.db.Exec(`UPDATE mailboxes SET bundle = ? WHERE fp = ?`, mallory.Public().Bundle(), fp); err != nil {
			t.Fatal(err)
		}
		h.clock.advance(2 * time.Minute)
		before := logged()
		if status, msg := post(alice); status != http.StatusForbidden || msg != refusedSender {
			t.Fatalf("an admitted sender under a replaced bundle: %d %q", status, msg)
		}
		if got := logged() - before; got != 1 {
			t.Fatalf("%d log lines, want 1", got)
		}
		if status, body, _ := h.pushAllow(bob, bob, time.Now(), alice.Fingerprint()); status != http.StatusUnauthorized {
			t.Fatalf("the owner's own push under a replaced bundle: %d %s, want 401", status, body)
		}
		if status, body := h.do(bob, "GET", "/v1/mailbox/"+fp, nil, nil); status != http.StatusUnauthorized {
			t.Fatalf("the owner's own listing under a replaced bundle: %d %s, want 401", status, body)
		}
		if _, err := h.store.db.Exec(`UPDATE mailboxes SET bundle = ? WHERE fp = ?`, bundle, fp); err != nil {
			t.Fatal(err)
		}
		if status, _ := post(alice); status != http.StatusOK {
			t.Fatal("alice was refused with the bundle put back")
		}
	})
}

// A row with no signature — as the migration from before signed lists
// writes it, or as an intruder who blanked a signature leaves it — is
// broken: it refuses every sender at once, whoever it names; the listing,
// the owner's fetch and the administrator's record say broken; and a
// signed push replaces it whatever its issue time, which is the relay's
// clock and not the owner's.
func TestAnUnsignedAllowlistIsBroken(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	for _, id := range people {
		h.register(id)
	}
	fp := bob.Fingerprint()
	unsigned, _ := json.Marshal(&allowlist.Document{V: 1, Owner: fp, Issued: time.Now().Add(time.Hour).UTC(), Senders: []string{alice.Fingerprint()}})
	if _, err := h.store.db.Exec(`INSERT INTO allowlists (fp, doc, sig, issued, count) VALUES (?, ?, X'', ?, 1)`,
		fp, unsigned, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	before := strings.Count(h.logs.String(), "allow list for "+fp+" does not verify")
	// The sender the document names, and one it does not: both refused,
	// with the sentence a refused sender always gets.
	for _, from := range []*identity.Identity{alice, carol} {
		if status, body := h.do(from, "POST", "/v1/mailbox/"+fp, sealed(t, from, bob.Public(), "x"), nil); status != http.StatusForbidden || errorText(t, body) != refusedSender {
			t.Fatalf("%s under an unsigned row: %d %s", from.Name, status, body)
		}
	}
	if got := strings.Count(h.logs.String(), "allow list for "+fp+" does not verify") - before; got != 1 {
		t.Fatalf("%d log lines for two refusals inside a minute, want 1", got)
	}
	// The owner's own post still goes through, before the list is read.
	if status, _ := h.do(bob, "POST", "/v1/mailbox/"+fp, sealed(t, bob, bob.Public(), "x"), nil); status != http.StatusOK {
		t.Fatal("the owner's own post was refused under an unsigned row")
	}
	if got := h.listState(bob); got != relayapi.AllowBroken {
		t.Fatalf("the listing says %q, want broken", got)
	}
	_, _, resp := h.getAllow(bob, fp)
	if resp.State != relayapi.AllowBroken || len(resp.Signature) != 0 || string(resp.Document) != string(unsigned) {
		t.Fatalf("the owner's fetch of an unsigned row: %+v", resp)
	}
	rec, _ := h.store.MailboxRecord(fp)
	if rec.Allow != relayapi.AllowBroken || rec.AllowlistSize != 1 {
		t.Fatalf("the administrator's record: %+v", rec)
	}
	// A signed push, issued now, replaces the row though the row's time is
	// an hour ahead: that time was the relay's, not the owner's.
	if status, body, _ := h.pushAllow(bob, bob, time.Now(), carol.Fingerprint()); status != http.StatusNoContent {
		t.Fatalf("a signed push over an unsigned row: %d %s", status, body)
	}
	if got := h.listState(bob); got != relayapi.AllowSigned {
		t.Fatalf("the listing says %q after the push, want signed", got)
	}
	if status, _ := h.do(carol, "POST", "/v1/mailbox/"+fp, sealed(t, carol, bob.Public(), "x"), nil); status != http.StatusOK {
		t.Fatal("the signed list did not replace the unsigned one")
	}
}
