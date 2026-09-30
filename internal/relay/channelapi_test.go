package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// pushDirectory signs a directory for owner and PUTs it as the caller, who
// is usually the owner. It returns the status, the body and the signed pair.
func (h *harness) pushDirectory(caller, owner *identity.Identity, issued time.Time, chs ...channels.Channel) (int, []byte, relayapi.ChannelsRequest) {
	h.t.Helper()
	d := &channels.Directory{Issued: issued, Channels: chs}
	doc, sig, err := channels.Sign(owner, d)
	if err != nil {
		h.t.Fatal(err)
	}
	req := relayapi.ChannelsRequest{Document: doc, Signature: sig}
	status, body := h.do(caller, "PUT", "/v1/mailbox/"+owner.Fingerprint()+"/channels", req, nil)
	return status, body, req
}

// getDirectory fetches a mailbox's directory as the caller.
func (h *harness) getDirectory(caller *identity.Identity, fp string) (int, []byte, relayapi.ChannelsResponse) {
	h.t.Helper()
	status, body := h.do(caller, "GET", "/v1/mailbox/"+fp+"/channels", nil, nil)
	var resp relayapi.ChannelsResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &resp); err != nil {
			h.t.Fatalf("the directory response is not JSON: %s", body)
		}
	}
	return status, body, resp
}

// signRaw encodes and signs a directory without checking it, for the
// documents Sign would refuse to make.
func signRaw(t *testing.T, id *identity.Identity, d *channels.Directory) relayapi.ChannelsRequest {
	t.Helper()
	doc, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return relayapi.ChannelsRequest{Document: doc, Signature: mustSign(t, id, append([]byte("ccx-channels-v1"), doc...))}
}

var (
	bugs = channels.Channel{Name: "bug reports", Description: "One bug per message; attach the log"}
	dflt = channels.Channel{Name: channels.Default, Description: "Anything that fits nowhere else"}
)

// The push is the owner's alone, checked in the order the plan gives: the
// caller, the body, the signature, the rules, the owner, the store.
func TestOnlyTheOwnerPushesADirectory(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, id := range people {
		h.register(id)
	}
	at := time.Date(2026, 9, 13, 1, 19, 29, 0, time.UTC)

	// Another identity, with a directory bob signed: refused before the
	// body is looked at, and nothing is stored.
	status, body, _ := h.pushDirectory(alice, bob, at, dflt, bugs)
	if status != http.StatusForbidden || errorText(t, body) != "not your mailbox" {
		t.Fatalf("another identity's push: %d %s", status, body)
	}
	if _, _, found, _ := h.store.Directory(bob.Fingerprint()); found {
		t.Fatal("a push by another identity was stored")
	}

	// A body that is not a channels request.
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/channels", []byte(`[1,2]`), nil)
	if status != http.StatusBadRequest || errorText(t, body) != "malformed channels request" {
		t.Fatalf("a malformed body: %d %s", status, body)
	}

	// Signed by bob's mailbox but under alice's key: the owner is bob, the
	// signature is not.
	d := &channels.Directory{Owner: bob.Fingerprint(), Issued: at, Channels: []channels.Channel{dflt}}
	doc, _ := json.Marshal(&channels.Directory{V: 1, Owner: d.Owner, Issued: d.Issued, Channels: d.Channels})
	wrongKey := mustSign(t, alice, append([]byte("ccx-channels-v1"), doc...))
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/channels",
		relayapi.ChannelsRequest{Document: doc, Signature: wrongKey}, nil)
	if status != http.StatusUnauthorized || errorText(t, body) != "directory signature does not verify" {
		t.Fatalf("a directory under the wrong key: %d %s", status, body)
	}
	if _, _, found, _ := h.store.Directory(bob.Fingerprint()); found {
		t.Fatal("a directory under the wrong key was stored")
	}

	// A rule broken, under bob's own key: the validator's sentence. Sign
	// refuses to sign it, so it is signed by hand, as a client that skipped
	// its own check would.
	long := channels.Channel{Name: "bug reports", Description: strings.Repeat("d", 1031)}
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/channels",
		signRaw(t, bob, &channels.Directory{V: 1, Owner: bob.Fingerprint(), Issued: at, Channels: []channels.Channel{dflt, long}}), nil)
	if status != http.StatusBadRequest {
		t.Fatalf("an invalid directory: %d %s", status, body)
	}
	if got := errorText(t, body); got != `channel "bug reports": description is 1031 bytes; at most 1024` {
		t.Fatalf("the refusal is %q, not the validator's sentence", got)
	}
	// And one the decoder refuses: a field this build does not know.
	with := strings.Replace(string(doc), `"v":1,`, `"v":1,"colour":"blue",`, 1)
	withSig := mustSign(t, bob, append([]byte("ccx-channels-v1"), with...))
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/channels",
		relayapi.ChannelsRequest{Document: []byte(with), Signature: withSig}, nil)
	if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), `unknown field "colour"`) {
		t.Fatalf("an unknown field: %d %s", status, body)
	}

	// Bob's key over a document naming alice as owner: what a client that
	// wrote the owner field itself would send.
	forged, _ := json.Marshal(&channels.Directory{V: 1, Owner: alice.Fingerprint(), Issued: at, Channels: []channels.Channel{dflt}})
	forgedSig := mustSign(t, bob, append([]byte("ccx-channels-v1"), forged...))
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/channels",
		relayapi.ChannelsRequest{Document: forged, Signature: forgedSig}, nil)
	if status != http.StatusBadRequest || errorText(t, body) != "directory owner is not this mailbox" {
		t.Fatalf("a document naming another owner: %d %s", status, body)
	}
	if _, _, found, _ := h.store.Directory(bob.Fingerprint()); found {
		t.Fatal("a refused directory was stored")
	}

	// The good one.
	status, body, first := h.pushDirectory(bob, bob, at, dflt, bugs)
	if status != http.StatusNoContent {
		t.Fatalf("the owner's push: %d %s", status, body)
	}
	if doc, sig, found, err := h.store.Directory(bob.Fingerprint()); err != nil || !found ||
		string(doc) != string(first.Document) || string(sig) != string(first.Signature) {
		t.Fatal("the pushed directory is not what was stored")
	}
	if len(body) != 0 {
		t.Fatalf("a 204 with a body: %s", body)
	}

	// An older one, from another machine: 409 naming the stored issue.
	status, body, _ = h.pushDirectory(bob, bob, at.Add(-time.Second), dflt)
	if status != http.StatusConflict {
		t.Fatalf("an older directory: %d %s", status, body)
	}
	if got := errorText(t, body); got != "a newer directory is already there (issued 2026-09-13T01:19:29Z)" {
		t.Fatalf("the 409 says %q", got)
	}
	if doc, _, _, _ := h.store.Directory(bob.Fingerprint()); string(doc) != string(first.Document) {
		t.Fatal("the older directory replaced the stored one")
	}
	// The same one again, from a machine catching the relay up: accepted,
	// like any push.
	status, body = h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/channels", first, nil)
	if status != http.StatusNoContent {
		t.Fatalf("pushing the stored directory again: %d %s", status, body)
	}
	// A newer one replaces it.
	status, body, second := h.pushDirectory(bob, bob, at.Add(time.Minute), dflt)
	if status != http.StatusNoContent {
		t.Fatalf("a newer directory: %d %s", status, body)
	}
	if doc, _, _, _ := h.store.Directory(bob.Fingerprint()); string(doc) != string(second.Document) {
		t.Fatal("the newer directory was not stored")
	}
	// The stored row's signature edited through the store's own handle,
	// one bit flipped, and its issued moved a day ahead by the same
	// editor: the owner's next push through the route is taken all the
	// same, since the row does not verify and a row that does not verify
	// says nothing about when the owner issued it.
	_, sig, _, _ := h.store.Directory(bob.Fingerprint())
	changed := append([]byte{}, sig...)
	changed[len(changed)/2] ^= 0x01
	ahead := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := h.store.db.Exec(`UPDATE directories SET sig = ?, issued = ? WHERE fp = ?`, changed, ahead, bob.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	status, body, third := h.pushDirectory(bob, bob, at.Add(2*time.Minute), dflt, bugs)
	if status != http.StatusNoContent {
		t.Fatalf("the push over an edited row issued ahead: %d %s", status, body)
	}
	if doc, _, _, _ := h.store.Directory(bob.Fingerprint()); string(doc) != string(third.Document) {
		t.Fatal("the push over an edited row did not replace it")
	}
}

// Who may read a directory is who may post: the mailbox must exist and not
// be blocked, and the allow list decides, before a word is said about
// channels. Then the owner sees counts and a sender sees the bytes alone.
func TestADirectoryIsReadByWhoMayPost(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "carol", "dave")
	alice, bob, carol, dave := people[0], people[1], people[2], people[3]
	for _, id := range people {
		h.register(id)
	}
	fp := bob.Fingerprint()

	// No directory yet: the sentence that says so, and its constant.
	status, body, _ := h.getDirectory(alice, fp)
	if status != http.StatusNotFound || errorText(t, body) != relayapi.MsgNoDirectory {
		t.Fatalf("a mailbox without a directory: %d %s", status, body)
	}
	if relayapi.MsgNoDirectory != "no directory: the mailbox has the one channel, default" {
		t.Fatalf("MsgNoDirectory is %q", relayapi.MsgNoDirectory)
	}
	// A mailbox that is not there.
	status, body, _ = h.getDirectory(alice, strings.Repeat("0", 64))
	if status != http.StatusNotFound || errorText(t, body) != "no such mailbox" {
		t.Fatalf("no such mailbox: %d %s", status, body)
	}

	// Bob admits alice and pushes a directory with two channels, one of
	// which has mail; dave's mail sits under a name that is not listed.
	if status, body := h.do(bob, "PUT", "/v1/mailbox/"+fp+"/allow",
		h.allowReq(bob, alice.Fingerprint()), nil); status != http.StatusNoContent {
		t.Fatalf("allow push: %d %s", status, body)
	}
	status, body, pushed := h.pushDirectory(bob, bob, time.Now(), dflt, bugs)
	if status != http.StatusNoContent {
		t.Fatalf("push: %d %s", status, body)
	}
	for _, ch := range []string{"bug reports", "bug reports", "gone"} {
		if _, err := h.store.Put(fp, ch, relayapi.KindEnvelope, "", sealed(t, alice, bob.Public(), "x"), Quotas{}, Forwarded{}); err != nil {
			t.Fatal(err)
		}
	}

	// A sender the allow list refuses: the post's sentence, and not the
	// directory's 404 for a mailbox that has none either — carol is refused
	// on dave's mailbox, which has no directory, with the same sentence.
	status, body, _ = h.getDirectory(carol, fp)
	if status != http.StatusForbidden || errorText(t, body) != "sender is not on the recipient's allow list" {
		t.Fatalf("a refused sender: %d %s", status, body)
	}
	if status, body := h.do(dave, "PUT", "/v1/mailbox/"+dave.Fingerprint()+"/allow",
		h.allowReq(dave, alice.Fingerprint()), nil); status != http.StatusNoContent {
		t.Fatalf("dave's allow push: %d %s", status, body)
	}
	status, body, _ = h.getDirectory(carol, dave.Fingerprint())
	if status != http.StatusForbidden || errorText(t, body) != "sender is not on the recipient's allow list" {
		t.Fatalf("a refused sender on a mailbox with no directory: %d %s", status, body)
	}

	// An admitted sender: the bytes verbatim, no counts, and the document
	// verifies against the key alice holds for bob.
	status, body, resp := h.getDirectory(alice, fp)
	if status != http.StatusOK {
		t.Fatalf("an admitted sender: %d %s", status, body)
	}
	if string(resp.Document) != string(pushed.Document) || string(resp.Signature) != string(pushed.Signature) {
		t.Fatal("the sender did not get the bytes the owner pushed")
	}
	if resp.Queued != nil || strings.Contains(string(body), "queued") {
		t.Fatalf("a sender was given counts: %s", body)
	}
	d, err := channels.Verify(bob.Public(), resp.Document, resp.Signature)
	if err != nil || len(d.Channels) != 2 || d.Channels[1].Name != "bug reports" {
		t.Fatalf("the served directory does not verify: %v %+v", err, d)
	}

	// The owner: the same bytes, with a count for every listed channel and
	// for the name mail still waits under.
	status, body, resp = h.getDirectory(bob, fp)
	if status != http.StatusOK {
		t.Fatalf("the owner: %d %s", status, body)
	}
	if string(resp.Document) != string(pushed.Document) {
		t.Fatal("the owner did not get the bytes pushed")
	}
	want := map[string]int64{"default": 0, "bug reports": 2, "gone": 1}
	if len(resp.Queued) != len(want) {
		t.Fatalf("the owner's counts: %v, want %v", resp.Queued, want)
	}
	for name, n := range want {
		if resp.Queued[name] != n {
			t.Errorf("the owner's count for %q is %d, want %d", name, resp.Queued[name], n)
		}
	}

	// Blocked: as a post would be, whoever asks.
	if err := h.store.SetBlock(fp, "spam", alice.Fingerprint(), time.Now()); err != nil {
		t.Fatal(err)
	}
	status, body, _ = h.getDirectory(alice, fp)
	if status != http.StatusForbidden || errorText(t, body) != "recipient is blocked on this relay" {
		t.Fatalf("a blocked mailbox's directory: %d %s", status, body)
	}
}

// The access log names the route and never a channel, under either mode.
func TestTheAccessLogNamesNoChannel(t *testing.T) {
	for _, mode := range []string{AccessLogFull, AccessLogMinimal} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, Config{AccessLog: mode})
			people := ids(t, "alice", "bob")
			alice, bob := people[0], people[1]
			for _, id := range people {
				h.register(id)
			}
			secret := channels.Channel{Name: "xylophone lessons", Description: "quiet ones only"}
			if status, body, _ := h.pushDirectory(bob, bob, time.Now(), dflt, secret); status != http.StatusNoContent {
				t.Fatalf("push: %d %s", status, body)
			}
			if status, body, _ := h.getDirectory(alice, bob.Fingerprint()); status != http.StatusOK {
				t.Fatalf("get: %d %s", status, body)
			}
			logs := h.logs.String()
			for _, word := range []string{"xylophone", "quiet ones", "default"} {
				if strings.Contains(logs, word) {
					t.Fatalf("the access log names a channel (%q):\n%s", word, logs)
				}
			}
			for _, route := range []string{"PUT", "GET"} {
				if !strings.Contains(logs, "method="+route) {
					t.Fatalf("no %s request was logged:\n%s", route, logs)
				}
			}
			if mode == AccessLogMinimal {
				if !strings.Contains(logs, "path=/v1/mailbox/{fp}/channels") {
					t.Fatalf("the minimal log does not name the route:\n%s", logs)
				}
				if strings.Contains(logs, bob.Fingerprint()[:16]) {
					t.Fatalf("the minimal log names the mailbox:\n%s", logs)
				}
			} else if !strings.Contains(logs, "path=/v1/mailbox/"+bob.Fingerprint()+"/channels") {
				t.Fatalf("the full log does not name the path:\n%s", logs)
			}
		})
	}
}

// listedDirectory is what the owner's own listing says their channel
// directory is.
func (h *harness) listedDirectory(owner *identity.Identity) string {
	h.t.Helper()
	status, body := h.do(owner, "GET", "/v1/mailbox/"+owner.Fingerprint(), nil, nil)
	if status != http.StatusOK {
		h.t.Fatalf("listing: %d %s", status, body)
	}
	var resp relayapi.ListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		h.t.Fatal(err)
	}
	return resp.Directory
}

// The relay routes a post by the directory the owner signed, verified at
// the post, and not by the channels rows it parsed at the push. A row
// inserted by hand for a name the document does not carry routes nothing,
// and a row whose period was edited to open a channel the document closes
// does not open it: the rows are the administrator's count and the
// watch's, and they decide nothing.
func TestAPostIsRoutedByTheVerifiedDirectoryAndNotTheRows(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	fp := bob.Fingerprint()
	// The relay judges a period by its own clock, which the harness sets,
	// so the bound is taken from there and not from time.Now.
	closed := h.clock.Now().Add(-2 * time.Hour)
	if status, body, _ := h.pushDirectory(bob, bob, time.Now(),
		channels.Channel{Name: "bug reports"},
		channels.Channel{Name: "cfp", NotAfter: &closed}); status != http.StatusNoContent {
		t.Fatalf("directory push: %d %s", status, body)
	}
	post := func(channel string) (int, string) {
		env := sealedTo(t, alice, bob.Public(), "x", channel)
		status, body := h.do(alice, "POST", "/v1/mailbox/"+fp, env, nil)
		if status == http.StatusOK {
			return status, ""
		}
		return status, errorText(t, body)
	}
	// The document routes: the open name is taken, the closed one refused
	// as closed, a name it does not carry refused as no such channel.
	if status, msg := post("bug reports"); status != http.StatusOK {
		t.Fatalf("a channel the document carries: %d %s", status, msg)
	}
	if status, msg := post("cfp"); status != http.StatusForbidden || !strings.Contains(msg, "is not open") {
		t.Fatalf("a channel the document closes: %d %s", status, msg)
	}
	if status, msg := post("invented"); status != http.StatusNotFound || !strings.Contains(msg, `no such channel "invented"`) {
		t.Fatalf("a channel nobody published: %d %s", status, msg)
	}

	// A row for a name the document does not carry, inserted as somebody
	// with the database open would: it routes nothing.
	if _, err := h.store.db.Exec(
		`INSERT INTO channels (fp, name, description, position) VALUES (?, 'invented', '', 9)`, fp); err != nil {
		t.Fatal(err)
	}
	if status, msg := post("invented"); status != http.StatusNotFound || !strings.Contains(msg, `no such channel "invented"`) {
		t.Fatalf("a channel the rows carry and the document does not: %d %s; want it refused", status, msg)
	}
	// And a row whose period is edited to open what the document closes.
	if _, err := h.store.db.Exec(`UPDATE channels SET not_after = NULL WHERE fp = ? AND name = 'cfp'`, fp); err != nil {
		t.Fatal(err)
	}
	if status, msg := post("cfp"); status != http.StatusForbidden || !strings.Contains(msg, "is not open") {
		t.Fatalf("a period the rows open and the document closes: %d %s; want it refused", status, msg)
	}
	// The owner's listing says the directory is signed throughout: the
	// rows are not what it reads either.
	if got := h.listedDirectory(bob); got != relayapi.DirectorySigned {
		t.Fatalf("the listing says %q, want signed", got)
	}
}

// A channel directory that does not verify closes the mailbox: every
// name is refused, default and the owner's own post included, since
// falling back to default would open a channel the owner's own document
// may have removed or closed, and a signed thing that no longer verifies
// refuses here as a broken allow list does. The sender is told only that
// there is no such channel; the owner's listing says broken, the relay's
// log says so once a minute naming the mailbox alone under either access
// log mode, and the owner's push is the whole repair.
func TestABrokenDirectoryClosesTheMailbox(t *testing.T) {
	for _, mode := range []string{AccessLogFull, AccessLogMinimal} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, Config{AccessLog: mode})
			people := ids(t, "alice", "bob")
			alice, bob := people[0], people[1]
			h.register(alice)
			h.register(bob)
			fp := bob.Fingerprint()
			if status, body, _ := h.pushDirectory(bob, bob, time.Now(),
				channels.Channel{Name: "bug reports"}); status != http.StatusNoContent {
				t.Fatalf("directory push: %d %s", status, body)
			}
			post := func(channel string) (int, string) {
				env := sealedTo(t, alice, bob.Public(), "x", channel)
				status, body := h.do(alice, "POST", "/v1/mailbox/"+fp, env, nil)
				if status == http.StatusOK {
					return status, ""
				}
				return status, errorText(t, body)
			}
			if status, msg := post("bug reports"); status != http.StatusOK {
				t.Fatalf("before the edit: %d %s", status, msg)
			}

			// One bit of the signature, as somebody with the database open.
			line := fmt.Sprintf("channel directory for %s does not verify; "+
				"refusing every post to it until the owner pushes again", fp)
			logged := func() int { return strings.Count(h.logs.String(), line) }
			m := logged()
			var sig []byte
			if err := h.store.db.QueryRow(`SELECT sig FROM directories WHERE fp = ?`, fp).Scan(&sig); err != nil {
				t.Fatal(err)
			}
			sig[0] ^= 1
			if _, err := h.store.db.Exec(`UPDATE directories SET sig = ? WHERE fp = ?`, sig, fp); err != nil {
				t.Fatal(err)
			}
			// Every named channel is refused, and the channels rows still
			// carry the name: it is the document that decides.
			for range 2 {
				if status, msg := post("bug reports"); status != http.StatusNotFound ||
					!strings.Contains(msg, `no such channel "bug reports"`) {
					t.Fatalf("a named channel under a broken directory: %d %s", status, msg)
				}
			}
			// And default, which a mailbox with no directory would have:
			// a directory that has gone wrong must not open a name its
			// owner's own document may have removed or closed.
			if status, msg := post(""); status != http.StatusNotFound ||
				!strings.Contains(msg, `no such channel "default"`) {
				t.Fatalf("default under a broken directory: %d %s; want it refused", status, msg)
			}
			// The owner's own note to themselves, which the allow list
			// lets through, meets the same closed mailbox.
			own := sealedTo(t, bob, bob.Public(), "x", "")
			if status, body := h.do(bob, "POST", "/v1/mailbox/"+fp, own, nil); status != http.StatusNotFound ||
				!strings.Contains(errorText(t, body), `no such channel "default"`) {
				t.Fatalf("the owner's own post under a broken directory: %d %s; want it refused", status, body)
			}
			// Nothing was stored by any of them.
			if n := h.messageCount(fp); n != 1 {
				t.Fatalf("%d messages after the refusals, want the one taken before the edit", n)
			}
			// One line for the burst, a second after the clock advances.
			if got := logged() - m; got != 1 {
				t.Fatalf("%d log lines for two refusals inside a minute, want 1", got)
			}
			h.clock.advance(2 * time.Minute)
			post("bug reports")
			if got := logged() - m; got != 2 {
				t.Fatalf("%d log lines after a minute, want 2", got)
			}
			// The line names the mailbox and never the sender.
			for _, l := range strings.Split(h.logs.String(), "\n") {
				if strings.Contains(l, "channel directory for ") && strings.Contains(l, alice.Fingerprint()[:16]) {
					t.Fatalf("the fault line names the sender:\n%s", l)
				}
			}
			// The owner is told on their own listing, and the operator
			// on the administrator's record, where the count of the
			// channels the push parsed stands beside the word that says
			// none of them routes.
			if got := h.listedDirectory(bob); got != relayapi.DirectoryBroken {
				t.Fatalf("the listing says %q, want broken", got)
			}
			rec, err := h.store.MailboxRecord(fp)
			if err != nil || rec.Directory != relayapi.DirectoryBroken || rec.Channels != 1 {
				t.Fatalf("the administrator's record under a broken directory: %+v, %v", rec, err)
			}
			// The repair: a fresh push, and the name routes again.
			if status, body, _ := h.pushDirectory(bob, bob, time.Now().Add(time.Second),
				channels.Channel{Name: "bug reports"}); status != http.StatusNoContent {
				t.Fatalf("the repairing push: %d %s", status, body)
			}
			if status, msg := post("bug reports"); status != http.StatusOK {
				t.Fatalf("after the repair: %d %s", status, msg)
			}
			if got := h.listedDirectory(bob); got != relayapi.DirectorySigned {
				t.Fatalf("the listing after the repair says %q, want signed", got)
			}
			if rec, err := h.store.MailboxRecord(fp); err != nil || rec.Directory != relayapi.DirectorySigned {
				t.Fatalf("the administrator's record after the repair: %+v, %v", rec, err)
			}
		})
	}
}

// The three words on the owner's listing, and what each means: none for a
// mailbox that has pushed no directory, signed for one that has, broken
// for one whose row no longer verifies.
func TestTheListingSaysTheDirectoryState(t *testing.T) {
	h := newHarness(t, Config{})
	bob := ids(t, "bob")[0]
	h.register(bob)
	if got := h.listedDirectory(bob); got != relayapi.DirectoryNone {
		t.Fatalf("a mailbox with no directory says %q, want none", got)
	}
	if status, body, _ := h.pushDirectory(bob, bob, time.Now(), channels.Channel{Name: "bug reports"}); status != http.StatusNoContent {
		t.Fatalf("directory push: %d %s", status, body)
	}
	if got := h.listedDirectory(bob); got != relayapi.DirectorySigned {
		t.Fatalf("a pushed directory says %q, want signed", got)
	}
	if _, err := h.store.db.Exec(`UPDATE directories SET sig = X'' WHERE fp = ?`, bob.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if got := h.listedDirectory(bob); got != relayapi.DirectoryBroken {
		t.Fatalf("a blanked signature says %q, want broken", got)
	}
}

// A directory padded past its own cap is refused at the push by the
// length, before the signature, with the sentence naming the bytes and
// the cap, and nothing is stored; at the cap it is taken and stored as
// signed. A row that holds one all the same — an edit on the host, since
// no push can put one there — reads as broken, which closes the mailbox,
// and the administrator's record says so.
func TestADirectoryIsHeldToItsCapAtThePushAndAtEveryReader(t *testing.T) {
	people := ids(t, "boss", "alice", "bob")
	boss, alice, bob := people[0], people[1], people[2]
	h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
	h.register(alice)
	h.register(bob)
	fp := bob.Fingerprint()

	compact, _ := json.Marshal(&channels.Directory{V: 1, Owner: fp, Issued: h.clock.Now(),
		Channels: []channels.Channel{{Name: "bug reports"}}})
	pad := func(n int) []byte {
		out := append([]byte{}, compact[:len(compact)-1]...)
		out = append(out, strings.Repeat(" ", n-len(compact))...)
		return append(out, '}')
	}
	push := func(doc []byte) (int, []byte) {
		return h.do(bob, "PUT", "/v1/mailbox/"+fp+"/channels", relayapi.ChannelsRequest{
			Document: doc, Signature: mustSign(t, bob, append([]byte("ccx-channels-v1"), doc...))}, nil)
	}

	over := pad(relayapi.MaxDirectoryBytes + 1)
	status, body := push(over)
	if status != http.StatusBadRequest ||
		errorText(t, body) != fmt.Sprintf("directory is malformed: the directory is %d bytes; at most %d, so send it compact",
			relayapi.MaxDirectoryBytes+1, relayapi.MaxDirectoryBytes) {
		t.Fatalf("a directory one over its cap: %d %s", status, body)
	}
	if _, _, found, err := h.store.Directory(fp); err != nil || found {
		t.Fatal("a directory over its cap was stored")
	}

	atCap := pad(relayapi.MaxDirectoryBytes)
	if status, body := push(atCap); status != http.StatusNoContent {
		t.Fatalf("a directory at its cap: %d %s", status, body)
	}
	got, _, found, err := h.store.Directory(fp)
	if err != nil || !found || string(got) != string(atCap) {
		t.Fatal("the padded directory at the cap was not stored as signed")
	}
	// It routes: the length is a cap and not a refusal of what is under it.
	if status, _ := h.do(alice, "POST", "/v1/mailbox/"+fp,
		sealedTo(t, alice, bob.Public(), "x", "bug reports"), nil); status != http.StatusOK {
		t.Fatal("a post to a channel of the directory at its cap was refused")
	}

	// The row edited past the cap on the host: every reader runs the same
	// rule, so the mailbox closes rather than the relay verifying bytes
	// no push could have put there.
	if _, err := h.store.db.Exec(`UPDATE directories SET doc = ?, sig = ? WHERE fp = ?`,
		over, mustSign(t, bob, append([]byte("ccx-channels-v1"), over...)), fp); err != nil {
		t.Fatal(err)
	}
	if state, err := h.store.DirectoryState(fp); err != nil || state != relayapi.DirectoryBroken {
		t.Fatalf("the owner's listing says %q, want broken", state)
	}
	if rec, err := h.store.MailboxRecord(fp); err != nil || rec.Directory != relayapi.DirectoryBroken {
		t.Fatalf("the administrator's record: %+v, %v", rec, err)
	}
	for _, channel := range []string{"bug reports", ""} {
		status, body := h.do(alice, "POST", "/v1/mailbox/"+fp, sealedTo(t, alice, bob.Public(), "x", channel), nil)
		if status != http.StatusNotFound {
			t.Fatalf("a post to %q under an over-long directory: %d %s", channel, status, body)
		}
	}
}
