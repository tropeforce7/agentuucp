package relay

import (
	"encoding/json"
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
		relayapi.AllowRequest{Allow: []string{alice.Fingerprint()}}, nil); status != http.StatusNoContent {
		t.Fatalf("allow push: %d %s", status, body)
	}
	status, body, pushed := h.pushDirectory(bob, bob, time.Now(), dflt, bugs)
	if status != http.StatusNoContent {
		t.Fatalf("push: %d %s", status, body)
	}
	for _, ch := range []string{"bug reports", "bug reports", "gone"} {
		if _, err := h.store.Put(fp, ch, sealed(t, alice, bob.Public(), "x"), Quotas{}); err != nil {
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
		relayapi.AllowRequest{Allow: []string{alice.Fingerprint()}}, nil); status != http.StatusNoContent {
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
