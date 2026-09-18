package agent

import (
	"crypto/ecdh"
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

// request builds a signing string the way relayapi.SigningString does,
// without importing it: this package must not link the relay's wire
// types, and internal/relay's TestTheClassifierAgreesWithTheRelay is
// what proves the shape is the same.
func signingString(method, pathWithQuery string) []byte {
	return []byte("ccx-http-v1\n" + method + "\n" + pathWithQuery + "\n1700000000\nAAAAAAAAAAAAAAAAAAAAAA\n" + strings.Repeat("0", 64))
}

var (
	fp    = strings.Repeat("a", 64)
	other = strings.Repeat("b", 64)
)

// TestTheClassifierAdmitsTheReceiveSetAndNothingElse walks the relay's
// route table as the plan lists it, then the strings an attacker would try,
// and asserts every one is classified as the table says: the receive set is
// receive and everything else, including everything malformed, is send.
func TestTheClassifierAdmitsTheReceiveSetAndNothingElse(t *testing.T) {
	receive := map[string]string{
		"the listing":                    "GET /v1/mailbox/" + fp,
		"wait, by query":                 "GET /v1/mailbox/" + fp + "?wait=60",
		"peers watch, by query":          "GET /v1/mailbox/" + fp + "?wait=60&peers=" + other + ":1",
		"stubs, by query":                "GET /v1/mailbox/" + fp + "?stubs=true",
		"a stream's payload":             "GET /v1/mailbox/" + fp + "/12/blob",
		"the allow list":                 "GET /v1/mailbox/" + fp + "/allow",
		"the directory":                  "GET /v1/mailbox/" + fp + "/channels",
		"this identity's certs":          "GET /v1/mailbox/" + fp + "/certs",
		"a lookup":                       "GET /v1/keys/" + fp,
		"a lookup by short id":           "GET /v1/keys/" + fp[:16],
		"acknowledging":                  "DELETE /v1/mailbox/" + fp + "/12",
		"how much the relay holds":       "HEAD /v1/uploads/u-1",
		"{id} equal to allow under blob": "GET /v1/mailbox/" + fp + "/allow/blob", // routed to the blob handler, which refuses the id; nothing originates
		"a certificate renewed":          "POST /v1/mailbox/" + fp + "/certs",
		"the health check":               "GET /v1/health",                       // signed by the client before it makes a key, ignored by the relay
		"another mailbox's certs":        "POST /v1/mailbox/" + other + "/certs", // by shape; the relay refuses "not your mailbox", and the signature is the caller's
	}
	send := map[string]string{
		"a post":                      "POST /v1/mailbox/" + fp,
		"a stream opened":             "POST /v1/mailbox/" + fp + "/streams",
		"a chunk appended":            "PATCH /v1/uploads/u-1",
		"an upload aborted":           "DELETE /v1/uploads/u-1",
		"an upload completed":         "POST /v1/uploads/u-1/complete",
		"an allow list pushed":        "PUT /v1/mailbox/" + fp + "/allow",
		"a directory pushed":          "PUT /v1/mailbox/" + fp + "/channels",
		"a registration":              "POST /v1/register",
		"admin status":                "GET /v1/admin/status",
		"admin mailboxes":             "GET /v1/admin/mailboxes",
		"admin one mailbox":           "GET /v1/admin/mailboxes/" + fp,
		"admin deregister":            "DELETE /v1/admin/mailboxes/" + fp,
		"admin purge":                 "DELETE /v1/admin/mailboxes/" + fp + "/messages",
		"admin blocks":                "GET /v1/admin/blocks",
		"admin block":                 "PUT /v1/admin/blocks/" + fp,
		"admin unblock":               "DELETE /v1/admin/blocks/" + fp,
		"admin certs":                 "GET /v1/admin/certs",
		"admin revoke cert":           "DELETE /v1/admin/certs/0123",
		"admin add token":             "POST /v1/admin/tokens",
		"admin tokens":                "GET /v1/admin/tokens",
		"admin revoke token":          "DELETE /v1/admin/tokens/t-1",
		"the trust anchor":            "GET /v1/trust-anchor",
		"HEAD of the health check":    "HEAD /v1/health",
		"a path with ..":              "GET /v1/mailbox/" + fp + "/../allow",
		"a path with . ":              "GET /v1/mailbox/./allow",
		"an extra segment":            "GET /v1/mailbox/" + fp + "/allow/x",
		"a method of get":             "get /v1/mailbox/" + fp,
		"an empty path":               "GET ",
		"no leading slash":            "GET v1/mailbox/" + fp,
		"a prefix of a receive route": "GET /v1/mailbox",
		"a prefix with a slash":       "GET /v1/mailbox/",
		"an empty segment":            "GET /v1/mailbox//allow",
		"HEAD of the listing":         "HEAD /v1/mailbox/" + fp, // served through the GET pattern on the relay; over-strict here, on purpose
		"HEAD of a lookup":            "HEAD /v1/keys/" + fp,
		"DELETE of the allow list":    "DELETE /v1/mailbox/" + fp + "/allow", // the relay routes it to the acknowledgement handler, which refuses the id; in the set by shape, so this proves the classifier and not the route
		"a double slash":              "GET //v1/mailbox/" + fp,
		"a query on a send route":     "POST /v1/mailbox/" + fp + "?x=1",
		"an encoded uploads":          "DELETE /v1/%75ploads/u-1", // the relay unescapes a segment before matching
		"a percent-encoded slash":     "GET /v1/mailbox/" + fp + "%2Fallow",
		"an encoded literal":          "GET /v1/%6Dailbox/" + fp,
		"an encoded allow":            "GET /v1/mailbox/" + fp + "/%61llow",
	}
	// DELETE of the allow list is by shape an acknowledgement of a message
	// whose id is "allow"; the relay's handler refuses that id. It stays in
	// the set because the shape is the set: assert it, so a change is seen.
	delete(send, "DELETE of the allow list")
	receive["DELETE with an id of allow"] = "DELETE /v1/mailbox/" + fp + "/allow"

	for name, req := range receive {
		method, path, _ := strings.Cut(req, " ")
		if got := ScopeOf(OpSign, KeyIdentity, signingString(method, path)); got != ScopeReceive {
			t.Errorf("%s (%s) is %s, want receive", name, req, got)
		}
	}
	for name, req := range send {
		method, path, _ := strings.Cut(req, " ")
		if got := ScopeOf(OpSign, KeyIdentity, signingString(method, path)); got != ScopeSend {
			t.Errorf("%s (%s) is %s, want send", name, req, got)
		}
	}

	// Strings that are not a signing string at all, however they begin.
	listing := "/v1/mailbox/" + fp
	for name, msg := range map[string][]byte{
		"empty":                       nil,
		"the domain alone":            []byte("ccx-http-v1\n"),
		"five parts":                  []byte("ccx-http-v1\nGET\n" + listing + "\n1700000000\nAAAA"),
		"seven parts":                 append(signingString("GET", listing), '\n'),
		"a newline in the query":      signingString("GET", listing+"?a=\nPOST"),
		"a timestamp with a letter":   []byte("ccx-http-v1\nGET\n" + listing + "\n17000000a0\nAAAA\n" + strings.Repeat("0", 64)),
		"an empty timestamp":          []byte("ccx-http-v1\nGET\n" + listing + "\n\nAAAA\n" + strings.Repeat("0", 64)),
		"an empty nonce":              []byte("ccx-http-v1\nGET\n" + listing + "\n1700000000\n\n" + strings.Repeat("0", 64)),
		"a nonce with a space":        []byte("ccx-http-v1\nGET\n" + listing + "\n1700000000\nAA AA\n" + strings.Repeat("0", 64)),
		"a short hash":                []byte("ccx-http-v1\nGET\n" + listing + "\n1700000000\nAAAA\n" + strings.Repeat("0", 63)),
		"an upper-case hash":          []byte("ccx-http-v1\nGET\n" + listing + "\n1700000000\nAAAA\n" + strings.Repeat("A", 64)),
		"the domain without newline":  []byte("ccx-http-v1GET\n" + listing + "\n1700000000\nAAAA\n" + strings.Repeat("0", 64) + "\n"),
		"a message":                   []byte("ccx-sig-v1" + fp + `{"from":"..."}`),
		"a stream manifest":           []byte("ccx-stream-sig-v1" + fp + `{"v":1}`),
		"a directory":                 []byte("ccx-channels-v1{}"),
		"an allow list":               []byte("ccx-allow-v1{}"),
		"a token":                     []byte("ccx-token-v1{}"),
		"a fingerprint domain":        []byte("ccx-id-v1"),
		"a domain of tomorrow":        []byte("ccx-http-v2\nGET\n" + listing + "\n1700000000\nAAAA\n" + strings.Repeat("0", 64)),
		"random bytes":                []byte{0, 1, 2, 3},
		"a receive request, embedded": append([]byte("x"), signingString("GET", listing)...),
	} {
		if got := ScopeOf(OpSign, KeyIdentity, msg); got != ScopeSend {
			t.Errorf("%s is %s, want send", name, got)
		}
	}

	// The key decides for a machine key, whatever the message: the TLS
	// handshake and a CSR originate nothing.
	for _, key := range []string{CertPrefix + "work", PendingPrefix + "work"} {
		for name, msg := range map[string][]byte{"a post": signingString("POST", listing), "empty": nil, "a transcript": []byte("tls13 transcript")} {
			if got := ScopeOf(OpSign, key, msg); got != ScopeReceive {
				t.Errorf("%s under %s is %s, want receive", name, key, got)
			}
		}
	}
	// An unknown key with a receive-shaped message is send: the key must be
	// one the agent knows for the shape to mean anything.
	if got := ScopeOf(OpSign, "nothing", signingString("GET", listing)); got != ScopeSend {
		t.Errorf("an unknown key is %s, want send", got)
	}

	// The operations that are not signatures.
	for op, want := range map[string]Scope{
		OpStatus: ScopeReceive, OpLock: ScopeReceive, OpStop: ScopeReceive,
		OpDecapsulate: ScopeReceive, OpExchange: ScopeReceive,
		OpGenerate: ScopeSend, "tomorrow": ScopeSend, "": ScopeSend,
	} {
		if got := ScopeOf(op, KeyIdentity, nil); got != want {
			t.Errorf("%q is %s, want %s", op, got, want)
		}
	}
	// generate: a machine key under a cert: name is renewal's, receive;
	// under any other name — the pending: handle it returns, the identity,
	// nothing — send, and not a name the agent makes keys under anyway.
	for key, want := range map[string]Scope{
		CertPrefix + "work": ScopeReceive, PendingPrefix + "work": ScopeSend,
		KeyIdentity: ScopeSend, "": ScopeSend, "work": ScopeSend,
	} {
		if got := ScopeOf(OpGenerate, key, nil); got != want {
			t.Errorf("generate under %q is %s, want %s", key, got, want)
		}
	}
}

// TestTheReceiveSentenceNamesTheDefaultSendTTL: the sentence the client
// prints verbatim says how long 'auu unlock --send' lasts, so the two must
// not drift apart.
func TestTheReceiveSentenceNamesTheDefaultSendTTL(t *testing.T) {
	minutes := int(DefaultSendTTL / time.Minute)
	if !strings.Contains(ReceiveOnlyMessage, "for the next "+itoa(minutes)+" minutes") {
		t.Errorf("ReceiveOnlyMessage %q does not name DefaultSendTTL of %d minutes", ReceiveOnlyMessage, minutes)
	}
	if strings.Contains(ReceiveOnlyMessage, LockedMessage) || strings.Contains(LockedMessage, ReceiveOnlyMessage) {
		t.Error("the two sentences contain one another, so the client could not tell them apart")
	}
}

// peerPoint is a valid X25519 public key, for an exchange that must be
// judged by scope and not refused by the curve.
func peerPoint(t *testing.T) []byte {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// TestReceiveScopeRefusesWhatOriginates: over the socket, in receive scope,
// every operation of the receive set is admitted and every one that
// originates is refused with the sentence; in send scope everything is
// admitted; locked comes before scope.
func TestReceiveScopeRefusesWhatOriginates(t *testing.T) {
	a := startAgent(t)
	a.home.addCert(t, "work", mldsa.MLDSA65())
	listing := "/v1/mailbox/" + fp

	receiveOps := map[string]func() error{
		"a listing": func() error { _, err := a.client.Sign(KeyIdentity, signingString("GET", listing), nil); return err },
		"an acknowledgement": func() error {
			_, err := a.client.Sign(KeyIdentity, signingString("DELETE", listing+"/12"), nil)
			return err
		},
		"a lookup": func() error {
			_, err := a.client.Sign(KeyIdentity, signingString("GET", "/v1/keys/"+fp), nil)
			return err
		},
		"the handshake, under the machine key": func() error {
			_, err := a.client.Sign(CertPrefix+"work", []byte("transcript"), []byte("tls"))
			return err
		},
		"decapsulate": func() error { _, err := a.client.Decapsulate(KeyIdentity, make([]byte, 1088)); return err },
		"exchange":    func() error { _, err := a.client.Exchange(KeyIdentity, peerPoint(t)); return err },
		"a renewal's new key": func() error {
			_, err := a.client.Generate(CertPrefix+"renewed", 65)
			return err
		},
		"a renewal's request": func() error {
			_, err := a.client.Sign(KeyIdentity, signingString("POST", listing+"/certs"), nil)
			return err
		},
	}
	sendOps := map[string]func() error{
		"a post": func() error { _, err := a.client.Sign(KeyIdentity, signingString("POST", listing), nil); return err },
		"a message's signature": func() error {
			_, err := a.client.Sign(KeyIdentity, []byte("ccx-sig-v1"+fp+"{}"), nil)
			return err
		},
		"a stream manifest": func() error {
			_, err := a.client.Sign(KeyIdentity, []byte("ccx-stream-sig-v1"+fp+"{}"), nil)
			return err
		},
		"a directory":   func() error { _, err := a.client.Sign(KeyIdentity, []byte("ccx-channels-v1{}"), nil); return err },
		"an allow list": func() error { _, err := a.client.Sign(KeyIdentity, []byte("ccx-allow-v1{}"), nil); return err },
		"a token":       func() error { _, err := a.client.Sign(KeyIdentity, []byte("ccx-token-v1{}"), nil); return err },
		"a registration": func() error {
			_, err := a.client.Sign(KeyIdentity, signingString("POST", "/v1/register"), nil)
			return err
		},
		"an admin call": func() error {
			_, err := a.client.Sign(KeyIdentity, signingString("GET", "/v1/admin/status"), nil)
			return err
		},
		"nothing in particular": func() error {
			_, err := a.client.Sign(KeyIdentity, []byte("m"), nil)
			return err
		},
	}

	// Locked: every one of them says locked, and nothing about scope.
	for name, op := range sendOps {
		if err := op(); err == nil || !errors.Is(err, identity.ErrLocked) && !strings.Contains(err.Error(), LockedMessage) {
			t.Errorf("locked, %s gave %v, want the locked sentence", name, err)
		} else if strings.Contains(err.Error(), ReceiveOnlyMessage) {
			t.Errorf("locked, %s spoke of scope: %v", name, err)
		}
	}

	a.unlock(t, DefaultTTL)
	if st, _ := a.client.Status(); st.Scope != ScopeReceive || !st.SendUntil.IsZero() {
		t.Fatalf("after unlock the agent is %+v, want receive scope", st)
	}
	for name, op := range receiveOps {
		if err := op(); err != nil {
			t.Errorf("receive scope refused %s: %v", name, err)
		}
	}
	for name, op := range sendOps {
		err := op()
		if err == nil || err.Error() != ReceiveOnlyMessage {
			t.Errorf("receive scope answered %s with %v, want %q exactly", name, err, ReceiveOnlyMessage)
		}
	}

	a.unlockSend(t, DefaultSendTTL)
	if st, _ := a.client.Status(); st.Scope != ScopeSend {
		t.Fatalf("after unlock --send the agent is %+v, want send scope", st)
	}
	for name, op := range receiveOps {
		if err := op(); err != nil {
			t.Errorf("send scope refused %s: %v", name, err)
		}
	}
	for name, op := range sendOps {
		if err := op(); err != nil {
			t.Errorf("send scope refused %s: %v", name, err)
		}
	}
}

// TestSendScopeExpiresToReceiveAndReceiveExpiresToLocked, on the injected
// clock: send scope ending drops the agent to receive scope without
// locking, and the receive TTL ending locks everything.
func TestSendScopeExpiresToReceiveAndReceiveExpiresToLocked(t *testing.T) {
	a := startAgent(t)
	start := a.clock.Now()
	listing := "/v1/mailbox/" + fp
	a.unlockSend(t, DefaultSendTTL)
	st, _ := a.client.Status()
	if st.Scope != ScopeSend || !st.SendUntil.Equal(start.Add(DefaultSendTTL).Truncate(time.Second)) ||
		!st.Until.Equal(start.Add(DefaultTTL).Truncate(time.Second)) {
		t.Fatalf("after unlock --send on a locked agent: %+v, want send for %s and receive for %s", st, DefaultSendTTL, DefaultTTL)
	}

	a.clock.Set(start.Add(DefaultSendTTL - time.Second))
	if _, err := a.client.Sign(KeyIdentity, signingString("POST", listing), nil); err != nil {
		t.Fatalf("a second before send scope ends: %v", err)
	}
	a.clock.Set(start.Add(DefaultSendTTL))
	if _, err := a.client.Sign(KeyIdentity, signingString("POST", listing), nil); err == nil || err.Error() != ReceiveOnlyMessage {
		t.Fatalf("at the end of send scope a post gave %v, want the receive sentence", err)
	}
	if _, err := a.client.Sign(KeyIdentity, signingString("GET", listing), nil); err != nil {
		t.Fatalf("at the end of send scope a listing gave %v, want it signed: the agent locked instead of narrowing", err)
	}
	st, _ = a.client.Status()
	if st.Locked || st.Scope != ScopeReceive || !st.SendUntil.IsZero() || !st.Until.Equal(start.Add(DefaultTTL).Truncate(time.Second)) {
		t.Fatalf("after send scope ended the agent is %+v, want receive until the receive expiry", st)
	}

	a.clock.Set(start.Add(DefaultTTL))
	if _, err := a.client.Sign(KeyIdentity, signingString("GET", listing), nil); !errors.Is(err, identity.ErrLocked) {
		t.Fatalf("at the receive expiry a listing gave %v, want locked", err)
	}
	if st, _ := a.client.Status(); !st.Locked || st.Scope != "" {
		t.Errorf("after the receive expiry the agent is %+v", st)
	}
}

// TestLockSendDropsToReceiveWithoutLocking: 'auu lock --send' narrows and
// zeroes nothing; on a locked agent it is nothing; a plain lock after it
// locks.
func TestLockSendDropsToReceiveWithoutLocking(t *testing.T) {
	a := startAgent(t)
	if err := a.client.LockSend(); err != nil {
		t.Fatalf("lock --send on a locked agent: %v", err)
	}
	if st, _ := a.client.Status(); !st.Locked {
		t.Fatal("lock --send on a locked agent unlocked something")
	}
	a.unlockSend(t, 0)
	st, _ := a.client.Status()
	if st.Scope != ScopeSend || !st.SendUntil.IsZero() || !st.Until.IsZero() {
		t.Fatalf("after unlock --send --ttl 0 the agent is %+v, want both until lock", st)
	}
	if err := a.client.LockSend(); err != nil {
		t.Fatal(err)
	}
	st, _ = a.client.Status()
	if st.Locked || st.Scope != ScopeReceive || !st.Until.IsZero() {
		t.Fatalf("after lock --send the agent is %+v, want receive until lock", st)
	}
	if _, err := a.client.Sign(KeyIdentity, signingString("POST", "/v1/mailbox/"+fp), nil); err == nil || err.Error() != ReceiveOnlyMessage {
		t.Errorf("after lock --send a post gave %v", err)
	}
	if _, err := a.client.Sign(KeyIdentity, signingString("GET", "/v1/mailbox/"+fp), nil); err != nil {
		t.Errorf("after lock --send a listing gave %v", err)
	}
	a.server.mu.Lock()
	held := a.server.homeKey != nil && a.server.ident != nil
	a.server.mu.Unlock()
	if !held {
		t.Error("lock --send dropped the keys")
	}
	if err := a.client.Lock(); err != nil {
		t.Fatal(err)
	}
	if st, _ := a.client.Status(); !st.Locked {
		t.Error("lock after lock --send did not lock")
	}
}

// TestTheTwoExpiriesFollowTheRule is the rule in Unlock's doc comment, case
// by case, on the injected clock.
func TestTheTwoExpiriesFollowTheRule(t *testing.T) {
	a := startAgent(t)
	start := a.clock.Now()
	at := func(d time.Duration) time.Time { return start.Add(d).Truncate(time.Second) }
	status := func(t *testing.T, scope Scope, until, sendUntil time.Time, what string) {
		t.Helper()
		st, err := a.client.Status()
		if err != nil {
			t.Fatal(err)
		}
		if st.Locked || st.Scope != scope || !st.Until.Equal(until) || !st.SendUntil.Equal(sendUntil) {
			t.Fatalf("%s: the agent is scope %s until %v send_until %v, want %s until %v send_until %v",
				what, st.Scope, st.Until, st.SendUntil, scope, until, sendUntil)
		}
	}
	var none time.Time

	// A second unlock --send extends: send from the second one's clock.
	a.unlockSend(t, DefaultSendTTL)
	status(t, ScopeSend, at(DefaultTTL), at(DefaultSendTTL), "unlock --send on a locked agent")
	a.clock.Set(start.Add(5 * time.Minute))
	a.unlockSend(t, DefaultSendTTL)
	status(t, ScopeSend, at(DefaultTTL), at(15*time.Minute), "a second unlock --send five minutes in")

	// A plain unlock while send is live re-verifies, resets receive, leaves
	// send alone.
	a.clock.Set(start)
	a.unlock(t, time.Hour)
	status(t, ScopeSend, at(time.Hour), at(15*time.Minute), "a plain unlock while send is live")

	// unlock --send on an unlocked agent whose receive expiry would fall
	// before the send expiry: receive is extended to it.
	a.client.Lock()
	a.unlock(t, 5*time.Minute)
	a.unlockSend(t, DefaultSendTTL)
	status(t, ScopeSend, at(DefaultSendTTL), at(DefaultSendTTL), "receive of 5m then unlock --send of 10m")

	// ... and one whose receive expiry is later: left alone.
	a.client.Lock()
	a.unlock(t, time.Hour)
	a.unlockSend(t, DefaultSendTTL)
	status(t, ScopeSend, at(time.Hour), at(DefaultSendTTL), "receive of 1h then unlock --send of 10m")

	// --ttl 0 on an unlocked agent: send until lock, so receive until lock.
	a.unlockSend(t, 0)
	status(t, ScopeSend, none, none, "unlock --send --ttl 0 on an unlocked agent")

	// --ttl 0 on a locked agent: both until lock.
	a.client.Lock()
	a.unlockSend(t, 0)
	status(t, ScopeSend, none, none, "unlock --send --ttl 0 on a locked agent")

	// A receive unlock of 1h over send-until-lock: receive resets to 1h,
	// send stays until-lock, and the receive expiry locking everything is
	// what keeps send from outliving it.
	a.unlock(t, time.Hour)
	status(t, ScopeSend, at(time.Hour), none, "a receive unlock over send until lock")
	a.clock.Set(start.Add(time.Hour))
	if st, _ := a.client.Status(); !st.Locked {
		t.Errorf("at the receive expiry the agent is %+v, want locked", st)
	}
}
