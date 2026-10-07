package relay

import (
	"crypto/mldsa"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// Every request body the relay reads goes through decodeRequest, and the
// rule it enforces is the same on all eleven: a field the request does not
// have is refused by name, a section is the one place something new may
// go, a section the relay does not know is ignored unless it is marked
// critical, and a critical one is refused with the code a client acts on.
// The table below holds each route to that rule through its real handler,
// under its real signature, built on the fixture its own tests succeed
// with, so that a twelfth body, or a route that stopped calling
// decodeRequest, is not one the rule silently skips.

// sending is one request ready to go: the good body as its fields, which a
// row adds keys to, and how to send a body to the route.
type sending struct {
	fields map[string]json.RawMessage
	send   func(body []byte) (int, []byte)
}

// requestCase is one route: what the call site names its request in the
// refusal's sentence, the status the route answers a good request with,
// and start, which builds the relay and returns a source of fresh good
// requests, one per row, since most of these routes refuse a repeat.
type requestCase struct {
	route  string
	what   string
	status int
	start  func(t *testing.T) func(t *testing.T) sending
}

// fieldsOf is a request's fields as raw JSON, kept byte for byte, so that
// a row can add a key to a body the route would otherwise accept and
// nothing about the rest of it changes.
func fieldsOf(t *testing.T, req any) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// bodyWith is the request's fields with one key added, as the bytes that
// are signed and sent. No key is added when key is empty.
func bodyWith(t *testing.T, fields map[string]json.RawMessage, key, value string) []byte {
	t.Helper()
	out := make(map[string]json.RawMessage, len(fields)+1)
	for k, v := range fields {
		out[k] = v
	}
	if key != "" {
		out[key] = json.RawMessage(value)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// refusal is an error body read with its code, which errorText drops.
func refusal(t *testing.T, body []byte) relayapi.ErrorResponse {
	t.Helper()
	var e relayapi.ErrorResponse
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("response is not an error object: %s", body)
	}
	return e
}

const (
	laterSection    = `[{"name":"later","critical":false,"data":1}]`
	mustKnowSection = `[{"name":"must-know","critical":true,"data":1}]`
)

func requestCases() []requestCase {
	// A fresh identity per row wherever the route keeps something per
	// identity: a list, card or directory issued no later than the one
	// stored is refused, a mailbox registers once, and a certificate is
	// renewed once before the old one stops working.
	fresh := func(t *testing.T, name string) *identity.Identity {
		t.Helper()
		return ids(t, name)[0]
	}
	return []requestCase{
		{
			route: "register", what: "register request", status: http.StatusOK,
			start: func(t *testing.T) func(t *testing.T) sending {
				h := newHarness(t, Config{})
				return func(t *testing.T) sending {
					id := fresh(t, "newcomer")
					return sending{
						fields: fieldsOf(t, h.registerBody(id, id.Name, "")),
						send: func(body []byte) (int, []byte) {
							return h.do(id, "POST", "/v1/register", body, nil)
						},
					}
				}
			},
		},
		{
			route: "allow", what: "allow request", status: http.StatusNoContent,
			start: func(t *testing.T) func(t *testing.T) sending {
				h := newHarness(t, Config{})
				return func(t *testing.T) sending {
					owner := fresh(t, "owner")
					h.register(owner)
					return sending{
						fields: fieldsOf(t, h.allowReq(owner, fresh(t, "friend").Fingerprint())),
						send: func(body []byte) (int, []byte) {
							return h.do(owner, "PUT", "/v1/mailbox/"+owner.Fingerprint()+"/allow", body, nil)
						},
					}
				}
			},
		},
		{
			route: "card", what: "card request", status: http.StatusNoContent,
			start: func(t *testing.T) func(t *testing.T) sending {
				h := newHarness(t, Config{})
				return func(t *testing.T) sending {
					owner := fresh(t, "owner")
					h.register(owner)
					_, doc, sig := signedCard(t, owner, time.Now(), true, true)
					return sending{
						fields: fieldsOf(t, relayapi.CardRequest{Document: doc, Signature: sig}),
						send: func(body []byte) (int, []byte) {
							return h.do(owner, "PUT", "/v1/mailbox/"+owner.Fingerprint()+"/card", body, nil)
						},
					}
				}
			},
		},
		{
			route: "channels", what: "channels request", status: http.StatusNoContent,
			start: func(t *testing.T) func(t *testing.T) sending {
				h := newHarness(t, Config{})
				return func(t *testing.T) sending {
					owner := fresh(t, "owner")
					h.register(owner)
					_, doc, sig := signedDirectory(t, owner, time.Now(), dflt, bugs)
					return sending{
						fields: fieldsOf(t, relayapi.ChannelsRequest{Document: doc, Signature: sig}),
						send: func(body []byte) (int, []byte) {
							return h.do(owner, "PUT", "/v1/mailbox/"+owner.Fingerprint()+"/channels", body, nil)
						},
					}
				}
			},
		},
		{
			route: "forward", what: "forward request", status: http.StatusCreated,
			start: func(t *testing.T) func(t *testing.T) sending {
				h := peered(t, []string{"bar"}, nil, nil)
				to := h.fpOf(t, "bob")
				n := 0
				return func(t *testing.T) sending {
					// A user of its own and an envelope of its own per row,
					// so that neither the per-poster bound nor the
					// duplicate check is what answers.
					n++
					user := h.user(t, fmt.Sprintf("sender%d", n))
					return sending{
						fields: fieldsOf(t, request(sealedFor(to, fmt.Sprintf("ct%d", n)), []string{"bar"}, nil)),
						send: func(body []byte) (int, []byte) {
							return h.do(user, "POST", "/v1/forward", body, nil)
						},
					}
				}
			},
		},
		{
			route: "forward failed", what: "report", status: http.StatusNoContent,
			start: func(t *testing.T) func(t *testing.T) sending {
				courier := neighbourID(t, "bar")
				h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
				h.enroll(courier)
				alice := h.user(t, "alice")
				n := int64(0)
				return func(t *testing.T) sending {
					// A row of its own per row: a report is taken once.
					n++
					theirs := 4710 + n
					h.handedRow(t, alice, h.fpOf(t, "bob"), fmt.Sprintf("ct%d", n), theirs)
					return sending{
						fields: fieldsOf(t, failedReq(theirs, relayapi.CodeRefused, "baz: no such mailbox")),
						send: func(body []byte) (int, []byte) {
							return h.do(courier, "POST", "/v1/forward/failed", body, nil)
						},
					}
				}
			},
		},
		{
			route: "certs", what: "certificate request", status: http.StatusOK,
			start: func(t *testing.T) func(t *testing.T) sending {
				h := newCertHarness(t, nil)
				return func(t *testing.T) sending {
					alice := fresh(t, "alice")
					m, status, body := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
					if m == nil {
						t.Fatalf("enrolling: %d %s", status, body)
					}
					key, err := mldsa.GenerateKey(mldsa.MLDSA65())
					if err != nil {
						t.Fatal(err)
					}
					csr, err := clientca.NewCSR(key, "laptop", "")
					if err != nil {
						t.Fatal(err)
					}
					return sending{
						fields: fieldsOf(t, relayapi.CertRequest{CSR: csr}),
						send: func(body []byte) (int, []byte) {
							return h.overTLS(alice, m.tlsCert(), "POST", "/v1/mailbox/"+alice.Fingerprint()+"/certs", body)
						},
					}
				}
			},
		},
		{
			route: "revoke cert", what: "revoke request", status: http.StatusOK,
			start: func(t *testing.T) func(t *testing.T) sending {
				h := newCertHarness(t, nil)
				return func(t *testing.T) sending {
					alice := fresh(t, "alice")
					m, status, body := h.enrolMachine(alice, h.registerToken(token.UseRegister, ""))
					if m == nil {
						t.Fatalf("enrolling: %d %s", status, body)
					}
					return sending{
						fields: fieldsOf(t, relayapi.RevokeCertRequest{Reason: "lost laptop"}),
						send: func(body []byte) (int, []byte) {
							return h.do(h.admin, "DELETE", "/v1/admin/certs/"+m.serial, body, nil)
						},
					}
				}
			},
		},
		{
			route: "block", what: "block request", status: http.StatusNoContent,
			start: func(t *testing.T) func(t *testing.T) sending {
				boss := fresh(t, "boss")
				h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
				return func(t *testing.T) sending {
					nuisance := fresh(t, "nuisance")
					h.register(nuisance)
					return sending{
						fields: fieldsOf(t, relayapi.BlockRequest{Reason: "flooding the relay"}),
						send: func(body []byte) (int, []byte) {
							return h.do(boss, "PUT", "/v1/admin/blocks/"+nuisance.Fingerprint(), body, nil)
						},
					}
				}
			},
		},
		{
			route: "token", what: "token request", status: http.StatusCreated,
			start: func(t *testing.T) func(t *testing.T) sending {
				boss := fresh(t, "boss")
				h := tokenHarness(t, boss)
				return func(t *testing.T) sending {
					// A token of its own per row: one registered twice is
					// refused.
					return sending{
						fields: fieldsOf(t, relayapi.RegisterTokenRequest{Token: h.issue(boss, nil)}),
						send: func(body []byte) (int, []byte) {
							return h.do(boss, "POST", "/v1/admin/tokens", body, nil)
						},
					}
				}
			},
		},
		{
			route: "streams", what: "stream request", status: http.StatusCreated,
			start: func(t *testing.T) func(t *testing.T) sending {
				h := newHarness(t, Config{})
				people := ids(t, "alice", "bob")
				alice, bob := people[0], people[1]
				h.register(alice)
				h.register(bob)
				return func(t *testing.T) sending {
					return sending{
						fields: fieldsOf(t, relayapi.OpenStreamRequest{Size: 100_000}),
						send: func(body []byte) (int, []byte) {
							return h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint()+"/streams", body, nil)
						},
					}
				}
			},
		},
	}
}

// TestEveryRequestTakesNothingNewButSections: the same four rows for each
// of the eleven request bodies — the good body, the good body with a field
// it does not have, with a section the relay may ignore, and with one it
// may not.
func TestEveryRequestTakesNothingNewButSections(t *testing.T) {
	for _, tc := range requestCases() {
		t.Run(tc.route, func(t *testing.T) {
			next := tc.start(t)

			t.Run("good", func(t *testing.T) {
				req := next(t)
				if status, body := req.send(bodyWith(t, req.fields, "", "")); status != tc.status {
					t.Fatalf("the good body: %d, want %d: %s", status, tc.status, body)
				}
			})

			t.Run("unknown field", func(t *testing.T) {
				req := next(t)
				status, body := req.send(bodyWith(t, req.fields, "colour", `"blue"`))
				if status != http.StatusBadRequest {
					t.Fatalf("a field the request does not have: %d, want 400: %s", status, body)
				}
				e := refusal(t, body)
				if want := fmt.Sprintf(`malformed %s: json: unknown field "colour"`, tc.what); e.Error != want {
					t.Errorf("error %q, want %q", e.Error, want)
				}
				if e.Code != "" {
					t.Errorf("code %q; a malformed body carries none", e.Code)
				}
			})

			t.Run("section it may ignore", func(t *testing.T) {
				req := next(t)
				if status, body := req.send(bodyWith(t, req.fields, "sections", laterSection)); status != tc.status {
					t.Fatalf("a section that is not critical: %d, want %d: %s", status, tc.status, body)
				}
			})

			t.Run("section it must know", func(t *testing.T) {
				req := next(t)
				status, body := req.send(bodyWith(t, req.fields, "sections", mustKnowSection))
				if status != http.StatusBadRequest {
					t.Fatalf("a critical section: %d, want 400: %s", status, body)
				}
				e := refusal(t, body)
				if want := fmt.Sprintf(relayapi.MsgNeedsNewer, relayapi.WireLevel, "must-know"); e.Error != want {
					t.Errorf("error %q, want %q", e.Error, want)
				}
				if e.Code != relayapi.CodeNeedsNewer {
					t.Errorf("code %q, want %q", e.Code, relayapi.CodeNeedsNewer)
				}
			})
		})
	}
}

// allowRows is how many allow lists the relay holds for a mailbox.
func (h *harness) allowRows(fp string) int {
	h.t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM allowlists WHERE fp = ?`, fp).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// TestARefusedRequestSpendsNoNonceItWouldNotHaveAndWritesNoRow: a critical
// section is refused where a malformed body always was. On an
// authenticated route that is after the signature, so the request spends
// its nonce exactly as a malformed body does, and nothing else; on
// register it is before the signature, so it spends none, and no mailbox
// is made.
func TestARefusedRequestSpendsNoNonceItWouldNotHaveAndWritesNoRow(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		h := newHarness(t, Config{})
		owner := ids(t, "owner")[0]
		h.register(owner)
		path := "/v1/mailbox/" + owner.Fingerprint() + "/allow"

		before := h.nonceCount()
		fields := fieldsOf(t, h.allowReq(owner, ids(t, "friend")[0].Fingerprint()))
		if status, body := h.do(owner, "PUT", path, bodyWith(t, fields, "sections", mustKnowSection), nil); status != http.StatusBadRequest {
			t.Fatalf("a critical section: %d, want 400: %s", status, body)
		}
		if got := h.nonceCount(); got != before+1 {
			t.Errorf("nonces %d after a critical section, want %d", got, before+1)
		}
		if got := h.allowRows(owner.Fingerprint()); got != 0 {
			t.Errorf("%d allow lists stored by a refused request", got)
		}

		// A malformed body, which this route has always refused at the
		// same place, spends the same one nonce.
		before = h.nonceCount()
		if status, body := h.do(owner, "PUT", path, []byte(`[1,2]`), nil); status != http.StatusBadRequest {
			t.Fatalf("a malformed body: %d, want 400: %s", status, body)
		}
		if got := h.nonceCount(); got != before+1 {
			t.Errorf("nonces %d after a malformed body, want %d", got, before+1)
		}
		if got := h.allowRows(owner.Fingerprint()); got != 0 {
			t.Errorf("%d allow lists stored by a malformed request", got)
		}
	})

	t.Run("streams", func(t *testing.T) {
		h := newHarness(t, Config{})
		people := ids(t, "alice", "bob")
		alice, bob := people[0], people[1]
		h.register(alice)
		h.register(bob)
		path := "/v1/mailbox/" + bob.Fingerprint() + "/streams"

		before := h.nonceCount()
		fields := fieldsOf(t, relayapi.OpenStreamRequest{Size: 100_000})
		if status, body := h.do(alice, "POST", path, bodyWith(t, fields, "sections", mustKnowSection), nil); status != http.StatusBadRequest {
			t.Fatalf("a critical section: %d, want 400: %s", status, body)
		}
		if got := h.nonceCount(); got != before+1 {
			t.Errorf("nonces %d after a critical section, want %d", got, before+1)
		}
		if got := h.reserved(bob.Fingerprint()); got != 0 {
			t.Errorf("%d uploads reserved by a refused request", got)
		}

		before = h.nonceCount()
		if status, body := h.do(alice, "POST", path, []byte(`[1,2]`), nil); status != http.StatusBadRequest {
			t.Fatalf("a malformed body: %d, want 400: %s", status, body)
		}
		if got := h.nonceCount(); got != before+1 {
			t.Errorf("nonces %d after a malformed body, want %d", got, before+1)
		}
		if got := h.reserved(bob.Fingerprint()); got != 0 {
			t.Errorf("%d uploads reserved by a malformed request", got)
		}
	})

	t.Run("register", func(t *testing.T) {
		h := newHarness(t, Config{})
		id := ids(t, "newcomer")[0]

		nonces, mailboxes := h.nonceCount(), h.mailboxCount()
		fields := fieldsOf(t, h.registerBody(id, id.Name, ""))
		if status, body := h.do(id, "POST", "/v1/register", bodyWith(t, fields, "sections", mustKnowSection), nil); status != http.StatusBadRequest {
			t.Fatalf("a critical section: %d, want 400: %s", status, body)
		}
		if got := h.nonceCount(); got != nonces {
			t.Errorf("nonces %d after a refused register, want %d: the refusal comes before the signature", got, nonces)
		}
		if got := h.mailboxCount(); got != mailboxes {
			t.Errorf("mailboxes %d after a refused register, want %d", got, mailboxes)
		}
	})
}
