package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// SetAllowlist sends all three fields, the array beside the signed pair,
// under the caller's own mailbox: a relay from before signed lists reads
// the array, and must never read an empty one for a list of somebody. A
// nil list goes as [] and not null, as it always did. A 409 comes back as
// the error it is, and the old relay's 400 sentence likewise.
func TestSetAllowlistSendsAllThreeFields(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: http.StatusNoContent},
		{status: http.StatusNoContent},
		{status: http.StatusConflict, body: relayapi.ErrorResponse{Error: "a newer allow list is already there (issued 2026-09-17T10:04:00Z)"}},
	}}
	c, _ := newTestClient(t, rec)
	doc, sig := []byte(`{"v":1,"owner":"me","senders":["a"]}`), []byte{1, 2, 3}
	senders := []string{strings.Repeat("a", 64)}
	if err := c.SetAllowlist(context.Background(), senders, doc, sig); err != nil {
		t.Fatal(err)
	}
	req, body := rec.last()
	if req != "PUT /v1/mailbox/"+c.id.Fingerprint()+"/allow" {
		t.Fatalf("asked %q", req)
	}
	var sent relayapi.AllowRequest
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("the body is not an allow request: %s", body)
	}
	if len(sent.Allow) != 1 || sent.Allow[0] != senders[0] {
		t.Fatalf("the array is not the senders: %s", body)
	}
	if string(sent.Document) != string(doc) || string(sent.Signature) != string(sig) {
		t.Fatalf("the bytes changed on the way: %s", body)
	}
	// The field names are the wire's, so that an old relay finds "allow".
	for _, want := range []string{`"allow":["`, `"document":"`, `"signature":"`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("the body lacks %s: %s", want, body)
		}
	}
	if err := c.SetAllowlist(context.Background(), nil, doc, sig); err != nil {
		t.Fatal(err)
	}
	if _, body := rec.last(); !strings.Contains(string(body), `"allow":[]`) {
		t.Fatalf("a nil list is not sent as []: %s", body)
	}
	var httpErr *HTTPError
	err := c.SetAllowlist(context.Background(), senders, doc, sig)
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusConflict || !strings.Contains(httpErr.Message, "issued 2026-09-17T10:04:00Z") {
		t.Fatalf("a 409: %v", err)
	}
	if rec.count() != 3 {
		t.Fatalf("a 409 was retried: %d calls", rec.count())
	}
}

// Allowlist gives back the pair verbatim with the relay's state, and None
// for a mailbox that has never pushed; the listing carries the state, and
// a relay from before it says nothing.
func TestAllowlistAndTheListingCarryTheState(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: http.StatusOK, body: relayapi.AllowResponse{Document: []byte(`{"v":1}`), Signature: []byte{9}, State: "signed"}},
		{status: http.StatusOK, body: relayapi.AllowResponse{State: "none"}},
		{status: http.StatusOK, body: map[string]any{"messages": []any{}, "queued": 0, "allow": "broken"}},
		{status: http.StatusOK, body: map[string]any{"messages": []any{}, "queued": 0}},
	}}
	c, _ := newTestClient(t, rec)
	ctx := context.Background()
	res, err := c.Allowlist(ctx)
	if err != nil || res.None || res.State != "signed" || string(res.Document) != `{"v":1}` || len(res.Signature) != 1 {
		t.Fatalf("a signed list: %+v, %v", res, err)
	}
	if req, _ := rec.last(); req != "GET /v1/mailbox/"+c.id.Fingerprint()+"/allow" {
		t.Fatalf("asked %q", req)
	}
	res, err = c.Allowlist(ctx)
	if err != nil || !res.None || res.State != "none" || res.Document != nil {
		t.Fatalf("no list: %+v, %v", res, err)
	}
	l, err := c.List(ctx, 0, 10)
	if err != nil || l.Allow != "broken" {
		t.Fatalf("a listing with the state: %+v, %v", l, err)
	}
	l, err = c.List(ctx, 0, 10)
	if err != nil || l.Allow != "" {
		t.Fatalf("a listing from before the state: %+v, %v", l, err)
	}
}
