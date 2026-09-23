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

// SetAllowlist sends the signed pair and nothing else under the caller's
// own mailbox: the document and the signature byte for byte, under the
// wire's field names, and no array of senders beside them, since a
// relay reads the document and nothing on the wire is from before. A 409
// comes back as the error it is.
func TestSetAllowlistSendsTheSignedPair(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: http.StatusNoContent},
		{status: http.StatusConflict, body: relayapi.ErrorResponse{Error: "a newer allow list is already there (issued 2026-09-17T10:04:00Z)"}},
	}}
	c, _ := newTestClient(t, rec)
	doc, sig := []byte(`{"v":1,"owner":"me","senders":["a"]}`), []byte{1, 2, 3}
	if err := c.SetAllowlist(context.Background(), doc, sig); err != nil {
		t.Fatal(err)
	}
	req, body := rec.last()
	if req != "PUT /v1/mailbox/"+c.id.Fingerprint()+"/allow" {
		t.Fatalf("asked %q", req)
	}
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("the body is not an object: %s", body)
	}
	if len(sent) != 2 || sent["document"] == nil || sent["signature"] == nil {
		t.Fatalf("the body carries other than the document and the signature: %s", body)
	}
	var pair relayapi.AllowRequest
	if err := json.Unmarshal(body, &pair); err != nil || string(pair.Document) != string(doc) || string(pair.Signature) != string(sig) {
		t.Fatalf("the bytes changed on the way: %s", body)
	}
	var httpErr *HTTPError
	err := c.SetAllowlist(context.Background(), doc, sig)
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusConflict || !strings.Contains(httpErr.Message, "issued 2026-09-17T10:04:00Z") {
		t.Fatalf("a 409: %v", err)
	}
	if rec.count() != 2 {
		t.Fatalf("a 409 was retried: %d calls", rec.count())
	}
}

// Allowlist gives back the pair verbatim with the relay's state, and None
// for a mailbox that has never pushed; the listing carries the state, one
// of its three words, and a listing without it is refused by name.
func TestAllowlistAndTheListingCarryTheState(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: http.StatusOK, body: relayapi.AllowResponse{Document: []byte(`{"v":1}`), Signature: []byte{9}, State: "signed"}},
		{status: http.StatusOK, body: relayapi.AllowResponse{State: "none"}},
		{status: http.StatusOK, body: map[string]any{"messages": []any{}, "queued": 0, "allow": "broken", "card": "none", "directory": "none"}},
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
	_, err = c.List(ctx, 0, 10)
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), "in the listing, allow is not one of signed, none, broken") {
		t.Fatalf("a listing without the state: %v; want it refused by name", err)
	}
}
