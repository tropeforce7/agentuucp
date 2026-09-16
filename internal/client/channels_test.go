package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// last is what the recorder saw on its most recent call.
func (r *recorder) last() (request string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests[len(r.requests)-1], r.bodies[len(r.bodies)-1]
}

// A listing from a relay that names the channel says so; one from a relay
// from before channels leaves ChannelKnown false, and the sealed record
// alone decides where the message goes.
func TestListSaysWhetherTheRelayNamedTheChannel(t *testing.T) {
	newRelay := map[string]any{
		"messages": []map[string]any{
			{"id": 1, "received": "2026-09-13T01:19:29Z", "kind": "envelope", "size": 3, "channel": "bug reports", "envelope": map[string]any{"v": 1, "to": "x", "ct": "AAA"}},
			{"id": 2, "received": "2026-09-13T01:19:30Z", "kind": "stream", "size": 5000, "channel": "default"},
		},
		"queued": 2,
	}
	oldRelay := map[string]any{
		"messages": []map[string]any{
			{"id": 1, "received": "2026-09-13T01:19:29Z", "kind": "envelope", "size": 3, "envelope": map[string]any{"v": 1, "to": "x", "ct": "AAA"}},
		},
	}
	rec := &recorder{replies: []reply{{status: http.StatusOK, body: newRelay}, {status: http.StatusOK, body: oldRelay}}}
	c, _ := newTestClient(t, rec)

	l, err := c.List(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Messages) != 2 {
		t.Fatalf("listed %d messages, want 2", len(l.Messages))
	}
	if m := l.Messages[0]; !m.ChannelKnown || m.Channel != "bug reports" {
		t.Fatalf("a named channel came back as %+v", m)
	}
	if m := l.Messages[1]; !m.ChannelKnown || m.Channel != "default" || !m.IsStream() {
		t.Fatalf("a stream under default came back as %+v", m)
	}
	l, err = c.List(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if m := l.Messages[0]; m.ChannelKnown || m.Channel != "" {
		t.Fatalf("an old relay's message came back as %+v; the relay said nothing", m)
	}
}

// The relay answers 404 both for a mailbox that is not there and for one
// with no directory. Only the second is an answer.
func TestDirectoryTellsNoDirectoryFromNoMailbox(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	rec := &recorder{replies: []reply{
		{status: http.StatusNotFound, body: relayapi.ErrorResponse{Error: relayapi.MsgNoDirectory}},
		{status: http.StatusNotFound, body: relayapi.ErrorResponse{Error: "no such mailbox"}},
		{status: http.StatusForbidden, body: relayapi.ErrorResponse{Error: "sender is not on the recipient's allow list"}},
		{status: http.StatusOK, body: relayapi.ChannelsResponse{Document: []byte(`{"v":1}`), Signature: []byte("sig"),
			Queued: map[string]int64{"default": 0, "bug reports": 2}}},
		{status: http.StatusOK, body: relayapi.ChannelsResponse{Document: []byte(`{"v":1}`), Signature: []byte("sig")}},
	}}
	c, _ := newTestClient(t, rec)
	ctx := context.Background()

	d, err := c.Directory(ctx, fp)
	if err != nil || d == nil || !d.None || d.Document != nil {
		t.Fatalf("no directory: %+v, %v; want None and no error", d, err)
	}
	if req, _ := rec.last(); req != "GET /v1/mailbox/"+fp+"/channels" {
		t.Fatalf("asked %q", req)
	}
	var httpErr *HTTPError
	if _, err := c.Directory(ctx, fp); !errors.As(err, &httpErr) || httpErr.Status != http.StatusNotFound ||
		httpErr.Message != "no such mailbox" {
		t.Fatalf("no such mailbox: %v; want the 404 as an error", err)
	}
	if _, err := c.Directory(ctx, fp); !errors.As(err, &httpErr) || httpErr.Status != http.StatusForbidden {
		t.Fatalf("a refused sender: %v; want the 403 as an error", err)
	}
	d, err = c.Directory(ctx, fp)
	if err != nil || d.None || string(d.Document) != `{"v":1}` || string(d.Signature) != "sig" {
		t.Fatalf("the owner's view: %+v, %v", d, err)
	}
	if d.Queued["bug reports"] != 2 || d.Queued["default"] != 0 || len(d.Queued) != 2 {
		t.Fatalf("the owner's counts: %v", d.Queued)
	}
	d, err = c.Directory(ctx, fp)
	if err != nil || d.None || d.Queued != nil {
		t.Fatalf("a sender's view: %+v, %v; want no counts", d, err)
	}
}

// SetDirectory sends the bytes as given, under the caller's own mailbox,
// and a 409 comes back as the error it is.
func TestSetDirectorySendsTheBytesAsSigned(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: http.StatusNoContent},
		{status: http.StatusConflict, body: relayapi.ErrorResponse{Error: "a newer directory is already there (issued 2026-09-13T01:19:29Z)"}},
	}}
	c, _ := newTestClient(t, rec)
	doc, sig := []byte(`{"v":1,"owner":"me"}`), []byte{1, 2, 3}
	if err := c.SetDirectory(context.Background(), doc, sig); err != nil {
		t.Fatal(err)
	}
	req, body := rec.last()
	if req != "PUT /v1/mailbox/"+c.id.Fingerprint()+"/channels" {
		t.Fatalf("asked %q", req)
	}
	var sent relayapi.ChannelsRequest
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("the body is not a channels request: %s", body)
	}
	if string(sent.Document) != string(doc) || string(sent.Signature) != string(sig) {
		t.Fatalf("the bytes changed on the way: %s", body)
	}
	var httpErr *HTTPError
	err := c.SetDirectory(context.Background(), doc, sig)
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusConflict || !strings.Contains(httpErr.Message, "issued 2026-09-13T01:19:29Z") {
		t.Fatalf("a 409: %v", err)
	}
	if rec.count() != 2 {
		t.Fatalf("a 409 was retried: %d calls", rec.count())
	}
}

// Post and OpenStream put the channel on the wire under its name, and put
// nothing for default.
func TestPostAndOpenStreamCarryTheChannel(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: http.StatusOK, body: relayapi.PostResponse{ID: 1}},
		{status: http.StatusOK, body: relayapi.PostResponse{ID: 2}},
		{status: http.StatusCreated, body: relayapi.OpenStreamResponse{Upload: "u"}},
		{status: http.StatusCreated, body: relayapi.OpenStreamResponse{Upload: "u"}},
	}}
	c, _ := newTestClient(t, rec)
	ctx := context.Background()
	to := strings.Repeat("cd", 32)

	env := &envelope.Envelope{V: 1, To: to, CT: []byte("ct")}
	if _, err := c.Post(ctx, env, "bug reports"); err != nil {
		t.Fatal(err)
	}
	if req, body := rec.last(); req != "POST /v1/mailbox/"+to || !strings.Contains(string(body), `"ch":"bug reports"`) {
		t.Fatalf("a post for a channel: %s %s", req, body)
	}
	if _, err := c.Post(ctx, env, ""); err != nil {
		t.Fatal(err)
	}
	if _, body := rec.last(); strings.Contains(string(body), `"ch"`) {
		t.Fatalf("a post for default names a channel: %s", body)
	}
	if _, err := c.OpenStream(ctx, to, "bug reports", 5000); err != nil {
		t.Fatal(err)
	}
	if req, body := rec.last(); req != "POST /v1/mailbox/"+to+"/streams" || !strings.Contains(string(body), `"channel":"bug reports"`) ||
		!strings.Contains(string(body), `"size":5000`) {
		t.Fatalf("a stream open for a channel: %s %s", req, body)
	}
	if _, err := c.OpenStream(ctx, to, "", 5000); err != nil {
		t.Fatal(err)
	}
	if _, body := rec.last(); strings.Contains(string(body), `"channel"`) {
		t.Fatalf("a stream open for default names a channel: %s", body)
	}
}
