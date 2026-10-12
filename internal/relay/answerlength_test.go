package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// lengthAnswer sends a signed request and hands back the answer's status,
// the length net/http read from its Content-Length (-1 for none), its
// transfer encodings and its body.
func (h *harness) lengthAnswer(id *identity.Identity, method, path string, payload any) (int, int64, []string, []byte) {
	h.t.Helper()
	var body []byte
	if payload != nil {
		var err error
		if raw, ok := payload.([]byte); ok {
			body = raw
		} else if body, err = json.Marshal(payload); err != nil {
			h.t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, h.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if err := relayapi.SignRequest(id, req, body); err != nil {
		h.t.Fatal(err)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(resp.Body); err != nil {
		h.t.Fatal(err)
	}
	return resp.StatusCode, resp.ContentLength, resp.TransferEncoding, out.Bytes()
}

// encoded is what json.NewEncoder(w).Encode(v) writes, the form writeJSON
// wrote before it declared a length.
func encoded(t *testing.T, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(v); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// G4: every answer writeJSON writes declares its length, so a client sizes
// its buffer to it rather than growing one, and its bytes are the encoder's
// as they were before: a listing page large enough that net/http would
// otherwise send it chunked, a refusal, and a 201, through a real relay;
// and a value with <, > and & in a string, which json.Marshal and the
// encoder both escape, through writeJSON itself.
func TestEveryAnswerDeclaresItsLength(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	for i := range 4 {
		status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
			sealed(t, alice, bob.Public(), strings.Repeat("x", 6000)+strconv.Itoa(i)), nil)
		if status != http.StatusOK {
			t.Fatalf("post %d: %d %s", i, status, body)
		}
	}

	check := func(what string, wantStatus int, status int, length int64, te []string, body []byte, v any) {
		t.Helper()
		if status != wantStatus {
			t.Fatalf("%s: status %d (%s); want %d", what, status, body, wantStatus)
		}
		if length != int64(len(body)) || len(te) != 0 {
			t.Errorf("%s: Content-Length %d, transfer encoding %v, for a body of %d bytes; want the body's length declared", what, length, te, len(body))
		}
		if err := json.Unmarshal(body, v); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if want := encoded(t, v); !bytes.Equal(body, want) {
			t.Errorf("%s: the body is not the encoder's bytes for the same value:\n got %q\nwant %q", what, body, want)
		}
	}

	status, length, te, body := h.lengthAnswer(bob, "GET", "/v1/mailbox/"+bob.Fingerprint()+"?after=0", nil)
	var list relayapi.ListResponse
	check("a listing page", http.StatusOK, status, length, te, body, &list)
	if len(list.Messages) != 4 || len(body) < 16<<10 {
		t.Errorf("the listing held %d messages in %d bytes; want 4, past what net/http would buffer and declare by itself", len(list.Messages), len(body))
	}

	status, length, te, body = h.lengthAnswer(alice, "GET", "/v1/mailbox/"+bob.Fingerprint()+"?after=0", nil)
	var refusal relayapi.ErrorResponse
	check("a refusal", http.StatusForbidden, status, length, te, body, &refusal)
	if refusal.Error == "" {
		t.Errorf("the refusal carried no sentence: %s", body)
	}

	status, length, te, body = h.lengthAnswer(alice, "POST", "/v1/mailbox/"+bob.Fingerprint()+"/streams",
		relayapi.OpenStreamRequest{Size: 1 << 20})
	var opened relayapi.OpenStreamResponse
	check("a stream opened", http.StatusCreated, status, length, te, body, &opened)

	const bs = "\\"
	// <, > and & are escaped to \u003c, \u003e and \u0026 by both.
	v := relayapi.ErrorResponse{Error: `a <b> & "c"`, Code: "x&y"}
	rec := httptest.NewRecorder()
	h.server.writeJSON(rec, http.StatusTeapot, v)
	if got, want := rec.Body.Bytes(), encoded(t, v); !bytes.Equal(got, want) {
		t.Errorf("writeJSON of %+v: %q; the encoder writes %q", v, got, want)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`a `+bs+`u003cb`+bs+`u003e `+bs+`u0026 `+bs+`"c`+bs+`"`)) {
		t.Errorf("writeJSON did not escape <, > and &: %q", rec.Body.Bytes())
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("writeJSON declared Content-Length %q for %d bytes", got, rec.Body.Len())
	}
	if rec.Code != http.StatusTeapot || rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("writeJSON wrote status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}
