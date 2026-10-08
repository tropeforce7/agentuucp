package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/recipients"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The code's row pair: a 413 with too-many-recipients is the sentinel, and
// the same sentence under a code nobody knows, or the code under another
// status, is not, so the client decides on the code and the status and
// never the words.
func TestTooManyRecipientsIsReadByItsCodeAndStatus(t *testing.T) {
	said := fmt.Sprintf(relayapi.MsgTooManyRecipients, 17, 16)
	for _, tc := range []struct {
		name   string
		status int
		code   string
		want   bool
	}{
		{"the code on a 413", http.StatusRequestEntityTooLarge, relayapi.CodeTooManyRecipients, true},
		{"the sentence under a code nobody knows", http.StatusRequestEntityTooLarge, "later-kind", false},
		{"the sentence with no code", http.StatusRequestEntityTooLarge, "", false},
		{"the code on another status", http.StatusBadRequest, relayapi.CodeTooManyRecipients, false},
	} {
		body := `{"error":` + jsonQuote(said) + `,"code":` + jsonQuote(tc.code) + `}`
		err := answering(t, tc.status, []byte(body)).do(context.Background(), "POST", "/v1/x", nil, nil, nil)
		var he *HTTPError
		if !errors.As(err, &he) || !strings.Contains(he.Message, said) {
			t.Fatalf("%s: %v; want the relay's sentence", tc.name, err)
		}
		if got := errors.Is(err, ErrTooManyRecipients); got != tc.want {
			t.Errorf("%s: errors.Is(err, ErrTooManyRecipients) = %v, want %v", tc.name, got, tc.want)
		}
		if errors.Is(err, ErrRelayNeedsNewer) {
			t.Errorf("%s: read as needs-newer", tc.name)
		}
	}
}

// healthWith is a health answer whole, with the sections given.
func healthWith(sections string) []byte {
	body := `{"ok":true,"max_bytes":16777216,"knock_max_bytes":16777216,"registration":"open","wire_level":1`
	if sections != "" {
		body += `,"sections":` + sections
	}
	return []byte(body + "}")
}

// The health answer's max-recipients section, four ways: absent, a relay
// that holds no setting and whose number is the protocol's ceiling;
// present and within the rule, taken; a number outside it, refused by name
// and never clamped; and a section of another shape, refused by name.
func TestTheHealthAnswersMaxRecipients(t *testing.T) {
	section := func(data string) string {
		return `[{"name":"max-recipients","critical":false,"data":` + data + `}]`
	}
	for _, tc := range []struct {
		name     string
		sections string
		want     int
		refused  bool
	}{
		{"absent", "", relayapi.MaxRecipients, false},
		{"sixteen", section(`{"max":16}`), 16, false},
		{"one", section(`{"max":1}`), 1, false},
		{"thirty-two", section(`{"max":32}`), 32, false},
		{"zero", section(`{"max":0}`), 0, true},
		{"thirty-three", section(`{"max":33}`), 0, true},
		{"negative", section(`{"max":-1}`), 0, true},
		{"not an integer", section(`{"max":16.5}`), 0, true},
		{"a field it does not have", section(`{"max":16,"min":1}`), 0, true},
		{"not an object", section(`16`), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := answering(t, http.StatusOK, healthWith(tc.sections))
			got, err := c.RecipientCap(context.Background())
			if tc.refused {
				if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), "the max-recipients section is not the relay's max_recipients") {
					t.Fatalf("got %d, %v; want the health answer refused naming the section", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

// The status answer carries the same section, held to the same rule: an
// administrator's tool from before it reads the answer still, and one with
// a number outside the rule is refused by name.
func TestTheStatusAnswersMaxRecipientsIsHeldToTheRule(t *testing.T) {
	status := func(sections string) []byte {
		v := relayapi.AdminStatusResponse{Registration: "open", ClientCerts: "off", AccessLog: "full", MaxBytes: 1}
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if sections == "" {
			return raw
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["sections"] = json.RawMessage(sections)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, tc := range []struct {
		name, sections string
		refused        bool
	}{
		{"absent", "", false},
		{"sixteen", `[{"name":"max-recipients","critical":false,"data":{"max":16}}]`, false},
		{"thirty-three", `[{"name":"max-recipients","critical":false,"data":{"max":33}}]`, true},
	} {
		_, err := answering(t, http.StatusOK, status(tc.sections)).AdminStatus(context.Background())
		if tc.refused != (err != nil) {
			t.Errorf("%s: %v; refused %v", tc.name, err, tc.refused)
		}
		if tc.refused && !strings.Contains(err.Error(), "the max-recipients section") {
			t.Errorf("%s: %v; want the section named", tc.name, err)
		}
	}
}

// The count goes on an open-stream request for a message to several and
// nowhere else: a stream to one, or a caller with no count, sends the bytes
// it always sent.
func TestOpenStreamCarriesTheCountForSeveralAlone(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"error":"stop here","code":""}`))
	}))
	t.Cleanup(srv.Close)
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	to := strings.Repeat("a", 64)
	for _, n := range []int{0, 1, 3} {
		_, _ = c.OpenStream(context.Background(), to, "", 5000, n)
	}
	if len(bodies) != 3 {
		t.Fatalf("%d requests, want 3", len(bodies))
	}
	for i, body := range bodies[:2] {
		if body != `{"size":5000}` {
			t.Errorf("request %d: %s; want the bytes a stream to one always sent", i+1, body)
		}
	}
	var req relayapi.OpenStreamRequest
	if err := json.Unmarshal([]byte(bodies[2]), &req); err != nil {
		t.Fatal(err)
	}
	data, ok := recipients.Find(req.Sections.Sections, recipients.CountName)
	if !ok {
		t.Fatalf("a stream to three carries no count: %s", bodies[2])
	}
	if n, err := recipients.CheckCount(data); err != nil || n != 3 {
		t.Errorf("the count reads %d, %v; want 3", n, err)
	}
	if _, err := c.OpenStream(context.Background(), to, "", 5000, relayapi.MaxRecipients+1); err == nil || len(bodies) != 3 {
		t.Errorf("a count over the ceiling: %v, %d requests; want it refused before anything is sent", err, len(bodies))
	}
}

// SetMaxRetryWait: a 429 that asks for longer than the cap comes back at
// once, with no sleep asked for at all, carrying what the relay asked; one
// that asks for the cap or less is waited out as ever; and with no cap the
// long one is waited out too, the ordinary way (R7, ruling 75).
func TestAWaitOverTheCapComesBackAtOnce(t *testing.T) {
	for _, tc := range []struct {
		name        string
		retryAfter  string
		cap         time.Duration
		wantSlept   bool
		wantAttempt int
	}{
		{"over the cap", "61", time.Minute, false, 1},
		{"an hour over the cap", "3600", time.Minute, false, 1},
		{"at the cap", "60", time.Minute, true, maxRetries + 1},
		{"no cap", "3600", 0, true, maxRetries + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				w.Header().Set("Retry-After", tc.retryAfter)
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limited: posts","code":""}`))
			}))
			t.Cleanup(srv.Close)
			me, err := identity.Generate("alice")
			if err != nil {
				t.Fatal(err)
			}
			c, err := New(srv.URL, me, nil)
			if err != nil {
				t.Fatal(err)
			}
			var slept []time.Duration
			c.sleep = func(_ context.Context, d time.Duration) error {
				slept = append(slept, d)
				return nil
			}
			c.SetMaxRetryWait(tc.cap)
			err = c.do(context.Background(), "POST", "/v1/x", nil, nil, nil)
			var he *HTTPError
			if !errors.As(err, &he) || he.Status != http.StatusTooManyRequests {
				t.Fatalf("got %v; want the 429", err)
			}
			if (len(slept) > 0) != tc.wantSlept {
				t.Errorf("slept %v; want a sleep %v", slept, tc.wantSlept)
			}
			for _, d := range slept {
				if tc.cap > 0 && d > tc.cap {
					t.Errorf("a sleep of %s was asked for, over the cap of %s", d, tc.cap)
				}
			}
			if got := attempts.Load(); got != int64(tc.wantAttempt) {
				t.Errorf("%d attempts; want %d", got, tc.wantAttempt)
			}
		})
	}
}
