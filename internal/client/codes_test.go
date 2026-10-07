package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// laterKind is a code no build knows: a refusal that carries it is shown as
// its sentence and acted on no further (ruling 67), which is the other half
// of every row pair below (ruling 68).
const laterKind = "later-kind"

// refusalServer answers every request with one refusal, counting them.
func refusalServer(t *testing.T, status int, e relayapi.ErrorResponse, header map[string]string) (*Client, *atomic.Int64) {
	t.Helper()
	var asked atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(e)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c, &asked
}

// over-budget: a 429 for a post bigger than a sender's whole budget ends the
// retries at once; the same sentence under another code is waited out.
func TestTheOverBudgetCodeEndsTheRetries(t *testing.T) {
	sentence := "rate limited: post_bytes; this message is 9 bytes and a sender's whole post_bytes_per_hour budget is 8, so " +
		relayapi.MsgWaitingWillNotHelp
	for _, tc := range []struct {
		code  string
		asked int64
	}{
		{relayapi.CodeOverBudget, 1},
		{laterKind, maxRetries + 1},
	} {
		c, asked := refusalServer(t, http.StatusTooManyRequests,
			relayapi.ErrorResponse{Error: sentence, Code: tc.code}, map[string]string{"Retry-After": "1"})
		err := c.Health(context.Background())
		var he *HTTPError
		if !errors.As(err, &he) || he.Status != http.StatusTooManyRequests || he.Message != sentence {
			t.Fatalf("code %q: %v; want the 429 and its sentence", tc.code, err)
		}
		if n := asked.Load(); n != tc.asked {
			t.Errorf("code %q: asked %d times, want %d", tc.code, n, tc.asked)
		}
	}
}

// no-directory: the 404 is an answer, a mailbox with the one channel; the
// same sentence under another code is the refusal it says it is.
func TestTheNoDirectoryCodeIsAnAnswer(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	c, _ := refusalServer(t, http.StatusNotFound, relayapi.ErrorResponse{Error: relayapi.MsgNoDirectory, Code: relayapi.CodeNoDirectory}, nil)
	if d, err := c.Directory(context.Background(), fp); err != nil || d == nil || !d.None {
		t.Errorf("no-directory: %+v, %v; want None", d, err)
	}
	c, _ = refusalServer(t, http.StatusNotFound, relayapi.ErrorResponse{Error: relayapi.MsgNoDirectory, Code: laterKind}, nil)
	var he *HTTPError
	if _, err := c.Directory(context.Background(), fp); !errors.As(err, &he) || he.Message != relayapi.MsgNoDirectory {
		t.Errorf("another code: %v; want the 404 and its sentence", err)
	}
}

// The six certificate codes: each known one names the machine's state, and
// the sentence under another code is said as it came. A refused certificate
// whose reason says "has expired" is not an expired one.
func TestTheCertificateCodesAreClassifiedByCode(t *testing.T) {
	for _, tc := range []struct {
		refusal relayapi.Refusal
		state   string
	}{
		{relayapi.RefusalCertRequired, "not accepted"},
		{relayapi.RefusalCertUnknown, "not known"},
		{relayapi.RefusalCertRevoked, "revoked"},
		{relayapi.RefusalCertExpired, "expired"},
		{relayapi.RefusalCertMismatch, "for another identity"},
	} {
		c, _ := refusalServer(t, http.StatusUnauthorized, relayapi.ErrorResponse{Error: tc.refusal.Msg, Code: tc.refusal.Code}, nil)
		var problem *CertProblem
		if err := ClassifyCertError(c.Health(t.Context()), true); !errors.As(err, &problem) || problem.State != tc.state {
			t.Errorf("%s: %v; want the state %q", tc.refusal.Code, err, tc.state)
		}
		c, _ = refusalServer(t, http.StatusUnauthorized, relayapi.ErrorResponse{Error: tc.refusal.Msg, Code: laterKind}, nil)
		if err := ClassifyCertError(c.Health(t.Context()), true); errors.As(err, &problem) {
			t.Errorf("%q under another code: classified %q; want it said as it came", tc.refusal.Msg, problem.State)
		}
	}
	refused := relayapi.MsgCertRefused + ": the certificate has expired"
	c, _ := refusalServer(t, http.StatusUnauthorized, relayapi.ErrorResponse{Error: refused, Code: relayapi.CodeCertRefused}, nil)
	var problem *CertProblem
	if err := ClassifyCertError(c.Health(t.Context()), true); errors.As(err, &problem) {
		t.Errorf("cert-refused saying %q: classified %q; want it said as it came", refused, problem.State)
	}
}

// at (ruling 68): the time a refusal is about comes as data. Present, it is
// on the error; absent, the error has none and the sentence is all there
// is; a value that is not a time is refused by the field's name and never
// repeated.
func TestARefusalsTimeIsData(t *testing.T) {
	issued := time.Date(2026, 10, 7, 9, 30, 0, 0, time.UTC)
	sentence := "a newer card is already there (issued " + issued.Format(time.RFC3339) + ")"

	c, _ := refusalServer(t, http.StatusConflict, relayapi.ErrorResponse{Error: sentence, Code: relayapi.CodeNewerCard, At: issued}, nil)
	var he *HTTPError
	if err := c.Health(context.Background()); !errors.As(err, &he) || !he.At.Equal(issued) || he.Message != sentence {
		t.Errorf("at present: %v (at %v); want %v and the sentence", err, codeAt(he), issued)
	}

	c, _ = refusalServer(t, http.StatusConflict, relayapi.ErrorResponse{Error: sentence, Code: relayapi.CodeNewerCard}, nil)
	if err := c.Health(context.Background()); !errors.As(err, &he) || !he.At.IsZero() || he.Message != sentence {
		t.Errorf("at absent: %v (at %v); want no time and the sentence", err, codeAt(he))
	}

	err := answering(t, http.StatusConflict, []byte(`{"error":"x","code":"newer-card","at":"yesterday"}`)).
		do(context.Background(), "GET", "/v1/x", nil, nil, nil)
	if !errors.As(err, &he) || he.Status != http.StatusConflict ||
		!strings.Contains(he.Message, `refused GET /v1/x (409) with an "at" that is not a time`) ||
		strings.Contains(he.Message, "yesterday") || he.Code != "" || !he.At.IsZero() {
		t.Errorf("a bad time: %v; want the 409 and the field named, not its value", err)
	}
}

func codeAt(he *HTTPError) time.Time {
	if he == nil {
		return time.Time{}
	}
	return he.At
}
