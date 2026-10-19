package relay

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The declared length judged before the identity (G12). The first review's
// TestAdv_ExistenceProbeIsNotMetered, at v0.17.0, is here as the regression
// test, its first probe's comparison, renamed for what it proves and
// carried to both wrappers that read a body under a signature:
// authedWithCert, which every authed and authedBody route is, and
// callerAuthedBody, the forward and its report.

// probeAnswer is everything a caller who signs nothing is told: the status,
// the body word for word, and whether the relay closes behind it.
type probeAnswer struct {
	status int
	body   string
	close  bool
}

// lengthProbe is unsignedProbe with the whole answer kept: one request
// under unsignedAuth(claimed) from addr, the body declared at length and
// none of it sent, or with chunk non-nil sent with no declared length.
func lengthProbe(t *testing.T, h *harness, addr, path, claimed string, length int64, chunk []byte) probeAnswer {
	t.Helper()
	var body io.Reader = http.NoBody
	if chunk != nil {
		body = bytes.NewReader(chunk)
	}
	req := httptest.NewRequest("POST", path, body)
	req.RemoteAddr = addr + ":40000"
	if chunk != nil {
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
	} else {
		req.ContentLength = length
	}
	req.Header.Set(relayapi.AuthHeader, unsignedAuth(claimed))
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	return probeAnswer{status: rec.Code, body: rec.Body.String(), close: rec.Header().Get("Connection") == "close"}
}

// TestAnOverCapBodyIsRefusedAlikeForAKnownAndAnUnknownFingerprint: a body
// declared over the route's cap, or declaring no length at all, is judged
// before the claimed fingerprint is looked up, so a caller who signs
// nothing is told the same thing whether the fingerprint has a mailbox
// here or not: 413 naming the cap for a body declared over it, 411 for a
// body of no declared length, each word for word the same and with the
// connection closed behind it. Before, the lookup came first and the same
// request was 413 for a registered fingerprint and 401 for anybody else's,
// which told a stranger at one token a probe which fingerprints have a
// mailbox. Each answer costs one token of the address's unauthenticated
// budget whoever is named, so every caller, each from an address of its
// own, is answered the burst's worth of times and then 429 at the same
// count; and no probe leaves a nonce behind. Shown on a mailbox route
// (authedWithCert) and on the forward and its report (callerAuthedBody),
// the latter on a relay with a courier configured and both a user and the
// enrolled courier as the registered callers.
func TestAnOverCapBodyIsRefusedAlikeForAKnownAndAnUnknownFingerprint(t *testing.T) {
	limits := Limits{UnauthenticatedPerMinute: probeBurst}
	const noLength = "a request to this route declares its body's length"
	overCap := func(limit int64) string { return fmt.Sprintf("%s: at most %d bytes", relayapi.MsgBodyTooLarge, limit) }

	type caller struct {
		who string
		fp  string
	}
	type route struct {
		name   string
		h      func() (*harness, []caller)
		path   func(fp string) string
		limit  func(h *harness) int64
		status int
		text   string
		chunk  bool
	}
	mailbox := func() (*harness, []caller) {
		h := newHarness(t, Config{Limits: limits})
		alice := h.user(t, "alice")
		return h, []caller{{"registered", alice.Fingerprint()}, {"unregistered", h.fpOf(t, "nobody")}}
	}
	forwarding := func() (*harness, []caller) {
		courier := neighbourID(t, "alpha")
		h := peeredWith(t, []string{"bar"}, []*identity.Identity{courier}, limits)
		h.enroll(courier)
		alice := h.user(t, "alice")
		return h, []caller{{"a registered user's", alice.Fingerprint()}, {"the enrolled courier's", courier.Fingerprint()},
			{"an unregistered", h.fpOf(t, "nobody")}}
	}
	post := func(fp string) string { return "/v1/mailbox/" + fp }
	forward := func(string) string { return "/v1/forward" }
	failed := func(string) string { return "/v1/forward/failed" }
	postCap := func(h *harness) int64 { return h.server.postCap() }
	forwardCap := func(h *harness) int64 { return h.server.forwardCap() }
	reportCap := func(*harness) int64 { return relayapi.MaxReportBytes }

	var routes []route
	for _, r := range []struct {
		name  string
		h     func() (*harness, []caller)
		path  func(string) string
		limit func(*harness) int64
	}{
		{"a post", mailbox, post, postCap},
		{"a forward", forwarding, forward, forwardCap},
		{"a forward's report", forwarding, failed, reportCap},
	} {
		routes = append(routes,
			route{r.name + " declared one byte over its cap", r.h, r.path, r.limit, http.StatusRequestEntityTooLarge, "", false},
			route{r.name + " of no declared length", r.h, r.path, r.limit, http.StatusLengthRequired, noLength, true})
	}

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			h, callers := rt.h()
			limit := rt.limit(h)
			want := rt.text
			if want == "" {
				want = overCap(limit)
			}
			var chunk []byte
			if rt.chunk {
				// Under the cap: a body of no declared length is refused for
				// that alone, whatever it would have come to.
				chunk = []byte("{}")
			}
			nonces := h.nonceCount()
			answers := make([][]probeAnswer, len(callers))
			for i, c := range callers {
				addr := fmt.Sprintf("192.0.2.%d", i+1)
				for range probeBurst + 1 {
					answers[i] = append(answers[i], lengthProbe(t, h, addr, rt.path(c.fp), c.fp, limit+1, chunk))
				}
				for n := range probeBurst {
					a := answers[i][n]
					if a.status != rt.status || a.body == "" || errorText(t, []byte(a.body)) != want || !a.close {
						t.Errorf("%s fingerprint, probe %d: %d %q close=%v; want %d %q with the connection closed",
							c.who, n+1, a.status, a.body, a.close, rt.status, want)
					}
				}
				if got := answers[i][probeBurst].status; got != http.StatusTooManyRequests {
					t.Errorf("%s fingerprint, probe %d: %d; want 429, the unauthenticated bucket charged one token for each refusal",
						c.who, probeBurst+1, got)
				}
			}
			// Word for word alike, probe by probe, the first caller against
			// every other: nothing in the answer says which has a mailbox.
			for i := 1; i < len(callers); i++ {
				for n := range probeBurst {
					if answers[i][n] != answers[0][n] {
						t.Errorf("probe %d: %s fingerprint is told %+v and %s fingerprint %+v: a stranger tells them apart",
							n+1, callers[0].who, answers[0][n], callers[i].who, answers[i][n])
					}
				}
				if a, b := spentIndex(statuses(answers[0])), spentIndex(statuses(answers[i])); a != b {
					t.Errorf("%s fingerprint is spent after %d refusals and %s after %d: the two cost differently",
						callers[0].who, a, callers[i].who, b)
				}
			}
			if got := h.nonceCount(); got != nonces {
				t.Errorf("nonces %d after the probes, want %d: nothing was signed", got, nonces)
			}
		})
	}
}

// statuses is the status of each answer.
func statuses(answers []probeAnswer) []int {
	var out []int
	for _, a := range answers {
		out = append(out, a.status)
	}
	return out
}
