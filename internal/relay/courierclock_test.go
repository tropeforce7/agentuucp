package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// courierClockLine is the relay's log line for a courier refused for its
// clock, as faults.noteCourierClock writes it.
const courierClockLine = "a neighbour's courier was refused: its clock and this relay's differ by more than a minute"

// sendAt sends a request whose auth header names fp and carries the
// timestamp ts, signed by signer: the relay's clock is not injected into
// freshness (R11), so a test that wants a request some seconds out signs
// it by hand at that second, as SignRequest would at its own. The version
// and the signing domain are relayapi's, written through SigningString;
// the version is pinned here as a literal, a wire constant.
func (h *harness) sendAt(fp string, signer *identity.Identity, path string, payload any, ts int64) (int, []byte, http.Header) {
	h.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		h.t.Fatal(err)
	}
	req, err := http.NewRequest("POST", h.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	signAt(h.t, req, fp, signer, body, ts)
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp.StatusCode, out, resp.Header
}

// signAt puts on req an auth header naming fp, stamped ts and signed by
// signer over body.
func signAt(t *testing.T, req *http.Request, fp string, signer *identity.Identity, body []byte, ts int64) {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	sig, err := signer.Sign(relayapi.SigningString(req.Method, req.URL.RequestURI(), ts, nonceB64, body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(relayapi.AuthHeader, strings.Join([]string{
		"v1", fp, strconv.FormatInt(ts, 10), nonceB64, base64.StdEncoding.EncodeToString(sig),
	}, " "))
}

// atOffset sends one request stamped off seconds from this machine's
// clock and answers it, trying again when the second turned between the
// signing and the answer, since the relay judges by the second it reads
// and a row at the edge would otherwise be a second off it. send is
// called once for each try and must build a request a retry does not
// collide with.
func atOffset(t *testing.T, off int64, send func(ts int64) (int, []byte, http.Header)) (int, []byte, http.Header) {
	t.Helper()
	for attempt := 0; attempt < 5; attempt++ {
		sec := time.Now().Unix()
		status, body, header := send(sec + off)
		if time.Now().Unix() == sec {
			return status, body, header
		}
	}
	t.Fatalf("%d s out: five tries each crossed a second", off)
	return 0, nil, nil
}

// refusedForTheClock asserts the courier-clock refusal whole: 503, a
// Retry-After of exactly sixty seconds, the code and the sentence.
func refusedForTheClock(t *testing.T, h *harness, label string, status int, body []byte, header http.Header) {
	t.Helper()
	if status != http.StatusServiceUnavailable {
		t.Errorf("%s: status %d (%s); want 503", label, status, body)
		return
	}
	if raw := header.Get("Retry-After"); raw != "60" {
		t.Errorf("%s: Retry-After %q; want \"60\"", label, raw)
	}
	if secs := h.retryAfter(header); time.Duration(secs)*time.Second != relayapi.CourierSkew {
		t.Errorf("%s: Retry-After %d s; want CourierSkew", label, secs)
	}
	var e relayapi.ErrorResponse
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("%s: not an error object: %s", label, body)
	}
	if e.Code != relayapi.CodeCourierClock || e.Error != relayapi.MsgCourierClock {
		t.Errorf("%s: code %q, said %q; want %q, %q", label, e.Code, e.Error, relayapi.CodeCourierClock, relayapi.MsgCourierClock)
	}
	// The sentence as a person reads it, pinned from outside relayapi.
	if e.Error != "this relay's clock and yours differ by more than a minute; relays keep to the minute" {
		t.Errorf("%s: said %q", label, e.Error)
	}
}

// notForTheClock asserts an answer is not the courier-clock refusal.
func notForTheClock(t *testing.T, label string, status int, body []byte) {
	t.Helper()
	var e relayapi.ErrorResponse
	_ = json.Unmarshal(body, &e)
	if status == http.StatusServiceUnavailable || e.Code == relayapi.CodeCourierClock {
		t.Errorf("%s: %d %s; refused for its clock", label, status, body)
	}
}

// TestACouriersRequestIsHeldToTheMinute (G5, D83, R10, R11): a courier's
// request on the forward route and on the failed-report route is held
// fresh within relayapi.CourierSkew of this relay's clock, after its
// signature has verified. Fifty-nine and sixty seconds out, either way,
// are taken; sixty-one is refused 503 with a minute's Retry-After, the
// code courier-clock and the sentence, nothing stored and the row a
// report names left as it was, and the relay's log says it once for a
// burst and again once the minute has passed, naming the neighbour by
// this relay's name for it. A user's request at sixty-one seconds and at
// four minutes is not refused for its clock: a user is held to MaxSkew.
// And a stranger naming a courier's fingerprint under a signature that
// does not verify is answered the 401 any bad signature gets, never the
// 503, so the answer says nothing about whose fingerprint it named.
func TestACouriersRequestIsHeldToTheMinute(t *testing.T) {
	clockLines := func(h *harness) int { return strings.Count(h.logs.String(), courierClockLine) }

	t.Run("forward", func(t *testing.T) {
		courier := neighbourID(t, "alpha")
		h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
		h.enroll(courier)
		alice := h.user(t, "alice")
		n := 0
		forwardAt := func(id *identity.Identity) func(ts int64) (int, []byte, http.Header) {
			return func(ts int64) (int, []byte, http.Header) {
				n++
				req := request(sealedFor(h.fpOf(t, "bob"), fmt.Sprintf("ct %d", n)), []string{"bar"}, nil)
				return h.sendAt(id.Fingerprint(), id, "/v1/forward", req, ts)
			}
		}

		for _, off := range []int64{59, 60, -59, -60} {
			status, body, _ := atOffset(t, off, forwardAt(courier))
			if status != http.StatusCreated {
				t.Errorf("a courier %d s out: %d %s; want taken", off, status, body)
			}
		}
		if lines := clockLines(h); lines != 0 {
			t.Errorf("%d clock lines after requests inside the minute", lines)
		}

		rows := h.outboundRows(t)
		for _, off := range []int64{61, -61} {
			status, body, header := atOffset(t, off, forwardAt(courier))
			refusedForTheClock(t, h, fmt.Sprintf("a courier %d s out", off), status, body, header)
		}
		if got := h.outboundRows(t); got != rows {
			t.Errorf("%d rows after two refusals; want %d", got, rows)
		}
		logs := h.logs.String()
		if lines := clockLines(h); lines != 1 {
			t.Errorf("%d clock lines for two refusals inside a minute; want one:\n%s", lines, logs)
		}
		if !strings.Contains(logs, "neighbour=alpha") {
			t.Errorf("the clock line does not name the neighbour by this relay's name for it:\n%s", logs)
		}
		if strings.Contains(logs, courier.Fingerprint()) {
			t.Error("the clock line names the courier's fingerprint")
		}
		h.clock.advance(2 * time.Minute)
		status, body, header := atOffset(t, 61, forwardAt(courier))
		refusedForTheClock(t, h, "a courier 61 s out, two minutes on", status, body, header)
		if lines := clockLines(h); lines != 2 {
			t.Errorf("%d clock lines once the minute has passed; want two", lines)
		}

		// A user is held to MaxSkew, not the courier's minute.
		for _, off := range []int64{61, -61, 240, -240} {
			status, body, _ := atOffset(t, off, forwardAt(alice))
			if status != http.StatusCreated {
				t.Errorf("a user %d s out: %d %s; want taken", off, status, body)
			}
		}
		if lines := clockLines(h); lines != 2 {
			t.Errorf("%d clock lines after a user's requests; want the courier's two", lines)
		}

		// A stranger naming the courier: the signature is refused first,
		// with the answer a bad signature under a user's fingerprint gets.
		stranger := neighbourID(t, "mallory")
		sStatus, sBody, _ := atOffset(t, 61, func(ts int64) (int, []byte, http.Header) {
			return h.sendAt(courier.Fingerprint(), stranger, "/v1/forward",
				request(sealedFor(h.fpOf(t, "bob"), "stranger"), []string{"bar"}, nil), ts)
		})
		uStatus, uBody, _ := atOffset(t, 61, func(ts int64) (int, []byte, http.Header) {
			return h.sendAt(alice.Fingerprint(), stranger, "/v1/forward",
				request(sealedFor(h.fpOf(t, "bob"), "stranger"), []string{"bar"}, nil), ts)
		})
		if sStatus != http.StatusUnauthorized || sStatus != uStatus || !bytes.Equal(sBody, uBody) {
			t.Errorf("a stranger naming a courier: %d %s; naming a user: %d %s; want the same 401", sStatus, sBody, uStatus, uBody)
		}
		if lines := clockLines(h); lines != 2 {
			t.Errorf("%d clock lines after a stranger's request; a refused signature says nothing of a clock", lines)
		}
	})

	t.Run("the failed route", func(t *testing.T) {
		courier := neighbourID(t, "bar")
		h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
		h.enroll(courier)
		alice := h.user(t, "alice")
		theirID := int64(4000)
		// Each try reports a row of its own, handed to the courier under
		// an id of its own, so a retry names a row still handed.
		var row int64
		reportAt := func(id *identity.Identity) func(ts int64) (int, []byte, http.Header) {
			return func(ts int64) (int, []byte, http.Header) {
				theirID++
				row = h.handedRow(t, alice, h.fpOf(t, "bob"), fmt.Sprintf("ct %d", theirID), theirID)
				return h.sendAt(id.Fingerprint(), id, "/v1/forward/failed",
					failedReq(theirID, relayapi.CodeRefused, "baz: no such mailbox"), ts)
			}
		}

		for _, off := range []int64{59, 60, -59, -60} {
			status, body, _ := atOffset(t, off, reportAt(courier))
			if status != http.StatusNoContent {
				t.Errorf("a courier's report %d s out: %d %s; want taken", off, status, body)
			}
			if got := h.outbound(t, row); got.State != OutFinal {
				t.Errorf("a courier's report %d s out left the row %q", off, got.State)
			}
		}
		for _, off := range []int64{61, -61} {
			status, body, header := atOffset(t, off, reportAt(courier))
			refusedForTheClock(t, h, fmt.Sprintf("a courier's report %d s out", off), status, body, header)
			if got := h.outbound(t, row); got.State != OutHanded {
				t.Errorf("a refused report %d s out moved the row to %q", off, got.State)
			}
		}
		if lines := clockLines(h); lines != 1 {
			t.Errorf("%d clock lines for two refused reports inside a minute; want one", lines)
		}

		// A user on the report route is refused as not a courier, at any
		// offset inside MaxSkew, and never for the clock.
		_, fresh := h.do(alice, "POST", "/v1/forward/failed", failedReq(1, relayapi.CodeRefused, "x"), nil)
		for _, off := range []int64{61, 240} {
			status, body, _ := atOffset(t, off, func(ts int64) (int, []byte, http.Header) {
				return h.sendAt(alice.Fingerprint(), alice, "/v1/forward/failed", failedReq(1, relayapi.CodeRefused, "x"), ts)
			})
			notForTheClock(t, fmt.Sprintf("a user's report %d s out", off), status, body)
			if !bytes.Equal(body, fresh) {
				t.Errorf("a user's report %d s out: %s; a fresh one: %s", off, body, fresh)
			}
		}

		// A stranger naming the courier on this route too.
		stranger := neighbourID(t, "mallory")
		sStatus, sBody, _ := atOffset(t, 61, func(ts int64) (int, []byte, http.Header) {
			return h.sendAt(courier.Fingerprint(), stranger, "/v1/forward/failed", failedReq(1, relayapi.CodeRefused, "x"), ts)
		})
		uStatus, uBody, _ := atOffset(t, 61, func(ts int64) (int, []byte, http.Header) {
			return h.sendAt(alice.Fingerprint(), stranger, "/v1/forward/failed", failedReq(1, relayapi.CodeRefused, "x"), ts)
		})
		if sStatus != http.StatusUnauthorized || sStatus != uStatus || !bytes.Equal(sBody, uBody) {
			t.Errorf("a stranger naming a courier: %d %s; naming a user: %d %s; want the same 401", sStatus, sBody, uStatus, uBody)
		}
		if lines := clockLines(h); lines != 1 {
			t.Errorf("%d clock lines after a stranger's report; want the courier's one", lines)
		}
	})
}

// workerClockLine is the worker's log line for a neighbour that refused
// this relay's courier for its clock, as classify writes it.
const workerClockLine = "courier: a neighbour says this relay's clock and its own differ by more than a minute"

// TestACourierClockRefusalIsWaitedOutAndSaid is the code's row pair at the
// client that acts on it, the forwarding worker. A neighbour's 503 under
// courier-clock with a Retry-After of sixty seconds leaves the row waiting
// sixty seconds, not maxRetry as a 401 would, and the worker says once a
// minute that it is this relay's clock; the same answer and sentence under
// a code nobody knows is waited out alike and said as nothing about a
// clock. The 429 the classify case shares is acted on the same way.
func TestACourierClockRefusalIsWaitedOutAndSaid(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
		lines  int
	}{
		{"503 courier-clock", http.StatusServiceUnavailable, relayapi.CodeCourierClock, 1},
		{"429 courier-clock", http.StatusTooManyRequests, relayapi.CodeCourierClock, 1},
		{"503 under a code nobody knows", http.StatusServiceUnavailable, "made-up-code", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := peered(t, []string{"bar"}, nil, nil)
			user := h.user(t, "alice")
			w := fakeNeighbour(t, h, func() (int64, error) {
				return 0, &client.HTTPError{Status: tc.status, Code: tc.code,
					Message: relayapi.MsgCourierClock, RetryAfter: relayapi.CourierSkew}
			})
			r, _ := w.courier.Neighbour("bar")
			for i := range 2 {
				_, answer, _ := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), fmt.Sprintf("ct %d", i)), []string{"bar"}, nil))
				out, wait := w.attempt(r, nil, h.outbound(t, answer.ID))
				if out != attemptBackOff || wait != 60*time.Second || wait == maxRetry {
					t.Errorf("attempt %d: %v, waiting %s; want backed off for the sixty seconds asked", i, out, wait)
				}
				if got := h.outbound(t, answer.ID); got.State != OutWaiting {
					t.Errorf("attempt %d: the row is %q; want waiting", i, got.State)
				}
			}
			if got := strings.Count(h.logs.String(), workerClockLine); got != tc.lines {
				t.Errorf("%d clock lines for two refusals inside a minute; want %d:\n%s", got, tc.lines, h.logs.String())
			}
			if tc.lines > 0 && !strings.Contains(h.logs.String(), "neighbour=bar") {
				t.Errorf("the clock line does not name the neighbour:\n%s", h.logs.String())
			}
		})
	}
}

// TestARelayAMinuteOutIsToldSoByARealNeighbour is the code's row through a
// real relay: A's worker hands an envelope to B, a real relay that admits
// A's courier, through a stand-in for A's clock, a proxy that signs the
// request again as A's courier sixty-one seconds ahead of this machine.
// Nothing else is between them. B refuses it for the clock, and A's worker,
// reading B's own answer through the real client, keeps the row waiting
// for B's sixty seconds and says once a minute that its clock is out; B
// says once that a neighbour's courier was refused, naming A by B's name
// for it. A relay that wrote the sentence without the code fails here.
//
// The client hands a courier-clock refusal to the worker at once rather than
// sleeping through its own retries first, since asking again within the
// minute cannot mend a clock: each attempt is one request through the proxy,
// and it returns well inside the Retry-After.
func TestARelayAMinuteOutIsToldSoByARealNeighbour(t *testing.T) {
	b := peered(t, []string{"onward"}, nil, nil)
	a := peer(t, b, "bar", "alpha", DefaultCourierLimits())

	var seen atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}
		out, err := http.NewRequest(r.Method, b.srv.URL+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}
		out.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		signAt(t, out, a.courier.Fingerprint(), a.courier, body, time.Now().Unix()+61)
		resp, err := b.srv.Client().Do(out)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for _, k := range []string{"Content-Type", "Retry-After"} {
			if v := resp.Header.Get(k); v != "" {
				rw.Header().Set(k, v)
			}
		}
		rw.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(rw, resp.Body)
	}))
	t.Cleanup(proxy.Close)

	c, err := client.New(proxy.URL, a.courier, nil)
	if err != nil {
		t.Fatal(err)
	}

	sender := a.h.user(t, "alice")
	w := worker(t, a.h)
	r, _ := w.courier.Neighbour("bar")
	try := func(i int) {
		t.Helper()
		status, answer, body := a.h.forward(sender, request(sealedFor(a.h.fpOf(t, "bob"), fmt.Sprintf("ct %d", i)), []string{"bar", "onward"}, nil))
		if status != 201 {
			t.Fatalf("the post to A: %d %s", status, body)
		}
		before, start := seen.Load(), time.Now()
		out, wait := w.attempt(r, c, a.h.outbound(t, answer.ID))
		if n, took := seen.Load()-before, time.Since(start); n != 1 || took > 10*time.Second {
			t.Errorf("attempt %d: the client asked B %d times over %s; want once, handed straight to the worker", i, n, took)
		}
		if out != attemptBackOff || wait != relayapi.CourierSkew {
			t.Errorf("attempt %d: %v, waiting %s; want backed off for B's sixty seconds", i, out, wait)
		}
		if got := a.h.outbound(t, answer.ID); got.State != OutWaiting {
			t.Errorf("attempt %d: A's row is %q; want waiting", i, got.State)
		}
	}
	try(0)
	try(1)
	if n := b.outboundRows(t); n != 0 {
		t.Errorf("B holds %d rows after refusing both", n)
	}
	if got := strings.Count(a.h.logs.String(), workerClockLine); got != 1 {
		t.Errorf("A said its clock %d times for two refusals inside a minute; want once:\n%s", got, a.h.logs.String())
	}
	if got := strings.Count(b.logs.String(), courierClockLine); got != 1 || !strings.Contains(b.logs.String(), "neighbour=alpha") {
		t.Errorf("B said %d clock lines; want one naming alpha:\n%s", got, b.logs.String())
	}
	a.h.clock.advance(2 * time.Minute)
	try(2)
	if got := strings.Count(a.h.logs.String(), workerClockLine); got != 2 {
		t.Errorf("A said its clock %d times once the minute had passed; want twice", got)
	}
}

// peeredWith is peered with the relay's request limits as given, for a test
// that counts the courier's request tokens.
func peeredWith(t *testing.T, neighbours []string, accept []*identity.Identity, lim Limits) *harness {
	t.Helper()
	urls := map[string]string{}
	for i, n := range neighbours {
		urls[n] = fmt.Sprintf("http://127.0.0.1:%d", i+1)
	}
	c, err := NewCourier(CourierConfig{
		Home: courierHome(t, urls), AuthorizedFile: couriersFile(t, accept...), PublicURL: "https://mine.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, Config{Courier: c, CourierLimits: DefaultCourierLimits(), Limits: lim})
	quiet(t, h)
	return h
}

// TestACourierClockRefusalSpendsTheRequestToken (M4): the minute is judged
// after chargeIdentity, so a courier refused for its clock has spent its
// request token as any verified request does, and a courier a minute out
// cannot ask again and again for nothing. With requests_per_minute at 1:
// the courier at 61 s is refused 503 courier-clock, and its next request,
// fresh, is 429 for requests, neither refused for the clock nor taken; a
// minute on the bucket has refilled, a request at +60 s is taken and the
// next is 429; and the same at -60 s.
func TestACourierClockRefusalSpendsTheRequestToken(t *testing.T) {
	courier := neighbourID(t, "alpha")
	h := peeredWith(t, []string{"bar"}, []*identity.Identity{courier}, Limits{RequestsPerMinute: 1})
	h.enroll(courier)
	n := 0
	forwardAt := func(ts int64) (int, []byte, http.Header) {
		n++
		req := request(sealedFor(h.fpOf(t, "bob"), fmt.Sprintf("ct %d", n)), []string{"bar"}, nil)
		return h.sendAt(courier.Fingerprint(), courier, "/v1/forward", req, ts)
	}
	// once sends at off seconds out with a full bucket, refilling and
	// trying again when the second turned under the request.
	once := func(off int64) (int, []byte, http.Header) {
		t.Helper()
		for attempt := 0; attempt < 5; attempt++ {
			h.clock.advance(time.Minute)
			sec := time.Now().Unix()
			status, body, header := forwardAt(sec + off)
			if time.Now().Unix() == sec {
				return status, body, header
			}
		}
		t.Fatalf("%d s out: five tries each crossed a second", off)
		return 0, nil, nil
	}
	spent := func(label string) {
		t.Helper()
		status, body, header := forwardAt(time.Now().Unix())
		if status != http.StatusTooManyRequests || errorText(t, body) != "rate limited: "+limitRequests {
			t.Errorf("%s, the next request: %d %s; want 429 rate limited: requests", label, status, body)
			return
		}
		h.retryAfter(header)
	}

	status, body, header := once(61)
	refusedForTheClock(t, h, "a courier 61 s out", status, body, header)
	spent("after the clock refusal")

	for _, off := range []int64{60, -60} {
		if status, body, _ := once(off); status != http.StatusCreated {
			t.Errorf("a courier %d s out with a full bucket: %d %s; want taken", off, status, body)
		}
		spent(fmt.Sprintf("after a request taken %d s out", off))
	}
}

// TestTheClockLineIsSaidForEachNeighbour (M9): the relay's line is limited
// by its name for the neighbour, never by the sentence alone, so two
// couriers a minute out inside one minute are two lines, one naming each,
// and two minutes on, one more refusal from each is two more.
func TestTheClockLineIsSaidForEachNeighbour(t *testing.T) {
	alpha, beta := neighbourID(t, "alpha"), neighbourID(t, "beta")
	h := peered(t, []string{"bar"}, []*identity.Identity{alpha, beta}, nil)
	h.enroll(alpha, beta)
	n := 0
	refuse := func(id *identity.Identity) {
		t.Helper()
		status, body, header := atOffset(t, 61, func(ts int64) (int, []byte, http.Header) {
			n++
			req := request(sealedFor(h.fpOf(t, "bob"), fmt.Sprintf("ct %d", n)), []string{"bar"}, nil)
			return h.sendAt(id.Fingerprint(), id, "/v1/forward", req, ts)
		})
		refusedForTheClock(t, h, id.Name+" 61 s out", status, body, header)
	}
	count := func() (all, a, b int) {
		for _, line := range strings.Split(h.logs.String(), "\n") {
			if !strings.Contains(line, courierClockLine) {
				continue
			}
			all++
			if strings.Contains(line, "neighbour=alpha") {
				a++
			}
			if strings.Contains(line, "neighbour=beta") {
				b++
			}
		}
		return
	}
	refuse(alpha)
	refuse(beta)
	refuse(alpha)
	if all, a, b := count(); all != 2 || a != 1 || b != 1 {
		t.Errorf("%d clock lines, %d naming alpha and %d beta; want one each:\n%s", all, a, b, h.logs.String())
	}
	h.clock.advance(2 * time.Minute)
	refuse(alpha)
	refuse(beta)
	if all, a, b := count(); all != 4 || a != 2 || b != 2 {
		t.Errorf("two minutes on: %d clock lines, %d naming alpha and %d beta; want two each:\n%s", all, a, b, h.logs.String())
	}
}

// TestTheWorkersClockLineIsSaidForEachNeighbour: the worker's line is
// limited by the neighbour that refused, so two neighbours refusing this
// relay's courier for its clock inside one minute are two lines, one
// naming each, and a second refusal from either inside the minute adds
// nothing.
func TestTheWorkersClockLineIsSaidForEachNeighbour(t *testing.T) {
	h := peered(t, []string{"bar", "baz"}, nil, nil)
	user := h.user(t, "alice")
	w := fakeNeighbour(t, h, func() (int64, error) {
		return 0, &client.HTTPError{Status: http.StatusServiceUnavailable, Code: relayapi.CodeCourierClock,
			Message: relayapi.MsgCourierClock, RetryAfter: relayapi.CourierSkew}
	})
	i := 0
	for _, name := range []string{"bar", "baz", "bar", "baz"} {
		i++
		_, answer, body := h.forward(user, request(sealedFor(h.fpOf(t, "bob"), fmt.Sprintf("ct %d", i)), []string{name}, nil))
		if answer.ID == 0 {
			t.Fatalf("queueing for %s: %s", name, body)
		}
		r, _ := w.courier.Neighbour(name)
		w.attempt(r, nil, h.outbound(t, answer.ID))
	}
	var all, bar, baz int
	for _, line := range strings.Split(h.logs.String(), "\n") {
		if !strings.Contains(line, workerClockLine) {
			continue
		}
		all++
		if strings.Contains(line, "neighbour=bar") {
			bar++
		}
		if strings.Contains(line, "neighbour=baz") {
			baz++
		}
	}
	if all != 2 || bar != 1 || baz != 1 {
		t.Errorf("%d clock lines, %d naming bar and %d baz; want one each:\n%s", all, bar, baz, h.logs.String())
	}
}
