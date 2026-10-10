package relay

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The third adversarial trace, at v0.17.0 (reviews/trace/trace-3-v0.17.0/):
// what a refusal made before the signature tells a caller who signs
// nothing. Its test is here as the regression test, renamed for what it
// proves, beside trace3_test.go's.

// probeBurst is the unauthenticated budget the probes run under: this
// many answers from one address, and the next is 429.
const probeBurst = 3

// unsignedAuth is a well-formed auth header naming claimed whose
// signature is zeros, the trace's probe: it parses, and verifies under
// nobody's key.
func unsignedAuth(claimed string) string {
	nonce := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	return fmt.Sprintf("v1 %s %d %s %s", claimed, time.Now().Unix(), nonce, sig)
}

// unsignedProbe sends one request under unsignedAuth(claimed) from addr,
// straight to the server's handler so that each caller has an address,
// and so a bucket, of its own. With chunk nil the body is declared at
// length and none of it is sent, the trace's probe; otherwise chunk is
// the body, sent with no declared length.
func unsignedProbe(t *testing.T, h *harness, addr, method, path, claimed string, length int64, chunk []byte) int {
	t.Helper()
	var body io.Reader = http.NoBody
	if chunk != nil {
		body = bytes.NewReader(chunk)
	}
	req := httptest.NewRequest(method, path, body)
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
	return rec.Code
}

// wireAnswer is what a caller on a real connection is told: the status,
// the refusal's sentence, and whether the relay closes behind it: the
// Connection header, which http.ReadResponse takes into Close.
type wireAnswer struct {
	status int
	text   string
	close  bool
}

// wireProbe sends one request under unsignedAuth(claimed) over a real
// connection to h, declaring declared bytes and sending sent of them,
// and with halfClose shuts its write side after, so a body declared and
// not delivered ends in a failed read rather than a wait.
func wireProbe(t *testing.T, h *harness, method, path, claimed string, declared int, sent []byte, halfClose bool) wireAnswer {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: relay\r\n%s: %s\r\nContent-Length: %d\r\n\r\n",
		method, path, relayapi.AuthHeader, unsignedAuth(claimed), declared)
	if _, err := conn.Write(sent); err != nil {
		t.Fatal(err)
	}
	if halfClose {
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	a := wireAnswer{status: resp.StatusCode, close: resp.Close}
	if resp.StatusCode != http.StatusTooManyRequests {
		a.text = errorText(t, body)
	}
	return a
}

// TestARefusalBeforeTheSignatureCostsTheSameWhoeverIsNamed: on every
// authenticated route the claimed fingerprint was looked up before the
// body was read, and a body declared over the route's cap was answered
// 413 when the fingerprint had a mailbox and 401 when it had not, only
// the 401 charged to the unauthenticated bucket; so a stranger with no
// key told registered fingerprints from unregistered ones as often as it
// liked, and on the admin route an administrator's from anyone's. Now a
// refusal of the body before the signature is charged as a refused
// signature is, on the mailbox wrapper, the forward wrapper (the forward
// and its report) and the admin wrapper: each fingerprint, from an
// address of its own, is answered 413 or 401 the burst's worth of times
// and then 429 at the same count. On the admin route the body is read
// before the administrator is looked up (T11, R12), so an
// administrator's fingerprint and anyone else's are both answered 413
// for a body declared over the cap, both 411 for a body of no declared
// length (R11), both 400 with the connection closed for a body declared
// and not delivered, and both 401 with the connection kept for a body
// sent whole under a signature that does not verify; and a relay with no
// administrators answers 403 charged (R12). A chunked body over a
// mailbox route's cap, refused by the read and not the declaration, and
// a mailbox route's body declared and not delivered, are charged the
// same. No request leaves a nonce behind.
//
// After each in-process row the store is closed and one more request
// sent: on the mailbox and forward rows the lookup then fails into
// authFailed, so the 429 shows the answer does not depend on the store,
// not that the store is untouched; the admin rows never use the store.
func TestARefusalBeforeTheSignatureCostsTheSameWhoeverIsNamed(t *testing.T) {
	type caller struct {
		who   string
		fp    string
		first int // the answer before the budget is spent
	}
	type row struct {
		name    string
		h       *harness
		method  string
		path    func(fp string) string
		length  int64
		chunk   []byte
		callers []caller
	}
	limits := Limits{UnauthenticatedPerMinute: probeBurst}

	mailbox := func() *harness { return newHarness(t, Config{Limits: limits}) }
	admin := ids(t, "admin")[0]
	adminPath := adminFile(t, admin)
	loaded, err := LoadAdmins(adminPath)
	if err != nil {
		t.Fatal(err)
	}
	admins := func() *harness {
		return newHarness(t, Config{Limits: limits, AdminFile: adminPath, Admins: loaded})
	}
	over := func(n int64) []byte { return bytes.Repeat([]byte("x"), int(n)+1) }

	var rows []row
	{
		h := mailbox()
		alice := h.user(t, "alice")
		rows = append(rows, row{"a post declared over the cap", h, "POST",
			func(fp string) string { return "/v1/mailbox/" + fp }, h.server.postCap() + 1, nil,
			[]caller{{"registered", alice.Fingerprint(), http.StatusRequestEntityTooLarge},
				{"unregistered", h.fpOf(t, "nobody"), http.StatusUnauthorized}}})
	}
	{
		h := mailbox()
		alice := h.user(t, "alice")
		rows = append(rows, row{"a stream open of no declared length over the cap", h, "POST",
			func(fp string) string { return "/v1/mailbox/" + fp + "/streams" }, 0, over(relayapi.FramingAllowance),
			[]caller{{"registered", alice.Fingerprint(), http.StatusRequestEntityTooLarge},
				{"unregistered", h.fpOf(t, "nobody"), http.StatusUnauthorized}}})
	}
	{
		h := mailbox()
		alice := h.user(t, "alice")
		rows = append(rows, row{"a forward declared over the cap", h, "POST",
			func(string) string { return "/v1/forward" }, h.server.forwardCap() + 1, nil,
			[]caller{{"registered", alice.Fingerprint(), http.StatusRequestEntityTooLarge},
				{"unregistered", h.fpOf(t, "nobody"), http.StatusUnauthorized}}})
	}
	{
		h := mailbox()
		alice := h.user(t, "alice")
		rows = append(rows, row{"a forward's report declared over the cap", h, "POST",
			func(string) string { return "/v1/forward/failed" }, relayapi.MaxReportBytes + 1, nil,
			[]caller{{"registered", alice.Fingerprint(), http.StatusRequestEntityTooLarge},
				{"unregistered", h.fpOf(t, "nobody"), http.StatusUnauthorized}}})
	}
	{
		h := admins()
		user := h.user(t, "user")
		rows = append(rows, row{"an admin token declared over the cap", h, "POST",
			func(string) string { return "/v1/admin/tokens" }, relayapi.FramingAllowance + 1, nil,
			[]caller{{"an administrator's", admin.Fingerprint(), http.StatusRequestEntityTooLarge},
				{"a user's", user.Fingerprint(), http.StatusRequestEntityTooLarge}}})
	}
	{
		h := admins()
		user := h.user(t, "user")
		rows = append(rows, row{"an admin token of no declared length", h, "POST",
			func(string) string { return "/v1/admin/tokens" }, 0, []byte("{}"),
			[]caller{{"an administrator's", admin.Fingerprint(), http.StatusLengthRequired},
				{"a user's", user.Fingerprint(), http.StatusLengthRequired}}})
	}
	{
		h := mailbox()
		user := h.user(t, "user")
		rows = append(rows, row{"an admin route on a relay with no administrators", h, "GET",
			func(string) string { return "/v1/admin/status" }, 0, nil,
			[]caller{{"the would-be administrator's", admin.Fingerprint(), http.StatusForbidden},
				{"a user's", user.Fingerprint(), http.StatusForbidden}}})
	}

	for _, rw := range rows {
		t.Run(rw.name, func(t *testing.T) {
			h := rw.h
			nonces := h.nonceCount()
			spentAt := make([]int, len(rw.callers))
			for i, c := range rw.callers {
				addr := fmt.Sprintf("192.0.2.%d", i+1)
				var got []int
				for range probeBurst + 1 {
					got = append(got, unsignedProbe(t, h, addr, rw.method, rw.path(c.fp), c.fp, rw.length, rw.chunk))
				}
				spentAt[i] = spentIndex(got)
				for n := range probeBurst {
					if got[n] != c.first {
						t.Errorf("%s fingerprint: answers %v; want %d %d times, then 429", c.who, got, c.first, probeBurst)
						break
					}
				}
				if spentAt[i] != probeBurst {
					t.Errorf("%s fingerprint: answers %v; want 429 on request %d, the unauthenticated bucket charged for every refusal", c.who, got, probeBurst+1)
				}
			}
			for i := range spentAt {
				if spentAt[i] != spentAt[0] {
					t.Errorf("%s fingerprint is spent after %d refusals and %s after %d: the two cost differently", rw.callers[0].who, spentAt[0], rw.callers[i].who, spentAt[i])
				}
			}
			if got := h.nonceCount(); got != nonces {
				t.Errorf("nonces %d after the probes, want %d: nothing was signed", got, nonces)
			}
			// One more request with the store closed: the 429 is answered
			// whatever the store says (see the comment above).
			if err := h.store.Close(); err != nil {
				t.Fatal(err)
			}
			for i, c := range rw.callers {
				addr := fmt.Sprintf("192.0.2.%d", i+1)
				if status := unsignedProbe(t, h, addr, rw.method, rw.path(c.fp), c.fp, rw.length, rw.chunk); status != http.StatusTooManyRequests {
					t.Errorf("%s fingerprint, the store closed: %d, want 429", c.who, status)
				}
			}
		})
	}

	// On a real connection, for a body declared and not delivered, which
	// only a half-close ends. Every connection here is from 127.0.0.1, so
	// each caller has a relay of its own and so a bucket of its own.
	type wireCaller struct {
		who  string
		h    *harness
		fp   string
		want wireAnswer // the answer before the budget is spent
	}
	unread400 := wireAnswer{status: http.StatusBadRequest, text: "could not read request body", close: true}
	refused401 := wireAnswer{status: http.StatusUnauthorized, text: "unauthorized"}
	wireRows := []struct {
		name      string
		method    string
		path      func(fp string) string
		declared  int
		sent      []byte
		halfClose bool
		callers   func() []wireCaller
	}{
		{"an admin token declared and not delivered", "POST",
			func(string) string { return "/v1/admin/tokens" }, 100, nil, true,
			func() []wireCaller {
				ha, hs := admins(), admins()
				return []wireCaller{{"an administrator's", ha, admin.Fingerprint(), unread400},
					{"a stranger's", hs, hs.fpOf(t, "stranger"), unread400}}
			}},
		{"an admin token sent whole under a signature that does not verify", "POST",
			func(string) string { return "/v1/admin/tokens" }, 2, []byte("{}"), false,
			func() []wireCaller {
				ha, hs := admins(), admins()
				return []wireCaller{{"an administrator's", ha, admin.Fingerprint(), refused401},
					{"a stranger's", hs, hs.fpOf(t, "stranger"), refused401}}
			}},
		{"a post declared and not delivered", "POST",
			func(fp string) string { return "/v1/mailbox/" + fp }, 100, []byte("0123456789"), true,
			func() []wireCaller {
				hr, hu := mailbox(), mailbox()
				return []wireCaller{{"registered", hr, hr.user(t, "alice").Fingerprint(), unread400},
					{"unregistered", hu, hu.fpOf(t, "nobody"), wireAnswer{status: http.StatusUnauthorized, text: "unauthorized", close: true}}}
			}},
	}
	for _, rw := range wireRows {
		t.Run(rw.name, func(t *testing.T) {
			callers := rw.callers()
			spentAt := make([]int, len(callers))
			for i, c := range callers {
				nonces := c.h.nonceCount()
				var got []wireAnswer
				var statuses []int
				for range probeBurst + 1 {
					a := wireProbe(t, c.h, rw.method, rw.path(c.fp), c.fp, rw.declared, rw.sent, rw.halfClose)
					got = append(got, a)
					statuses = append(statuses, a.status)
				}
				spentAt[i] = spentIndex(statuses)
				for n := range probeBurst {
					if got[n] != c.want {
						t.Errorf("%s fingerprint: answer %d is %+v; want %+v", c.who, n+1, got[n], c.want)
						break
					}
				}
				if spentAt[i] != probeBurst {
					t.Errorf("%s fingerprint: answers %v; want 429 on request %d, the unauthenticated bucket charged for every refusal", c.who, statuses, probeBurst+1)
				}
				if got := c.h.nonceCount(); got != nonces {
					t.Errorf("%s fingerprint: nonces %d after the probes, want %d", c.who, got, nonces)
				}
			}
			for i := range spentAt {
				if spentAt[i] != spentAt[0] {
					t.Errorf("%s fingerprint is spent after %d refusals and %s after %d: the two cost differently", callers[0].who, spentAt[0], callers[i].who, spentAt[i])
				}
			}
		})
	}
}

// spentIndex is the index of the first 429 in statuses, or -1.
func spentIndex(statuses []int) int {
	for n, status := range statuses {
		if status == http.StatusTooManyRequests {
			return n
		}
	}
	return -1
}

// TestARegistrationRefusedForItsSizeIsChargedOnce: the registration is
// charged to the unauthenticated bucket before anything of it is judged,
// so its body is read uncharged; a registration declared over its cap
// costs one token, the burst's worth of them are answered 413 and the
// next 429, and not half as many.
func TestARegistrationRefusedForItsSizeIsChargedOnce(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{UnauthenticatedPerMinute: probeBurst}})
	id := ids(t, "x")[0]
	var got []int
	for range probeBurst + 1 {
		got = append(got, unsignedProbe(t, h, "192.0.2.9", "POST", "/v1/register", id.Fingerprint(), relayapi.FramingAllowance+1, nil))
	}
	want := []int{http.StatusRequestEntityTooLarge, http.StatusRequestEntityTooLarge, http.StatusRequestEntityTooLarge, http.StatusTooManyRequests}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("registrations declared over the cap answered %v, want %v: one token each", got, want)
	}
}
