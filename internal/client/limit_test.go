package client

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// TestLimitRelayAnswerIntegers: every integer a relay's answer carries,
// checked as it comes off the wire. A count is zero or more, so a
// negative and the type's minimum are refused as malformed answers naming
// the field, and zero and the type's maximum are taken; a message id is
// one or more; a seconds field is within [0, MaxDurationSeconds]; an
// ML-DSA parameter set is 44, 65, 87 or 0 for none; a token's uses_left is
// within [0, uses]. Nothing of a refused answer reaches a caller.
func TestLimitRelayAnswerIntegers(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	fp := alice.Fingerprint()
	tokenID := strings.Repeat("7", 32)
	env, _, err := envelope.Seal(alice, bob.Public(), message.Body{Type: message.TypeNote, Thread: strings.Repeat("a", 32), Text: "hi"})
	if err != nil {
		t.Fatal(err)
	}

	// Each answer as a function of one integer, with the call that reads it.
	type shape struct {
		path   string
		answer func(n int64) any
		call   func(c *Client) error
	}
	status := func(set func(st *relayapi.AdminStatusResponse, n int64)) func(int64) any {
		return func(n int64) any {
			st := relayapi.AdminStatusResponse{CAFingerprint: fp, Registration: relayapi.RegistrationToken, ClientCerts: relayapi.ClientCertsRequired}
			set(&st, n)
			return st
		}
	}
	callStatus := func(c *Client) error { _, err := c.AdminStatus(context.Background()); return err }
	mailbox := func(set func(m *relayapi.MailboxRecord, n int64)) func(int64) any {
		return func(n int64) any {
			m := relayapi.MailboxRecord{FP: fp, Name: "alice", Allow: relayapi.AllowSigned}
			set(&m, n)
			return m
		}
	}
	callMailbox := func(c *Client) error { _, err := c.AdminMailbox(context.Background(), fp); return err }
	tokens := func(set func(tk *relayapi.TokenRecord, n int64)) func(int64) any {
		return func(n int64) any {
			tk := relayapi.TokenRecord{ID: tokenID, Issuer: fp, Use: token.UseRegister, State: relayapi.TokenLive, Uses: 5, UsesLeft: 5}
			set(&tk, n)
			return relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{tk}}
		}
	}
	callTokens := func(c *Client) error { _, err := c.AdminTokens(context.Background(), false); return err }
	listing := func(set func(l *relayapi.ListResponse, n int64)) func(int64) any {
		return func(n int64) any {
			l := relayapi.ListResponse{Messages: []relayapi.StoredMessage{{ID: 1, Size: 10, Kind: relayapi.KindStream}}}
			set(&l, n)
			return l
		}
	}
	callList := func(c *Client) error { _, err := c.List(context.Background(), 0, 10); return err }

	counts := []shape{
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Administrators = int(n) }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Mailboxes = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.QueuedMessages = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.QueuedBytes = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.LiveTokens = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Blocks = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.LiveCerts = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.MaxBytes = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.RequestsPerMinute = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.PostsPerMinute = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.PostBytesPerHour = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.UnauthenticatedPerMinute = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.RegistrationsPerHour = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.MaxMailboxes = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.MailboxMaxMessages = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.MailboxMaxBytes = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.RelayMaxBytes = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.MaxInflight = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.MaxWaiting = n }), callStatus},
		{"/v1/admin/mailboxes/" + fp, mailbox(func(m *relayapi.MailboxRecord, n int64) { m.QueuedMessages = n }), callMailbox},
		{"/v1/admin/mailboxes/" + fp, mailbox(func(m *relayapi.MailboxRecord, n int64) { m.QueuedBytes = n }), callMailbox},
		{"/v1/admin/mailboxes/" + fp, mailbox(func(m *relayapi.MailboxRecord, n int64) { m.Channels = n }), callMailbox},
		{"/v1/admin/mailboxes/" + fp, mailbox(func(m *relayapi.MailboxRecord, n int64) { m.AllowlistSize = n }), callMailbox},
		{"/v1/admin/tokens", tokens(func(tk *relayapi.TokenRecord, n int64) { tk.Uses, tk.UsesLeft = int(n), 0 }), callTokens},
		{"/v1/admin/tokens", tokens(func(tk *relayapi.TokenRecord, n int64) { tk.Uses, tk.UsesLeft = int(n), int(n) }), callTokens},
		{"/v1/mailbox/" + fp, listing(func(l *relayapi.ListResponse, n int64) { l.Queued = n }), callList},
		{"/v1/mailbox/" + fp, listing(func(l *relayapi.ListResponse, n int64) { l.Messages[0].Size = n }), callList},
		{"/v1/mailbox/" + bob.Fingerprint() + "/streams", func(n int64) any { return relayapi.OpenStreamResponse{Upload: "u", MaxRequest: n} },
			func(c *Client) error {
				_, err := c.OpenStream(context.Background(), bob.Fingerprint(), "", 5000)
				return err
			}},
	}
	ids := []shape{
		{"/v1/mailbox/" + fp, listing(func(l *relayapi.ListResponse, n int64) { l.Messages[0].ID = n }), callList},
		{"/v1/mailbox/" + bob.Fingerprint(), func(n int64) any { return relayapi.PostResponse{ID: n} },
			func(c *Client) error { _, err := c.Post(context.Background(), env, ""); return err }},
		{"/v1/uploads/u/complete", func(n int64) any { return relayapi.CompleteStreamResponse{ID: n} },
			func(c *Client) error { _, err := c.CompleteStream(context.Background(), "u"); return err }},
	}
	seconds := []shape{
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.TokenMaxAgeSecs = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.CertLifetimeSecs = n }), callStatus},
	}
	mldsa := []shape{
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.MLDSA = int(n) }), callStatus},
		{"/v1/health", func(n int64) any { return relayapi.HealthResponse{OK: true, MLDSA: int(n)} },
			func(c *Client) error { _, err := c.MLDSA(context.Background()); return err }},
		{"/v1/health", func(n int64) any { return relayapi.HealthResponse{OK: true, MLDSA: int(n)} },
			func(c *Client) error { return c.Health(context.Background()) }},
	}

	try := func(t *testing.T, sh shape, n int64) error {
		t.Helper()
		srv := fakeRelay(t, map[string]any{sh.path: sh.answer(n)})
		c, err := New(srv.URL, alice, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sh.call(c)
	}
	refused := func(t *testing.T, sh shape, n int64) {
		t.Helper()
		err := try(t, sh, n)
		if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), " is not ") {
			t.Errorf("%s at %d: %v; want ErrMalformedAnswer naming the field", sh.path, n, err)
		}
	}
	taken := func(t *testing.T, sh shape, n int64) {
		t.Helper()
		if err := try(t, sh, n); err != nil {
			t.Errorf("%s at %d: %v; want the answer taken", sh.path, n, err)
		}
	}
	for i, sh := range counts {
		t.Run("count "+strconv.Itoa(i), func(t *testing.T) {
			for _, n := range []int64{-1, math.MinInt64} {
				refused(t, sh, n)
			}
			for _, n := range []int64{0, math.MaxInt64} {
				taken(t, sh, n)
			}
		})
	}
	for i, sh := range ids {
		t.Run("id "+strconv.Itoa(i), func(t *testing.T) {
			for _, n := range []int64{0, -1, math.MinInt64} {
				refused(t, sh, n)
			}
			for _, n := range []int64{1, math.MaxInt64} {
				taken(t, sh, n)
			}
		})
	}
	for i, sh := range seconds {
		t.Run("seconds "+strconv.Itoa(i), func(t *testing.T) {
			for _, n := range []int64{-1, math.MinInt64, relayapi.MaxDurationSeconds + 1, math.MaxInt64} {
				refused(t, sh, n)
			}
			for _, n := range []int64{0, relayapi.MaxDurationSeconds} {
				taken(t, sh, n)
			}
		})
	}
	for i, sh := range mldsa {
		t.Run("mldsa "+strconv.Itoa(i), func(t *testing.T) {
			for _, n := range []int64{-1, 1, 43, 45, 64, 66, 86, 88, math.MinInt, math.MaxInt} {
				refused(t, sh, n)
			}
			for _, n := range []int64{0, 44, 65, 87} {
				taken(t, sh, n)
			}
		})
	}
	t.Run("uses_left over uses", func(t *testing.T) {
		over := shape{"/v1/admin/tokens", tokens(func(tk *relayapi.TokenRecord, n int64) { tk.Uses, tk.UsesLeft = 5, int(n) }), callTokens}
		for _, n := range []int64{6, math.MaxInt} {
			refused(t, over, n)
		}
		taken(t, over, 5)
	})
}

// TestLimitUploadOffsetAnswer: the byte count a relay reports for an
// upload, in the header the upload routes answer with, is zero or more: a
// negative, the type's minimum, the text one past the type's maximum, an
// empty header and a digit outside ASCII are each a malformed answer, from
// an offset query, from an append taken, and from an append the relay
// answered with a conflict; zero, a plus sign and the type's maximum are
// taken.
func TestLimitUploadOffsetAnswer(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	var header string
	var status int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(relayapi.UploadOffsetHeader, header)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		call func() (int64, error)
		code int
	}{
		{"UploadOffset", func() (int64, error) { return c.UploadOffset(ctx, "u") }, http.StatusOK},
		{"AppendStream taken", func() (int64, error) { return c.AppendStream(ctx, "u", 0, strings.NewReader("x"), 1) }, http.StatusNoContent},
	} {
		status = tc.code
		for _, h := range []string{"-1", strconv.FormatInt(math.MinInt64, 10), "9223372036854775808", "", "\u0661", "1-2"} {
			header = h
			_, err := tc.call()
			if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), relayapi.UploadOffsetHeader) {
				t.Errorf("%s with the header %q: %v; want ErrMalformedAnswer naming the header", tc.name, h, err)
			}
		}
		for _, tc2 := range []struct {
			h    string
			want int64
		}{{"0", 0}, {"+1", 1}, {"9223372036854775807", math.MaxInt64}} {
			header = tc2.h
			n, err := tc.call()
			if err != nil || n != tc2.want {
				t.Errorf("%s with the header %q: %d %v; want %d", tc.name, tc2.h, n, err, tc2.want)
			}
		}
	}
	// A conflict names where the upload is; a conflict whose header is not
	// a byte count is the conflict alone, at the offset the caller sent.
	status = http.StatusConflict
	for _, h := range []string{"-1", "x", ""} {
		header = h
		n, err := c.AppendStream(ctx, "u", 7, strings.NewReader("x"), 1)
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != http.StatusConflict || n != 7 {
			t.Errorf("a conflict with the header %q: %d %v; want the conflict at the caller's offset", h, n, err)
		}
	}
	header = "3"
	if n, err := c.AppendStream(ctx, "u", 7, strings.NewReader("x"), 1); n != 3 || err == nil {
		t.Errorf("a conflict at 3: %d %v; want 3 and the conflict", n, err)
	}
}

// TestLimitRetryAfter: the seconds a relay asks a client to wait, read
// from the header as text, are within [0, a day]: a negative and the
// type's minimum are no advice, and so are the text one past the type's
// maximum, a sign inside the digits and a digit outside ASCII; zero is
// none; a value over a day is a day, which is the client's own ceiling on
// how long it will wait on any relay's word, applied before the
// multiplication that would otherwise overflow.
func TestLimitRetryAfter(t *testing.T) {
	day := int64(maxRetryAfter / time.Second)
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{
		{"-1", 0}, {strconv.FormatInt(math.MinInt64, 10), 0}, {"9223372036854775808", 0}, {"1-2", 0}, {"\u0661", 0}, {"", 0}, {"x", 0},
		{"0", 0}, {"-0", 0}, {"+1", time.Second}, {" 1 ", time.Second}, {"1", time.Second},
		{strconv.FormatInt(day, 10), maxRetryAfter}, {strconv.FormatInt(day+1, 10), maxRetryAfter},
		{"9223372036854775807", maxRetryAfter},
	} {
		h := http.Header{}
		h.Set("Retry-After", tc.raw)
		if got := retryAfter(h); got != tc.want {
			t.Errorf("Retry-After %q: %s, want %s", tc.raw, got, tc.want)
		}
	}
}
