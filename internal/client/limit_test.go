package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// One queue row as a function of one integer: the rest of it is a row
	// the shape check would pass, so the integer is the only thing under
	// test.
	queue := func(set func(q *relayapi.QueuedMessage, n int64)) func(int64) any {
		return func(n int64) any {
			row := relayapi.QueuedMessage{ID: 1, Neighbour: "bar", State: "waiting", Tries: 0}
			set(&row, n)
			return relayapi.QueueResponse{Queued: []relayapi.QueuedMessage{row}}
		}
	}
	callQueue := func(c *Client) error { _, err := c.Queue(context.Background()); return err }
	mailbox := func(set func(m *relayapi.MailboxRecord, n int64)) func(int64) any {
		return func(n int64) any {
			m := relayapi.MailboxRecord{FP: fp, Name: "alice", Allow: relayapi.AllowSigned}
			set(&m, n)
			return relayapi.MailboxAnswer{Mailbox: m}
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
			one := int64(1)
			l := relayapi.ListResponse{First: &one, Last: &one, Allow: relayapi.AllowNone, Card: relayapi.CardNone,
				Directory: relayapi.DirectoryNone,
				Messages:  []relayapi.StoredMessage{{ID: 1, Size: 10, Kind: relayapi.KindStream, Channel: "default"}}}
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
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.MaxOpenUploads = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.MaxInflight = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.MaxWaiting = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.KnockMaxBytes = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.MaxKnocksWaiting = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.Limits.KnocksPerHour = n }), callStatus},
		{"/v1/admin/mailboxes/" + fp, mailbox(func(m *relayapi.MailboxRecord, n int64) { m.QueuedMessages = n }), callMailbox},
		{"/v1/admin/mailboxes/" + fp, mailbox(func(m *relayapi.MailboxRecord, n int64) { m.QueuedBytes = n }), callMailbox},
		{"/v1/admin/mailboxes/" + fp, mailbox(func(m *relayapi.MailboxRecord, n int64) { m.Channels = n }), callMailbox},
		{"/v1/admin/mailboxes/" + fp, mailbox(func(m *relayapi.MailboxRecord, n int64) { m.AllowlistSize = n }), callMailbox},
		{"/v1/admin/tokens", tokens(func(tk *relayapi.TokenRecord, n int64) { tk.Uses, tk.UsesLeft = int(n), 0 }), callTokens},
		{"/v1/admin/tokens", tokens(func(tk *relayapi.TokenRecord, n int64) { tk.Uses, tk.UsesLeft = int(n), int(n) }), callTokens},
		{"/v1/mailbox/" + fp, listing(func(l *relayapi.ListResponse, n int64) { l.Queued = n }), callList},
		// The span of ids held, both ends at one integer: the shape that
		// is valid for every count, so the range alone is what is held.
		{"/v1/mailbox/" + fp, listing(func(l *relayapi.ListResponse, n int64) {
			first, last := n, n
			l.First, l.Last = &first, &last
		}), callList},
		{"/v1/mailbox/" + fp, listing(func(l *relayapi.ListResponse, n int64) { l.Messages[0].Size = n }), callList},
		{"/v1/listed", func(n int64) any { return relayapi.ListedResponse{Entries: []relayapi.ListedEntry{}, Listed: n} },
			func(c *Client) error { _, err := c.Listed(context.Background()); return err }},
		{"/v1/mailbox/" + bob.Fingerprint() + "/streams", func(n int64) any { return relayapi.OpenStreamResponse{Upload: "u", ResumeThreshold: n} },
			func(c *Client) error {
				_, err := c.OpenStream(context.Background(), bob.Fingerprint(), "", 5000, 0)
				return err
			}},
		{"/v1/mailbox/" + fp + "/channels", func(n int64) any {
			return relayapi.ChannelsResponse{Document: []byte("{}"), Signature: []byte("s"), Queued: map[string]int64{"default": n}}
		}, func(c *Client) error { _, err := c.Directory(context.Background(), fp); return err }},
		{"/v1/mailbox/" + fp + "/queue", queue(func(q *relayapi.QueuedMessage, n int64) { q.Tries = n }), callQueue},
	}
	ids := []shape{
		{"/v1/mailbox/" + fp, listing(func(l *relayapi.ListResponse, n int64) { l.Messages[0].ID = n }), callList},
		{"/v1/mailbox/" + fp + "/queue", queue(func(q *relayapi.QueuedMessage, n int64) { q.ID = n }), callQueue},
		{"/v1/mailbox/" + bob.Fingerprint(), func(n int64) any { return relayapi.PostResponse{ID: n} },
			func(c *Client) error { _, err := c.Post(context.Background(), env, ""); return err }},
		{"/v1/forward", func(n int64) any { return relayapi.ForwardResponse{ID: n} },
			func(c *Client) error {
				raw, err := json.Marshal(env)
				if err != nil {
					return err
				}
				_, err = c.Forward(context.Background(), &relayapi.ForwardRequest{
					Envelope: raw, Path: []string{"bar"}, Via: []string{},
				})
				return err
			}},
	}
	seconds := []shape{
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.TokenMaxAgeSecs = n }), callStatus},
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.CertLifetimeSecs = n }), callStatus},
		{"/v1/mailbox/" + bob.Fingerprint() + "/streams", func(n int64) any { return relayapi.OpenStreamResponse{Upload: "u", ResumeWindow: n} },
			func(c *Client) error {
				_, err := c.OpenStream(context.Background(), bob.Fingerprint(), "", 5000, 0)
				return err
			}},
	}
	mldsa := []shape{
		{"/v1/admin/status", status(func(st *relayapi.AdminStatusResponse, n int64) { st.MLDSA = int(n) }), callStatus},
		{"/v1/health", func(n int64) any {
			return relayapi.HealthResponse{OK: true, MLDSA: int(n), MaxBytes: relayapi.DefaultMaxBytes, KnockMaxBytes: relayapi.DefaultMaxBytes, Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel}
		},
			func(c *Client) error { _, err := c.MLDSA(context.Background()); return err }},
		{"/v1/health", func(n int64) any {
			return relayapi.HealthResponse{OK: true, MLDSA: int(n), MaxBytes: relayapi.DefaultMaxBytes, KnockMaxBytes: relayapi.DefaultMaxBytes, Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel}
		},
			func(c *Client) error { return c.Health(context.Background()) }},
	}
	// The health answer's max_bytes: what a listing page follows, held to
	// [1, MaxBytesCeiling]; zero, which is what an absent field decodes
	// to, is refused by name. Read by Health here, and by the first listing, which sizes
	// what the client will hold of a page by it (TestLimitAnAnswerIsHeldToWhatItsRouteHolds).
	maxBytes := []shape{
		{"/v1/health", func(n int64) any {
			return relayapi.HealthResponse{OK: true, MaxBytes: n, KnockMaxBytes: relayapi.DefaultMaxBytes, Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel}
		},
			func(c *Client) error { return c.Health(context.Background()) }},
		// knock_max_bytes, held to the same range: what a knock is sealed
		// against before it is sent, zero refused as the absent field.
		{"/v1/health", func(n int64) any {
			return relayapi.HealthResponse{OK: true, MaxBytes: relayapi.DefaultMaxBytes, KnockMaxBytes: n, Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel}
		},
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
	for i, sh := range maxBytes {
		t.Run("max_bytes "+strconv.Itoa(i), func(t *testing.T) {
			for _, n := range []int64{0, -1, math.MinInt64, relayapi.MaxBytesCeiling + 1, math.MaxInt64} {
				refused(t, sh, n)
			}
			for _, n := range []int64{1, relayapi.MaxBytesCeiling} {
				taken(t, sh, n)
			}
		})
	}
	// The health answer's wire_level: 1 or more, with no ceiling, since a
	// level rises with what a relay can do; zero, which is what an absent
	// field decodes to, is refused by name, and the client keeps the level
	// it was given (D40).
	t.Run("wire_level", func(t *testing.T) {
		level := shape{"/v1/health", func(n int64) any {
			return relayapi.HealthResponse{OK: true, MaxBytes: relayapi.DefaultMaxBytes, KnockMaxBytes: relayapi.DefaultMaxBytes,
				Registration: relayapi.RegistrationOpen, WireLevel: int(n)}
		}, func(c *Client) error { return c.Health(context.Background()) }}
		for _, n := range []int64{0, -1, math.MinInt} {
			refused(t, level, n)
		}
		for _, n := range []int64{1, 2, math.MaxInt} {
			srv := fakeRelay(t, map[string]any{level.path: level.answer(n)})
			c, err := New(srv.URL, alice, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Health(context.Background()); err != nil || int64(c.WireLevel()) != n {
				t.Errorf("wire_level %d: %v, kept %d", n, err, c.WireLevel())
			}
		}
	})
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
// upload, in the header a 409 to an attempt carries, is zero or more and
// is what a sender resumes from: a negative, the type's minimum, the text
// one past the type's maximum, an empty header, a digit outside ASCII and
// a sign inside the digits are each the conflict alone, with no offset to
// resume from (not a ResumeError); zero, a plus sign and the type's
// maximum are read. The id a 201 carries is held to a message id.
func TestLimitUploadOffsetAnswer(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	var header string
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(relayapi.UploadOffsetHeader, header)
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	put := func() (int64, error) { return c.PutStream(ctx, "u", 7, strings.NewReader("x"), 1) }
	status, body = http.StatusConflict, `{"code":"","error":"upload is at offset 3, not 7"}`
	for _, h := range []string{"-1", strconv.FormatInt(math.MinInt64, 10), "9223372036854775808", "", "\u0661", "1-2"} {
		header = h
		_, err := put()
		var resume *ResumeError
		var httpErr *HTTPError
		if errors.As(err, &resume) || !errors.As(err, &httpErr) || httpErr.Status != http.StatusConflict {
			t.Errorf("a conflict with the header %q: %v; want the conflict alone, nothing to resume from", h, err)
		}
	}
	for _, tc := range []struct {
		h    string
		want int64
	}{{"0", 0}, {"+1", 1}, {"9223372036854775807", math.MaxInt64}} {
		header = tc.h
		_, err := put()
		var resume *ResumeError
		if !errors.As(err, &resume) || resume.At != tc.want {
			t.Errorf("a conflict with the header %q: %v; want a ResumeError at %d", tc.h, err, tc.want)
		}
	}
	// The placed message's id, from the 201: zero, a negative and the
	// type's minimum are malformed; one and the maximum are taken.
	status, header = http.StatusCreated, ""
	for _, id := range []int64{0, -1, math.MinInt64} {
		body = `{"id":` + strconv.FormatInt(id, 10) + `}`
		if _, err := put(); !errors.Is(err, ErrMalformedAnswer) {
			t.Errorf("a 201 with id %d: %v; want ErrMalformedAnswer", id, err)
		}
	}
	for _, id := range []int64{1, math.MaxInt64} {
		body = `{"id":` + strconv.FormatInt(id, 10) + `}`
		if got, err := put(); err != nil || got != id {
			t.Errorf("a 201 with id %d: %d %v; want it taken", id, got, err)
		}
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

// TestLimitAnswerShapesOneShort: every fingerprint, serial and token id
// in a relay's answer is held to its shape in shape.go before a command
// slices its first sixteen or twelve characters; one character short of
// the shape is a malformed answer naming the field, and nothing of the
// answer is returned.
func TestLimitAnswerShapesOneShort(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	fp := alice.Fingerprint()
	shortFP := strings.Repeat("a", 63)
	shortSerial := strings.Repeat("0", 31)
	shortToken := strings.Repeat("7", 31)
	for _, tc := range []struct {
		path, field string
		answer      any
		call        func(c *Client) error
	}{
		{"/v1/admin/status", "ca_fingerprint", relayapi.AdminStatusResponse{CAFingerprint: shortFP},
			func(c *Client) error { _, err := c.AdminStatus(context.Background()); return err }},
		{"/v1/admin/mailboxes", "fp", relayapi.MailboxListResponse{Mailboxes: []relayapi.MailboxRecord{{FP: shortFP}}},
			func(c *Client) error { _, err := c.AdminMailboxes(context.Background(), "", 0); return err }},
		{"/v1/admin/mailboxes", "next", relayapi.MailboxListResponse{Next: shortFP},
			func(c *Client) error { _, err := c.AdminMailboxes(context.Background(), "", 0); return err }},
		{"/v1/admin/mailboxes/" + fp, "fp", relayapi.MailboxAnswer{Mailbox: relayapi.MailboxRecord{FP: shortFP}},
			func(c *Client) error { _, err := c.AdminMailbox(context.Background(), fp); return err }},
		{"/v1/admin/blocks", "fp", relayapi.BlocksResponse{Blocks: []relayapi.BlockRecord{{FP: shortFP, ByFP: fp}}},
			func(c *Client) error { _, err := c.AdminBlocks(context.Background()); return err }},
		{"/v1/admin/blocks", "by_fp", relayapi.BlocksResponse{Blocks: []relayapi.BlockRecord{{FP: fp, ByFP: shortFP}}},
			func(c *Client) error { _, err := c.AdminBlocks(context.Background()); return err }},
		{"/v1/admin/tokens", "id", relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: shortToken, Issuer: fp, Use: token.UseRegister, State: relayapi.TokenLive}}},
			func(c *Client) error { _, err := c.AdminTokens(context.Background(), false); return err }},
		{"/v1/admin/tokens", "issuer", relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: strings.Repeat("7", 32), Issuer: shortFP, Use: token.UseRegister, State: relayapi.TokenLive}}},
			func(c *Client) error { _, err := c.AdminTokens(context.Background(), false); return err }},
		{"/v1/admin/tokens", "subject", relayapi.TokenListResponse{Tokens: []relayapi.TokenRecord{{ID: strings.Repeat("7", 32), Issuer: fp, Subject: shortFP, Use: token.UseRegister, State: relayapi.TokenLive}}},
			func(c *Client) error { _, err := c.AdminTokens(context.Background(), false); return err }},
		{"/v1/admin/certs", "serial", relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: shortSerial, FP: fp}}},
			func(c *Client) error { _, err := c.AdminCerts(context.Background(), "", false); return err }},
		{"/v1/admin/certs", "fp", relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: strings.Repeat("0", 32), FP: shortFP}}},
			func(c *Client) error { _, err := c.AdminCerts(context.Background(), "", false); return err }},
		{"/v1/mailbox/" + fp + "/certs", "serial", relayapi.CertsResponse{Certs: []relayapi.CertRecord{{Serial: shortSerial}}},
			func(c *Client) error { _, err := c.Certs(context.Background()); return err }},
	} {
		srv := fakeRelay(t, map[string]any{tc.path: tc.answer})
		c, err := New(srv.URL, alice, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = tc.call(c)
		if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), tc.field+" is not") {
			t.Errorf("%s with %s one short: %v; want ErrMalformedAnswer naming the field", tc.path, tc.field, err)
		}
	}
}

// TestLimitAConflictsForwardIDIsHeldToItsShape: the id a relay sends with a
// 409 on the forward route comes from a relay and goes into a row, so it is
// held to the shape every id from a relay is held to. A negative one, which
// no relay of this tree sends, leaves the field at zero — which already means
// "no row of this caller's to name" — rather than reaching a database as a
// number nothing would ever match.
func TestLimitAConflictsForwardIDIsHeldToItsShape(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int64
	}{
		{`{"id":7}`, 7},
		{`{"id":0}`, 0},
		{`{"id":-1}`, 0},
		{`{"id":-9223372036854775808}`, 0},
		{`{}`, 0},
		{`not json`, 0},
	} {
		resp := &http.Response{StatusCode: http.StatusConflict}
		if got := httpError(resp, []byte(tc.body)).ForwardID; got != tc.want {
			t.Errorf("%s: ForwardID %d, want %d", tc.body, got, tc.want)
		}
	}
	// And no other answer carries one, whatever its body says.
	resp := &http.Response{StatusCode: http.StatusBadRequest}
	if got := httpError(resp, []byte(`{"id":7}`)).ForwardID; got != 0 {
		t.Errorf("a 400 carried ForwardID %d, want 0", got)
	}
}

// TestLimitAConflictsCodeIsHeldToItsSet: the code a relay sends with a 409
// for an ended row decides that this relay ends its own row the same way, so
// it is one of the two a report may carry or it is dropped, and the sentence
// with it, leaving the id alone — which is the plain hand-over it would have
// been read as before the code existed. A code comes only with an id: without
// one there is no row of the caller's for it to be about. And the sentence
// goes through the same escaping as every other sentence from a relay.
func TestLimitAConflictsCodeIsHeldToItsSet(t *testing.T) {
	for _, tc := range []struct {
		body       string
		id         int64
		code, said string
	}{
		{`{"id":7,"code":"refused","said":"baz: no"}`, 7, "refused", "baz: no"},
		{`{"id":7,"code":"gave-up","said":"baz: three days"}`, 7, "gave-up", "baz: three days"},
		{`{"id":7,"code":"delivered","said":"baz: yes"}`, 7, "", ""},
		{`{"id":7,"code":"Refused","said":"baz: no"}`, 7, "", ""},
		{`{"id":7,"code":"","said":"baz: no"}`, 7, "", ""},
		{`{"id":0,"code":"refused","said":"baz: no"}`, 0, "", ""},
		{`{"id":-1,"code":"refused","said":"baz: no"}`, 0, "", ""},
		{`{"id":7,"code":"refused","said":"baz: \u001b[2J"}`, 7, "refused", `baz: \x1b[2J`},
	} {
		resp := &http.Response{StatusCode: http.StatusConflict}
		e := httpError(resp, []byte(tc.body))
		if e.ForwardID != tc.id || e.ForwardCode != tc.code || e.ForwardSaid != tc.said {
			t.Errorf("%s: %d %q %q, want %d %q %q", tc.body, e.ForwardID, e.ForwardCode, e.ForwardSaid,
				tc.id, tc.code, tc.said)
		}
	}
	resp := &http.Response{StatusCode: http.StatusBadRequest}
	if e := httpError(resp, []byte(`{"id":7,"code":"refused","said":"x"}`)); e.ForwardCode != "" || e.ForwardSaid != "" {
		t.Errorf("a 400 carried code %q said %q", e.ForwardCode, e.ForwardSaid)
	}
}

// TestLimitAQueueRowIsHeldToItsShape: the queue's strings, beside the
// integers the table above holds.
//
// A row's neighbour and path are relay names an operator gave, and they are
// printed to a person and go nowhere else — but a name that is not a name is
// a relay putting its own text on somebody's terminal, and the path is the
// same shape as an address, so both are held to the rule that makes a name
// one. The state is one of three words for the same reason: a fourth is a
// relay saying something this client has no meaning for.
func TestLimitAQueueRowIsHeldToItsShape(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	fp := alice.Fingerprint()
	good := relayapi.QueuedMessage{ID: 1, Neighbour: "bar", Path: "baz", State: "waiting"}

	for _, tc := range []struct {
		name  string
		row   relayapi.QueuedMessage
		field string
	}{
		{"a neighbour that is not a name", with(good, func(q *relayapi.QueuedMessage) { q.Neighbour = "b ar" }), "neighbour"},
		{"a neighbour of two bytes", with(good, func(q *relayapi.QueuedMessage) { q.Neighbour = "b!" }), "neighbour"},
		{"no neighbour at all", with(good, func(q *relayapi.QueuedMessage) { q.Neighbour = "" }), "neighbour"},
		{"a path name that is not a name", with(good, func(q *relayapi.QueuedMessage) { q.Path = "baz!b ar" }), "path"},
		{"a path of more than max_hops", with(good, func(q *relayapi.QueuedMessage) {
			q.Path = strings.TrimSuffix(strings.Repeat("r!", relayapi.MaxHops+1), "!")
		}), "path"},
		{"a state this client has no meaning for", with(good, func(q *relayapi.QueuedMessage) { q.State = "posted" }), "state"},
		// The code is a word a relay chose that this program prints beside
		// its own text, so it is held to the shape of a word. Without that
		// a relay can clear the screen and write lines that look like the
		// tool's own, or add a line to a piped transcript.
		{"a code with an escape in it", with(good, func(q *relayapi.QueuedMessage) {
			q.Code = "\x1b[2J\x1b[H\rgave-up"
		}), "code"},
		{"a code with a newline in it", with(good, func(q *relayapi.QueuedMessage) {
			q.Code = "gave-up\n  forged line from the relay"
		}), "code"},
		{"a code that is a paragraph", with(good, func(q *relayapi.QueuedMessage) {
			q.Code = strings.Repeat("a", 33)
		}), "code"},
		{"no state at all", with(good, func(q *relayapi.QueuedMessage) { q.State = "" }), "state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeRelay(t, map[string]any{"/v1/mailbox/" + fp + "/queue": relayapi.QueueResponse{
				Queued: []relayapi.QueuedMessage{tc.row},
			}})
			c, err := New(srv.URL, alice, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Queue(context.Background())
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("%v; want the field named", err)
			}
			if !strings.Contains(err.Error(), "the queue") {
				t.Errorf("%v; want the answer named", err)
			}
		})
	}
	// A page over the route's own limit is refused as a page, not read
	// short: a relay answering more rows than it says it will is a relay
	// this client has stopped agreeing with.
	rows := make([]relayapi.QueuedMessage, relayapi.MaxQueueLimit+1)
	for i := range rows {
		rows[i] = relayapi.QueuedMessage{ID: int64(i + 1), Neighbour: "bar", State: "waiting"}
	}
	srv := fakeRelay(t, map[string]any{"/v1/mailbox/" + fp + "/queue": relayapi.QueueResponse{Queued: rows}})
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Queue(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "queued") {
		t.Errorf("a page of %d rows: %v", len(rows), err)
	}
	// And a good row is taken, so none of the above passes by refusing
	// everything.
	srv = fakeRelay(t, map[string]any{"/v1/mailbox/" + fp + "/queue": relayapi.QueueResponse{
		Queued: []relayapi.QueuedMessage{good},
	}})
	if c, err = New(srv.URL, alice, nil); err != nil {
		t.Fatal(err)
	}
	if queued, err := c.Queue(context.Background()); err != nil || len(queued) != 1 {
		t.Fatalf("a row that is right: %d rows, %v", len(queued), err)
	}
}

// with is a copy of a row with one field changed.
func with(row relayapi.QueuedMessage, set func(*relayapi.QueuedMessage)) relayapi.QueuedMessage {
	set(&row)
	return row
}

// TestLimitAViaIsHeldToTheAddressRule: what a relay says about where a
// message has been is held to the rule every relay ran on the way.
//
// The rule is store.CheckAddress, the relay's own, not a copy: ruling 4 puts
// it over the whole address and every hop runs it after appending its own
// name, so a via that breaks it reached this client through a relay that did
// not run it. A repeated name is that rather than a coincidence — the rule
// refuses the honest case too, which is the trade ruling 4 chose.
func TestLimitAViaIsHeldToTheAddressRule(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := envelope.Seal(alice, bob.Public(), message.Body{
		Type: message.TypeNote, Thread: strings.Repeat("a", 32), Text: "hi",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	fp := alice.Fingerprint()
	row := func(via string) any {
		one := int64(1)
		return relayapi.ListResponse{
			First: &one, Last: &one,
			Messages: []relayapi.StoredMessage{{
				ID: 1, Received: time.Now().UTC(), Kind: relayapi.KindEnvelope,
				Channel: "default", Via: via, Envelope: raw,
			}},
			Allow: "none", Card: "none", Directory: "none",
		}
	}
	for _, tc := range []struct{ name, via string }{
		{"nothing, which is mail that came no distance", ""},
		{"one hop", "alpha"},
		{"several", "alpha!beta!gamma"},
		{"at the ceiling", joinNames(relayapi.MaxHops)},
	} {
		t.Run("taken: "+tc.name, func(t *testing.T) {
			srv := fakeRelay(t, map[string]any{"/v1/mailbox/" + fp: row(tc.via)})
			c, err := New(srv.URL, alice, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.List(context.Background(), 0, 10); err != nil {
				t.Errorf("via %q: %v", tc.via, err)
			}
		})
	}
	for _, tc := range []struct{ name, via string }{
		{"a name that is not one", "alpha!b ta"},
		{"an empty name between two", "alpha!!gamma"},
		{"the reserved word", "self"},
		{"a name of 65 bytes", strings.Repeat("r", identity.MaxNameBytes+1)},
		{"one relay named twice", "alpha!alpha"},
		{"named twice, folded", "alpha!Alpha"},
		{"one over max_hops", joinNames(relayapi.MaxHops + 1)},
	} {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			srv := fakeRelay(t, map[string]any{"/v1/mailbox/" + fp: row(tc.via)})
			c, err := New(srv.URL, alice, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.List(context.Background(), 0, 10)
			if err == nil {
				t.Fatalf("via %q was taken", tc.via)
			}
			if !errors.Is(err, ErrMalformedAnswer) {
				t.Errorf("via %q: %v; want ErrMalformedAnswer", tc.via, err)
			}
			if !strings.Contains(err.Error(), "via") || !strings.Contains(err.Error(), "the listing") {
				t.Errorf("via %q: %v; want the field and the answer named", tc.via, err)
			}
		})
	}
}

// joinNames is n distinct relay names joined by "!", for the hop-count cases.
func joinNames(n int) string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("r%d", i)
	}
	return strings.Join(names, "!")
}

// TestLimitACourierListingIsHeldToItsShape: the courier listing's two strings,
// each held before anything slices or prints it.
//
// Both are printed to a person and the fingerprint is sliced to sixteen
// characters for the terminal, so a short one would panic and a name that is
// not a name is a relay putting its own text on somebody's screen. The name is
// held to store.ValidRelayName and not the laxer identity.ValidName because
// that is the rule the relay runs over the same name when it loads its couriers
// file, and because this end makes a directory of it under relays/ — one name,
// one rule, both ends, which is ruling 36.
//
// No name twice is here for a reason the relay cannot cover: its own file
// refuses one fingerprint under two names and its answer is keyed by
// fingerprint, so the case it cannot rule out is two fingerprints under one
// name, and a name is what a person types to admit one.
func TestLimitACourierListingIsHeldToItsShape(t *testing.T) {
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	full := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)

	for _, tc := range []struct {
		name  string
		list  []relayapi.Courier
		field string
	}{
		{"a name that is not a name", []relayapi.Courier{{Name: "b ar", FP: full}}, "name"},
		{"no name at all", []relayapi.Courier{{Name: "", FP: full}}, "name"},
		{"a name with a path in it", []relayapi.Courier{{Name: "../x", FP: full}}, "name"},
		{"a name that is a Windows device", []relayapi.Courier{{Name: "con", FP: full}}, "name"},
		{"the reserved name", []relayapi.Courier{{Name: "self", FP: full}}, "name"},
		{"a name with an escape in it", []relayapi.Courier{{Name: "\x1b[2Jbar", FP: full}}, "name"},
		// The slice is [:16], so a fingerprint one character short is the
		// value that would panic if it reached the terminal unchecked.
		{"a fingerprint one short", []relayapi.Courier{{Name: "bar", FP: strings.Repeat("a", 63)}}, "fp"},
		{"a fingerprint one long", []relayapi.Courier{{Name: "bar", FP: strings.Repeat("a", 65)}}, "fp"},
		{"no fingerprint at all", []relayapi.Courier{{Name: "bar", FP: ""}}, "fp"},
		{"upper-case hex", []relayapi.Courier{{Name: "bar", FP: strings.Repeat("A", 64)}}, "fp"},
		{"a fingerprint that is not hex", []relayapi.Courier{{Name: "bar", FP: strings.Repeat("z", 64)}}, "fp"},
		{"one name twice", []relayapi.Courier{{Name: "bar", FP: full}, {Name: "bar", FP: other}}, "name"},
		// Folded, because the relay folds: its own loader refuses two
		// neighbours whose names differ only in case, so an answer holding
		// both is one no honest file produced, and taking it would leave the
		// ambiguity this check exists to refuse.
		{"two names differing only in case", []relayapi.Courier{
			{Name: "bar", FP: full}, {Name: "Bar", FP: other},
		}, "name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeRelay(t, map[string]any{"/v1/couriers": relayapi.CouriersResponse{Couriers: tc.list}})
			c, err := New(srv.URL, alice, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Couriers(context.Background()); err == nil {
				t.Fatal("accepted")
			} else {
				if !strings.Contains(err.Error(), tc.field) {
					t.Errorf("%v; want the field named", err)
				}
				if !strings.Contains(err.Error(), "the courier listing") {
					t.Errorf("%v; want the answer named", err)
				}
			}
		})
	}
	// An absent list is refused, since absent and empty are one value after a
	// decode and empty is the honest one for a relay that peers with nobody.
	srv := fakeRelay(t, map[string]any{"/v1/couriers": map[string]any{}})
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Couriers(context.Background()); err == nil {
		t.Error("an answer with no couriers key was accepted")
	}
	// More entries than the relay's own file could hold is a relay answering
	// about something other than its file.
	over := make([]relayapi.Courier, 0, relayapi.MaxCouriers+1)
	for i := range relayapi.MaxCouriers + 1 {
		over = append(over, relayapi.Courier{
			Name: fmt.Sprintf("r%d", i), FP: strings.Repeat(string("0123456789abcdef"[i%16]), 64),
		})
	}
	srv = fakeRelay(t, map[string]any{"/v1/couriers": relayapi.CouriersResponse{Couriers: over}})
	c, err = New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Couriers(context.Background()); err == nil {
		t.Errorf("%d couriers were accepted", len(over))
	}
	// And a listing at every bound is taken, so the checks above are refusing
	// the shape and not the route.
	good := []relayapi.Courier{{Name: "bar", FP: full}, {Name: "baz", FP: other}}
	srv = fakeRelay(t, map[string]any{"/v1/couriers": relayapi.CouriersResponse{Couriers: good}})
	c, err = New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Couriers(context.Background()); err != nil || len(got) != 2 {
		t.Errorf("a good listing: %+v %v", got, err)
	}
}

// TestLimitContentRange: the answer to a range request is held to the span
// asked for. The three numbers of "bytes start-end/size" are decimals at
// or above zero within int64: 0, 1 and MaxInt64 are taken where the rest
// of the header allows them, and a sign, a space, a negative, an overflow
// past int64, an unknown size, a list and a header without its "bytes "
// are refused; end below start is refused, and size must pass end, so
// size == end is refused and size == end+1 taken. Then checkRange: the
// status is 206, the header is present, start is the from asked for and
// end the to asked for or the file's last byte where the file ends sooner
// or no end was asked for, and a Content-Length, when given, is the span's,
// which checkRange returns; a 200 to a range is refused, an open-ended one
// from past the start among them, Blob without a range still takes a 200,
// and a 206 that sends more than its span with no length is read as the
// span and no further.
func TestLimitContentRange(t *testing.T) {
	const max = "9223372036854775807"
	const over = "9223372036854775808"
	for _, tc := range []struct {
		v                string
		start, end, size int64
		ok               bool
	}{
		{"bytes 0-0/1", 0, 0, 1, true},
		{"bytes 1-1/2", 1, 1, 2, true},
		{"bytes 0-1/2", 0, 1, 2, true},
		{"bytes 0-9/10", 0, 9, 10, true},
		{"bytes 0-9223372036854775806/" + max, 0, math.MaxInt64 - 1, math.MaxInt64, true},
		{"bytes 9223372036854775806-9223372036854775806/" + max, math.MaxInt64 - 1, math.MaxInt64 - 1, math.MaxInt64, true},
		// end at MaxInt64 leaves no size above it.
		{"bytes 0-" + max + "/" + max, 0, 0, 0, false},
		{"bytes 0-" + max + "/" + over, 0, 0, 0, false},
		{"bytes " + over + "-1/2", 0, 0, 0, false},
		{"bytes 0-" + over + "/" + over, 0, 0, 0, false},
		{"bytes 0-1/" + over, 0, 0, 0, false},
		{"bytes 0-1/18446744073709551616", 0, 0, 0, false},
		// Negatives, signs and spaces, in each place.
		{"bytes -1-1/2", 0, 0, 0, false},
		{"bytes 0--1/2", 0, 0, 0, false},
		{"bytes 0-1/-1", 0, 0, 0, false},
		{"bytes 0-1/-3", 0, 0, 0, false},
		{"bytes +1-1/2", 0, 0, 0, false},
		{"bytes 0-+1/2", 0, 0, 0, false},
		{"bytes 0-1/+2", 0, 0, 0, false},
		{"bytes  1-1/2", 0, 0, 0, false},
		{"bytes 0- 1/2", 0, 0, 0, false},
		{"bytes 0-1/ 2", 0, 0, 0, false},
		{"bytes 0-1/2 ", 0, 0, 0, false},
		{"bytes 0-1 /2", 0, 0, 0, false},
		{"bytes -/2", 0, 0, 0, false},
		{"bytes 0-1/", 0, 0, 0, false},
		// end below start; size not above end.
		{"bytes 5-4/10", 0, 0, 0, false},
		{"bytes 1-0/2", 0, 0, 0, false},
		{"bytes 0-9/9", 0, 0, 0, false},
		{"bytes 0-9/8", 0, 0, 0, false},
		{"bytes 0-0/0", 0, 0, 0, false},
		// An unknown size, an unsatisfied range, a list, other units.
		{"bytes 0-9/*", 0, 0, 0, false},
		{"bytes */10", 0, 0, 0, false},
		{"bytes 0-1/2, 3-4/5", 0, 0, 0, false},
		{"bytes 0-1,3-4/5", 0, 0, 0, false},
		{"0-9/10", 0, 0, 0, false},
		{"Bytes 0-9/10", 0, 0, 0, false},
		{"bytes=0-9/10", 0, 0, 0, false},
		{"bytes0-9/10", 0, 0, 0, false},
		{"items 0-9/10", 0, 0, 0, false},
		{"bytes 0-9", 0, 0, 0, false},
		{"bytes 9/10", 0, 0, 0, false},
		{"", 0, 0, 0, false},
	} {
		start, end, size, ok := parseContentRange(tc.v)
		if ok != tc.ok || start != tc.start || end != tc.end || size != tc.size {
			t.Errorf("parseContentRange(%q) = %d, %d, %d, %v; want %d, %d, %d, %v",
				tc.v, start, end, size, ok, tc.start, tc.end, tc.size, tc.ok)
		}
	}

	c, _ := rangeClient(t, "http://relay.example")
	const none = "absent"
	for _, tc := range []struct {
		name     string
		from, to int64
		status   int
		cr       string
		length   int64
		ok       bool
	}{
		{"the span asked for", 10, 19, 206, "bytes 10-19/100", 10, true},
		{"the span with no length", 10, 19, 206, "bytes 10-19/100", -1, true},
		{"the first byte", 0, 0, 206, "bytes 0-0/1", 1, true},
		{"the whole file as a range", 0, 99, 206, "bytes 0-99/100", 100, true},
		{"a 200 to a range", 10, 19, 200, "", 100, false},
		{"a 200 with the right header", 10, 19, 200, "bytes 10-19/100", 10, false},
		{"a 206 without the header", 10, 19, 206, none, 10, false},
		{"an unknown size", 10, 19, 206, "bytes 10-19/*", 10, false},
		{"a list", 10, 19, 206, "bytes 10-19/100, 30-39/100", 10, false},
		{"start one late", 10, 19, 206, "bytes 11-19/100", 9, false},
		{"start one early", 10, 19, 206, "bytes 9-19/100", 11, false},
		{"end one short", 10, 19, 206, "bytes 10-18/100", 9, false},
		{"end one long", 10, 19, 206, "bytes 10-20/100", 11, false},
		{"the start of the file for a range past it", 10, 19, 206, "bytes 0-9/100", 10, false},
		{"open-ended to the last byte", 10, -1, 206, "bytes 10-99/100", 90, true},
		{"open-ended one short of the last byte", 10, -1, 206, "bytes 10-98/100", 89, false},
		{"open-ended from 0", 0, -1, 206, "bytes 0-9/10", 10, true},
		{"an end past the file, clamped", 0, 999, 206, "bytes 0-9/10", 10, true},
		{"an end past the file, one short of its last byte", 0, 999, 206, "bytes 0-8/10", 9, false},
		{"an end past the file, answered as asked", 0, 999, 206, "bytes 0-999/1000", 1000, true},
		{"an end at the file's last byte", 0, 9, 206, "bytes 0-9/10", 10, true},
		{"a length one long", 10, 19, 206, "bytes 10-19/100", 11, false},
		{"a length one short", 10, 19, 206, "bytes 10-19/100", 9, false},
		{"a length of the whole file", 10, 19, 206, "bytes 10-19/100", 100, false},
		{"a length of zero", 10, 19, 206, "bytes 10-19/100", 0, false},
	} {
		h := http.Header{}
		if tc.cr != none {
			h.Set("Content-Range", tc.cr)
		}
		resp := &http.Response{StatusCode: tc.status, Header: h, ContentLength: tc.length}
		span, err := c.checkRange(resp, tc.from, tc.to)
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s (asked %d-%d, %d %q, length %d): %v; want it taken", tc.name, tc.from, tc.to, tc.status, tc.cr, tc.length, err)
		case tc.ok:
			start, end, _, _ := parseContentRange(tc.cr)
			if span != end-start+1 {
				t.Errorf("%s (%q): span %d, want %d", tc.name, tc.cr, span, end-start+1)
			}
		case !tc.ok && !errors.Is(err, ErrMalformedAnswer):
			t.Errorf("%s (asked %d-%d, %d %q, length %d): %v; want ErrMalformedAnswer", tc.name, tc.from, tc.to, tc.status, tc.cr, tc.length, err)
		case !tc.ok && (!strings.Contains(err.Error(), "relay.example") || !strings.Contains(err.Error(), "range")):
			t.Errorf("%s: %q does not name the relay and the range", tc.name, err)
		}
	}

	// Through Blob, on the wire: each answer is what a server sends,
	// Content-Length and all.
	file := []byte("0123456789")
	for _, tc := range []struct {
		name      string
		from, to  int64
		rangeSent string
		answer    func(w http.ResponseWriter)
		want      string
	}{
		{"no range and a 200", 0, -1, "", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusOK)
			w.Write(file)
		}, "0123456789"},
		{"a range and its 206", 2, 5, "bytes=2-5", func(w http.ResponseWriter) {
			w.Header().Set("Content-Range", "bytes 2-5/10")
			w.WriteHeader(http.StatusPartialContent)
			w.Write(file[2:6])
		}, "2345"},
		{"an open-ended range and its 206", 4, -1, "bytes=4-", func(w http.ResponseWriter) {
			w.Header().Set("Content-Range", "bytes 4-9/10")
			w.WriteHeader(http.StatusPartialContent)
			w.Write(file[4:])
		}, "456789"},
		{"an end past the file, clamped", 0, 999, "bytes=0-999", func(w http.ResponseWriter) {
			w.Header().Set("Content-Range", "bytes 0-9/10")
			w.WriteHeader(http.StatusPartialContent)
			w.Write(file)
		}, "0123456789"},
		{"a range and a 200", 2, 5, "bytes=2-5", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusOK)
			w.Write(file)
		}, ""},
		{"a 206 without Content-Range", 2, 5, "bytes=2-5", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusPartialContent)
			w.Write(file[2:6])
		}, ""},
		{"a 206 of another span", 2, 5, "bytes=2-5", func(w http.ResponseWriter) {
			w.Header().Set("Content-Range", "bytes 3-6/10")
			w.WriteHeader(http.StatusPartialContent)
			w.Write(file[3:7])
		}, ""},
		{"a 206 whose length is not the span's", 2, 5, "bytes=2-5", func(w http.ResponseWriter) {
			w.Header().Set("Content-Range", "bytes 2-5/10")
			w.Header().Set("Content-Length", "5")
			w.WriteHeader(http.StatusPartialContent)
			w.Write(file[2:7])
		}, ""},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Range"); got != tc.rangeSent {
				t.Errorf("%s: Range %q, want %q", tc.name, got, tc.rangeSent)
			}
			tc.answer(w)
		}))
		c, id := rangeClient(t, srv.URL)
		body, _, err := c.Blob(context.Background(), id.Fingerprint(), 1, tc.from, tc.to)
		if tc.want == "" {
			if body != nil {
				body.Close()
			}
			if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), srv.URL) || body != nil {
				t.Errorf("%s: body=%v err=%v; want no body and ErrMalformedAnswer naming %s", tc.name, body != nil, err, srv.URL)
			}
			srv.Close()
			continue
		}
		if err != nil {
			t.Errorf("%s: %v; want it taken", tc.name, err)
			srv.Close()
			continue
		}
		got, err := io.ReadAll(body)
		body.Close()
		if err != nil || string(got) != tc.want {
			t.Errorf("%s: read %q (%v), want %q", tc.name, got, err, tc.want)
		}
		srv.Close()
	}

	// An open-ended range from past the start, the resume's N-, answered 200
	// with the whole file: refused, as a closed range is, and not taken as
	// the remainder.
	var sent []string
	whole := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = append(sent, r.Header.Get("Range"))
		w.WriteHeader(http.StatusOK)
		w.Write(file)
	}))
	defer whole.Close()
	wc, wid := rangeClient(t, whole.URL)
	wb, wn, err := wc.Blob(context.Background(), wid.Fingerprint(), 1, 4, -1)
	if wb != nil {
		wb.Close()
	}
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), "bytes 4-") ||
		!strings.Contains(err.Error(), whole.URL) || wb != nil || wn != 0 {
		t.Errorf("a 200 to bytes=4-: body=%v n=%d err=%v; want no body and ErrMalformedAnswer naming %s and bytes 4-",
			wb != nil, wn, err, whole.URL)
	}
	if len(sent) != 1 || sent[0] != "bytes=4-" {
		t.Errorf("Blob(4, -1) sent Range %q; want one request, bytes=4-", sent)
	}

	// A 206 of the span asked for, its header right, no Content-Length (the
	// flush before any byte makes it chunked), and a body longer than the
	// span (bytes 2-9 sent for 2-5): Blob says the span's length and reads
	// the span and nothing past it.
	long := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 2-5/10")
		w.WriteHeader(http.StatusPartialContent)
		w.(http.Flusher).Flush()
		w.Write(file[2:]) // the span, then four bytes past it
	}))
	defer long.Close()
	lc, lid := rangeClient(t, long.URL)
	body, n, err := lc.Blob(context.Background(), lid.Fingerprint(), 1, 2, 5)
	if err != nil {
		t.Fatalf("a chunked 206 of bytes 2-5 with a body of 8: %v; want it taken", err)
	}
	got, err := io.ReadAll(body)
	body.Close()
	if n != 4 || err != nil || string(got) != "2345" {
		t.Errorf("a chunked 206 of bytes 2-5 with a body of 8: n=%d, read %q (%v); want 4 and %q", n, got, err, "2345")
	}
}
