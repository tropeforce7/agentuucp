// Package client talks to a relay on behalf of one identity.
//
// Everything here treats the relay as hostile: it authenticates its own
// requests, and it never trusts what comes back beyond the point where the
// envelope layer can check it.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// Retry policy for a relay that is refusing work rather than failing. A 429 or
// a 503 both mean the relay rejected the request before acting on it, so even a
// POST is safe to send again.
const (
	maxRetries    = 3
	maxRetrySleep = 30 * time.Second
	// minRetrySleep is used when the relay refused without saying for how long.
	minRetrySleep = time.Second
)

// Client is a relay client bound to one identity.
type Client struct {
	base string
	id   *identity.Identity
	http *http.Client
	// stream is the client the stream routes use, the PUT of an attempt
	// and the GET of a blob: the same transport and no whole-exchange
	// timeout, since a stream's length is the transfer's, and a stall rule
	// in its place — no byte read from the request body or arriving on
	// the response body for stall cancels the request. Under the
	// one-request wire a first attempt the client cut at two minutes was
	// kept by the relay only if it had reached max_bytes, so a stream
	// needing more than about four minutes on the link could never be
	// placed.
	stream *http.Client
	// stall is the stream rule's window, relayapi.ResumeWindow, the
	// relay's deadline on a blob read and longer than its hunk window on
	// an upload; tests set it short.
	stall time.Duration
	// maxBytes is the relay's max_bytes as its health answer said it,
	// fetched once on the first listing and kept: what a listing page is
	// sized to, and so what the client will hold of one. Zero until then.
	maxBytes int64
	// wireLevel is the relay's wire level as its last health answer said
	// it, zero until one has been read. Atomic, since a health answer is
	// checked both under mu (a listing's) and outside it.
	wireLevel atomic.Int64
	// maxRecipients is the most recipients the relay takes on a message
	// to several, from its health answer's max-recipients section, or the
	// protocol's ceiling when the answer carries none; zero until a health
	// answer has been read. Atomic for the reason wireLevel is.
	maxRecipients atomic.Int64
	// channelCeiling is the largest max_bytes a channel on the relay may
	// name, from its last health answer's channel-max-bytes section, or
	// zero when that answer carried none, as a relay below wire level 2
	// never does. Atomic for the reason wireLevel is.
	channelCeiling atomic.Int64
	mu             sync.Mutex
	// transport is the one carrying the client certificate, kept so a
	// renewal can drop the connections using the old one.
	transport *http.Transport
	// certless reaches the same relay the same way, offering nothing. It is
	// nil unless this machine holds a certificate, and it exists to answer
	// one question: see diagnoseRefusal.
	certless *http.Client
	// sleep waits between retries. Tests replace it so they need not wait.
	sleep func(context.Context, time.Duration) error
	// maxRetryWait, when set, is the longest Retry-After this Client waits
	// out: a refusal that asks for longer comes back at once, for a caller
	// that has something better to do than wait, as a send to several
	// does, which leaves what it has not posted in the outbox and says
	// when to try. Zero is the ordinary wait.
	maxRetryWait time.Duration
}

// SetMaxRetryWait makes a refusal whose Retry-After is over d come back at
// once rather than be waited out. Zero restores the ordinary wait.
func (c *Client) SetMaxRetryWait(d time.Duration) { c.maxRetryWait = d }

// New returns a client for the relay at base.
//
// cert, when not nil, is this machine's client certificate, presented in the
// TLS handshake. A relay that requires one refuses every mailbox route
// without it; a relay that does not is unaffected by offering one, because a
// server only asks for a certificate it has an authority for.
func New(base string, id *identity.Identity, cert *tls.Certificate) (*Client, error) {
	return NewWithAnchor(base, id, cert, nil)
}

// NewWithAnchor is New for a relay whose certificate chains to a private trust
// anchor this machine has pinned. With one, the system roots are not trusted
// for this relay at all: a relay behind a pinned anchor is not additionally
// reachable through any public authority, which is the point of pinning.
func NewWithAnchor(base string, id *identity.Identity, cert *tls.Certificate, anchor *Anchor) (*Client, error) {
	if base == "" {
		return nil, errors.New("no relay configured: set one with 'auu init --relay URL'")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("bad relay URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("relay URL must be http or https, got %q", u.Scheme)
	}
	// Always the project's own transport, with the pin in it, and never
	// http.DefaultTransport by omission: a relay with a public certificate
	// and no client certificates gave this constructor nothing to add, and
	// for three releases that path left Transport nil and made Go's default
	// handshake — TLS 1.2 and any curve — against a relay that offered less
	// than the hybrid. A pin in a helper is a pin only where every path
	// reaches the helper.
	transport := transportFor(cert, anchor)
	c := &Client{
		base:      strings.TrimSuffix(base, "/"),
		id:        id,
		http:      relayHTTP(transport, 2*time.Minute),
		stream:    relayHTTP(transport, 0),
		stall:     relayapi.ResumeWindow,
		transport: transport,
		sleep:     sleep,
	}
	if cert != nil {
		probe := transportFor(nil, anchor)
		// The diagnostic must not advance the anchor's ratchet. That has
		// side effects — it records the authority this machine has seen,
		// and says so out loud on a rotation — and the connection that
		// just failed has already had its say. The anchor's certificate
		// is still the only root, so it remains the relay that answers.
		if probe.TLSClientConfig != nil {
			probe.TLSClientConfig.VerifyConnection = nil
		}
		c.certless = relayHTTP(probe, 2*time.Minute)
	}
	return c, nil
}

// relayHTTP is the one way this package builds an http.Client, and it
// follows no redirect: every client it returns hands a 3xx back as the
// answer, and the caller refuses it. A relay API has no reason to
// redirect; the signed request header is not one Go strips on a redirect
// to another host, so following one would hand it to whoever the Location
// named; and a URL the relay chose would be the request a sentence then
// names. Like transportFor, it is a rule only where every path reaches it,
// and a test holds that none builds a client any other way.
func relayHTTP(transport http.RoundTripper, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// redirected is the refusal of a 3xx answer, which this build does not
// follow. The Location is not repeated, the relay having chosen it.
func (c *Client) redirected(method, path string, status int) error {
	return fmt.Errorf("%w: the relay at %s answered %s %s with a redirect (%d), which this build does not follow; nothing of the answer was used",
		ErrMalformedAnswer, c.base, method, path, status)
}

// transportFor is the process's transport with what this relay needs added:
// the certificate to present, and the anchor to verify it against.
//
// The clone is added to rather than replaced, so whatever the process already
// established about reaching this relay — its roots, a proxy's settings —
// survives being given a certificate to present.
func transportFor(cert *tls.Certificate, anchor *Anchor) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsCfg := transport.TLSClientConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	} else {
		tlsCfg = tlsCfg.Clone()
	}
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	pinTransport(tlsCfg)
	if anchor != nil {
		tlsCfg = anchor.tlsConfig(tlsCfg)
	}
	transport.TLSClientConfig = tlsCfg
	boundTransport(transport)
	return transport
}

// boundTransport is what every transport this package makes has beyond
// its TLS pins: one protocol and two caps. HTTP/1.1 alone — the clone of
// http.DefaultTransport carried ForceAttemptHTTP2, so every deployed
// exchange was HTTP/2 while every test in the tree ran HTTP/1.1; the
// relay offers http/1.1 alone now and the client asks for nothing else,
// so the wire's properties hold under the one protocol both ends run. A
// response's headers are capped at relayapi.MaxHeaderBytes, the relay's
// own cap on a request's, and refused by the transport over it; and a
// relay that takes the request whole and then says nothing is waited on
// for relayapi.MaxWait plus thirty seconds, the longest a listing is held
// for a watcher plus room for the answer — the plan's thirty seconds
// alone would have cut every held listing. The stream routes' bodies are
// bounded by the stall rule, not by this.
//
// And no connection is kept for a second request (G28, R42). net/http's
// transport sends again, as it was, an idempotent request that got no
// answer on a reused connection, and a signed request sent again carries
// its spent nonce and its old stamp: the relay refuses the replay 401, as
// it must, and a 401 for a replay cannot be told from any other, so a
// watch whose held listing lost its connection ended on "unauthorized".
// A request cannot be signed again inside the transport's retry, and an
// idle connection left by an unsigned call (health, keys) would be reused
// by the next signed one, so the transport keeps none: each request has a
// connection of its own, and one that dies is the request's failure,
// which the caller sees and signs afresh if it asks again.
func boundTransport(t *http.Transport) {
	t.DisableKeepAlives = true
	// An upload asks before it sends its body (PutStream); a relay that
	// never answers the ask is sent the body after this wait.
	t.ExpectContinueTimeout = time.Second
	t.ForceAttemptHTTP2 = false
	t.TLSClientConfig.NextProtos = []string{"http/1.1"}
	t.MaxResponseHeaderBytes = relayapi.MaxHeaderBytes
	t.ResponseHeaderTimeout = relayapi.MaxWait + 30*time.Second
}

// responseHeadersTooLarge recognises the transport's refusal of a response
// whose headers exceed MaxResponseHeaderBytes. net/http has no sentinel
// for it: the transport's readLoop returns fmt.Errorf("net/http: server
// response headers exceeded %d bytes; aborted") (Go 1.27, transport.go),
// so the text is matched, as pinnedHandshakeRefused matches the TLS
// alerts, and a change in net/http's wording is found by
// TestLimitResponseHeadersAreCapped.
func responseHeadersTooLarge(err error) bool {
	return err != nil && strings.Contains(err.Error(), "net/http: server response headers exceeded")
}

// pinTransport is the one TLS policy every connection this project makes
// or takes has: TLS 1.3 and the hybrid post-quantum key exchange, nothing
// less, nothing to negotiate. ML-DSA certificates need 1.3 anyway, and 1.3
// is the first version to encrypt the client's certificate rather than
// send it in the clear; the curve is what keeps a recording of who talked
// to whom under the same protection as the messages. Every relay is built
// from this tree, so there is nothing older to be compatible with, and no
// option relaxes it.
func pinTransport(cfg *tls.Config) {
	cfg.MinVersion = tls.VersionTLS13
	cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
}

// NoPQTransportError is a far end that would not make the pinned
// handshake: something that is not this relay, or a TLS terminator in
// front of it that does not offer X25519MLKEM768 or TLS 1.3. Go's own
// words for it are an alert, "handshake failure" or "protocol version not
// supported", and are kept in brackets.
type NoPQTransportError struct{ Err error }

func (e *NoPQTransportError) Error() string {
	return "no TLS 1.3 with the post-quantum key exchange; what answered is not this relay, or a TLS terminator in front of it lacks X25519MLKEM768 (" + e.Err.Error() + ")"
}

func (e *NoPQTransportError) Unwrap() error { return e.Err }

// pinnedHandshakeRefused reports whether err is the far end refusing the
// pinned handshake: a remote alert of handshake failure (no key exchange in
// common) or of an unsupported protocol version. Both arrive as a
// net.OpError whose Op is "remote error" and whose inner error is
// crypto/tls's unexported alert type, so the alert is read by its text; a
// certificate that does not verify is a different error and is not this.
func pinnedHandshakeRefused(err error) bool {
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" || op.Err == nil {
		return false
	}
	msg := op.Err.Error()
	return msg == "tls: handshake failure" || msg == "tls: protocol version not supported"
}

// CloseIdle drops pooled connections, so the next request makes a fresh
// handshake. A renewal must not go on using the certificate it replaced.
// The transports keep no connection for a second request (G28), so there
// is none to drop today; it is kept so that holds if that ever changes.
func (c *Client) CloseIdle() {
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	if c.certless != nil {
		c.certless.CloseIdleConnections()
	}
}

// sleep waits for d, or until the context is cancelled.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// HTTPError is a non-2xx response from the relay.
type HTTPError struct {
	Status  int
	Message string
	// RetryAfter is how long the relay asked to be left alone for, from the
	// Retry-After header. Zero when it did not say.
	RetryAfter time.Duration
	// ForwardID is the id a relay sent with a 409 on the forward route:
	// the row it already holds for the caller's own envelope, or the
	// message the envelope became there, or zero. It is on the error and
	// not returned beside it because a 409 with it is a fact about the
	// caller's own attempt, and the id is what an undeliverable coming back
	// for it will name. Zero means the envelope was never the caller's
	// there, which a relay's worker reads as a loop and refuses.
	ForwardID int64
	// ForwardCode and ForwardSaid come with a ForwardID when the caller's
	// row there has ended: the code it ended with, one of the two a report
	// may carry, and the sentence. The code is held to that set here and
	// dropped otherwise, together with the sentence, since a code nobody
	// defined is not one to act on; the sentence goes through
	// identity.PrintableText as Message does.
	ForwardCode string
	ForwardSaid string
	// Code is the error body's code, empty for a refusal of no particular
	// kind. A caller acts on the codes it knows and otherwise shows the
	// sentence, so a code a later relay adds is a sentence to an older
	// client and never a break (ruling 67). An error body without a code,
	// or with one that fails wire.ValidName, keeps its status and says so
	// in place of the relay's sentence.
	Code string
	// Relay is the base URL of the relay that refused, as this client was
	// given it, for advice given where the command that failed is no longer
	// in hand. It is the client's own word, never the relay's.
	Relay string
	// At is the time the refusal is about, for the codes whose sentence
	// names one (relayapi.ErrorResponse.At); zero when it names none. A
	// caller shows it from here, in local time, and never from the
	// sentence.
	At time.Time
}

// ErrRelayNeedsNewer is what errors.Is finds on a 400 whose code is
// relayapi.CodeNeedsNewer: the relay does not know a critical section of the
// request, and needs a newer auu before it can take it. The client reads the
// code and never the sentence; the sentence is the message a person reads.
var ErrRelayNeedsNewer = errors.New("the relay needs a newer auu for this request")

// ErrTooManyRecipients is what errors.Is finds on a 413 whose code is
// relayapi.CodeTooManyRecipients: the request carried a copy of a message
// to more recipients than the relay's max_recipients. The sentence names
// both numbers and is what a person reads.
var ErrTooManyRecipients = errors.New("the message is to more recipients than the relay takes")

// Is makes errors.Is true of a needs-newer refusal for ErrRelayNeedsNewer,
// and of a too-many-recipients one for ErrTooManyRecipients, each by its
// status and code and never its words.
func (e *HTTPError) Is(target error) bool {
	switch target {
	case ErrRelayNeedsNewer:
		return e.Status == http.StatusBadRequest && e.Code == relayapi.CodeNeedsNewer
	case ErrTooManyRecipients:
		return e.Status == http.StatusRequestEntityTooLarge && e.Code == relayapi.CodeTooManyRecipients
	}
	return false
}

// httpError is the one place an HTTPError is made from a relay's answer.
// The relay's sentence goes through identity.PrintableText here, at
// construction, so no caller can print it unescaped: a relay is in the
// client's model as something that may be hostile, and its refusal is the
// one thing from it that reached every terminal as it came. Printable
// ASCII is unchanged, so a caller that looks for a known sentence in the
// message still finds it.
func httpError(resp *http.Response, body []byte) *HTTPError {
	he := &HTTPError{Status: resp.StatusCode, RetryAfter: retryAfter(resp.Header)}
	// Every refusal is read strictly (P1), as an error body, or on the
	// forward route's 409 as the row the relay already holds. One that is
	// neither keeps its status and says, with the route, that its words
	// could not be read, so a newer relay's refusal is never an empty
	// sentence; and one with a section it must not be read without says
	// that, with the section's name.
	var e relayapi.ErrorResponse
	var fwd relayapi.ForwardResponse
	var sections []wire.Section
	var badTime *time.ParseError
	decodeErr := wire.Decode(body, &e)
	switch {
	case errors.As(decodeErr, &badTime):
		// The one field whose value has a reader of its own: a time that
		// is not one is said by the field's name, never its value.
		he.Message = fmt.Sprintf("the relay at %s refused %s (%d) with an \"at\" that is not a time",
			relayOf(resp), routeOf(resp), resp.StatusCode)
		return he
	case decodeErr == nil:
		// The code is required: encoding/json leaves an absent string
		// empty, so its presence is asked of the body, which the strict
		// decode has already read whole.
		var present struct {
			Code *string `json:"code"`
		}
		_ = json.Unmarshal(body, &present)
		switch {
		case present.Code == nil:
			he.Message = fmt.Sprintf("the relay at %s refused %s (%d) in an error body without its \"code\"",
				relayOf(resp), routeOf(resp), resp.StatusCode)
			return he
		case e.Code != "" && wire.ValidName(e.Code) != nil:
			// A code has the shape of a section's name; one that has not
			// is no code, and the body is not one this build can read.
			he.Message = fmt.Sprintf("the relay at %s refused %s (%d) with an error code that is not one",
				relayOf(resp), routeOf(resp), resp.StatusCode)
			return he
		}
		he.Message = identity.PrintableText(e.Error)
		he.Code = e.Code
		he.At = e.At
		sections = e.Sections.Sections
	case resp.StatusCode == http.StatusConflict && wire.Decode(body, &fwd) == nil:
		// A 409 on the forward route carries the id of the row the relay
		// already holds. It is read here rather than by the caller because
		// this is the one place an answer becomes an error, and a caller
		// cannot reach the body afterwards.
		//
		// It is held to the shape every id from a relay is held to, since
		// it comes from one and goes into a row: a relay that answers
		// zero, a negative or nothing at all leaves it zero, which already
		// means "no row of this caller's to name". The 201's own id goes
		// through checkID on the way out of Forward; this is that check
		// for the other answer, at the one place this one can be read.
		if fwd.ID > 0 {
			he.ForwardID = fwd.ID
			if fwd.Code == relayapi.CodeRefused || fwd.Code == relayapi.CodeGaveUp {
				he.ForwardCode, he.ForwardSaid = fwd.Code, identity.PrintableText(fwd.Said)
			}
		}
		sections = fwd.Sections.Sections
	default:
		he.Message = fmt.Sprintf("the relay at %s refused %s (%d) in words this build cannot read",
			relayOf(resp), routeOf(resp), resp.StatusCode)
		return he
	}
	if err := sectionsProblem(sections); err != nil {
		// Nothing of the body is used, its code included.
		he.Message = fmt.Sprintf("the relay at %s refused %s (%d) %s",
			relayOf(resp), routeOf(resp), resp.StatusCode, err)
		he.Code = ""
		he.At = time.Time{}
	}
	return he
}

// relayOf and routeOf name the relay and the request a refusal answered,
// for a sentence about a refusal whose own words could not be read. Both
// are escaped: after a redirect resp.Request is the last request, whose
// URL the relay chose, and a path decodes %1b to the byte itself.
func relayOf(resp *http.Response) string {
	if resp.Request == nil || resp.Request.URL == nil {
		return "the relay"
	}
	return identity.PrintableText(resp.Request.URL.Scheme + "://" + resp.Request.URL.Host)
}

func routeOf(resp *http.Response) string {
	if resp.Request == nil || resp.Request.URL == nil {
		return "the request"
	}
	return identity.PrintableText(resp.Request.Method + " " + resp.Request.URL.Path)
}

// sectionsProblem is what is wrong with a body's sections, or nil (D28, R4):
// the list held to wire.Check, then to wire.MaxAPISectionBytes as this build
// encodes it compactly (the body's own hold has already bounded what
// arrived), and then sorted, a section this build does not know ignored and
// one marked critical refusing the body by its name.
func sectionsProblem(list []wire.Section) error {
	err := wire.CheckBody(list, wire.OnAnswer)
	var size *wire.SizeError
	var newer *wire.NeedsNewerError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &size):
		return fmt.Errorf("with sections of %d bytes, over the %d an answer may carry", size.Bytes, wire.MaxAPISectionBytes)
	case errors.As(err, &newer):
		return fmt.Errorf("with a section it must not be read without (section %q); update auu", newer.Name)
	default:
		return fmt.Errorf("with sections that are not a list of sections (%v)", err)
	}
}

// checkSections holds an answer's sections to sectionsProblem: one that
// fails makes the whole answer a malformed answer, said with the relay and
// the request, and nothing of it is used.
func (c *Client) checkSections(method, path string, out any) error {
	sl, ok := out.(interface{ SectionList() []wire.Section })
	if !ok {
		return nil
	}
	if err := sectionsProblem(sl.SectionList()); err != nil {
		return fmt.Errorf("%w: the relay at %s answered %s %s %v", ErrMalformedAnswer, c.base, method, path, err)
	}
	return nil
}

func (e *HTTPError) Error() string {
	msg := fmt.Sprintf("relay returned %d", e.Status)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.RetryAfter > 0 {
		// This is only ever surfaced once the retries are spent, so it is
		// advice about what to do next rather than noise.
		msg += fmt.Sprintf("; it asked for %s before the next attempt", e.RetryAfter)
	}
	return msg
}

// retryable reports whether a status means "not now" rather than "no".
// retryable reports whether an answer is one to try again. A 503 always
// is: the relay is busy and says when to come back, and sends a
// Retry-After with it. A 429 is only when the relay said how long to
// wait: every bucket the relay refuses from answers with the seconds to
// a token, and the one refusal that carries none — a mailbox holding as
// many knocks as the relay allows — is not waiting on a bucket at all
// but on its owner fetching, which the relay cannot time. Retrying that
// one spends the sender's own budget on an answer that will not change
// inside a minute and a half.
func retryable(e *HTTPError) bool {
	switch e.Status {
	case http.StatusServiceUnavailable:
		return true
	case http.StatusTooManyRequests:
		return e.RetryAfter > 0
	}
	return false
}

// maxRetryAfter clamps what a relay may ask for. The header is a number from
// the network: without a bound, seconds multiplied into a Duration overflows
// int64 and comes back negative, and even a value that fits is not a reason to
// wait a year.
const maxRetryAfter = 24 * time.Hour

// retryAfter reads the header the relay sends with a 429 or a 503. It is
// always an integer number of seconds; anything else is ignored rather than
// guessed at, and anything absurd is clamped rather than believed.
func retryAfter(h http.Header) time.Duration {
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || secs < 0 {
		return 0
	}
	// Clamped before the multiplication, which is where the overflow is.
	if secs > int64(maxRetryAfter/time.Second) {
		return maxRetryAfter
	}
	return time.Duration(secs) * time.Second
}

// retryWait is how long to wait before trying again.
func retryWait(e *HTTPError) time.Duration {
	d := e.RetryAfter
	if d <= 0 {
		d = minRetrySleep
	}
	return min(d, maxRetrySleep)
}

// do performs a signed request and decodes a JSON response into out, retrying
// while the relay says it is out of budget rather than out of order.
//
// Every attempt is signed afresh: the signature covers a nonce the relay spends
// once, so a replayed request would be refused as a replay.
func (c *Client) do(ctx context.Context, method, path string, payload any, out any, headers map[string]string) error {
	return c.doWithin(ctx, method, path, payload, out, headers, relayapi.DefaultMaxBytes*2)
}

// doWithin is do with the most of the answer's body the client will hold:
// every JSON answer but a listing page is small and reads under twice the
// default max_bytes as it always did; a listing page follows the relay's
// max_bytes and reads under listingCap.
func (c *Client) doWithin(ctx context.Context, method, path string, payload any, out any, headers map[string]string, hold int64) error {
	var body []byte
	if payload != nil {
		var err error
		if raw, ok := payload.([]byte); ok {
			body = raw
		} else if body, err = json.Marshal(payload); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		err := c.attempt(ctx, method, path, body, out, headers, hold)
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || !retryable(httpErr) || attempt >= maxRetries {
			return err
		}
		if httpErr.Status == http.StatusTooManyRequests && httpErr.Code == relayapi.CodeOverBudget {
			// The relay has said this request is refused for its size, not for
			// its timing. Sleeping through the remaining attempts would only
			// make the same answer take a minute and a half to arrive.
			return err
		}
		if httpErr.Code == relayapi.CodeCourierClock {
			// A neighbour holds this relay's clock to the minute and finds
			// it further out. A clock is not fixed by asking again within
			// the minute, so the courier's worker is told at once and waits
			// the Retry-After on the row, where the operator is told why.
			return err
		}
		if c.maxRetryWait > 0 && httpErr.RetryAfter > c.maxRetryWait {
			// The caller has said it would rather know now than wait this
			// long; what the relay asked for is on the error.
			return err
		}
		if sleepErr := c.sleep(ctx, retryWait(httpErr)); sleepErr != nil {
			return err
		}
	}
}

// readCapped reads an answer's body under the route's hold. A body that
// declares its length under the hold is read into a buffer of that length,
// so a page at the hold costs its own size and not the doublings io.ReadAll
// grows by (G4); one that declares more than the hold is refused before a
// byte of it is read (errDeclaredOver); and one that declares none, a
// chunked body, is read as before, hold plus one at most. net/http holds the
// body to the length it declared.
func readCapped(body io.Reader, declared, hold int64) ([]byte, error) {
	switch {
	case declared > hold:
		return nil, errDeclaredOver
	case declared >= 0:
		buf := make([]byte, declared)
		if _, err := io.ReadFull(body, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	return io.ReadAll(io.LimitReader(body, hold+1))
}

// errDeclaredOver is an answer whose Content-Length is over the route's
// hold, refused as one read over it.
var errDeclaredOver = errors.New("declared length over the hold")

// errOverHold marks a malformed-answer refusal made for the answer's size
// alone, so that a listing can tell a page over a hold it sized to a
// max_bytes the relay may since have raised from any other malformed
// answer.
var errOverHold = errors.New("answer over the hold")

// listingCap is the most the client holds of a listing page: twice the
// relay's max_bytes plus the framing allowance, up to MaxListingHold. The
// relay ends a page before an envelope that would take its inline bytes
// past max_bytes, or past MaxPageBytes on a relay of this release,
// admitting the first whatever its size, so a page's envelopes never
// exceed that unless the first alone does; in the answer they travel as
// the JSON they were posted as, so twice holds them with room for the
// rows around them. This holds the page for the relay the client talks to
// rather than for the ceiling, which is a gigabyte the client should
// never allocate, and never above MaxListingHold whatever the relay says.
// The relay's figure comes from its health answer, fetched once per
// Client on the first listing and kept; a page refused for its size asks
// once more, since an operator may have raised the setting under a client
// that runs for days, and grew reports whether the hold it sizes rose. A
// figure that fell is not taken: the hold only ever widens to what the
// relay says now.
func (c *Client) listingCap(ctx context.Context, again bool) (hold int64, grew bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maxBytes == 0 || again {
		var resp relayapi.HealthResponse
		if err := c.do(ctx, "GET", "/v1/health", nil, &resp, nil); err != nil {
			return 0, false, fmt.Errorf("asking the relay's max_bytes before a listing: %w", err)
		}
		if err := c.checkHealth(&resp); err != nil {
			return 0, false, err
		}
		before := holdFor(c.maxBytes)
		if resp.MaxBytes > c.maxBytes {
			c.maxBytes = resp.MaxBytes
		}
		grew = holdFor(c.maxBytes) > before
	}
	return holdFor(c.maxBytes), grew, nil
}

// holdFor is the listing hold for a relay's max_bytes: twice it plus the
// framing allowance, and never more than MaxListingHold, so a relay that
// says a gigabyte on its health answer cannot have a page of two read
// whole. maxBytes is held to [1, MaxBytesCeiling] by checkHealth, or is
// the zero no health answer has set, so the product does not overflow.
func holdFor(maxBytes int64) int64 {
	return min(2*maxBytes+relayapi.FramingAllowance, relayapi.MaxListingHold)
}

// verifiedRoute says whether the relay verifies a signature on this
// request. The client signs only those: a signature nobody verifies buys
// nothing, tells the relay's log who is asking on a route that did not
// need to know, and had to be admitted by the key agent's scope classifier
// as if it were something. The relay serves the health check to anybody
// and never reads the header on it (handleHealth); the key lookup is
// gated by the client certificate and the unauthenticated limiter and
// never reads the header either (handleKeys), so a signature there only
// put the looker-up's fingerprint in a full-mode access log on a route
// about somebody else; the trust anchor is fetched without an identity at
// all (FetchTrustAnchor); registration is verified, against the bundle in
// the body, and stays signed. Everything else the relay verifies.
func verifiedRoute(method, path string) bool {
	if method != "GET" {
		return true
	}
	return path != "/v1/health" && !strings.HasPrefix(path, "/v1/keys/")
}

// attempt is one request, signed where the relay verifies a signature.
func (c *Client) attempt(ctx context.Context, method, path string, body []byte, out any, headers map[string]string, hold int64) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.id != nil && verifiedRoute(method, path) {
		if err := relayapi.SignRequest(c.id, req, body); err != nil {
			return err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if pinnedHandshakeRefused(err) {
			return &NoPQTransportError{Err: err}
		}
		if responseHeadersTooLarge(err) {
			return c.malformed("the answer", "the headers", fmt.Sprintf("under %d bytes", relayapi.MaxHeaderBytes))
		}
		return c.diagnoseRefusal(ctx, fmt.Errorf("contacting relay: %w", err))
	}
	defer resp.Body.Close()

	// Cap the response: a hostile relay does not get to exhaust our memory,
	// and an answer over what this route holds is refused by name rather
	// than read short and failed as JSON.
	respBody, err := readCapped(resp.Body, resp.ContentLength, hold)
	if err != nil && !errors.Is(err, errDeclaredOver) {
		return fmt.Errorf("reading relay response: %w", err)
	}
	if errors.Is(err, errDeclaredOver) || int64(len(respBody)) > hold {
		return fmt.Errorf("%w: %w", errOverHold, c.malformed("the answer", "the body", fmt.Sprintf("under %d bytes, the most this route holds", hold)))
	}
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return c.redirected(method, path, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		he := httpError(resp, respBody)
		he.Relay = c.base
		return he
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	// Strictly (P1): a field the answer does not have is refused, so that
	// sections are the only place something new may go. The decoder's
	// words are escaped, since encoding/json names a map key the relay
	// chose in a type error.
	if err := wire.Decode(respBody, out); err != nil {
		return fmt.Errorf("%w: the relay at %s answered %s %s in a shape this build cannot read: %s",
			ErrMalformedAnswer, c.base, method, path, identity.PrintableText(err.Error()))
	}
	return c.checkSections(method, path, out)
}

// WireLevel is the relay's wire level as its last health answer said it
// (D40), zero before one has been read. A feature that depends on what a
// relay can do reads it; nothing in this release does.
func (c *Client) WireLevel() int { return int(c.wireLevel.Load()) }

// ChannelCeiling is the largest max_bytes a channel on the relay may name,
// as its last health answer said, or zero when that answer carried no
// channel-max-bytes section: the caller asks HealthInfo first.
func (c *Client) ChannelCeiling() int64 { return c.channelCeiling.Load() }

// RecipientCap is the most recipients the relay takes on a message to
// several: the number its health answer's max-recipients section gives, or
// relayapi.MaxRecipients from a relay whose answer carries none, which
// holds no setting of its own. The health answer is asked only when no
// health answer has been read yet; every later one this Client reads, for
// a listing or anything else, replaces the number with what the relay
// says then.
func (c *Client) RecipientCap(ctx context.Context) (int, error) {
	if n := c.maxRecipients.Load(); n > 0 {
		return int(n), nil
	}
	if _, err := c.HealthInfo(ctx); err != nil {
		return 0, fmt.Errorf("asking the relay's max_recipients: %w", err)
	}
	return int(c.maxRecipients.Load()), nil
}

// Health checks that the relay is reachable.
func (c *Client) Health(ctx context.Context) error {
	_, err := c.HealthInfo(ctx)
	return err
}

// HealthInfo is Health with the answer: the relay's max_bytes, its
// registration mode and the parameter set it wants of a client
// certificate, each held to its shape, since the answer is unsigned and
// unauthenticated and a relay's word all the same.
func (c *Client) HealthInfo(ctx context.Context) (*relayapi.HealthResponse, error) {
	var resp relayapi.HealthResponse
	if err := c.do(ctx, "GET", "/v1/health", nil, &resp, nil); err != nil {
		return nil, err
	}
	if err := c.checkHealth(&resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, errors.New("relay reported unhealthy")
	}
	return &resp, nil
}

// Register creates or updates this identity's mailbox on the relay.
//
// csr is this machine's certificate request. It carries the enrolment token,
// when one is needed, as a challengePassword: one signature over the key and
// the authorisation together, and the request around it is signed by the
// identity, so the relay learns that one holder has both.
//
// The returned certificate is present only when the relay issues them.
func (c *Client) Register(ctx context.Context, csr []byte) (*relayapi.RegisterResponse, error) {
	var resp relayapi.RegisterResponse
	req := relayapi.RegisterRequest{Bundle: c.id.Public().Bundle(), Name: c.id.Name, CSR: csr}
	if err := c.do(ctx, "POST", "/v1/register", req, &resp, nil); err != nil {
		return nil, err
	}
	if resp.FP != c.id.Fingerprint() {
		return nil, errors.New("relay registered a different fingerprint than ours")
	}
	return &resp, nil
}

// RenewCert asks for a fresh certificate for this identity.
//
// The request is authenticated by the certificate it arrives on and signed by
// the identity key, so it needs no token: both halves of what a token would
// have bought are already proved.
func (c *Client) RenewCert(ctx context.Context, csr []byte) (*relayapi.CertResponse, error) {
	var resp relayapi.CertResponse
	path := "/v1/mailbox/" + c.id.Fingerprint() + "/certs"
	if err := c.do(ctx, "POST", path, relayapi.CertRequest{CSR: csr}, &resp, nil); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Certs lists the certificates this identity holds on the relay.
func (c *Client) Certs(ctx context.Context) ([]relayapi.CertRecord, error) {
	var resp relayapi.CertsResponse
	path := "/v1/mailbox/" + c.id.Fingerprint() + "/certs"
	if err := c.do(ctx, "GET", path, nil, &resp, nil); err != nil {
		return nil, err
	}
	if err := c.checkCerts("this identity's certificate listing", resp.Certs, true); err != nil {
		return nil, err
	}
	return resp.Certs, nil
}

// MLDSA reports the ML-DSA parameter set the relay requires of a client
// certificate key — 44, 65 or 87 — so a machine generates the right one
// before it builds a request. A relay that does not say, because it issues no
// certificates or predates the field, gets the default; the relay refuses a
// key it does not want either way, so this is a hint and not a trust decision.
func (c *Client) MLDSA(ctx context.Context) (int, error) {
	var resp relayapi.HealthResponse
	if err := c.do(ctx, "GET", "/v1/health", nil, &resp, nil); err != nil {
		return 0, err
	}
	if err := c.checkHealth(&resp); err != nil {
		return 0, err
	}
	if resp.MLDSA == 0 {
		return clientca.DefaultMLDSA, nil
	}
	return resp.MLDSA, nil
}

// Lookup is what the relay knows about an identity: its keys, the name it
// registered under, and when.
type Lookup struct {
	Public *identity.Public
	// Registered is when the mailbox was created, as the relay said.
	Registered time.Time
}

// Lookup asks the relay about an identity, by a whole fingerprint or by the
// 16-character short id that listings print. The caller must still confirm
// the fingerprint with the human out of band before trusting any of it.
func (c *Client) Lookup(ctx context.Context, query string) (*Lookup, error) {
	if !identity.ValidFingerprint(query) && !identity.ValidShortID(query) {
		return nil, errors.New("look up a fingerprint of 64 lowercase hex characters, or a short id of 16")
	}
	var resp relayapi.KeysResponse
	if err := c.do(ctx, "GET", "/v1/keys/"+query, nil, &resp, nil); err != nil {
		return nil, err
	}
	if err := c.checkKeys(&resp); err != nil {
		return nil, err
	}
	pub, err := identity.ParseBundle(resp.Bundle)
	if err != nil {
		return nil, fmt.Errorf("relay returned a malformed bundle: %w", err)
	}
	// The relay does not get to decide who a fingerprint belongs to: the
	// bundle's own fingerprint must be the one asked for, or begin with it.
	if !strings.HasPrefix(pub.Fingerprint(), query) {
		return nil, errors.New("relay returned a bundle for a different fingerprint")
	}
	// The relay's word for the name, made printable before it reaches
	// anything that prints: a relay that is not ours could answer an
	// escape sequence, and the export line built from this is what the
	// person is shown to paste. A name that had to be escaped will not
	// parse as an export line, which is right: it was never a name.
	pub.Name = identity.Printable(resp.Name)
	return &Lookup{Public: pub, Registered: resp.Created}, nil
}

// FetchKey looks a bundle up on the relay by its whole fingerprint. The caller
// must still confirm the fingerprint with the human out of band before
// trusting it.
func (c *Client) FetchKey(ctx context.Context, fp string) (*identity.Public, error) {
	if !identity.ValidFingerprint(fp) {
		return nil, errors.New("fingerprint must be 64 lowercase hex characters")
	}
	found, err := c.Lookup(ctx, fp)
	if err != nil {
		return nil, err
	}
	return found.Public, nil
}

// SetDirectory pushes this mailbox's channel directory: the document bytes
// as signed and the signature over them. The relay verifies the pair
// against this identity's registered key and answers 409 when it holds a
// directory issued no earlier, which comes back as an HTTPError.
func (c *Client) SetDirectory(ctx context.Context, doc, sig []byte) error {
	body, err := documentBody("the directory", doc, relayapi.MaxDirectoryBytes,
		relayapi.ChannelsRequest{Document: doc, Signature: sig}, relayapi.MaxDocumentBytes)
	if err != nil {
		return err
	}
	return c.do(ctx, "PUT", "/v1/mailbox/"+c.id.Fingerprint()+"/channels", body, nil, nil)
}

// documentBody holds one of the three owner-signed documents to its own
// cap and then the request that carries it to the route's, before a byte
// goes on the wire, so that what a relay would refuse is refused here with
// the bytes and the cap in the sentence rather than after the upload.
//
// The two caps are different things and both are run. A document's cap —
// relayapi.MaxDirectoryBytes, MaxAllowlistBytes, MaxCardBytes — is the
// wire's rule about the bytes the owner signed, the same rule the relay
// runs at the push and at every reading of a stored document, and the same
// sentence, so that a caller who hands this client a document from
// somewhere else is told here rather than at the relay. The route's cap —
// relayapi.MaxDocumentBytes for the two large ones, FramingAllowance for
// the card — is about the envelope the document travels in, base64 and
// all. What runs over either is whitespace inside the signed document,
// which is the signer's encoder's, and the answer to both is to send it
// compact.
//
// With the document caps in place the second refusal cannot fire through
// the three calls here: a document at its own cap, carried base64 beside
// a signature, is well inside the route's cap — 699 KiB against 1 MiB for
// a directory, 175 KiB for an allow list, a kilobyte against 64 KiB for a
// card. It stays because the two caps are independent numbers that a
// later change may move apart, and this client must not send what the
// relay would refuse; TestLimitADocumentIsHeldToTheCapBeforeThePut pins
// the arithmetic so that a change to either number is seen here.
func documentBody(what string, doc []byte, docLimit int, req any, bodyLimit int) ([]byte, error) {
	if len(doc) > docLimit {
		return nil, fmt.Errorf("%s is %d bytes; at most %d, so send it compact; nothing was sent",
			what, len(doc), docLimit)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if len(body) > bodyLimit {
		return nil, fmt.Errorf("%s is %d bytes as sent, over the relay's cap of %d; nothing was sent",
			what, len(body), bodyLimit)
	}
	return body, nil
}

// DirectoryResult is a mailbox's channel directory as the relay serves it:
// the bytes the owner signed, to be verified against the key the caller
// holds for them, and never trusted before. Queued is filled only when the
// caller asked about its own mailbox. None means the relay has no directory
// for the mailbox, which has the one channel, default.
type DirectoryResult struct {
	Document  []byte
	Signature []byte
	Queued    map[string]int64
	None      bool
}

// Directory fetches a mailbox's channel directory. The relay answers 404
// both for a mailbox that is not there and for one with no directory; the
// two are told apart by the sentence, since only the second is an answer
// rather than an error.
func (c *Client) Directory(ctx context.Context, fp string) (*DirectoryResult, error) {
	var resp relayapi.ChannelsResponse
	err := c.do(ctx, "GET", "/v1/mailbox/"+fp+"/channels", nil, &resp, nil)
	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound &&
		httpErr.Code == relayapi.CodeNoDirectory {
		return &DirectoryResult{None: true}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := c.checkDirectory(&resp); err != nil {
		return nil, err
	}
	return &DirectoryResult{Document: resp.Document, Signature: resp.Signature, Queued: resp.Queued}, nil
}

// SetAllowlist replaces this mailbox's allow list on the relay: the
// document bytes as signed and the signature over them, which the relay
// verifies against this identity's registered key. A relay holding a list
// issued no earlier answers 409, which comes back as an HTTPError.
func (c *Client) SetAllowlist(ctx context.Context, doc, sig []byte) error {
	body, err := documentBody("the allow list", doc, relayapi.MaxAllowlistBytes,
		relayapi.AllowRequest{Document: doc, Signature: sig}, relayapi.MaxDocumentBytes)
	if err != nil {
		return err
	}
	return c.do(ctx, "PUT", "/v1/mailbox/"+c.id.Fingerprint()+"/allow", body, nil, nil)
}

// AllowlistResult is this mailbox's allow list as the relay serves it: the
// bytes this identity signed, to be verified with its own key and never
// trusted before, and the state the relay reads them as. None means the
// relay holds no list, and any registered sender may post.
type AllowlistResult struct {
	Document  []byte
	Signature []byte
	State     string
	None      bool
}

// Allowlist fetches this mailbox's allow list.
func (c *Client) Allowlist(ctx context.Context) (*AllowlistResult, error) {
	var resp relayapi.AllowResponse
	if err := c.do(ctx, "GET", "/v1/mailbox/"+c.id.Fingerprint()+"/allow", nil, &resp, nil); err != nil {
		return nil, err
	}
	return &AllowlistResult{Document: resp.Document, Signature: resp.Signature, State: resp.State,
		None: resp.State == relayapi.AllowNone}, nil
}

// SetCard replaces this mailbox's card on the relay: the document bytes
// as signed and the signature over them, which the relay verifies against
// this identity's registered key. A relay holding a card issued no earlier
// answers 409, which comes back as an HTTPError.
func (c *Client) SetCard(ctx context.Context, doc, sig []byte) error {
	body, err := documentBody("the card", doc, relayapi.MaxCardBytes,
		relayapi.CardRequest{Document: doc, Signature: sig}, relayapi.FramingAllowance)
	if err != nil {
		return err
	}
	return c.do(ctx, "PUT", "/v1/mailbox/"+c.id.Fingerprint()+"/card", body, nil, nil)
}

// CardResult is this mailbox's card as the relay serves it: the bytes this
// identity signed, to be verified with its own key and never trusted
// before, and the state the relay reads them as. None means the relay
// holds no card: the mailbox is not listed and takes no knocks.
type CardResult struct {
	Document  []byte
	Signature []byte
	State     string
	None      bool
}

// Card fetches this mailbox's card.
func (c *Client) Card(ctx context.Context) (*CardResult, error) {
	var resp relayapi.CardResponse
	if err := c.do(ctx, "GET", "/v1/mailbox/"+c.id.Fingerprint()+"/card", nil, &resp, nil); err != nil {
		return nil, err
	}
	if err := c.checkCard(&resp); err != nil {
		return nil, err
	}
	return &CardResult{Document: resp.Document, Signature: resp.Signature, State: resp.State,
		None: resp.State == relayapi.CardNone}, nil
}

// Post drops a sealed envelope into the recipient's mailbox, under a
// channel: the name goes on the outer envelope for the relay to route by,
// and empty means default and puts nothing on the wire. The sealed record
// inside must already carry the same name; this is the one place the outer
// field is set.
func (c *Client) Post(ctx context.Context, env *envelope.Envelope, channel string) (int64, error) {
	env.Ch = channel
	raw, err := json.Marshal(env)
	if err != nil {
		return 0, err
	}
	var resp relayapi.PostResponse
	if err := c.do(ctx, "POST", "/v1/mailbox/"+env.To, raw, &resp, nil); err != nil {
		return 0, err
	}
	if err := c.checkID("the post answer", resp.ID); err != nil {
		return 0, err
	}
	return resp.ID, nil
}

// Forward hands a sealed envelope to a relay for it to carry on towards a
// relay that is not this one.
//
// It is what a sender's client calls with a path a person wrote, and what a
// relay's own courier calls to pass an envelope to its neighbour; the request
// is the same either way, and which of the two the caller is is decided by
// the relay from the fingerprint that signed it, never by anything in the
// body. The envelope goes verbatim: these bytes are what every hop stores and
// forwards, so nothing here re-marshals it.
//
// A 409 means the relay has this envelope already, and what came with it
// says why: an id alone is a retry whose answer was lost, an id with a code
// is that retry to a row that has since ended, and nothing is a loop ending
// there. All three are on the error, as ForwardID, ForwardCode and
// ForwardSaid, for the caller to decide; a relay's worker decides as its
// classify says.
func (c *Client) Forward(ctx context.Context, req *relayapi.ForwardRequest) (int64, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return 0, err
	}
	var resp relayapi.ForwardResponse
	if err := c.do(ctx, "POST", "/v1/forward", raw, &resp, nil); err != nil {
		return 0, err
	}
	if err := c.checkID("the forward answer", resp.ID); err != nil {
		return 0, err
	}
	return resp.ID, nil
}

// Queue is the caller's own rows in this relay's forwarding queue: mail they
// addressed to somebody on another relay which this relay has taken and has
// still to hand over, has handed over, or has given up on.
//
// A relay that forwards nothing answers 403 with MsgForwardsNothing, which
// the caller reads as "there is nowhere for anything to wait here" rather
// than as an empty queue.
func (c *Client) Queue(ctx context.Context) ([]relayapi.QueuedMessage, error) {
	var resp relayapi.QueueResponse
	if err := c.do(ctx, "GET", "/v1/mailbox/"+c.id.Fingerprint()+"/queue", nil, &resp, nil); err != nil {
		return nil, err
	}
	if err := c.checkQueue(&resp); err != nil {
		return nil, err
	}
	return resp.Queued, nil
}

// Couriers is every relay this one accepts forwarded mail from, this relay's
// own name for each and the fingerprint its couriers file admits, in name
// order.
//
// It is what somebody needs in order to be reachable from another relay.
// Delivery of a forwarded message asks the recipient's allow list about the
// courier that handed the envelope over — a relay cannot open one, so the only
// sender it can prove is its neighbour — which means a recipient who has pushed
// a list at all must admit these fingerprints or be unreachable from off their
// own relay.
//
// The names are the relay's and mean nothing anywhere else: two relays may call
// the same neighbour different things, and what a neighbour calls itself is
// published nowhere. So a name from here is good for addressing mail through
// this relay and for nothing else.
//
// The answer is held to MaxCouriersBytes and to the same rules the relay ran
// over its own file: every name a relay name, every fingerprint a fingerprint,
// no name twice, no more entries than the file could have held.
func (c *Client) Couriers(ctx context.Context) ([]relayapi.Courier, error) {
	var resp relayapi.CouriersResponse
	if err := c.doWithin(ctx, "GET", "/v1/couriers", nil, &resp, nil, relayapi.MaxCouriersBytes); err != nil {
		return nil, err
	}
	if err := c.checkCouriers(&resp); err != nil {
		return nil, err
	}
	return resp.Couriers, nil
}

// ReportFailed tells a neighbour that a message it handed this relay cannot be
// delivered: the first control message, sent by a relay's courier and by
// nothing else.
//
// id is the id that neighbour answered with when it handed the envelope over,
// which is the one number both sides hold. A 404 means it holds no such row,
// a 409 that the row is not one it is waiting to hear about — either never
// handed or already told — and both are final: a report is taken once, and the
// caller writes a line rather than retrying.
func (c *Client) ReportFailed(ctx context.Context, id int64, code, said string) error {
	raw, err := json.Marshal(relayapi.ForwardFailedRequest{ID: id, Code: code, Said: said})
	if err != nil {
		return err
	}
	return c.do(ctx, "POST", "/v1/forward/failed", raw, nil, nil)
}

// Knock posts a sealed knock to the knock route of a mailbox whose owner
// has said, on their signed card, that they take them. It is the one post
// that goes to somebody who has not admitted the sender, so it has a
// route and a cap of its own, and the envelope names no channel: the
// relay files it under the default one.
//
// A 429 the relay sends without a Retry-After — the recipient holding as
// many knocks as the relay allows — is final here as everywhere: do does
// not retry it, and the caller says the sentence the relay gave.
func (c *Client) Knock(ctx context.Context, env *envelope.Envelope) (int64, error) {
	env.Ch = ""
	raw, err := json.Marshal(env)
	if err != nil {
		return 0, err
	}
	var resp relayapi.PostResponse
	if err := c.do(ctx, "POST", "/v1/mailbox/"+env.To+"/knock", raw, &resp, nil); err != nil {
		return 0, err
	}
	if err := c.checkID("the knock answer", resp.ID); err != nil {
		return 0, err
	}
	return resp.ID, nil
}

// EnvelopeSize reports the number of bytes an envelope occupies on the wire.
func EnvelopeSize(env *envelope.Envelope) (int, error) {
	raw, err := json.Marshal(env)
	if err != nil {
		return 0, err
	}
	return len(raw), nil
}

// Message is one envelope waiting on the relay.
//
// Envelope is nil when the relay returned bytes that are not a well formed
// envelope. Such a message can never be opened by anyone, so the caller should
// acknowledge it to clear the mailbox rather than leaving it queued forever.
type Message struct {
	ID       int64
	Received time.Time
	// Kind is relayapi.KindEnvelope or KindStream. A stream's body is not
	// here: it is fetched from its own endpoint, because it may be larger
	// than memory.
	Kind     string
	Size     int64
	Envelope *envelope.Envelope
	// Raw is the envelope as the relay served it, byte for byte, for a
	// receiver that keeps what it could not open. Nil for a stream.
	Raw []byte
	// Channel is the name the relay listed the message under, always
	// said: a listing whose row names none is refused before it is read.
	Channel string
	// Via is the relays this message came through before the one holding
	// it, nearest the sender first, joined by "!"; empty for mail posted
	// to that relay directly. Held to relay names and a hop count before
	// it is read, since it becomes the path of a reply.
	Via string
}

// IsStream reports whether this message must be fetched as a stream.
func (m Message) IsStream() bool { return m.Kind == relayapi.KindStream }

// Listing is one page of the mailbox and how many messages it holds in all.
type Listing struct {
	Messages []Message
	// Queued is the relay's count of everything in the mailbox, whatever
	// the page: an empty page beside a count above zero means the cursor
	// asked from is past mail. Zero from a relay that predates the field,
	// which is indistinguishable from an empty mailbox and is meant to be.
	Queued int64
	// First and Last are the lowest and highest ids the mailbox holds,
	// both zero for an empty mailbox, held to that shape: a cursor above
	// Last is past everything the relay holds.
	First, Last int64
	// DirectoriesChanged names the watched peers whose directory the relay
	// holds an issue of other than the request said. Empty when none has,
	// when nothing was watched, and from a relay that predates the field.
	DirectoriesChanged []string
	// Allow is the state of this mailbox's allow list as the relay holds
	// it, one of the relayapi.Allow* words, and empty from a relay that
	// predates signed lists, which is nothing to say.
	Allow string
	// Card is the state of this mailbox's card as the relay holds it, one
	// of the relayapi.Card* words, always sent.
	Card string
	// Directory is the state of this mailbox's channel directory as the
	// relay holds it, one of the relayapi.Directory* words, always sent.
	// A directory that does not verify refuses every named channel the
	// owner published, which is why the owner is told.
	Directory string
}

// ListRequest is what a listing asks for beyond the page.
type ListRequest struct {
	// After is the relay id to list from; Limit the most rows, at most
	// relayapi.MaxListLimit, the default when not positive.
	After int64
	Limit int
	// Wait asks the relay to hold the listing open until a message arrives
	// after After, or a watched directory is replaced, or Wait elapses.
	// Zero asks for no hold. Above relayapi.MaxWait it is clamped, here
	// as on the relay, so the request says what the relay will do. A relay
	// over its cap on holds answers at once, and nothing here can tell.
	Wait time.Duration
	// Peers names the peers whose channel directories to watch, by
	// fingerprint, each with the issue time of the directory held for
	// them: the relay wakes the hold when one is replaced and names in
	// DirectoriesChanged every peer whose directory is issued other than
	// that. A zero time is a peer with no directory held, and goes on the
	// wire as Unix zero, which every issue but Unix zero's differs from.
	Peers map[string]time.Time
	// Stubs asks for the rows without their envelopes, for a caller that
	// wants the ids and nothing else — checking which of the messages it
	// left on the relay are still queued. A listing asked for as stubs
	// whose row carries an envelope is refused by name.
	Stubs bool
}

// List fetches messages waiting after the given relay id, with the relay's
// count of everything in the mailbox. It asks for no hold.
func (c *Client) List(ctx context.Context, after int64, limit int) (Listing, error) {
	return c.ListWait(ctx, ListRequest{After: after, Limit: limit})
}

// ListWait is List with the hold and the watched peers. It derives no
// deadline of its own: the caller's context must outlive the hold, and the
// transport's per-request timeout (two minutes) already does.
func (c *Client) ListWait(ctx context.Context, req ListRequest) (Listing, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = relayapi.DefaultListLimit
	}
	var rest string
	if req.Wait > 0 {
		rest += "&wait=" + min(req.Wait, relayapi.MaxWait).String()
	}
	if req.Stubs {
		rest += "&stubs=1"
	}
	if len(req.Peers) > 0 {
		// Sorted, so the same watch is the same request: the signature
		// covers the query, and a map's order is nobody's.
		fps := make([]string, 0, len(req.Peers))
		for fp := range req.Peers {
			fps = append(fps, fp)
		}
		sort.Strings(fps)
		entries := make([]string, 0, len(fps))
		for _, fp := range fps {
			// UnixNano of the zero time is outside int64 and undefined;
			// no directory held is Unix zero.
			var nanos int64
			if issued := req.Peers[fp]; !issued.IsZero() {
				nanos = issued.UnixNano()
			}
			entries = append(entries, fp+":"+strconv.FormatInt(nanos, 10))
		}
		rest += "&peers=" + strings.Join(entries, ",")
	}
	pathFor := func(limit int) string {
		return "/v1/mailbox/" + c.id.Fingerprint() +
			"?after=" + strconv.FormatInt(req.After, 10) +
			"&limit=" + strconv.Itoa(limit) + rest
	}
	var resp relayapi.ListResponse
	hold, _, err := c.listingCap(ctx, false)
	if err != nil {
		return Listing{}, err
	}
	err = c.doWithin(ctx, "GET", pathFor(limit), nil, &resp, nil, hold)
	if errors.Is(err, errOverHold) {
		// A page over the hold this client sized to the relay's max_bytes
		// as it learned it. The relay's setting may have been raised
		// since: ask once more, and take the page under the new hold
		// when the figure grew.
		wider, grew, herr := c.listingCap(ctx, true)
		if herr == nil && grew {
			hold = wider
			err = c.doWithin(ctx, "GET", pathFor(limit), nil, &resp, nil, hold)
		}
	}
	// A page over a hold already at MaxListingHold is one a relay built
	// past it: a relay before this release fills a page to its whole
	// max_bytes, which may be a gigabyte, where an upgraded one stops at
	// MaxPageBytes. Fewer rows make a smaller page, so the same page is
	// asked for again with the limit halved, the same after and the same
	// stubs, down to one row; there the refusal stands, since a lone row
	// over the hold is over it whatever the page. The limit is taken from
	// no more than MaxListLimit, the most a relay lists, so from 200 that
	// is seven asks more at the most: 100, 50, 25, 12, 6, 3 and 1.
	for errors.Is(err, errOverHold) && hold == relayapi.MaxListingHold && limit > 1 {
		limit = min(limit, relayapi.MaxListLimit) / 2
		resp = relayapi.ListResponse{}
		err = c.doWithin(ctx, "GET", pathFor(limit), nil, &resp, nil, hold)
	}
	if err != nil {
		return Listing{}, err
	}
	// A page holds no more rows than were asked for, the limit as the
	// halving left it and never past MaxListLimit (G15): the listing hold
	// bounds a page's bytes and commit 4's cap a fetch's pages, and this
	// bounds the rows taken from one, before any of them is.
	if asked := min(limit, relayapi.MaxListLimit); len(resp.Messages) > asked {
		return Listing{}, c.malformed("the listing", "the count of its messages",
			fmt.Sprintf("at most %d, the limit asked for (%d listed)", asked, len(resp.Messages)))
	}
	if err := c.checkListing(&resp, req.After, req.Stubs); err != nil {
		return Listing{}, err
	}
	out := make([]Message, 0, len(resp.Messages))
	for _, m := range resp.Messages {
		msg := Message{ID: m.ID, Received: m.Received, Kind: m.Kind, Size: m.Size,
			Channel: m.Channel, Via: m.Via}
		if m.Kind != relayapi.KindStream {
			msg.Raw = []byte(m.Envelope)
			var env envelope.Envelope
			if err := json.Unmarshal(m.Envelope, &env); err == nil {
				msg.Envelope = &env
			}
		}
		out = append(out, msg)
	}
	return Listing{Messages: out, Queued: resp.Queued, First: *resp.First, Last: *resp.Last,
		DirectoriesChanged: resp.DirectoriesChanged,
		Allow:              resp.Allow, Card: resp.Card, Directory: resp.Directory}, nil
}

// Ack deletes a message from the relay once it is safely on disk locally.
func (c *Client) Ack(ctx context.Context, id int64) error {
	err := c.do(ctx, "DELETE", "/v1/mailbox/"+c.id.Fingerprint()+"/"+strconv.FormatInt(id, 10), nil, nil, nil)
	var httpErr *HTTPError
	// Already gone is the state we wanted.
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound {
		return nil
	}
	return err
}
