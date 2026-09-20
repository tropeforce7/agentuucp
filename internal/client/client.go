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
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
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
	// relay's own stall deadline; tests set it short.
	stall time.Duration
	// maxBytes is the relay's max_bytes as its health answer said it,
	// fetched once on the first listing and kept: what a listing page is
	// sized to, and so what the client will hold of one. Zero until then.
	maxBytes int64
	mu       sync.Mutex
	// transport is the one carrying the client certificate, kept so a
	// renewal can drop the connections using the old one.
	transport *http.Transport
	// certless reaches the same relay the same way, offering nothing. It is
	// nil unless this machine holds a certificate, and it exists to answer
	// one question: see diagnoseRefusal.
	certless *http.Client
	// sleep waits between retries. Tests replace it so they need not wait.
	sleep func(context.Context, time.Duration) error
}

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
	httpClient := &http.Client{Timeout: 2 * time.Minute, Transport: transport}
	c := &Client{
		base:      strings.TrimSuffix(base, "/"),
		id:        id,
		http:      httpClient,
		stream:    &http.Client{Transport: transport},
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
		c.certless = &http.Client{Transport: probe, Timeout: 2 * time.Minute}
	}
	return c, nil
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
func boundTransport(t *http.Transport) {
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
}

// httpError is the one place an HTTPError is made from a relay's answer.
// The relay's sentence goes through identity.PrintableText here, at
// construction, so no caller can print it unescaped: a relay is in the
// client's model as something that may be hostile, and its refusal is the
// one thing from it that reached every terminal as it came. Printable
// ASCII is unchanged, so a caller that looks for a known sentence in the
// message still finds it.
func httpError(resp *http.Response, body []byte) *HTTPError {
	var e relayapi.ErrorResponse
	_ = json.Unmarshal(body, &e)
	return &HTTPError{
		Status:     resp.StatusCode,
		Message:    identity.PrintableText(e.Error),
		RetryAfter: retryAfter(resp.Header),
	}
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
func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
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
		if !errors.As(err, &httpErr) || !retryable(httpErr.Status) || attempt >= maxRetries {
			return err
		}
		if strings.Contains(httpErr.Message, relayapi.MsgWaitingWillNotHelp) {
			// The relay has said this request is refused for its size, not for
			// its timing. Sleeping through the remaining attempts would only
			// make the same answer take a minute and a half to arrive.
			return err
		}
		if sleepErr := c.sleep(ctx, retryWait(httpErr)); sleepErr != nil {
			return err
		}
	}
}

// listingCap is the most the client holds of a listing page: twice the
// relay's max_bytes plus the framing allowance. The relay ends a page
// before an envelope that would take its inline bytes past max_bytes,
// admitting the first whatever its size, so a page's envelopes never
// exceed max_bytes unless the first alone does, which only one posted
// under a larger earlier max_bytes can; in the answer they travel as
// base64, four thirds of their bytes, under twice. This holds the page
// for the relay the client talks to rather than for the ceiling, which
// is a gigabyte the client should never allocate. The relay's figure
// comes from its health answer, fetched once per Client on the first
// listing and kept.
func (c *Client) listingCap(ctx context.Context) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maxBytes == 0 {
		var resp relayapi.HealthResponse
		if err := c.do(ctx, "GET", "/v1/health", nil, &resp, nil); err != nil {
			return 0, fmt.Errorf("asking the relay's max_bytes before a listing: %w", err)
		}
		if err := c.checkHealth(&resp); err != nil {
			return 0, err
		}
		c.maxBytes = resp.MaxBytes
	}
	return 2*c.maxBytes + relayapi.FramingAllowance, nil
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
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, hold+1))
	if err != nil {
		return fmt.Errorf("reading relay response: %w", err)
	}
	if int64(len(respBody)) > hold {
		return c.malformed("the answer", "the body", fmt.Sprintf("under %d bytes, the most this route holds", hold))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return httpError(resp, respBody)
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	return json.Unmarshal(respBody, out)
}

// Health checks that the relay is reachable.
func (c *Client) Health(ctx context.Context) error {
	var resp relayapi.HealthResponse
	if err := c.do(ctx, "GET", "/v1/health", nil, &resp, nil); err != nil {
		return err
	}
	if err := c.checkHealth(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return errors.New("relay reported unhealthy")
	}
	return nil
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
	body, err := documentBody("the directory", relayapi.ChannelsRequest{Document: doc, Signature: sig})
	if err != nil {
		return err
	}
	return c.do(ctx, "PUT", "/v1/mailbox/"+c.id.Fingerprint()+"/channels", body, nil, nil)
}

// documentBody marshals one of the two owner-signed documents' requests
// and holds it to relayapi.MaxDocumentBytes, the relay's cap on the
// route, before a byte goes on the wire: a document over it is refused
// here with the bytes and the cap in the sentence rather than 413 by the
// relay after the upload. The cap holds either document at every
// maximum as this client marshals it; what runs over it is whitespace
// inside the signed document, which is the signer's encoder's.
func documentBody(what string, req any) ([]byte, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if len(body) > relayapi.MaxDocumentBytes {
		return nil, fmt.Errorf("%s is %d bytes as sent, over the relay's cap of %d; nothing was sent",
			what, len(body), relayapi.MaxDocumentBytes)
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
		httpErr.Message == relayapi.MsgNoDirectory {
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
	body, err := documentBody("the allow list", relayapi.AllowRequest{Document: doc, Signature: sig})
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
	// DirectoriesChanged names the watched peers whose directory the relay
	// holds a newer issue of than the request said. Empty when none has,
	// when nothing was watched, and from a relay that predates the field.
	DirectoriesChanged []string
	// Allow is the state of this mailbox's allow list as the relay holds
	// it, one of the relayapi.Allow* words, and empty from a relay that
	// predates signed lists, which is nothing to say.
	Allow string
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
	// DirectoriesChanged every peer whose directory is issued later. A
	// zero time is a peer with no directory held, and goes on the wire
	// as Unix zero, which every issue is after.
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
	path := "/v1/mailbox/" + c.id.Fingerprint() +
		"?after=" + strconv.FormatInt(req.After, 10) +
		"&limit=" + strconv.Itoa(limit)
	if req.Wait > 0 {
		path += "&wait=" + min(req.Wait, relayapi.MaxWait).String()
	}
	if req.Stubs {
		path += "&stubs=1"
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
		path += "&peers=" + strings.Join(entries, ",")
	}
	var resp relayapi.ListResponse
	hold, err := c.listingCap(ctx)
	if err != nil {
		return Listing{}, err
	}
	if err := c.doWithin(ctx, "GET", path, nil, &resp, nil, hold); err != nil {
		return Listing{}, err
	}
	if err := c.checkListing(&resp, req.Stubs); err != nil {
		return Listing{}, err
	}
	out := make([]Message, 0, len(resp.Messages))
	for _, m := range resp.Messages {
		msg := Message{ID: m.ID, Received: m.Received, Kind: m.Kind, Size: m.Size, Channel: m.Channel}
		if m.Kind != relayapi.KindStream {
			msg.Raw = []byte(m.Envelope)
			var env envelope.Envelope
			if err := json.Unmarshal(m.Envelope, &env); err == nil {
				msg.Envelope = &env
			}
		}
		out = append(out, msg)
	}
	return Listing{Messages: out, Queued: resp.Queued, DirectoriesChanged: resp.DirectoriesChanged, Allow: resp.Allow}, nil
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
