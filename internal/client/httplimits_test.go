package client

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/tls"
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

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestTheClientSpeaksHTTP11Alone: the client's transports pin HTTP/1.1.
// transportFor cloned http.DefaultTransport, whose ForceAttemptHTTP2 is
// true, so every deployed exchange was HTTP/2 while every test in the tree
// ran HTTP/1.1; now ForceAttemptHTTP2 is off and the TLS config offers
// http/1.1 alone by ALPN, so a relay that offers h2 — as the relay did
// until this plan's first commit, and as a terminator might — is answered
// over HTTP/1.1 at both ends. The transport carries the wire's caps too:
// a response's headers at relayapi.MaxHeaderBytes and the wait for a
// response's headers at MaxWait plus thirty seconds, longer than the hold
// a watcher asks a listing to be kept for.
func TestTheClientSpeaksHTTP11Alone(t *testing.T) {
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	server, err := clientca.NewServer(bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216,"knock_max_bytes":16777216,"registration":"open","wire_level":1}`))
	}))
	// The server offers h2 first and serves it when negotiated (EnableHTTP2
	// installs the handler); a client offering http/1.1 alone is answered
	// over HTTP/1.1 with that negotiated. (Offering h2 alone would show
	// less: crypto/tls lets an http/1.1-only client through an h2-only
	// server with no protocol negotiated, as a fallback.)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	if got := srv.TLS.NextProtos; len(got) != 2 || got[0] != "h2" {
		t.Fatalf("the test's server offers %v; want h2 first, to show the client declining it", got)
	}

	c, err := NewWithAnchor(srv.URL, testIdentity(t, "alice"), nil, &Anchor{Cert: bundle.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range []*http.Transport{c.transport, c.stream.Transport.(*http.Transport)} {
		if tr.ForceAttemptHTTP2 {
			t.Error("the transport forces h2")
		}
		if got := tr.TLSClientConfig.NextProtos; len(got) != 1 || got[0] != "http/1.1" {
			t.Errorf("the transport offers %v by ALPN; want http/1.1 alone", got)
		}
		if tr.MaxResponseHeaderBytes != relayapi.MaxHeaderBytes {
			t.Errorf("MaxResponseHeaderBytes is %d, want relayapi.MaxHeaderBytes %d", tr.MaxResponseHeaderBytes, relayapi.MaxHeaderBytes)
		}
		if tr.ResponseHeaderTimeout != relayapi.MaxWait+30*time.Second {
			t.Errorf("ResponseHeaderTimeout is %s, want MaxWait + 30 s", tr.ResponseHeaderTimeout)
		}
	}
	if c.stream.Timeout != 0 {
		t.Errorf("the stream client has a whole-exchange timeout of %s; want none", c.stream.Timeout)
	}
	resp, err := c.http.Get(srv.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Proto != "HTTP/1.1" || resp.Header.Get("X-Proto") != "HTTP/1.1" || resp.TLS.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("against a server offering h2 the client got %s (server saw %s, ALPN %q); want HTTP/1.1 at both ends",
			resp.Proto, resp.Header.Get("X-Proto"), resp.TLS.NegotiatedProtocol)
	}
	if err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestLimitResponseHeadersAreCapped: a relay's answer whose headers run
// past relayapi.MaxHeaderBytes is refused by the transport, and the client
// says so as the malformed answer it is, naming the relay and the cap;
// headers at the cap are taken. The transport's edge is its own: the
// header block is read through the transport's buffer, so a block at the
// cap is taken, and one of twice the cap refused (the exact byte at which
// Go's transport counts the block past the cap is not this test's claim;
// the relay never sends more than a few hundred bytes of headers).
func TestLimitResponseHeadersAreCapped(t *testing.T) {
	var junk atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := junk.Load(); n > 0 {
			w.Header().Set("X-Junk", strings.Repeat("j", int(n)))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216,"knock_max_bytes":16777216,"registration":"open","wire_level":1}`))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	junk.Store(relayapi.MaxHeaderBytes - 1024)
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("headers of about the cap: %v; want them taken", err)
	}
	junk.Store(2 * relayapi.MaxHeaderBytes)
	err = c.Health(context.Background())
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), srv.URL) ||
		!strings.Contains(err.Error(), fmt.Sprintf("under %d bytes", relayapi.MaxHeaderBytes)) {
		t.Fatalf("headers of twice the cap: %v; want the malformed answer naming the relay and the cap", err)
	}
}

// TestLimitAnAnswerIsHeldToWhatItsRouteHolds: every JSON answer is read
// under its route's hold, at the hold taken and one byte over refused as
// a malformed answer naming the hold rather than read short and failed
// as JSON. A listing page follows the relay's max_bytes, so the client
// sizes what it holds of one to that relay — twice max_bytes plus the
// framing allowance — learning max_bytes from the health answer once per
// Client on the first listing; a page of the card listing is held to
// relayapi.MaxListedBytes, sized to its hundred entries and shown by
// TestLimitAListingPageIsHeldToItsBytes; every other answer keeps the
// fixed hold of twice the default max_bytes, since none scales with
// max_bytes, shown on the health answer itself.
func TestLimitAnAnswerIsHeldToWhatItsRouteHolds(t *testing.T) {
	const maxBytes = 100 << 10
	var page atomic.Int64
	var healths atomic.Int64
	var healthSize atomic.Int64 // when set, the health answer is padded to this many bytes
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			healths.Add(1)
			if n := healthSize.Load(); n > 0 {
				w.Write(paddedJSON(fmt.Sprintf(`{"ok":true,"max_bytes":%d,"knock_max_bytes":16777216,"registration":"open","wire_level":1`, maxBytes), n))
				return
			}
			json.NewEncoder(w).Encode(relayapi.HealthResponse{OK: true, MaxBytes: maxBytes, KnockMaxBytes: relayapi.DefaultMaxBytes, Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel})
			return
		}
		// A listing of one envelope whose ct is page bytes of base64.
		json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{"id": 1, "received": "2026-09-20T00:00:00Z", "kind": "envelope",
				"size": page.Load(), "channel": "default", "envelope": map[string]any{"v": 1, "to": "x", "ct": strings.Repeat("A", int(page.Load()))}}},
			"queued": 1, "first": 1, "last": 1,
			"allow": "none", "card": "none", "directory": "none",
		})
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	hold := int64(2*maxBytes + relayapi.FramingAllowance)
	page.Store(hold - 250) // the answer's fields and the envelope's framing are under 250 bytes
	if _, err := c.List(context.Background(), 0, 10); err != nil {
		t.Fatalf("a page under the cap: %v; want it taken", err)
	}
	if _, err := c.List(context.Background(), 0, 10); err != nil {
		t.Fatal(err)
	}
	if n := healths.Load(); n != 1 {
		t.Fatalf("the relay's max_bytes was asked %d times over two listings; want once", n)
	}
	page.Store(hold + 1)
	_, err = c.List(context.Background(), 0, 10)
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), fmt.Sprintf("under %d bytes", hold)) {
		t.Fatalf("a page over the cap: %v; want the malformed answer naming the cap of %d", err, hold)
	}
	// A page refused for its size asks the relay's max_bytes once more,
	// in case it was raised; it was not, and the refusal stands.
	if n := healths.Load(); n != 2 {
		t.Fatalf("the relay's max_bytes was asked %d times after a page over the cap; want once more, 2", n)
	}

	// The fixed hold, on the health answer: at it, taken; one over, refused.
	fixed := int64(2 * relayapi.DefaultMaxBytes)
	healthSize.Store(fixed)
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("a health answer at the fixed hold of %d: %v; want it taken", fixed, err)
	}
	healthSize.Store(fixed + 1)
	err = c.Health(context.Background())
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), fmt.Sprintf("under %d bytes", fixed)) {
		t.Fatalf("a health answer one over the fixed hold: %v; want the malformed answer naming the hold of %d", err, fixed)
	}
}

// TestARaisedMaxBytesIsLearnedWhenAPageIsRefusedForItsSize: a client
// learns the relay's max_bytes once and holds it; an operator who raises
// the setting under a client that runs for days would otherwise leave it
// refusing every page the relay now builds larger, and a watch ending on
// a malformed answer. So a page refused for its size asks health once
// more: when the figure grew, the page is taken under the new hold; when
// it did not, or when the page is over the new hold too, the refusal
// stands. The health is asked once per refusal and never otherwise.
func TestARaisedMaxBytesIsLearnedWhenAPageIsRefusedForItsSize(t *testing.T) {
	var maxBytes atomic.Int64
	maxBytes.Store(100 << 10)
	var page, healths, listings atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			healths.Add(1)
			json.NewEncoder(w).Encode(relayapi.HealthResponse{OK: true, MaxBytes: maxBytes.Load(), KnockMaxBytes: relayapi.DefaultMaxBytes, Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel})
			return
		}
		listings.Add(1)
		json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{"id": 1, "received": "2026-09-20T00:00:00Z", "kind": "envelope",
				"size": page.Load(), "channel": "default", "envelope": map[string]any{"v": 1, "to": "x", "ct": strings.Repeat("A", int(page.Load()))}}},
			"queued": 1, "first": 1, "last": 1,
			"allow": "none", "card": "none", "directory": "none",
		})
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	holdFor := func(m int64) int64 { return 2*m + relayapi.FramingAllowance }
	old := holdFor(100 << 10)
	page.Store(old - 250) // the answer's fields and the envelope's framing
	if _, err := c.List(context.Background(), 0, 10); err != nil {
		t.Fatalf("a page under the hold: %v", err)
	}
	if healths.Load() != 1 || listings.Load() != 1 {
		t.Fatalf("healths %d, listings %d after one page; want 1 and 1", healths.Load(), listings.Load())
	}

	// The operator raises max_bytes and the relay builds a larger page:
	// refused under the old hold, health asked once more, the figure
	// grew, the page taken under the new hold, all in one List.
	maxBytes.Store(200 << 10)
	page.Store(old + 1)
	if _, err := c.List(context.Background(), 0, 10); err != nil {
		t.Fatalf("a page over the old hold after max_bytes was raised: %v; want it taken under the new", err)
	}
	if healths.Load() != 2 || listings.Load() != 3 {
		t.Fatalf("healths %d, listings %d; want 2 (asked once more) and 3 (the refused page and the retry)", healths.Load(), listings.Load())
	}
	// The new figure is kept: the next page of that size needs no asking.
	if _, err := c.List(context.Background(), 0, 10); err != nil {
		t.Fatal(err)
	}
	if healths.Load() != 2 || listings.Load() != 4 {
		t.Fatalf("healths %d, listings %d; want 2 and 4", healths.Load(), listings.Load())
	}

	// A page over the new hold too: health asked once more, the figure
	// did not grow, the refusal stands naming the new hold, and the
	// listing is not tried again.
	now := holdFor(200 << 10)
	page.Store(now + 1)
	_, err = c.List(context.Background(), 0, 10)
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), fmt.Sprintf("under %d bytes", now)) {
		t.Fatalf("a page over the new hold: %v; want the malformed answer naming %d", err, now)
	}
	if healths.Load() != 3 || listings.Load() != 5 {
		t.Fatalf("healths %d, listings %d; want 3 and 5", healths.Load(), listings.Load())
	}
	// A figure that fell is not taken: a page over the hold asks once
	// more, the relay now says less, and the refusal names the hold as it
	// grew to, not the smaller figure.
	maxBytes.Store(50 << 10)
	_, err = c.List(context.Background(), 0, 10)
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), fmt.Sprintf("under %d bytes", now)) {
		t.Fatalf("a page over the hold after the relay's figure fell: %v; want the refusal naming %d, the hold as learned", err, now)
	}
	if healths.Load() != 4 || listings.Load() != 6 {
		t.Fatalf("healths %d, listings %d; want 4 and 6", healths.Load(), listings.Load())
	}
}

// paddedJSON is an answer of exactly n bytes: head, an object left open,
// then spaces and the closing brace. The padding is white space, which JSON
// allows between any two tokens and a strict decode takes, rather than a
// field: a field the answer does not have is refused now (P1), and a
// section, the one place something new may go, is held to 16 KiB (R4),
// far under the holds these tests reach.
func paddedJSON(head string, n int64) []byte {
	pad := int(n) - len(head) - 1
	if pad < 0 {
		panic(fmt.Sprintf("paddedJSON: %d bytes is under the head", n))
	}
	return []byte(head + strings.Repeat(" ", pad) + "}")
}

// TestLimitAStreamAnswerIsHeldTo64KiB: the two stream routes' answers —
// the placed stream's id from a PUT, and an error's sentence from a blob
// GET — are read under streamAnswerHold, at it taken and one byte over
// refused as a malformed answer naming the hold, the same rule as every
// other answer's and not a cut that fails later as JSON.
func TestLimitAStreamAnswerIsHeldTo64KiB(t *testing.T) {
	var size atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "PUT":
			w.WriteHeader(http.StatusCreated)
			w.Write(paddedJSON(`{"id":7`, size.Load()))
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/blob"):
			w.WriteHeader(http.StatusNotFound)
			w.Write(paddedJSON(`{"error":"no such message"`, size.Load()))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	fp := strings.Repeat("a", 64)
	upload := strings.Repeat("b", 32)
	body := func() io.Reader { return bytes.NewReader([]byte("sealed")) }

	size.Store(streamAnswerHold)
	if id, err := c.PutStream(context.Background(), upload, 0, body(), 6); err != nil || id != 7 {
		t.Fatalf("a PUT answer at the hold: id %d, %v; want 7 and no error", id, err)
	}
	rc, _, err := c.Blob(context.Background(), fp, 7, 0, -1)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusNotFound || httpErr.Message != "no such message" {
		t.Fatalf("a blob error at the hold: %v; want the 404 with its sentence", err)
	}
	if rc != nil {
		rc.Close()
	}

	size.Store(streamAnswerHold + 1)
	want := fmt.Sprintf("under %d bytes, the most this route holds", streamAnswerHold)
	_, err = c.PutStream(context.Background(), upload, 0, body(), 6)
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
		t.Fatalf("a PUT answer one over the hold: %v; want the malformed answer saying %q", err, want)
	}
	rc, _, err = c.Blob(context.Background(), fp, 7, 0, -1)
	if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
		t.Fatalf("a blob error one over the hold: %v; want the malformed answer saying %q", err, want)
	}
	if rc != nil {
		rc.Close()
	}
}

// TestLimitADocumentIsHeldToTheCapBeforeThePut: the client holds the three
// owner-signed documents to two caps before a byte goes on the wire: the
// document's own — MaxDirectoryBytes, MaxAllowlistBytes, MaxCardBytes —
// and then its route's, MaxDocumentBytes for the two large ones and
// FramingAllowance for the card. A directory and an allow list at every
// maximum, marshalled as the client marshals them, and a card at its own
// are sent, and each is measured against its own cap here so that a
// remeasurement is due the moment one of them grows; a document one byte
// over its cap is refused with the bytes and the cap in the sentence and
// the relay sees nothing of it. The two caps' order is pinned as well: a
// document at its own cap still fits in a request its route admits, so
// the second refusal cannot fire through these three calls.
func TestLimitADocumentIsHeldToTheCapBeforeThePut(t *testing.T) {
	var puts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			puts.Add(1)
			io.Copy(io.Discard, r.Body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	owner := testIdentity(t, "alice")
	c, err := New(srv.URL, owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)

	var chs []channels.Channel
	for i := 0; i < relayapi.MaxChannels; i++ {
		nb, na := at, at.Add(time.Hour)
		chs = append(chs, channels.Channel{
			Name:        strings.Repeat("&", relayapi.MaxChannelNameBytes-2) + fmt.Sprintf("%02d", i),
			Description: strings.Repeat("<", relayapi.MaxChannelDescriptionBytes),
			NotBefore:   &nb, NotAfter: &na,
		})
	}
	full := &channels.Directory{Issued: at, Channels: chs}
	doc, sig, err := channels.Sign(owner, full)
	if err != nil {
		t.Fatal(err)
	}
	if wire, _ := json.Marshal(relayapi.ChannelsRequest{Document: doc, Signature: sig}); len(wire) < 500_000 || len(wire) > relayapi.MaxDocumentBytes {
		t.Fatalf("the full directory is %d bytes on the wire; want between 500,000 and the cap", len(wire))
	}
	// The document itself against its own cap, and the claim
	// MaxDirectoryBytes's comment makes about the room above the
	// measurement: that the same document indented still fits, since the
	// bytes are the signer's encoder's and another client may indent. If
	// either fails the measurement is stale and the cap would refuse what
	// this client, or a wider one, signed.
	indented, _ := json.MarshalIndent(full, "", "    ")
	if len(doc) >= relayapi.MaxDirectoryBytes || len(indented) >= relayapi.MaxDirectoryBytes {
		t.Fatalf("a directory at every maximum is %d bytes compact and %d indented, against a cap of %d: remeasure",
			len(doc), len(indented), relayapi.MaxDirectoryBytes)
	}
	if err := c.SetDirectory(context.Background(), doc, sig); err != nil {
		t.Fatalf("a directory at every maximum: %v; want it sent", err)
	}
	senders := make([]string, 0, relayapi.MaxAllowlist)
	for i := 0; i < relayapi.MaxAllowlist; i++ {
		senders = append(senders, fmt.Sprintf("%064x", i+1))
	}
	fullList := &allowlist.Document{Issued: at, Senders: senders}
	adoc, asig, err := allowlist.Sign(owner, fullList)
	if err != nil {
		t.Fatal(err)
	}
	aIndented, _ := json.MarshalIndent(fullList, "", "    ")
	if len(adoc) >= relayapi.MaxAllowlistBytes || len(aIndented) >= relayapi.MaxAllowlistBytes {
		t.Fatalf("an allow list at every maximum is %d bytes compact and %d indented, against a cap of %d: remeasure",
			len(adoc), len(aIndented), relayapi.MaxAllowlistBytes)
	}
	if err := c.SetAllowlist(context.Background(), adoc, asig); err != nil {
		t.Fatalf("an allow list at every maximum: %v; want it sent", err)
	}
	cdoc, csig, err := card.Sign(owner, &card.Document{Issued: at, Name: strings.Repeat("a", identity.MaxNameBytes), Listed: true, Knocks: true})
	if err != nil {
		t.Fatal(err)
	}
	if wire, _ := json.Marshal(relayapi.CardRequest{Document: cdoc, Signature: csig}); len(wire) < 300 || len(wire) > relayapi.FramingAllowance {
		t.Fatalf("the full card is %d bytes on the wire; want between 300 and the general cap", len(wire))
	}
	if err := c.SetCard(context.Background(), cdoc, csig); err != nil {
		t.Fatalf("a card at its maximum: %v; want it sent", err)
	}
	if n := puts.Load(); n != 3 {
		t.Fatalf("the relay saw %d PUTs, want 3", n)
	}

	// One byte over the document's own cap: the bytes are the signer's,
	// so a document the cap does not hold is made by size alone, and the
	// refusal is the one the relay would give, before a request.
	over := func(t *testing.T, name string, limit int, send func(doc []byte) error) {
		t.Helper()
		before := puts.Load()
		err := send(bytes.Repeat([]byte("d"), limit+1))
		want := fmt.Sprintf("%s is %d bytes; at most %d, so send it compact; nothing was sent", name, limit+1, limit)
		if err == nil || err.Error() != want {
			t.Fatalf("%s one byte over its cap: %v; want %q", name, err, want)
		}
		if puts.Load() != before {
			t.Fatalf("%s over its cap reached the relay", name)
		}
	}
	over(t, "the directory", relayapi.MaxDirectoryBytes, func(d []byte) error { return c.SetDirectory(context.Background(), d, []byte("s")) })
	over(t, "the allow list", relayapi.MaxAllowlistBytes, func(d []byte) error { return c.SetAllowlist(context.Background(), d, []byte("s")) })
	over(t, "the card", relayapi.MaxCardBytes, func(d []byte) error { return c.SetCard(context.Background(), d, []byte("s")) })

	// The two caps in their order: a document at its own cap always fits
	// in a request the route's cap admits, which is what documentBody's
	// comment claims and why its second refusal cannot fire through these
	// three calls. Measured on the request this client builds, since the
	// document travels base64-encoded beside its signature.
	for _, tc := range []struct {
		name          string
		docCap, route int
		req           func(doc, sig []byte) any
	}{
		{"the directory", relayapi.MaxDirectoryBytes, relayapi.MaxDocumentBytes,
			func(d, s []byte) any { return relayapi.ChannelsRequest{Document: d, Signature: s} }},
		{"the allow list", relayapi.MaxAllowlistBytes, relayapi.MaxDocumentBytes,
			func(d, s []byte) any { return relayapi.AllowRequest{Document: d, Signature: s} }},
		{"the card", relayapi.MaxCardBytes, relayapi.FramingAllowance,
			func(d, s []byte) any { return relayapi.CardRequest{Document: d, Signature: s} }},
	} {
		wire, _ := json.Marshal(tc.req(bytes.Repeat([]byte("d"), tc.docCap), sig))
		if len(wire) >= tc.route {
			t.Errorf("%s at its cap is %d bytes as sent, which the route's cap of %d does not hold",
				tc.name, len(wire), tc.route)
		}
	}
}

// TestAStalledStreamIsCutInsideTheWindow: the stream routes run on a client
// with no whole-exchange timeout and a stall rule of the relay's window on
// both bodies. A relay that takes a kilobyte of a PUT and then stops
// reading is a request whose body nobody reads: no byte read for the
// window cancels it, and the error says so with the window in whole
// seconds; a relay that sends a kilobyte of a blob and then stops is cut
// the same on the body's next Read. A relay that keeps taking, or keeps
// sending, a little at a time for longer than the window completes — and
// would for longer than any whole-exchange timeout, there being none.
func TestAStalledStreamIsCutInsideTheWindow(t *testing.T) {
	const window = 2 * time.Second
	mode := struct{ atomic.Value }{}
	mode.Store("stall")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flush := func() {
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		switch {
		case r.Method == "PUT":
			buf := make([]byte, 1024)
			if _, err := io.ReadFull(r.Body, buf); err != nil {
				return
			}
			if mode.Load() == "stall" {
				// A kilobyte taken and no more: the sender's writes block
				// on the socket, its body goes unread, and the client's
				// watch ends it. The handler waits out the window and a
				// little rather than on the request's context: a server
				// with a body it has not read cannot see the client go.
				time.Sleep(window + 3*time.Second)
				return
			}
			// A trickle: 64 KiB every twentieth of a second, longer than
			// the window in all, to the end. The body is larger than the
			// socket's buffers, so the sender's reads follow the relay's.
			chunk := make([]byte, 64<<10)
			for {
				if _, err := io.ReadFull(r.Body, chunk); err != nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":7}`))
		case r.Method == "GET":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte("b"), 1024))
			flush()
			if mode.Load() == "stall" {
				<-r.Context().Done()
				return
			}
			for i := 0; i < 30; i++ {
				time.Sleep(100 * time.Millisecond)
				if _, err := w.Write(bytes.Repeat([]byte("b"), 1024)); err != nil {
					return
				}
				flush()
			}
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.stall = window
	upload := strings.Repeat("u", 32)
	body := func(n int) io.Reader { return bytes.NewReader(bytes.Repeat([]byte("p"), n)) }

	t.Run("a PUT the relay stops reading is cut", func(t *testing.T) {
		mode.Store("stall")
		start := time.Now()
		_, err := c.PutStream(context.Background(), upload, 0, body(8<<20), 8<<20)
		elapsed := time.Since(start)
		if err == nil || !strings.Contains(err.Error(), "the relay stopped taking the upload: no byte was read for 2 seconds") {
			t.Fatalf("a stalled PUT: %v in %s; want the stall's sentence", err, elapsed)
		}
		if errors.Is(err, ErrMalformedAnswer) {
			t.Fatal("the stall is answered as a malformed answer; want a transport failure")
		}
		if elapsed < window || elapsed > window+3*time.Second {
			t.Fatalf("the stalled PUT ended after %s; want the window of %s and little more", elapsed, window)
		}
	})
	t.Run("a PUT the relay keeps taking slowly completes", func(t *testing.T) {
		mode.Store("trickle")
		start := time.Now()
		id, err := c.PutStream(context.Background(), upload, 0, body(8<<20), 8<<20)
		if err != nil || id != 7 {
			t.Fatalf("a trickling PUT: %d %v; want the placed id", id, err)
		}
		if elapsed := time.Since(start); elapsed < window {
			t.Fatalf("the trickle took %s, under the window of %s; the test did not outlast it", elapsed, window)
		}
	})
	t.Run("a GET the relay stops sending is cut", func(t *testing.T) {
		mode.Store("stall")
		rc, _, err := c.Blob(context.Background(), strings.Repeat("a", 64), 1, 0, -1)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		start := time.Now()
		n, err := io.Copy(io.Discard, rc)
		elapsed := time.Since(start)
		if n != 1024 || err == nil || !strings.Contains(err.Error(), "the relay stopped sending the stream: no byte arrived for 2 seconds") {
			t.Fatalf("a stalled GET: %d bytes, %v in %s; want the kilobyte and the stall's sentence", n, err, elapsed)
		}
		if elapsed < window || elapsed > window+3*time.Second {
			t.Fatalf("the stalled GET ended after %s; want the window and little more", elapsed)
		}
	})
	t.Run("a GET the relay keeps sending slowly completes", func(t *testing.T) {
		mode.Store("trickle")
		rc, _, err := c.Blob(context.Background(), strings.Repeat("a", 64), 1, 0, -1)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		start := time.Now()
		n, err := io.Copy(io.Discard, rc)
		if err != nil || n != 31*1024 {
			t.Fatalf("a trickling GET: %d bytes, %v; want all 31 KiB", n, err)
		}
		if elapsed := time.Since(start); elapsed < window {
			t.Fatalf("the trickle took %s, under the window; the test did not outlast it", elapsed)
		}
	})
}

// TestAHeldListingCompletes: a listing a watcher asks the relay to hold is
// answered at the hold's end, relayapi.MaxWait at most, and the transport's
// wait for a response's headers is longer than that — MaxWait plus thirty
// seconds — so the held answer is taken rather than cut as a relay that
// said nothing. The relay here holds for the whole of MaxWait.
func TestAHeldListingCompletes(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			json.NewEncoder(w).Encode(relayapi.HealthResponse{OK: true, MaxBytes: relayapi.DefaultMaxBytes, KnockMaxBytes: relayapi.DefaultMaxBytes, Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel})
			return
		}
		time.Sleep(relayapi.MaxWait)
		json.NewEncoder(w).Encode(map[string]any{"messages": []any{}, "queued": 0, "first": 0, "last": 0, "allow": "none", "card": "none", "directory": "none"})
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.ListWait(context.Background(), ListRequest{Wait: relayapi.MaxWait}); err != nil {
		t.Fatalf("a listing held for %s: %v after %s; want it answered", relayapi.MaxWait, err, time.Since(start))
	}
}
