package relay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// rawRequest is one request written by hand on a connection of the test's
// own: the request line, Host, the headers given, a Content-Length of
// declared when it is not negative, and then sent bytes of the body — none,
// for a request that declares a body it never sends. The request asks to
// keep the connection, as the client's does, so that a refusal before the
// body is shown to close it on the relay's own decision: net/http reads up
// to 256 KiB of an unread body before answering on a connection it will
// keep, and waits for a body that never comes. The answer is read from the
// same connection under a deadline, so a relay that waited on the body
// rather than answering fails the test in bounded time rather than
// hanging it. When from is not nil the request is signed by it over sent,
// as the client would sign.
func (h *harness) rawRequest(from *identity.Identity, method, path string, headers map[string]string,
	declared int64, sent []byte) (int, []byte, http.Header) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if from != nil {
		if err := relayapi.SignRequest(from, req, sent); err != nil {
			h.t.Fatal(err)
		}
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		h.t.Fatal(err)
	}
	defer conn.Close()
	var wire bytes.Buffer
	fmt.Fprintf(&wire, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, req.URL.RequestURI(), req.Host)
	if declared >= 0 {
		fmt.Fprintf(&wire, "Content-Length: %d\r\n", declared)
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&wire, "%s: %s\r\n", k, v)
		}
	}
	wire.WriteString("\r\n")
	wire.Write(sent)
	if _, err := conn.Write(wire.Bytes()); err != nil {
		h.t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		h.t.Fatalf("reading the answer to a hand-written %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	// ReadResponse takes Connection: close out of the header map into
	// resp.Close; it is put back so a test can read it where it was sent.
	if resp.Close {
		resp.Header.Set("Connection", "close")
	}
	return resp.StatusCode, out, resp.Header
}

// TestLimitRequestHeadersAreCapped: the request line and headers together
// are capped at relayapi.MaxHeaderBytes, 32 KiB, which net/http enforces
// before any handler runs, answering 431. The largest header this protocol
// carries, the auth header at MaxAuthHeader bytes, is two orders of
// magnitude under it, shown by TestLimitAuthHeaderLength; here a header
// block at the cap is taken, one carrying a value the size of an ML-DSA-87
// signature in base64 (the figure the plan first sized the cap by, before
// the request signature was found to be Ed25519) is taken with room, and
// the edge is net/http's own: it reads the header block through a buffer
// of 4096 bytes of slop above MaxHeaderBytes (Server.initialReadLimitSize),
// so a block of MaxHeaderBytes + 4096 is taken and one byte more is 431,
// with the sentence net/http writes and the handler never reached.
func TestLimitRequestHeadersAreCapped(t *testing.T) {
	h := newHarness(t, Config{})
	const slop = 4096
	// The bytes of the block around the one header the test sizes.
	frame := len("GET /v1/health HTTP/1.1\r\nHost: \r\nX-Junk: \r\n\r\n") + len(strings.TrimPrefix(h.srv.URL, "http://"))
	for _, tc := range []struct {
		name  string
		total int
		want  int
	}{
		{"an ML-DSA-87 signature's worth of header", frame + 6200, http.StatusOK},
		{"a block at MaxHeaderBytes", relayapi.MaxHeaderBytes, http.StatusOK},
		{"a block at MaxHeaderBytes plus net/http's slop", relayapi.MaxHeaderBytes + slop, http.StatusOK},
		{"one byte over", relayapi.MaxHeaderBytes + slop + 1, http.StatusRequestHeaderFieldsTooLarge},
		{"twice the cap", 2 * relayapi.MaxHeaderBytes, http.StatusRequestHeaderFieldsTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := h.rawRequest(nil, "GET", "/v1/health",
				map[string]string{"X-Junk": strings.Repeat("j", tc.total-frame)}, -1, nil)
			if status != tc.want {
				t.Fatalf("a header block of %d bytes: %d %.120s; want %d", tc.total, status, body, tc.want)
			}
			if status == http.StatusRequestHeaderFieldsTooLarge && !strings.Contains(string(body), "Request Header Fields Too Large") {
				t.Errorf("the 431's body: %.120s; want net/http's own sentence", body)
			}
		})
	}
	// The relay is unharmed by the refusals: the next request is answered.
	if status, _, _ := h.rawRequest(nil, "GET", "/v1/health", nil, -1, nil); status != http.StatusOK {
		t.Errorf("health after the refusals: %d, want 200", status)
	}
}

// fullDirectory is a channel directory at every maximum, marshalled the
// way the client sends it: MaxChannels channels with 64-byte names of &
// (a name refuses <, which Windows forbids) and 1024-byte descriptions
// of < (which the description rule admits), each written by encoding/json
// as a six-byte \u escape, both times on every channel, signed by owner.
func fullDirectory(t *testing.T, owner *identity.Identity, at time.Time) relayapi.ChannelsRequest {
	t.Helper()
	var chs []channels.Channel
	for i := 0; i < relayapi.MaxChannels; i++ {
		nb, na := at, at.Add(time.Hour)
		chs = append(chs, channels.Channel{
			Name:        strings.Repeat("&", relayapi.MaxChannelNameBytes-2) + fmt.Sprintf("%02d", i),
			Description: strings.Repeat("<", relayapi.MaxChannelDescriptionBytes),
			NotBefore:   &nb, NotAfter: &na,
		})
	}
	doc, sig, err := channels.Sign(owner, &channels.Directory{Issued: at, Channels: chs})
	if err != nil {
		t.Fatal(err)
	}
	return relayapi.ChannelsRequest{Document: doc, Signature: sig}
}

// fullAllowList is an allow list of MaxAllowlist senders, marshalled the
// way the client sends it, the senders once plain and once in the signed
// document.
func fullAllowList(t *testing.T, owner *identity.Identity, at time.Time) relayapi.AllowRequest {
	t.Helper()
	senders := make([]string, 0, relayapi.MaxAllowlist)
	for i := 0; i < relayapi.MaxAllowlist; i++ {
		senders = append(senders, fmt.Sprintf("%064x", i+1))
	}
	doc, sig, err := allowlist.Sign(owner, &allowlist.Document{Issued: at, Senders: senders})
	if err != nil {
		t.Fatal(err)
	}
	return relayapi.AllowRequest{Document: doc, Signature: sig}
}

// TestLimitBodyCapsPerRoute: every route that reads a body reads it under
// its own cap, and a body that declares itself over the cap is answered
// 413 before a byte of it is read, the sentence naming the cap in bytes
// and the connection closed behind the answer. The post route takes
// max_bytes + FramingAllowance, and the knock route knock_max_bytes +
// FramingAllowance, which at knock_max_bytes zero is the post's
// (TestLimitAKnockIsHeldToKnockMaxBytes walks the setting); two of the three owner-signed documents
// take MaxDocumentBytes on the body, and a directory and an allow list
// built at every maximum and marshalled as the client marshals them are
// taken under it, one byte over refused with the hint to send the
// document compact; the documents inside have caps of their own,
// MaxDirectoryBytes and MaxAllowlistBytes, which the packages that own
// them test and which the measurements live in the comments of; the report
// route takes MaxReportBytes, which is derived from MaxSaid because JSON
// escaping expands a legal sentence up to sixfold and
// TestLimitAReportAtItsBoundFitsItsBodyCap holds the arithmetic to every
// character that expands; every other body route takes FramingAllowance
// alone, shown on the card, the registration, the stream open and an
// admin token. A card at its maximum, a name of 64 bytes, is a few
// hundred bytes and is taken under the general cap.
// The refusals are proved by requests that declare the body and send none
// of it, answered anyway.
func TestLimitBodyCapsPerRoute(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: 1 << 20})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	at := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)

	// The two documents at their maxima are taken.
	dir := fullDirectory(t, alice, at)
	wire, err := json.Marshal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > relayapi.MaxDocumentBytes || len(wire) < 500_000 {
		t.Fatalf("the full directory is %d bytes on the wire; want under MaxDocumentBytes %d and above 500,000", len(wire), relayapi.MaxDocumentBytes)
	}
	if status, body := h.do(alice, "PUT", "/v1/mailbox/"+alice.Fingerprint()+"/channels", dir, nil); status/100 != 2 {
		t.Fatalf("a directory at every maximum, %d bytes: %d %.200s; want it taken", len(wire), status, body)
	}
	list := fullAllowList(t, alice, at)
	wire, err = json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > relayapi.MaxDocumentBytes || len(wire) < 85_000 {
		t.Fatalf("the full allow list is %d bytes on the wire; want under MaxDocumentBytes %d and above 85,000", len(wire), relayapi.MaxDocumentBytes)
	}
	if status, body := h.do(alice, "PUT", "/v1/mailbox/"+alice.Fingerprint()+"/allow", list, nil); status/100 != 2 {
		t.Fatalf("an allow list at every maximum, %d bytes: %d %.200s; want it taken", len(wire), status, body)
	}
	big := &card.Document{Issued: at, Name: strings.Repeat("a", identity.MaxNameBytes), Listed: true, Knocks: true}
	bigDoc, bigSig, err := card.Sign(alice, big)
	if err != nil {
		t.Fatal(err)
	}
	fullCard := relayapi.CardRequest{Document: bigDoc, Signature: bigSig}
	wire, err = json.Marshal(fullCard)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > relayapi.FramingAllowance || len(wire) < 300 {
		t.Fatalf("the full card is %d bytes on the wire; want under FramingAllowance %d and above 300", len(wire), relayapi.FramingAllowance)
	}
	if status, body := h.do(alice, "PUT", "/v1/mailbox/"+alice.Fingerprint()+"/card", fullCard, nil); status/100 != 2 {
		t.Fatalf("a card at its maximum, %d bytes: %d %.200s; want it taken", len(wire), status, body)
	}

	// One byte over each route's cap, declared and never sent: 413 before
	// a byte, naming the cap; at the cap the body is waited for, which
	// the deadline turns into a read error, so the edge under the cap is
	// shown by the documents above and by the routes' own tests.
	me := alice.Fingerprint()
	for _, tc := range []struct {
		name, method, path string
		from               *identity.Identity
		limit              int64
		hint               string
	}{
		{"the directory", "PUT", "/v1/mailbox/" + me + "/channels", alice, relayapi.MaxDocumentBytes, hintCompact},
		{"the allow list", "PUT", "/v1/mailbox/" + me + "/allow", alice, relayapi.MaxDocumentBytes, hintCompact},
		{"the card", "PUT", "/v1/mailbox/" + me + "/card", alice, relayapi.FramingAllowance, hintCompact},
		{"the post", "POST", "/v1/mailbox/" + bob.Fingerprint(), alice, 1<<20 + relayapi.FramingAllowance, ""},
		{"the knock", "POST", "/v1/mailbox/" + bob.Fingerprint() + "/knock", alice, 1<<20 + relayapi.FramingAllowance, ""},
		{"the stream open", "POST", "/v1/mailbox/" + bob.Fingerprint() + "/streams", alice, relayapi.FramingAllowance, ""},
		{"the forward", "POST", "/v1/forward", alice, 1<<20 + relayapi.FramingAllowance, ""},
		// The report route's cap is reached before the handler's check that
		// the caller is a courier, declaredLength running inside
		// callerAuthedBody, so a user shows the cap as well as a neighbour
		// would.
		{"the report", "POST", "/v1/forward/failed", alice, relayapi.MaxReportBytes, ""},
		{"the registration", "POST", "/v1/register", alice, relayapi.FramingAllowance, ""},
		{"the certificate request", "POST", "/v1/mailbox/" + me + "/certs", alice, relayapi.FramingAllowance, ""},
	} {
		t.Run(tc.name+" one byte over its cap", func(t *testing.T) {
			status, body, hdr := h.rawRequest(tc.from, tc.method, tc.path, nil, tc.limit+1, nil)
			if status != http.StatusRequestEntityTooLarge {
				t.Fatalf("%d %.200s; want 413", status, body)
			}
			want := fmt.Sprintf("%s: at most %d bytes", relayapi.MsgBodyTooLarge, tc.limit)
			if tc.hint != "" {
				want += "; " + tc.hint
			}
			if got := errorText(t, body); got != want {
				t.Errorf("the sentence is %q, want %q", got, want)
			}
			if hdr.Get("Connection") != "close" {
				t.Errorf("Connection is %q, want close: the unsent body is not waited for", hdr.Get("Connection"))
			}
		})
	}
	// An admin token route, under the admin's key.
	admin := ids(t, "admin")[0]
	adminPath := adminFile(t, admin)
	loaded, err := LoadAdmins(adminPath)
	if err != nil {
		t.Fatal(err)
	}
	ha := newHarness(t, Config{AdminFile: adminPath, Admins: loaded})
	status, body, _ := ha.rawRequest(admin, "POST", "/v1/admin/tokens", nil, relayapi.FramingAllowance+1, nil)
	if status != http.StatusRequestEntityTooLarge || errorText(t, body) != fmt.Sprintf("%s: at most %d bytes", relayapi.MsgBodyTooLarge, relayapi.FramingAllowance) {
		t.Errorf("an admin token one byte over FramingAllowance: %d %.200s; want 413 naming the cap", status, body)
	}
	// A body without a length that runs past the cap. On a route under a
	// signature it is refused 411 before a byte of it is read and before
	// the caller is looked up (G12: the declared length is judged before
	// the identity, so every caller is answered alike, and a body that
	// declares none cannot be judged then); on the registration, which
	// reads the body under no signature of anybody known, it is cut at
	// the cap by MaxBytesReader and answered 413, after the cap's worth
	// was read and no more.
	chunked := append(bytes.Repeat([]byte("x"), relayapi.FramingAllowance+1), []byte("\r\n0\r\n\r\n")...)
	size := fmt.Sprintf("%x\r\n", relayapi.FramingAllowance+1)
	status, body, hdr := h.rawRequest(alice, "POST", "/v1/mailbox/"+bob.Fingerprint()+"/streams",
		map[string]string{"Transfer-Encoding": "chunked"}, -1, append([]byte(size), chunked...))
	if status != http.StatusLengthRequired || errorText(t, body) != "a request to this route declares its body's length" {
		t.Errorf("a chunked body over the cap on the stream open: %d %.200s; want 411 asking for the length", status, body)
	}
	if hdr.Get("Connection") != "close" {
		t.Errorf("Connection is %q after the 411, want close: the unread body is not waited for", hdr.Get("Connection"))
	}
	status, body, _ = h.rawRequest(alice, "POST", "/v1/register",
		map[string]string{"Transfer-Encoding": "chunked"}, -1, append([]byte(size), chunked...))
	if status != http.StatusRequestEntityTooLarge || errorText(t, body) != fmt.Sprintf("%s: at most %d bytes", relayapi.MsgBodyTooLarge, relayapi.FramingAllowance) {
		t.Errorf("a chunked registration over the cap: %d %.200s; want 413 naming the cap", status, body)
	}
}

// TestTheAuthHeaderIsReadBeforeTheBody: on every authenticated route the
// order is the certificate, the auth header parsed, the declared length
// judged, the identity looked up, then the body, then the signature. A
// request under a fingerprint no mailbox has, declaring a body up to the
// route's cap and sending none of it, is answered 401 before the body is
// read; one whose header will not parse the same, even declaring a body
// over the cap, since the header is parsed before the length is judged;
// and the registration, whose signer is not yet anybody, parses the header
// before the body too. A stranger's body declared over the route's cap is
// 413, as a registered caller's is (G12: the declared length is judged
// before the identity, so every caller is answered alike). The signature is checked after the body,
// as it must be, since it is over the body: a registered identity's
// well-formed request over a declared body that never comes is waited
// for, which is the signature's read of the body, and a wrong signature
// after the body is 401 as TestBadSignaturesAreChargedButNeverBlockAGoodOne
// shows.
func TestTheAuthHeaderIsReadBeforeTheBody(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: 16 << 20})
	people := ids(t, "alice", "stranger")
	alice, stranger := people[0], people[1]
	h.register(alice)
	const sixteen = 16 << 20
	// The directory's cap is MaxDocumentBytes, under sixteen megabytes:
	// a stranger's directory declares the cap itself, the most the length
	// check lets through to the lookup.
	notParsing := map[string]string{relayapi.AuthHeader: "v1 not a header"}
	for _, tc := range []struct {
		name     string
		from     *identity.Identity
		hdr      map[string]string
		path     string
		declared int64
	}{
		{"a stranger's post", stranger, nil, "/v1/mailbox/" + alice.Fingerprint(), sixteen},
		{"a stranger's directory", stranger, nil, "/v1/mailbox/" + alice.Fingerprint() + "/channels", relayapi.MaxDocumentBytes},
		{"a header that will not parse", nil, notParsing, "/v1/mailbox/" + alice.Fingerprint(), sixteen},
		{"a header that will not parse, over the directory's cap", nil, notParsing, "/v1/mailbox/" + alice.Fingerprint() + "/channels", sixteen},
		{"no header at all", nil, nil, "/v1/mailbox/" + alice.Fingerprint(), sixteen},
		{"no header at all, over the directory's cap", nil, nil, "/v1/mailbox/" + alice.Fingerprint() + "/channels", sixteen},
		{"a registration with no header", nil, nil, "/v1/register", sixteen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := "POST"
			if strings.HasSuffix(tc.path, "/channels") {
				method = "PUT"
			}
			start := time.Now()
			status, body, hdr := h.rawRequest(tc.from, method, tc.path, tc.hdr, tc.declared, nil)
			if status != http.StatusUnauthorized {
				t.Fatalf("%d %.200s in %s; want 401 with the %d bytes unsent", status, body, time.Since(start), tc.declared)
			}
			if hdr.Get("Connection") != "close" {
				t.Errorf("the connection is kept after a refusal before the body; want it closed, the body unread")
			}
			// Under net/http's 256 KiB drain: a small declared body, never
			// sent, is answered at once too, because the relay closes the
			// connection rather than wait for it.
			start = time.Now()
			if status, _, hdr := h.rawRequest(tc.from, method, tc.path, tc.hdr, 4000, nil); status != http.StatusUnauthorized || hdr.Get("Connection") != "close" {
				t.Errorf("4000 bytes declared and unsent: %d close=%q in %s; want 401 with the connection closed", status, hdr.Get("Connection"), time.Since(start))
			}
		})
	}
	// A stranger's directory declared over its cap is 413 naming the cap,
	// as alice's own is (TestLimitBodyCapsPerRoute): the length is judged
	// before the identity is looked up (G12), so the answer does not say
	// whether the fingerprint has a mailbox.
	wantCap := fmt.Sprintf("%s: at most %d bytes; %s", relayapi.MsgBodyTooLarge, relayapi.MaxDocumentBytes, hintCompact)
	for _, from := range []*identity.Identity{stranger, alice} {
		status, body, hdr := h.rawRequest(from, "PUT", "/v1/mailbox/"+alice.Fingerprint()+"/channels", nil, sixteen, nil)
		if status != http.StatusRequestEntityTooLarge || errorText(t, body) != wantCap || hdr.Get("Connection") != "close" {
			t.Errorf("%s's directory declaring sixteen megabytes: %d %.200s close=%q; want 413 %q with the connection closed",
				from.Name, status, body, hdr.Get("Connection"), wantCap)
		}
	}
	// A registered identity's well-formed request over a declared body
	// that never comes is waited for: the signature is over the body, so
	// the body is read first. The read deadline in the test's connection
	// shows the wait; the server's own five-minute read timeout would end
	// it in deployment.
	req, _ := http.NewRequest("POST", h.srv.URL+"/v1/mailbox/"+alice.Fingerprint(), nil)
	if err := relayapi.SignRequest(alice, req, nil); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 1024\r\n%s: %s\r\n\r\n",
		req.URL.RequestURI(), req.Host, relayapi.AuthHeader, req.Header.Get(relayapi.AuthHeader))
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("a registered identity's request was answered before its body: the signature cannot have been checked")
	}
}

// TestLimitABlobReaderThatStopsIsCutInsideTheWindow: the blob GET is served
// under a write deadline the relay moves on every write that delivers
// bytes, the PUT's read deadline turned round, so a large blob on a slow
// link is served to the end while the reader keeps taking it and a reader
// that stops is cut inside the window rather than holding the connection
// to the server's five-minute write timeout. With the stall timeout at
// 200 ms: a reader that takes the headers and stops sees the connection
// end within two seconds with less than the blob delivered; one that reads
// 64 KiB at a time with a pause between reads, longer than the window in
// all, gets the whole blob.
//
// The 24 MiB upload that makes the blob is not run under the 200 ms
// stall: the PUT's read deadline is the same setting turned round, and
// under the race detector with other packages' tests beside it the
// loopback delivery of 24 MiB paused for longer than that between reads
// often enough — two runs in four, the reviewer's logs — to cut the
// fixture's own upload short with "the attempt stopped short at N of
// 25167148 bytes". The upload goes through a relay at the default stall,
// and the blob is read through a second relay over the same store at
// 200 ms, since the setting is the server's and is not changed under a
// running one.
func TestLimitABlobReaderThatStopsIsCutInsideTheWindow(t *testing.T) {
	uploader := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	uploader.register(alice)
	uploader.register(bob)
	// Larger than the loopback socket buffers on any platform this runs
	// on, so a reader that stops makes the relay's write block.
	blob := fakeStream(200, 24<<20)
	id := uploader.uploadStream(alice, bob.Fingerprint(), blob)
	h := serveStore(t, uploader.store, Config{StallTimeout: 200 * time.Millisecond})
	path := fmt.Sprintf("/v1/mailbox/%s/%d/blob", bob.Fingerprint(), id)

	open := func(t *testing.T) (net.Conn, *bufio.Reader) {
		t.Helper()
		req, err := http.NewRequest("GET", h.srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := relayapi.SignRequest(bob, req, nil); err != nil {
			t.Fatal(err)
		}
		conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n%s: %s\r\n\r\n",
			req.URL.RequestURI(), req.Host, relayapi.AuthHeader, req.Header.Get(relayapi.AuthHeader))
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || resp.ContentLength != int64(len(blob)) {
			t.Fatalf("%d, length %d; want 200 and %d", resp.StatusCode, resp.ContentLength, len(blob))
		}
		return conn, br
	}

	t.Run("a reader that stops is cut", func(t *testing.T) {
		conn, br := open(t)
		defer conn.Close()
		// The headers were read and nothing more for longer than the
		// window; the relay's write then blocks on the full socket
		// buffers, the deadline ends it, and the connection is closed.
		time.Sleep(600 * time.Millisecond)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		start := time.Now()
		n, err := io.Copy(io.Discard, br)
		if err == nil && n == int64(len(blob)) {
			t.Fatalf("the whole blob arrived to a reader that stopped for three windows")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("draining what the relay had written took %s; want the connection already cut", elapsed)
		}
	})
	t.Run("a reader slower than the window in all completes", func(t *testing.T) {
		conn, br := open(t)
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		var got int64
		buf := make([]byte, 64<<10)
		start := time.Now()
		for got < int64(len(blob)) {
			n, err := io.ReadFull(br, buf[:min(int64(len(buf)), int64(len(blob))-got)])
			got += int64(n)
			if err != nil {
				t.Fatalf("after %d of %d bytes in %s: %v", got, len(blob), time.Since(start), err)
			}
			time.Sleep(2 * time.Millisecond)
		}
		if elapsed := time.Since(start); elapsed < 400*time.Millisecond {
			t.Logf("the slow read took %s, under two windows; the test's pace did not exercise the deadline", elapsed)
		}
	})
}

// TestLimitAListingPageFollowsMaxBytes: a page of a listing had no bound in
// bytes — up to MaxListLimit envelopes of up to max_bytes each, which a
// client sized to hold a page cannot hold, and a mailbox nobody could list
// is one nobody could acknowledge. Now the relay ends a page before the
// envelope that would take its inline bytes past max_bytes, admitting the
// first whatever its size, so a page's envelopes never exceed max_bytes
// unless the first alone does, and the rows the budget left off are the
// next page's. With
// max_bytes 16 KiB and five envelopes of about 10 KiB each (a sealed
// envelope carries about 4.3 KiB of keys and signature before its text),
// every page holds one and the five come over five pages in order, queued
// saying five the whole way; two small envelopes that fit the budget
// together come as one page; an envelope near the budget's whole size
// comes alone, and behind the two small ones it is the next page; and a
// stubs listing, which carries no body, lists them all at once.
func TestLimitAListingPageFollowsMaxBytes(t *testing.T) {
	const maxBytes = 16 << 10
	h := newHarness(t, Config{MaxBytes: maxBytes})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	post := func(t *testing.T, text string) int64 {
		t.Helper()
		status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), sealed(t, alice, bob.Public(), text), nil)
		if status != http.StatusOK {
			t.Fatalf("post: %d %s", status, body)
		}
		var resp relayapi.PostResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
		return resp.ID
	}
	page := func(t *testing.T, after int64, query string) relayapi.ListResponse {
		t.Helper()
		status, body := h.do(bob, "GET", fmt.Sprintf("/v1/mailbox/%s?after=%d&limit=200%s", bob.Fingerprint(), after, query), nil, nil)
		if status != http.StatusOK {
			t.Fatalf("list after %d: %d %s", after, status, body)
		}
		var list relayapi.ListResponse
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
		return list
	}
	inline := func(l relayapi.ListResponse) int {
		n := 0
		for _, m := range l.Messages {
			n += len(m.Envelope)
		}
		return n
	}

	// Five of about 10 KiB: one a page.
	var ids []int64
	for i := 0; i < 5; i++ {
		ids = append(ids, post(t, strings.Repeat("x", 5000)))
	}
	var after int64
	for i := 0; i < 5; i++ {
		l := page(t, after, "")
		if len(l.Messages) != 1 || l.Messages[0].ID != ids[i] || l.Queued != 5 {
			t.Fatalf("page %d: %d messages (first %d), queued %d; want the one message %d and queued 5", i, len(l.Messages), l.Messages[0].ID, l.Queued, ids[i])
		}
		if n := inline(l); n <= maxBytes/2 || n > maxBytes {
			t.Fatalf("page %d carries %d inline bytes; want one envelope of about 10 KiB", i, n)
		}
		after = l.Messages[0].ID
	}
	if l := page(t, after, ""); len(l.Messages) != 0 || l.Queued != 5 {
		t.Fatalf("after the five: %d messages, queued %d; want none and 5", len(l.Messages), l.Queued)
	}
	// Stubs carry no body and are not budgeted.
	if l := page(t, 0, "&stubs=1"); len(l.Messages) != 5 {
		t.Fatalf("a stubs listing: %d messages, want all 5", len(l.Messages))
	}
	for _, id := range ids {
		if status, body := h.do(bob, "DELETE", fmt.Sprintf("/v1/mailbox/%s/%d", bob.Fingerprint(), id), nil, nil); status/100 != 2 {
			t.Fatalf("delete %d: %d %s", id, status, body)
		}
	}

	// Two small ones together, then one of the budget's whole size alone.
	small1, small2 := post(t, "a"), post(t, "b")
	l := page(t, 0, "")
	if len(l.Messages) != 2 || l.Messages[0].ID != small1 || l.Messages[1].ID != small2 {
		t.Fatalf("two small envelopes: %d messages; want both on one page", len(l.Messages))
	}
	big := post(t, strings.Repeat("y", 8500))
	if n := len(sealed(t, alice, bob.Public(), strings.Repeat("y", 8500))); n > maxBytes {
		t.Fatalf("the test's large envelope is %d bytes, over max_bytes", n)
	}
	l = page(t, small2, "")
	if len(l.Messages) != 1 || l.Messages[0].ID != big || len(l.Messages[0].Envelope) <= 8500 {
		t.Fatalf("an envelope near the budget: %d messages, first %d of %d bytes; want it alone", len(l.Messages), l.Messages[0].ID, len(l.Messages[0].Envelope))
	}
	// And listed with the small ones before it: the page ends before it.
	l = page(t, 0, "")
	if len(l.Messages) != 2 {
		t.Fatalf("the small ones with the large behind: %d messages on the page; want the two small and the large on the next", len(l.Messages))
	}
}

// TestTheHealthAnswerCarriesMaxBytes: the health answer says the relay's
// max_bytes, always, so a client can size what it holds of a listing page
// to the relay it talks to; it is the relay's own figure, the operator's
// setting or the default.
func TestTheHealthAnswerCarriesMaxBytes(t *testing.T) {
	for _, maxBytes := range []int64{0, 4096} {
		h := newHarness(t, Config{MaxBytes: maxBytes})
		status, body := h.do(nil, "GET", "/v1/health", nil, nil)
		if status != http.StatusOK {
			t.Fatalf("health: %d %s", status, body)
		}
		var resp relayapi.HealthResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
		want := maxBytes
		if want == 0 {
			want = relayapi.DefaultMaxBytes
		}
		if resp.MaxBytes != want || !strings.Contains(string(body), `"max_bytes":`) {
			t.Fatalf("with max_bytes %d the health answer says %d (%s); want %d, always present", maxBytes, resp.MaxBytes, body, want)
		}
	}
}
