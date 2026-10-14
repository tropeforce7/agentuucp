package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// An upload attempt the relay refuses before reading its body is answered
// with the refusal, not a reset (R42a): the relay answers a resumed
// attempt from zero 409 with where its copy ends and the body unread, and
// with no connection kept (G28) a body already on the wire met a reset and
// the answer was lost, so a resume failed where it should have resumed.
// The attempt asks before it sends, so the body is never sent to a relay
// that refuses it.
func TestAnUploadRefusedUnreadIsAnsweredNotReset(t *testing.T) {
	// The relay's refusal: answered with the body unread, as refuseUnread
	// answers it, the connection closed after.
	var asked atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Store(r.Header.Get("Expect") == "100-continue")
		w.Header().Set(relayapi.UploadOffsetHeader, "1048576")
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"the relay holds 1048576 bytes of this upload; resume from there","code":""}`))
	}))
	t.Cleanup(srv.Close)
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	const size = 32 << 20
	_, err = c.PutStream(context.Background(), "0123456789abcdef0123456789abcdef", 0, bytes.NewReader(make([]byte, size)), size)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusConflict {
		t.Fatalf("an attempt refused unread: %v; want the relay's 409, not a transport failure", err)
	}
	if !asked.Load() {
		t.Fatal("the attempt did not ask before sending its body")
	}
	// The wait for the relay's answer to the ask is set on the transport:
	// at zero the body would go at once, asked or not.
	if c.transport == nil || c.transport.ExpectContinueTimeout < time.Second {
		t.Fatalf("the transport's ExpectContinueTimeout is %v; want a second", c.transport.ExpectContinueTimeout)
	}
}

// A relay that does not answer the ask, as one in front of no Go server
// might not, is sent the body after the wait and takes the attempt: asking
// costs it a second and nothing else.
func TestAnUploadToARelayThatIgnoresTheAskIsSentAfterTheWait(t *testing.T) {
	var got atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Go's server answers the ask itself on the first read; a hijack
		// reads the raw request, as a server that never answers it would.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("no hijacker")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		n, _ := io.CopyN(io.Discard, buf, r.ContentLength)
		got.Store(n)
		_, _ = conn.Write([]byte("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nConnection: close\r\n" +
			relayapi.UploadOffsetHeader + ": 4096\r\nContent-Length: 8\r\n\r\n{\"id\":7}"))
	}))
	t.Cleanup(srv.Close)
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	id, err := c.PutStream(context.Background(), "0123456789abcdef0123456789abcdef", 0, bytes.NewReader(make([]byte, 4096)), 4096)
	if err != nil || id != 7 {
		t.Fatalf("an attempt to a relay that ignores the ask: %d, %v; want it taken", id, err)
	}
	if got.Load() != 4096 {
		t.Fatalf("the relay was sent %d bytes; want the whole body", got.Load())
	}
	if waited := time.Since(start); waited < 900*time.Millisecond || waited > 10*time.Second {
		t.Fatalf("the attempt took %v; want about the second's wait", waited)
	}
}
