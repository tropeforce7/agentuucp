package relay

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// stalled is a request parked inside a handler: it declares a body and
// sends only part of it, so readBody blocks and the in-flight slot stays held
// until the connection is closed.
//
// A raw connection rather than an io.Reader body through Go's client, on
// purpose. A body that yields nothing signals the test on the *client's* first
// read, which happens while the request is being written and says nothing
// about whether the server has dispatched the handler; here the bytes on the
// wire are the test's own, and the server's answer, if any, arrives on a
// socket the test is watching.
//
// Since PLAN-HTTP a request is parked in readBody only when everything the
// relay judges before the body has passed: it carries a registered
// identity's auth header, since the header is parsed and the identity
// looked up before the body, and it declares a body under the route's cap,
// since one declared over it is refused unread. The stalled request used to
// carry no header and declare a gigabyte; either is now answered before a
// byte, which is the property those two rules bought, and a stall must be
// an honest request that stops.
type stalled struct {
	conn net.Conn
	// answered goes true if the relay replies, which means this request was
	// the one refused and something else holds the slot.
	answered atomic.Bool
}

func stallPost(t *testing.T, h *harness, id *identity.Identity, declared int64) *stalled {
	t.Helper()
	signed, err := http.NewRequest("POST", h.srv.URL+"/v1/mailbox/"+id.Fingerprint(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayapi.SignRequest(id, signed, nil); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(h.srv.URL, "http://"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req := fmt.Sprintf("POST /v1/mailbox/%s HTTP/1.1\r\nHost: x\r\n%s: %s\r\n"+
		"Content-Length: %d\r\n\r\n0123456789", id.Fingerprint(), relayapi.AuthHeader, signed.Header.Get(relayapi.AuthHeader), declared)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	s := &stalled{conn: conn}
	go func() {
		if _, err := conn.Read(make([]byte, 64)); err == nil {
			s.answered.Store(true)
		}
	}()
	return s
}

func (s *stalled) close() { s.conn.Close() }

// holdsTheSlot waits until the relay refuses another request, which is the
// only proof the stalled one is actually occupying the handler.
//
// It reports lost when the relay answered the stalled request instead: another
// request took the slot first, and this attempt proved nothing. Neither
// outcome after the deadline means the cap is not working, which is a failure
// rather than a race, and the caller says so.
func (s *stalled) holdsTheSlot(t *testing.T, h *harness, probe string) (status int, body []byte, header http.Header, lost bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if s.answered.Load() {
			return 0, nil, nil, true
		}
		status, body, header = h.send(nil, "GET", probe, nil, nil)
		if status == http.StatusServiceUnavailable {
			return status, body, header, false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return status, body, header, false
}
