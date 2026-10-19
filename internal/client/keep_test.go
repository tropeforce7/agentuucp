package client

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// tripRecorder is a RoundTripper that writes down what it was handed.
type tripRecorder struct {
	mu   sync.Mutex
	seen []*http.Request
}

func (r *tripRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.seen = append(r.seen, req)
	r.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: http.NoBody, Request: req}, nil
}

// The kept transport is handed only what net/http cannot send again: a
// POST with a body, its GetBody taken away, and no idempotency header.
// Everything else goes on the fresh transport, which keeps nothing.
func TestTheKeptTransportSendsOnlyWhatCannotBeSentAgain(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		body   string
		header string
		kept   bool
	}{
		{"a POST with a body", "POST", "{}", "", true},
		{"a GET", "GET", "", "", false},
		{"a GET with a body", "GET", "{}", "", false},
		{"a PUT with a body", "PUT", "{}", "", false},
		{"a HEAD", "HEAD", "", "", false},
		{"a POST with no body", "POST", "", "", false},
		{"a POST with an Idempotency-Key", "POST", "{}", "Idempotency-Key", false},
		{"a POST with an X-Idempotency-Key", "POST", "{}", "X-Idempotency-Key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var kept, fresh tripRecorder
			k := &keepTransport{kept: &kept, fresh: &fresh}
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req, err := http.NewRequest(tc.method, "http://relay.test/v1/forward", body)
			if err != nil {
				t.Fatal(err)
			}
			if tc.header != "" {
				req.Header[tc.header] = []string{"k"}
			}
			if _, err := k.RoundTrip(req); err != nil {
				t.Fatal(err)
			}
			if got := len(kept.seen) == 1; got != tc.kept || len(kept.seen)+len(fresh.seen) != 1 {
				t.Fatalf("kept %d, fresh %d; want it on the kept transport: %v", len(kept.seen), len(fresh.seen), tc.kept)
			}
			if tc.kept && kept.seen[0].GetBody != nil {
				t.Fatal("the kept transport was handed a request whose body it can make again")
			}
			if req.GetBody == nil && tc.body != "" {
				t.Fatal("the caller's own request lost its GetBody")
			}
		})
	}
}

// rawRelay is a plain HTTP server that reads each request whole and either
// answers it, keeping the connection, or closes the connection without a
// word, counting every request by its X-Nonce header and every connection.
type rawRelay struct {
	ln    net.Listener
	mu    sync.Mutex
	seen  map[string]int
	conns int
	// cut is the nonce of a request read whole and then not answered.
	cut string
	// closeAfter is the nonce of a request answered and then its
	// connection closed, as a relay's idle timeout closes one.
	closeAfter string
}

func startRawRelay(t *testing.T) *rawRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &rawRelay{ln: ln, seen: map[string]int{}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.conns++
			r.mu.Unlock()
			go r.serve(conn)
		}
	}()
	return r
}

func (r *rawRelay) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		io.Copy(io.Discard, req.Body)
		nonce := req.Header.Get("X-Nonce")
		r.mu.Lock()
		r.seen[nonce]++
		cut, closeAfter := nonce == r.cut, nonce == r.closeAfter
		r.mu.Unlock()
		if cut {
			return
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
			return
		}
		if closeAfter {
			return
		}
	}
}

func (r *rawRelay) count(nonce string) (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[nonce], r.conns
}

func (r *rawRelay) post(t *testing.T, rt http.RoundTripper, nonce string, header string) error {
	t.Helper()
	req, err := http.NewRequest("POST", "http://"+r.ln.Addr().String()+"/v1/forward", bytes.NewReader([]byte(`{"n":"`+nonce+`"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Nonce", nonce)
	if header != "" {
		req.Header.Set(header, nonce)
	}
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

func keptPair() (*keepTransport, *http.Transport) {
	kept := &http.Transport{MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, IdleConnTimeout: keptIdle}
	return &keepTransport{kept: kept, fresh: &http.Transport{DisableKeepAlives: true}}, kept
}

// A request on a kept connection that dies after the request was read
// whole is the request's failure and is not sent again, on that
// connection or another: the relay reads it once. A connection the relay
// closed while idle is let go, and the next request goes on a new one,
// read once. The control row is the same fault for a request net/http
// may send again, an Idempotency-Key and its body able to be made again
// on the kept transport itself: the relay reads that one twice, which is
// how the rows above would show a request sent again.
func TestAKeptConnectionThatDiesIsNotSentAgain(t *testing.T) {
	t.Run("cut after the request was read", func(t *testing.T) {
		r := startRawRelay(t)
		r.cut = "second"
		k, kept := keptPair()
		defer kept.CloseIdleConnections()
		if err := r.post(t, k, "first", ""); err != nil {
			t.Fatal(err)
		}
		if err := r.post(t, k, "second", ""); err == nil {
			t.Fatal("a request whose connection died got an answer")
		}
		time.Sleep(200 * time.Millisecond)
		if n, conns := r.count("second"); n != 1 || conns != 1 {
			t.Fatalf("the relay read the request %d times on %d connections; want once, on the one kept", n, conns)
		}
	})
	t.Run("closed while idle", func(t *testing.T) {
		r := startRawRelay(t)
		r.closeAfter = "first"
		k, kept := keptPair()
		defer kept.CloseIdleConnections()
		if err := r.post(t, k, "first", ""); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		err := r.post(t, k, "second", "")
		n, conns := r.count("second")
		if err != nil && n != 1 {
			t.Fatalf("the next request failed (%v) and was read %d times", err, n)
		}
		if n != 1 || conns != 2 {
			t.Fatalf("the next request was read %d times on %d connections; want once, on a new one", n, conns)
		}
	})
	t.Run("control: a request net/http may send again is sent again", func(t *testing.T) {
		r := startRawRelay(t)
		r.cut = "second"
		_, kept := keptPair()
		defer kept.CloseIdleConnections()
		if err := r.post(t, kept, "first", "Idempotency-Key"); err != nil {
			t.Fatal(err)
		}
		r.post(t, kept, "second", "Idempotency-Key")
		time.Sleep(200 * time.Millisecond)
		if n, _ := r.count("second"); n < 2 {
			t.Fatalf("net/http read the replayable request %d times; the fixture cannot see a request sent again", n)
		}
	})
}
