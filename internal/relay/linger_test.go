package relay

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// endless is a body that never ends, counting what is read of it.
type endless struct{ n int64 }

func (e *endless) Read(p []byte) (int, error) {
	e.n += int64(len(p))
	return len(p), nil
}

// A refused attempt whose body had begun is read on after its answer, up
// to lingerBytes and no further, so the sender reads the answer before the
// close (R42b); one refused before a byte of its body was read is not
// read at all, since a sender that asked first sends nothing once refused.
func TestARefusedAttemptIsReadOnUpToTheBound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before int64
		want   int64
	}{
		{"refused after the body began", 1, lingerBytes},
		{"refused before the body began", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &endless{}
			body := &deadlineReader{r: src, extend: func() {}, hunk: 1 << 16, read: tc.before}
			rec := httptest.NewRecorder()
			(&Server{}).lingerAfterRefusal(http.NewResponseController(rec), body)
			if src.n != tc.want {
				t.Fatalf("read %d bytes after the refusal; want %d", src.n, tc.want)
			}
		})
	}
}

// Through a real connection: the answer reaches the sender before the
// drain begins, and the drain ends at lingerWait though the body is still
// coming (R42b). The sender trickles its body and reads the answer as it
// writes; the handler's own time is the drain's.
func TestARefusedAttemptsAnswerIsFlushedBeforeTheDrainAndTheDrainEndsInTime(t *testing.T) {
	handled := make(chan time.Duration, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		body := &deadlineReader{r: r.Body, extend: func() {}, hunk: 1 << 16}
		if _, err := io.ReadFull(body, make([]byte, 4)); err != nil {
			t.Error(err)
		}
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusInsufficientStorage)
		(&Server{}).lingerAfterRefusal(http.NewResponseController(w), body)
		handled <- time.Since(start)
	}))
	t.Cleanup(srv.Close)
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "PUT /up HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000000\r\nConnection: close\r\n\r\nabcd"); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := conn.Write([]byte("x")); err != nil {
				return
			}
		}
	}()
	sent := time.Now()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, "507") {
		t.Fatalf("the answer: %q, %v", line, err)
	}
	if took := time.Since(sent); took > lingerWait/2 {
		t.Fatalf("the answer came after %v; want it before the drain, at once", took)
	}
	select {
	case took := <-handled:
		if took < lingerWait-200*time.Millisecond || took > lingerWait+time.Second {
			t.Fatalf("the drain took %v; want about %v, the bound", took, lingerWait)
		}
	case <-time.After(lingerWait + 3*time.Second):
		t.Fatal("the drain did not end at its bound")
	}
}

// Through the upload route itself (R42b, the reader's gap): an attempt
// refused after its body began, a first attempt whose header is the wrong
// shape, is answered at once and its connection held for the drain, about
// lingerWait, though the sender sends nothing more; a placed attempt is
// answered without the wait.
func TestTheUploadRouteDrainsAnAttemptRefusedAfterItsBodyBegan(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: 2048})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	blob := fakeStream(200, 3000)
	// A manifest length past what any stream may carry: the shape the
	// relay refuses once it has read the header.
	bad := append([]byte{}, blob...)
	binary.BigEndian.PutUint32(bad[stream.EncSize:stream.EncSize+4], 1<<30)

	status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(bad)))
	if status != http.StatusCreated {
		t.Fatalf("open: %d %s", status, body)
	}
	req, err := http.NewRequest("PUT", h.srv.URL+"/v1/uploads/"+opened.Upload, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(bad))
	req.Header.Set(relayapi.UploadOffsetHeader, "0")
	if err := relayapi.SignRequest(alice, req, nil); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var wire bytes.Buffer
	fmt.Fprintf(&wire, "PUT %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n", req.URL.RequestURI(), req.Host, req.ContentLength)
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&wire, "%s: %s\r\n", k, v)
		}
	}
	wire.WriteString("\r\n")
	wire.Write(bad[:stream.HeaderSize])
	sent := time.Now()
	if _, err := conn.Write(wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(lingerWait + 5*time.Second))
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		t.Fatalf("the answer: %v", err)
	}
	answered := time.Since(sent)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("the bad shape: %d; want 400", resp.StatusCode)
	}
	if answered > lingerWait/2 {
		t.Fatalf("the answer came after %v; want it at once, before the drain", answered)
	}
	// The connection closes when the drain ends, at its bound.
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("more after the answer")
	}
	if held := time.Since(sent); held < lingerWait-200*time.Millisecond {
		t.Fatalf("the connection closed after %v; want it held for the drain, about %v", held, lingerWait)
	}

	// A placed attempt: no drain.
	start := time.Now()
	h.uploadStream(alice, bob.Fingerprint(), blob)
	if took := time.Since(start); took > lingerWait/2 {
		t.Fatalf("a placed upload took %v; want no drain", took)
	}
}
