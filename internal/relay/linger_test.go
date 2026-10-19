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
	"os"
	"strconv"
	"strings"
	"syscall"
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
// read at all, since a sender that asked first sends nothing once refused;
// one whose body stalled is read on to the same bound while it keeps
// coming, and not past the first read that finds it quiet.
func TestARefusedAttemptIsReadOnUpToTheBound(t *testing.T) {
	for _, tc := range []struct {
		name    string
		before  int64
		stalled bool
		want    int64
	}{
		{"refused after the body began", 1, false, lingerBytes},
		{"refused before the body began", 0, false, 0},
		{"refused after its body stalled, still coming", 1, true, lingerBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &endless{}
			body := &deadlineReader{r: src, extend: func() {}, hunk: 1 << 16, read: tc.before, stalled: tc.stalled}
			rec := httptest.NewRecorder()
			(&Server{}).lingerAfterRefusal(http.NewResponseController(rec), body)
			if src.n != tc.want {
				t.Fatalf("read %d bytes after the refusal; want %d", src.n, tc.want)
			}
		})
	}
	t.Run("refused after its body stalled, quiet", func(t *testing.T) {
		src := &silent{}
		body := &deadlineReader{r: src, extend: func() {}, hunk: 1 << 16, read: 1, stalled: true}
		(&Server{}).lingerAfterRefusal(http.NewResponseController(httptest.NewRecorder()), body)
		if src.reads != 1 {
			t.Fatalf("read %d times after the refusal; want once, stopping at the quiet read", src.reads)
		}
	})
}

// silent is a body whose every read times out, as a silent sender's does
// under the read deadline.
type silent struct{ reads int }

func (q *silent) Read(p []byte) (int, error) {
	q.reads++
	return 0, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
}

// failing is a body that gives a few bytes and then err.
type failing struct {
	gave bool
	err  error
}

func (f *failing) Read(p []byte) (int, error) {
	if !f.gave {
		f.gave = true
		return copy(p, "abcd"), nil
	}
	return 0, f.err
}

// A body is stalled only when a read ended on the connection's read
// deadline, wrapped as net/http and net give it; a sender that closed its
// side, or a connection that failed some other way, is not.
func TestABodyIsStalledOnlyByTheReadDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the read deadline", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, true},
		{"the end of the body", io.EOF, false},
		{"a short body", io.ErrUnexpectedEOF, false},
		{"a reset", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &deadlineReader{r: &failing{err: tc.err}, extend: func() {}, hunk: 1 << 16}
			io.Copy(io.Discard, body)
			if body.stalled != tc.want {
				t.Fatalf("stalled is %v after %v; want %v", body.stalled, tc.err, tc.want)
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

// Through the upload route: an attempt the hunk deadline ended is read on
// after its answer only while its body is still arriving. A sender silent
// with its side of the connection still open has its connection closed
// soon after the answer, within lingerIdle and well inside lingerWait,
// not held for bytes that are not coming; a sender still trickling below
// the hunk pace, which the deadline ends as well, is read on to the
// bound, as R42b needs, so the close does not reset the answer away.
func TestAStalledAttemptIsReadOnOnlyWhileItsBodyArrives(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trickle bool
	}{
		{"silent", false},
		{"still trickling", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{MaxBytes: 2048, StallTimeout: 200 * time.Millisecond})
			people := ids(t, "alice", "bob")
			alice, bob := people[0], people[1]
			h.register(alice)
			h.register(bob)
			blob := fakeStream(200, 8000)

			status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
			if status != http.StatusCreated {
				t.Fatalf("open: %d %s", status, body)
			}
			req, err := http.NewRequest("PUT", h.srv.URL+"/v1/uploads/"+opened.Upload, nil)
			if err != nil {
				t.Fatal(err)
			}
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
			fmt.Fprintf(&wire, "PUT %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %s\r\nConnection: close\r\n", req.URL.RequestURI(), req.Host, strconv.Itoa(len(blob)))
			for k, vs := range req.Header {
				for _, v := range vs {
					fmt.Fprintf(&wire, "%s: %s\r\n", k, v)
				}
			}
			wire.WriteString("\r\n")
			wire.Write(blob[:3000])
			if _, err := conn.Write(wire.Bytes()); err != nil {
				t.Fatal(err)
			}
			if tc.trickle {
				// One byte every 50 ms, from before the stall to past the
				// bound: far below the hunk pace, and never quiet for
				// lingerIdle. Within the blob, so the body never ends.
				stop := make(chan struct{})
				defer close(stop)
				go func() {
					for i := 3000; i < len(blob); i++ {
						select {
						case <-stop:
							return
						case <-time.After(50 * time.Millisecond):
						}
						if _, err := conn.Write(blob[i : i+1]); err != nil {
							return
						}
					}
				}()
			}
			conn.SetReadDeadline(time.Now().Add(lingerWait + 5*time.Second))
			r := bufio.NewReader(conn)
			resp, err := http.ReadResponse(r, req)
			if err != nil {
				t.Fatalf("the answer: %v", err)
			}
			answered := time.Now()
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(got), "kept for one resume") {
				t.Fatalf("a stalled attempt: %d %s; want 400 saying it is kept", resp.StatusCode, got)
			}
			if _, err := r.ReadByte(); err == nil {
				t.Fatal("more after the answer")
			}
			held := time.Since(answered)
			if !tc.trickle && held > lingerWait/2 {
				t.Fatalf("the connection closed %v after the answer; want it closed soon after, not held for the drain", held)
			}
			if tc.trickle && held < lingerWait-300*time.Millisecond {
				t.Fatalf("the connection closed %v after the answer with the body still arriving; want it read on for about %v", held, lingerWait)
			}
		})
	}
}
