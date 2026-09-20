package relay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// putRaw is one attempt at an upload written by hand on a connection of
// the test's own: the request line, the headers given, and then upTo
// bytes of the body from the offset. When closeWrite is set the test's
// side of the connection is closed after them, as a sender whose link
// dropped would; otherwise the connection stays open with nothing more
// sent, as a stalled sender's does. The answer is read from the same
// connection under a deadline, so a relay that waited on the body rather
// than answering fails the test in bounded time rather than hanging it.
func (h *harness) putRaw(from *identity.Identity, upload string, headers map[string]string,
	blob []byte, offset, upTo int, closeWrite bool, wait time.Duration) (int, []byte, http.Header, time.Duration) {
	h.t.Helper()
	req, err := http.NewRequest("PUT", h.srv.URL+"/v1/uploads/"+upload, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if err := relayapi.SignRequest(from, req, nil); err != nil {
		h.t.Fatal(err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		h.t.Fatal(err)
	}
	defer conn.Close()
	var wire bytes.Buffer
	fmt.Fprintf(&wire, "PUT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", req.URL.RequestURI(), req.Host)
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&wire, "%s: %s\r\n", k, v)
		}
	}
	wire.WriteString("\r\n")
	if upTo > offset {
		wire.Write(blob[offset:upTo])
	}
	start := time.Now()
	if _, err := conn.Write(wire.Bytes()); err != nil {
		h.t.Fatal(err)
	}
	if closeWrite {
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			h.t.Fatal(err)
		}
	}
	conn.SetReadDeadline(time.Now().Add(wait))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		h.t.Fatalf("reading the answer to a hand-written attempt: %v", err)
	}
	defer resp.Body.Close()
	out := make([]byte, 0, 512)
	buf := make([]byte, 512)
	for {
		n, err := resp.Body.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			break
		}
	}
	return resp.StatusCode, out, resp.Header, time.Since(start)
}

// putParked is a first attempt written by hand that sends upTo bytes of
// the body and then calls parked while the connection stays open with
// nothing more coming; when parked returns the test's side is closed, as
// a sender whose link dropped would close it, and the answer is read
// under a deadline.
func (h *harness) putParked(from *identity.Identity, upload string, blob []byte, upTo int, parked func()) (int, []byte, http.Header) {
	h.t.Helper()
	req, err := http.NewRequest("PUT", h.srv.URL+"/v1/uploads/"+upload, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.ContentLength = int64(len(blob))
	req.Header.Set(relayapi.UploadOffsetHeader, "0")
	if err := relayapi.SignRequest(from, req, nil); err != nil {
		h.t.Fatal(err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		h.t.Fatal(err)
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
	wire.Write(blob[:upTo])
	if _, err := conn.Write(wire.Bytes()); err != nil {
		h.t.Fatal(err)
	}
	parked()
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		h.t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		h.t.Fatalf("reading the answer to a parked attempt: %v", err)
	}
	defer resp.Body.Close()
	out := make([]byte, 0, 512)
	buf := make([]byte, 512)
	for {
		n, err := resp.Body.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			break
		}
	}
	return resp.StatusCode, out, resp.Header
}

// uploadLeft reports the row and the file an upload has on the relay.
func (h *harness) uploadLeft(id string) (row bool, file int64) {
	h.t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads WHERE id = ?`, id).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	info, err := os.Stat(h.store.uploadPath(id))
	if err != nil {
		if !os.IsNotExist(err) {
			h.t.Fatal(err)
		}
		return n != 0, -1
	}
	return n != 0, info.Size()
}

// TestLimitAnAttemptRunsToTheEndOrKeepsNothing: the rule for an attempt
// that stops short, at the threshold's edges and one step past. With
// max_bytes 2048 as the threshold, a fresh attempt that stops at 2047
// bytes leaves no file and no row; one that stops at 2048 and one at
// 2049 each leave a partial of that many bytes with expires = now + 60 s,
// said in the answer; a resumed attempt from a kept partial that stops
// short deletes the upload whole, file and row, as the plan's settled
// point 5 has it (the plan's test line before that ruling had the file
// put back and the row kept), and the next attempt at the id is 404; a
// resumed attempt that runs to the end places the message, the answer's
// id in the recipient's listing. Before a byte of a body is read: an
// attempt whose offset and Content-Length do not reach the size is 400
// naming the rule (one short, one over, and the type's maximum, which
// the length check meets as a difference and never a sum), one with no
// Content-Length is 411, and one at the wrong offset is 409 carrying the
// offset the relay's copy ends at; the answers arrive with no body sent,
// and leave the partial as it was.
func TestLimitAnAttemptRunsToTheEndOrKeepsNothing(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: 2048})
	clock := h.clock
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	blob := fakeStream(200, 8000)
	open := func(t *testing.T) string {
		t.Helper()
		status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		if opened.ResumeThreshold != 2048 || opened.ResumeWindow != relayapi.ResumeWindowSeconds {
			t.Fatalf("the open announces threshold %d and window %d; want 2048 and %d",
				opened.ResumeThreshold, opened.ResumeWindow, relayapi.ResumeWindowSeconds)
		}
		return opened.Upload
	}

	t.Run("a fresh attempt one byte under the threshold keeps nothing", func(t *testing.T) {
		id := open(t)
		status, body, hdr := h.putPartial(alice, id, blob, 0, 2047)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "nothing is kept") {
			t.Fatalf("stopped at 2047: %d %s; want 400 saying nothing is kept", status, body)
		}
		if hdr.Get(relayapi.UploadOffsetHeader) != "0" {
			t.Errorf("the answer's offset is %q, want 0", hdr.Get(relayapi.UploadOffsetHeader))
		}
		if row, file := h.uploadLeft(id); row || file >= 0 {
			t.Fatalf("after 2047 bytes: row %v, file %d bytes; want neither", row, file)
		}
		if status, _, _ := h.putStream(alice, id, blob, 0); status != http.StatusNotFound {
			t.Errorf("the next attempt at the id: %d, want 404", status)
		}
	})

	for _, held := range []int{2048, 2049} {
		t.Run(fmt.Sprintf("a fresh attempt stopping at %d is kept for the window", held), func(t *testing.T) {
			id := open(t)
			want := clock.Now().Add(relayapi.ResumeWindow).UTC().Truncate(time.Second)
			status, body, hdr := h.putPartial(alice, id, blob, 0, held)
			if status != http.StatusBadRequest || !strings.Contains(string(body), "kept for one resume until "+want.Format(time.RFC3339)) {
				t.Fatalf("stopped at %d: %d %s; want 400 saying kept until %s", held, status, body, want.Format(time.RFC3339))
			}
			if hdr.Get(relayapi.UploadOffsetHeader) != strconv.Itoa(held) {
				t.Errorf("the answer's offset is %q, want %d", hdr.Get(relayapi.UploadOffsetHeader), held)
			}
			if row, file := h.uploadLeft(id); !row || file != int64(held) {
				t.Fatalf("after %d bytes: row %v, file %d bytes; want the row and %d bytes", held, row, file, held)
			}
			u, err := h.store.Upload(id)
			if err != nil || u.Received != int64(held) || !u.Expires.Equal(want) {
				t.Fatalf("the kept row: %+v %v; want received %d and expires %s", u, err, held, want)
			}
		})
	}

	t.Run("a resumed attempt that stops short deletes the upload whole", func(t *testing.T) {
		id := open(t)
		if status, body, _ := h.putPartial(alice, id, blob, 0, 3000); status != http.StatusBadRequest || !strings.Contains(string(body), "kept for one resume") {
			t.Fatalf("the first attempt: %d %s; want it kept at 3000", status, body)
		}
		status, body, hdr := h.putPartial(alice, id, blob, 3000, 6000)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "nothing is kept") {
			t.Fatalf("the resumed attempt stopping at 6000: %d %s; want 400 saying nothing is kept", status, body)
		}
		if hdr.Get(relayapi.UploadOffsetHeader) != "0" {
			t.Errorf("the answer's offset is %q, want 0: nothing is kept", hdr.Get(relayapi.UploadOffsetHeader))
		}
		if row, file := h.uploadLeft(id); row || file >= 0 {
			t.Fatalf("after the resumed attempt: row %v, file %d bytes; want neither", row, file)
		}
		if status, _, _ := h.putStream(alice, id, blob, 3000); status != http.StatusNotFound {
			t.Errorf("the next attempt at the id: %d, want 404", status)
		}
	})

	t.Run("a resumed attempt that runs to the end places the message", func(t *testing.T) {
		id := open(t)
		if status, body, _ := h.putPartial(alice, id, blob, 0, 3000); status != http.StatusBadRequest {
			t.Fatalf("the first attempt: %d %s; want it kept at 3000", status, body)
		}
		status, body, hdr := h.putStream(alice, id, blob, 3000)
		if status != http.StatusCreated {
			t.Fatalf("the resumed attempt to the end: %d %s; want 201", status, body)
		}
		if hdr.Get(relayapi.UploadOffsetHeader) != strconv.Itoa(len(blob)) {
			t.Errorf("the answer's offset is %q, want the size %d", hdr.Get(relayapi.UploadOffsetHeader), len(blob))
		}
		var placed relayapi.PutStreamResponse
		if err := json.Unmarshal(body, &placed); err != nil || placed.ID <= 0 {
			t.Fatalf("the answer: %s (%v); want a message id", body, err)
		}
		if row, file := h.uploadLeft(id); row || file >= 0 {
			t.Fatalf("after placement: row %v, file %d bytes; want neither", row, file)
		}
		status, listed := h.do(bob, "GET", "/v1/mailbox/"+bob.Fingerprint(), nil, nil)
		if status != http.StatusOK {
			t.Fatalf("bob's listing: %d %s", status, listed)
		}
		var list relayapi.ListResponse
		if err := json.Unmarshal(listed, &list); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, m := range list.Messages {
			if m.ID == placed.ID && m.Kind == relayapi.KindStream && m.Size == int64(len(blob)) {
				found = true
			}
		}
		if !found {
			t.Fatalf("message %d is not in bob's listing as a stream of %d bytes: %+v", placed.ID, len(blob), list.Messages)
		}
		if status, _, _ := h.putStream(alice, id, blob, 0); status != http.StatusNotFound {
			t.Errorf("an attempt at the placed upload: %d, want 404", status)
		}
	})

	t.Run("the three refusals before a byte is read", func(t *testing.T) {
		id := open(t)
		if status, body, _ := h.putPartial(alice, id, blob, 0, 3000); status != http.StatusBadRequest {
			t.Fatalf("the first attempt: %d %s; want it kept at 3000", status, body)
		}
		// Each request declares a body and sends none of it, the
		// connection left open: the answer can only come from a relay
		// that judged the headers.
		const wait = 5 * time.Second
		for _, tc := range []struct {
			name    string
			headers map[string]string
			status  int
			says    string
			offset  string
		}{
			{"not to the end", map[string]string{
				relayapi.UploadOffsetHeader: "3000", "Content-Length": strconv.Itoa(len(blob) - 3001),
			}, http.StatusBadRequest, relayapi.MsgNotToTheEnd, ""},
			{"past the end", map[string]string{
				relayapi.UploadOffsetHeader: "3000", "Content-Length": strconv.Itoa(len(blob) - 2999),
			}, http.StatusBadRequest, relayapi.MsgNotToTheEnd, ""},
			{"the type's maximum", map[string]string{
				relayapi.UploadOffsetHeader: "3000", "Content-Length": strconv.FormatInt(math.MaxInt64, 10),
			}, http.StatusBadRequest, relayapi.MsgNotToTheEnd, ""},
			{"no length", map[string]string{
				relayapi.UploadOffsetHeader: "3000", "Transfer-Encoding": "chunked",
			}, http.StatusLengthRequired, relayapi.MsgLengthRequired, ""},
			{"wrong offset", map[string]string{
				relayapi.UploadOffsetHeader: "0", "Content-Length": strconv.Itoa(len(blob)),
			}, http.StatusConflict, "resume from there", "3000"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				status, body, hdr, took := h.putRaw(alice, id, tc.headers, blob, 0, 0, false, wait)
				if status != tc.status || !strings.Contains(string(body), tc.says) {
					t.Fatalf("%d %s; want %d saying %q", status, body, tc.status, tc.says)
				}
				if took >= wait {
					t.Fatalf("the answer took %s; it waited on a body that was never sent", took)
				}
				if tc.offset != "" && hdr.Get(relayapi.UploadOffsetHeader) != tc.offset {
					t.Errorf("the answer's offset is %q, want %s", hdr.Get(relayapi.UploadOffsetHeader), tc.offset)
				}
				if row, file := h.uploadLeft(id); !row || file != 3000 {
					t.Fatalf("after the refusal: row %v, file %d bytes; want the partial as it was", row, file)
				}
			})
		}
	})
}

// TestLimitTheResumeWindowIsSixtySeconds: a kept partial may be resumed
// for sixty seconds on the relay's clock and no longer. A resume 59 s
// after the partial was kept is taken, one at 60 s is taken (the edge is
// inclusive: at exactly expires the upload is still here), and one at
// 61 s is 410 with the partial gone, file and row; a partial nobody
// resumes is gone at the first purge past its window. The announced
// window's shape as the client reads it is TestLimitRelayAnswerIntegers'
// seconds row, in internal/client.
func TestLimitTheResumeWindowIsSixtySeconds(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: 2048})
	clock := h.clock
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	blob := fakeStream(200, 8000)
	kept := func(t *testing.T) string {
		t.Helper()
		status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		if status, body, _ := h.putPartial(alice, opened.Upload, blob, 0, 3000); status != http.StatusBadRequest || !strings.Contains(string(body), "kept for one resume") {
			t.Fatalf("the first attempt: %d %s; want it kept at 3000", status, body)
		}
		return opened.Upload
	}

	for _, tc := range []struct {
		after  time.Duration
		status int
	}{
		{59 * time.Second, http.StatusCreated},
		{60 * time.Second, http.StatusCreated},
		{61 * time.Second, http.StatusGone},
	} {
		t.Run(fmt.Sprintf("a resume %s after the partial was kept", tc.after), func(t *testing.T) {
			id := kept(t)
			clock.advance(tc.after)
			status, body, _ := h.putStream(alice, id, blob, 3000)
			if status != tc.status {
				t.Fatalf("%d %s; want %d", status, body, tc.status)
			}
			if row, file := h.uploadLeft(id); row || file >= 0 {
				t.Fatalf("after the resume: row %v, file %d bytes; want neither, placed or gone", row, file)
			}
		})
	}

	t.Run("a partial nobody resumes is purged past its window", func(t *testing.T) {
		id := kept(t)
		clock.advance(60 * time.Second)
		if purged, _, err := h.store.PurgeUploads(clock.Now()); err != nil || len(purged) != 0 {
			t.Fatalf("a purge at the edge: purged %d (%v); want none, the edge being inclusive", len(purged), err)
		}
		if row, file := h.uploadLeft(id); !row || file != 3000 {
			t.Fatalf("at the edge: row %v, file %d bytes; want the partial still there", row, file)
		}
		clock.advance(time.Second)
		if purged, _, err := h.store.PurgeUploads(clock.Now()); err != nil || len(purged) != 1 {
			t.Fatalf("a purge one past the edge: purged %d (%v); want the one partial", len(purged), err)
		}
		if row, file := h.uploadLeft(id); row || file >= 0 {
			t.Fatalf("after the purge: row %v, file %d bytes; want neither", row, file)
		}
	})
}

// TestLimitTheWindowRunsFromWhenTheAttemptStopped: the sixty seconds a
// kept partial lives are counted from the moment the attempt stopped,
// read from the relay's clock once the copy has ended, and not from when
// the request began. The first cut stamped expires before the copy, so a
// first attempt whose transfer ran longer than the window before its link
// dropped was kept already expired, and at the shipped stall deadline of
// sixty seconds every stall-cut partial was: the large upload the kept
// rule exists for met 410 on its resume. Here a first attempt past the
// threshold is parked with its bytes on the disk — the copy has begun, so
// any moment the handler read before it has passed — while the clock
// moves ninety seconds, then closed; the row's expires and the answer's
// sentence say stop + 60 s, a resume at stop + 59 s is taken and one at
// stop + 61 s is 410 with the partial gone.
func TestLimitTheWindowRunsFromWhenTheAttemptStopped(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: 2048})
	clock := h.clock
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	blob := fakeStream(200, 8000)
	parked := func(t *testing.T) (id string, stop time.Time) {
		t.Helper()
		status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		status, body, hdr := h.putParked(alice, opened.Upload, blob, 3000, func() {
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, file := h.uploadLeft(opened.Upload); file == 3000 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the 3000 bytes never reached the disk")
				}
				time.Sleep(5 * time.Millisecond)
			}
			clock.advance(90 * time.Second)
			stop = clock.Now()
		})
		want := stop.Add(relayapi.ResumeWindow).UTC().Truncate(time.Second)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "kept for one resume until "+want.Format(time.RFC3339)) {
			t.Fatalf("the parked attempt: %d %s; want 400 saying kept until %s, the window from the stop", status, body, want.Format(time.RFC3339))
		}
		if hdr.Get(relayapi.UploadOffsetHeader) != "3000" {
			t.Errorf("the answer's offset is %q, want 3000", hdr.Get(relayapi.UploadOffsetHeader))
		}
		u, err := h.store.Upload(opened.Upload)
		if err != nil || u.Received != 3000 || !u.Expires.Equal(want) {
			t.Fatalf("the kept row: %+v %v; want received 3000 and expires %s, sixty seconds from the stop and not from the start", u, err, want)
		}
		return opened.Upload, stop
	}

	for _, tc := range []struct {
		after  time.Duration
		status int
	}{
		{59 * time.Second, http.StatusCreated},
		{61 * time.Second, http.StatusGone},
	} {
		t.Run(fmt.Sprintf("a resume %s after the attempt stopped", tc.after), func(t *testing.T) {
			id, _ := parked(t)
			clock.advance(tc.after)
			status, body, _ := h.putStream(alice, id, blob, 3000)
			if status != tc.status {
				t.Fatalf("%d %s; want %d", status, body, tc.status)
			}
			if row, file := h.uploadLeft(id); row || file >= 0 {
				t.Fatalf("after the resume: row %v, file %d bytes; want neither, placed or gone", row, file)
			}
		})
	}
}

// TestLimitAStalledPutEndsInsideTheWindow: a sender that stops sending
// part way through an attempt and keeps the connection open is cut by
// the relay's stall deadline, not the server's five-minute read timeout,
// and the attempt is judged as one that stopped short: past the threshold
// the partial is kept and the answer says so; under it nothing is kept.
// The stall timeout is the server's own field, set to 200 ms here on a
// loopback connection, and the wall time from the last byte to the answer
// is bounded by the test at two seconds; under the default the same
// deadline is the resume window.
func TestLimitAStalledPutEndsInsideTheWindow(t *testing.T) {
	h := newHarness(t, Config{MaxBytes: 2048, StallTimeout: 200 * time.Millisecond})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	blob := fakeStream(200, 8000)
	const bound = 2 * time.Second

	for _, tc := range []struct {
		name string
		upTo int
		says string
		row  bool
		file int64
	}{
		{"past the threshold, kept", 3000, "kept for one resume", true, 3000},
		{"under the threshold, nothing kept", 1000, "nothing is kept", false, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
			if status != http.StatusCreated {
				t.Fatalf("open: %d %s", status, body)
			}
			headers := map[string]string{
				relayapi.UploadOffsetHeader: "0",
				"Content-Length":            strconv.Itoa(len(blob)),
			}
			status, body, hdr, took := h.putRaw(alice, opened.Upload, headers, blob, 0, tc.upTo, false, bound)
			if status != http.StatusBadRequest || !strings.Contains(string(body), tc.says) {
				t.Fatalf("a stalled attempt after %d bytes: %d %s; want 400 saying %q", tc.upTo, status, body, tc.says)
			}
			if took >= bound {
				t.Fatalf("the answer took %s; the stall deadline did not end the attempt", took)
			}
			if got := hdr.Get(relayapi.UploadOffsetHeader); got != strconv.FormatInt(max(tc.file, 0), 10) {
				t.Errorf("the answer's offset is %q, want %d", got, max(tc.file, 0))
			}
			if row, file := h.uploadLeft(opened.Upload); row != tc.row || file != tc.file {
				t.Fatalf("after the stall: row %v, file %d bytes; want row %v, file %d", row, file, tc.row, tc.file)
			}
		})
	}
}

// TestLimitOneByteAttemptsCostOneRequestEach: the trickle property under
// the one-attempt wire, re-pointed from the append wire's. A sender
// cannot build a stream up on the relay a byte at a time: nothing is kept
// of an attempt that stops under the threshold, a message is placed by
// at most two attempts that left bytes on one id (the first, kept only
// past the threshold, and the one resume, which places or deletes), and
// each attempt is one request against requests_per_minute whatever it
// delivered. With a budget of six requests: the open is one; a one-byte
// attempt keeps nothing and the id is gone (two); a second open (three)
// and an attempt kept at the threshold (four); a one-byte resume deletes
// the upload whole (five); an attempt at the gone id is 404 and the sixth
// request; the seventh is 429. Bytes on the relay at the end: none.
func TestLimitOneByteAttemptsCostOneRequestEach(t *testing.T) {
	const budget = 6
	h := newHarness(t, Config{MaxBytes: 2048, Limits: Limits{RequestsPerMinute: budget}})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	blob := fakeStream(200, 8000)
	// Registration spent requests of alice's; a fresh minute for the count.
	h.clock.advance(time.Minute)

	status, first, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
	if status != http.StatusCreated {
		t.Fatalf("open (1): %d %s", status, body)
	}
	if status, body, _ := h.putPartial(alice, first.Upload, blob, 0, 1); status != http.StatusBadRequest || !strings.Contains(string(body), "nothing is kept") {
		t.Fatalf("a one-byte attempt (2): %d %s; want 400 saying nothing is kept", status, body)
	}
	if row, file := h.uploadLeft(first.Upload); row || file >= 0 {
		t.Fatalf("after one byte: row %v, file %d bytes; want neither", row, file)
	}
	status, second, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
	if status != http.StatusCreated {
		t.Fatalf("open (3): %d %s", status, body)
	}
	if status, body, _ := h.putPartial(alice, second.Upload, blob, 0, 2048); status != http.StatusBadRequest || !strings.Contains(string(body), "kept for one resume") {
		t.Fatalf("an attempt at the threshold (4): %d %s; want it kept", status, body)
	}
	if status, body, _ := h.putPartial(alice, second.Upload, blob, 2048, 2049); status != http.StatusBadRequest || !strings.Contains(string(body), "nothing is kept") {
		t.Fatalf("a one-byte resume (5): %d %s; want 400 saying nothing is kept", status, body)
	}
	if row, file := h.uploadLeft(second.Upload); row || file >= 0 {
		t.Fatalf("after the one-byte resume: row %v, file %d bytes; want neither", row, file)
	}
	if status, body, _ := h.putStream(alice, second.Upload, blob, 2049); status != http.StatusNotFound {
		t.Fatalf("an attempt at the gone id (6): %d %s; want 404", status, body)
	}
	if status, body, _ := h.putStream(alice, second.Upload, blob, 0); status != http.StatusTooManyRequests {
		t.Fatalf("the seventh request in the minute: %d %s; want 429, each attempt having cost one", status, body)
	}
	var rows int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(h.store.uploadDir())
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if rows != 0 || len(entries) != 0 {
		t.Fatalf("%d upload rows and %d files remain; want none: a trickle leaves nothing", rows, len(entries))
	}
}

// TestADownloadResumesByRange: a receiver that holds the first half of a
// stored stream asks for the rest from there and gets exactly the rest,
// 206 with the range said, the two halves together being the stream; a
// Range from the end or past it is 416 with the size said. The blob
// route serves through http.ServeContent, which is what does the range
// arithmetic; the test holds it to the answers a receiver's resume
// depends on.
func TestADownloadResumesByRange(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	blob := fakeStream(200, 8000)
	id := h.uploadStream(alice, bob.Fingerprint(), blob)
	path := "/v1/mailbox/" + bob.Fingerprint() + "/" + strconv.FormatInt(id, 10) + "/blob"
	half := len(blob) / 2

	status, first, hdr := h.send(bob, "GET", path, nil, map[string]string{"Range": "bytes=0-" + strconv.Itoa(half-1)})
	if status != http.StatusPartialContent || len(first) != half {
		t.Fatalf("the first half: %d, %d bytes; want 206 with %d bytes", status, len(first), half)
	}
	status, rest, hdr := h.send(bob, "GET", path, nil, map[string]string{"Range": "bytes=" + strconv.Itoa(half) + "-"})
	if status != http.StatusPartialContent {
		t.Fatalf("the rest from %d: %d %s; want 206", half, status, rest)
	}
	if want := fmt.Sprintf("bytes %d-%d/%d", half, len(blob)-1, len(blob)); hdr.Get("Content-Range") != want {
		t.Errorf("Content-Range %q, want %q", hdr.Get("Content-Range"), want)
	}
	if !bytes.Equal(append(first, rest...), blob) {
		t.Fatalf("the two halves are not the stream: %d + %d bytes of %d", len(first), len(rest), len(blob))
	}
	for _, from := range []int{len(blob), len(blob) + 1} {
		status, body, hdr := h.send(bob, "GET", path, nil, map[string]string{"Range": "bytes=" + strconv.Itoa(from) + "-"})
		if status != http.StatusRequestedRangeNotSatisfiable {
			t.Errorf("a range from %d of %d: %d %s; want 416", from, len(blob), status, body)
		}
		if want := "bytes */" + strconv.Itoa(len(blob)); hdr.Get("Content-Range") != want {
			t.Errorf("a range from %d: Content-Range %q, want %q", from, hdr.Get("Content-Range"), want)
		}
	}
}
