package relay

// An upload is fed from its first ten seconds, hunk by hunk, and opens are
// counted (D82). The first three tests are the second review's for F1, kept
// under names that say what they now prove with their assertions as
// written; the two TestLimit tests are the hunk's edge and the opens cap.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// trickle starts one attempt on an upload that sends the stream a byte
// at a time, every `every`, for as long as the test lets it: an honest
// attempt in every respect the relay can judge, only slow. The returned
// function closes the connection, which ends the attempt short.
func trickle(t *testing.T, h *harness, from *identity.Identity, upload string, blob []byte, every time.Duration) (stop func(), sent *atomic.Int64) {
	t.Helper()
	req, err := http.NewRequest("PUT", h.srv.URL+"/v1/uploads/"+upload, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(relayapi.UploadOffsetHeader, "0")
	if err := relayapi.SignRequest(from, req, nil); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var head bytes.Buffer
	fmt.Fprintf(&head, "PUT %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n", req.URL.RequestURI(), req.Host, len(blob))
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	head.WriteString("\r\n")
	if _, err := conn.Write(head.Bytes()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	sent = &atomic.Int64{}
	go func() {
		tick := time.NewTicker(every)
		defer tick.Stop()
		for i := 0; i < len(blob); i++ {
			select {
			case <-done:
				return
			case <-tick.C:
			}
			if _, err := conn.Write(blob[i : i+1]); err != nil {
				return
			}
			sent.Add(1)
		}
	}()
	var once atomic.Bool
	stop = func() {
		if once.CompareAndSwap(false, true) {
			close(done)
			conn.Close()
		}
	}
	t.Cleanup(stop)
	return stop, sent
}

// TestATrickledAttemptIsCutAtTheHunkWindow: the review found that an
// attempt in flight holds its upload's lock, the purge and the 507 path's
// purge pass over a locked upload, and the stall deadline moved on every
// byte, so a sender trickling a byte inside each window kept its
// reservation as long as it liked for the one charge its open made; one
// identity with post_bytes_per_hour a quarter of the mailbox opened a
// quarter each hour and held the whole mailbox past every expiry. The
// attempt's deadline now moves only when a whole hunk, relayapi.HunkBytes,
// has arrived since it last moved (D82), so each trickled attempt is cut
// within the window from its start, under the threshold, leaving nothing:
// the reservation goes with it, and an honest post four hours on is taken
// and listed to the victim.
func TestATrickledAttemptIsCutAtTheHunkWindow(t *testing.T) {
	holdMailbox(t, true)
}

// TestAnUnfedOpenIsLetGoAtTenSeconds is the control for the test above:
// the same four opens an hour apart with no attempt in flight, and the
// honest post's 507 path purges the expired reservations and is taken.
// And the edge of the start window on the relay's clock: an attempt
// started exactly relayapi.StartWindow after the open is taken, the edge
// being inclusive, and one a second past it is refused 410 as gone, the
// row with it.
func TestAnUnfedOpenIsLetGoAtTenSeconds(t *testing.T) {
	t.Run("four unfed opens an hour apart", func(t *testing.T) {
		holdMailbox(t, false)
	})

	h := newHarness(t, Config{})
	alice, bob := h.user(t, "alice"), h.user(t, "bob")
	blob := fakeStream(200, 3000)
	t.Run("an attempt at the start window is taken", func(t *testing.T) {
		status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		h.clock.advance(relayapi.StartWindow)
		if status, body, _ := h.putStream(alice, opened.Upload, blob, 0); status != http.StatusCreated {
			t.Fatalf("an attempt %s after the open: %d %s; want 201, the edge being inclusive",
				relayapi.StartWindow, status, body)
		}
	})
	t.Run("an attempt a second past it is gone", func(t *testing.T) {
		status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		h.clock.advance(relayapi.StartWindow + time.Second)
		status, body, _ = h.putStream(alice, opened.Upload, blob, 0)
		if status != http.StatusGone || !strings.Contains(string(body), "expired at "+opened.Expires.UTC().Format(time.RFC3339)) {
			t.Fatalf("an attempt %s after the open: %d %s; want 410 saying it expired at %s",
				relayapi.StartWindow+time.Second, status, body, opened.Expires.UTC().Format(time.RFC3339))
		}
		if row, file := h.uploadLeft(opened.Upload); row || file >= 0 {
			t.Fatalf("after the refusal: row %v, file %d; want neither", row, file)
		}
	})
}

func holdMailbox(t *testing.T, trickled bool) {
	const quota = int64(4 << 20)
	const budget = quota / 4 // the defaults' ratio: 256 MiB an hour, 1 GiB a mailbox
	const reserve = budget - 64
	stall := 400 * time.Millisecond
	h := newHarness(t, Config{
		Limits:       Limits{MailboxMaxBytes: quota, PostBytesPerHour: budget, MaxOpenUploads: 4},
		StallTimeout: stall,
	})
	attacker, victim, sender := h.user(t, "attacker"), h.user(t, "victim"), h.user(t, "sender")
	to := victim.Fingerprint()
	blob := fakeStream(200, int(reserve)-stream.HeaderSize-200)
	if int64(len(blob)) != reserve {
		t.Fatalf("the test stream is %d bytes, want %d", len(blob), reserve)
	}

	var trickles []*atomic.Int64
	uncut := false
	for hour := range 4 {
		status, opened, body := h.openStream(attacker, to, reserve)
		if status != http.StatusCreated {
			t.Fatalf("hour %d: open of %d bytes with a budget of %d: %d %s", hour, reserve, budget, status, body)
		}
		if trickled {
			_, sent := trickle(t, h, attacker, opened.Upload, blob, stall/4)
			trickles = append(trickles, sent)
		}
		// Let the attempt start, so its lock is held, then let the relay's
		// clock run an hour: the upload's expiry passes and the budget
		// refills.
		time.Sleep(3 * stall)
		if trickled && !uncut {
			// The trickled attempt is cut within its window from its
			// start, leaving nothing under the threshold. Polled, not
			// assumed: a loaded machine answers late, and a deadline every
			// byte moved never cuts it at all. Said and not fatal, so the
			// test goes on to the honest post the review asserted on.
			deadline := time.Now().Add(5 * time.Second)
			for {
				if row, _ := h.uploadLeft(opened.Upload); !row {
					break
				}
				if time.Now().After(deadline) {
					t.Errorf("hour %d: the trickled attempt still holds its upload %s after its start, "+
						"with %d bytes sent; want it cut at the hunk window of %s", hour, 3*stall+5*time.Second,
						trickles[len(trickles)-1].Load(), stall)
					uncut = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		h.clock.advance(time.Hour)
	}
	h.clock.advance(10 * time.Minute)
	// Several stall deadlines of wall time.
	time.Sleep(4 * stall)

	var sentTotal int64
	for _, s := range trickles {
		sentTotal += s.Load()
	}
	status, body := h.do(sender, "POST", "/v1/mailbox/"+to, sealed(t, sender, victim.Public(), "hello"), nil)
	_, listBody := h.do(victim, "GET", "/v1/mailbox/"+to, nil, nil)
	var l relayapi.ListResponse
	_ = json.Unmarshal(listBody, &l)
	t.Logf("one identity, 4 opens of %d an hour apart, %d bytes trickled in all, 4h10m past the first expiry: honest post %d %s; victim sees queued %d",
		reserve, sentTotal, status, body, l.Queued)
	if status == http.StatusInsufficientStorage {
		t.Errorf("one identity with post_bytes_per_hour a quarter of the mailbox holds the whole mailbox full past every reservation's expiry, "+
			"by trickling %d bytes in all; the guide says it takes four identities, each holding a minute or more", sentTotal)
	}
	if status != http.StatusOK {
		t.Errorf("the honest post: %d %s; want 200", status, body)
	}
	if l.Queued < 1 {
		t.Errorf("the victim's listing shows queued %d; want the honest post: %s", l.Queued, listBody)
	}
}

// TestAnHonestSenderOpensOneStreamOfNearlyItsBudget answers the question
// the first-cycle refusal of the original churn test raised: the 429
// there is the second open (cycle index 1) after an unfed abort, not the
// first. One open of nearly the hourly budget is taken, charged once, and
// placed.
func TestAnHonestSenderOpensOneStreamOfNearlyItsBudget(t *testing.T) {
	const quota = int64(1 << 20)
	h := newHarness(t, Config{Limits: Limits{MailboxMaxBytes: quota, PostBytesPerHour: quota, MaxOpenUploads: 4}})
	alice, bob := h.user(t, "alice"), h.user(t, "bob")
	blob := fakeStream(200, int(quota-64)-stream.HeaderSize-200)
	status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
	if status != http.StatusCreated {
		t.Fatalf("one open of %d against a budget of %d: %d %s", len(blob), quota, status, body)
	}
	if got := left(h.server.lim.postBytes, alice.Fingerprint()); got != quota-int64(len(blob)) {
		t.Fatalf("after one open the budget holds %d, want %d (charged once)", got, quota-int64(len(blob)))
	}
	if status, body, _ := h.putStream(alice, opened.Upload, blob, 0); status != http.StatusCreated {
		t.Fatalf("the upload: %d %s", status, body)
	}
}

// pace is one step of a paced attempt: after waiting `after`, the bytes
// of the stream up to upTo are written.
type pace struct {
	after time.Duration
	upTo  int
}

// putPaced is a first attempt written by hand on a connection of the
// test's own, its body sent in the steps given. The answer is read from
// the same connection by a goroutine from the start, so an attempt the
// relay cuts is seen as answered and no more of the body is written to a
// connection the relay has finished with. took is from the moment the
// request's head and first step were written to the answer.
func (h *harness) putPaced(from *identity.Identity, upload string, blob []byte, steps []pace, wait time.Duration) (int, []byte, time.Duration) {
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
	var head bytes.Buffer
	fmt.Fprintf(&head, "PUT %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n", req.URL.RequestURI(), req.Host, req.ContentLength)
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	head.WriteString("\r\n")

	type answer struct {
		status int
		body   []byte
		err    error
		at     time.Time
	}
	answered := make(chan answer, 1)
	conn.SetReadDeadline(time.Now().Add(wait))
	go func() {
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			answered <- answer{err: err, at: time.Now()}
			return
		}
		defer resp.Body.Close()
		var out bytes.Buffer
		out.ReadFrom(resp.Body)
		answered <- answer{status: resp.StatusCode, body: out.Bytes(), at: time.Now()}
	}()

	sent := 0
	var start time.Time
	var got *answer
	for i, s := range steps {
		if i > 0 {
			select {
			case a := <-answered:
				got = &a
			case <-time.After(s.after):
			}
			if got != nil {
				break
			}
		}
		chunk := blob[sent:s.upTo]
		if i == 0 {
			chunk = append(head.Bytes(), chunk...)
		}
		if _, err := conn.Write(chunk); err != nil {
			break
		}
		if i == 0 {
			start = time.Now()
		}
		sent = s.upTo
	}
	if got == nil {
		a := <-answered
		got = &a
	}
	if got.err != nil {
		h.t.Fatalf("reading the answer to a paced attempt after %d of %d bytes: %v", sent, len(blob), got.err)
	}
	return got.status, got.body, got.at.Sub(start)
}

// TestLimitAnAttemptsDeadlineMovesOnlyByAWholeHunk: an attempt's read and
// write deadlines run a window from its start and move by the window only
// when a whole relayapi.HunkBytes has arrived since they last moved
// (D82). The window is the stall timeout, set short here on loopback as
// TestLimitAStalledPutEndsInsideTheWindow sets it; the deadline is the
// wall clock's. A hunk less one byte at once and nothing more is cut
// within the window from the start, as stopped short. A hunk less two
// bytes, one more byte inside the window and the rest past it is cut at
// the window, since a hunk less one byte has not moved the deadline,
// where a deadline every byte moved would take it. A hunk less one byte,
// the byte that completes the hunk inside the window and the rest past
// the first window is placed: the hunk's edge is at exactly HunkBytes.
// And whole hunks, each inside the window of the last, are placed however
// long the whole takes.
func TestLimitAnAttemptsDeadlineMovesOnlyByAWholeHunk(t *testing.T) {
	const window = 600 * time.Millisecond
	const slack = 1500 * time.Millisecond
	// max_bytes 2048, the threshold, so what a cut attempt delivered is
	// kept and its answer says how much that was.
	h := newHarness(t, Config{MaxBytes: 2048, StallTimeout: window})
	alice, bob := h.user(t, "alice"), h.user(t, "bob")
	const hunk = relayapi.HunkBytes
	blob := fakeStream(200, 4*hunk)
	size := len(blob)
	open := func(t *testing.T) string {
		t.Helper()
		status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(size))
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		return opened.Upload
	}
	short := func(at int) string {
		return fmt.Sprintf("the attempt stopped short at %d of %d bytes; kept for one resume", at, size)
	}

	t.Run("a hunk less one byte, then nothing, is cut at the window", func(t *testing.T) {
		id := open(t)
		status, body, took := h.putPaced(alice, id, blob, []pace{{0, hunk - 1}}, window+slack+5*time.Second)
		if status != http.StatusBadRequest || !strings.Contains(string(body), short(hunk-1)) {
			t.Fatalf("a hunk less one byte and then nothing: %d %s; want 400 saying %q", status, body, short(hunk-1))
		}
		if took >= window+slack {
			t.Fatalf("the attempt was cut %s after its start; want within the window of %s and %s of slack", took, window, slack)
		}
		if row, file := h.uploadLeft(id); !row || file != hunk-1 {
			t.Fatalf("after the cut: row %v, file %d; want the %d bytes kept", row, file, hunk-1)
		}
	})

	t.Run("a hunk less one byte does not move the deadline", func(t *testing.T) {
		id := open(t)
		status, body, _ := h.putPaced(alice, id, blob, []pace{
			{0, hunk - 2},
			{window * 6 / 10, hunk - 1},
			{window * 7 / 10, size},
		}, window+slack+5*time.Second)
		if status != http.StatusBadRequest || !strings.Contains(string(body), short(hunk-1)) {
			t.Fatalf("a hunk less one byte in two parts, the rest past the window: %d %s; want 400 saying %q",
				status, body, short(hunk-1))
		}
		if row, file := h.uploadLeft(id); !row || file != hunk-1 {
			t.Fatalf("after the cut: row %v, file %d; want the %d bytes kept", row, file, hunk-1)
		}
	})

	t.Run("the byte that completes a hunk moves the deadline", func(t *testing.T) {
		id := open(t)
		status, body, _ := h.putPaced(alice, id, blob, []pace{
			{0, hunk - 1},
			{window * 6 / 10, hunk},
			{window * 7 / 10, size},
		}, window+slack+5*time.Second)
		if status != http.StatusCreated {
			t.Fatalf("a hunk less one byte, its last byte inside the window, the rest past the first window: %d %s; want 201",
				status, body)
		}
	})

	t.Run("whole hunks inside the window are placed however long they take", func(t *testing.T) {
		id := open(t)
		steps := []pace{{0, hunk}}
		for n := 2; n <= 4; n++ {
			steps = append(steps, pace{window * 6 / 10, n * hunk})
		}
		steps = append(steps, pace{window * 6 / 10, size})
		status, body, took := h.putPaced(alice, id, blob, steps, 4*window+slack+5*time.Second)
		if status != http.StatusCreated {
			t.Fatalf("whole hunks %s apart: %d %s; want 201", window*6/10, status, body)
		}
		if took <= 2*window {
			t.Fatalf("the paced attempt took %s; it must outlast two windows of %s to show the deadline moved", took, window)
		}
	})
}

// TestLimitUploadOpensAtTheCapAndOneOver: one sender may open
// max_upload_opens_per_hour uploads an hour, whatever became of them
// (D82). At three: three opens are taken, the fourth is 429 naming the
// limit in its sentence and the log, with a Retry-After, and reserves
// nothing: no upload row, and the post-bytes budget as it stood. An open
// refused for a full mailbox or for the post-bytes budget spends no open,
// since it reserved nothing. An hour on the opens are there again.
func TestLimitUploadOpensAtTheCapAndOneOver(t *testing.T) {
	const opens = 3
	const quota = int64(1 << 20)
	const budget = int64(4 << 20)
	h := newHarness(t, Config{Limits: Limits{
		UploadOpensPerHour: opens, MaxOpenUploads: 1000, MailboxMaxBytes: quota, PostBytesPerHour: budget,
	}})
	alice, bob := h.user(t, "alice"), h.user(t, "bob")
	from, to := alice.Fingerprint(), bob.Fingerprint()
	const size = 4096
	rows := func() int {
		t.Helper()
		var n int
		if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	opensLeft := func() int64 { return left(h.server.lim.uploadOpens, from) }

	h.openOrFail(alice, to, size)
	h.openOrFail(alice, to, size)

	// A refusal that reserves nothing gives its open back: a mailbox too
	// small for the size, and a size past the post-bytes budget.
	if status, _, body := h.openStream(alice, to, quota+1); status != http.StatusInsufficientStorage {
		t.Fatalf("an open past the mailbox: %d %s; want 507", status, body)
	}
	if got := opensLeft(); got != 1 {
		t.Fatalf("after two opens and one refused 507 the sender has %d opens left, want 1", got)
	}
	if status, _, body := h.openStream(alice, to, budget); status != http.StatusTooManyRequests ||
		!strings.HasPrefix(errorText(t, body), "rate limited: post bytes") {
		t.Fatalf("an open past the post-bytes budget: %d %s; want 429 for post bytes", status, body)
	}
	if got := opensLeft(); got != 1 {
		t.Fatalf("after an open refused for post bytes the sender has %d opens left, want 1", got)
	}

	// At the cap: the third taken, the fourth refused.
	h.openOrFail(alice, to, size)
	beforeRows, beforeBytes := rows(), left(h.server.lim.postBytes, from)
	status, body, hdr := h.send(alice, "POST", "/v1/mailbox/"+to+"/streams", relayapi.OpenStreamRequest{Size: size}, nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("an open past the cap of %d an hour: %d %s; want 429", opens, status, body)
	}
	want := "rate limited: upload opens; a sender may open 3 uploads an hour on this relay"
	if got := errorText(t, body); got != want {
		t.Fatalf("the refusal says %q\nwant %q", got, want)
	}
	if secs := h.retryAfter(hdr); secs > 3600 {
		t.Fatalf("Retry-After %d, past the hour the opens refill in", secs)
	}
	if !strings.Contains(h.logs.String(), `limit="upload opens"`) {
		t.Fatalf("the refusal did not name its limit in the log:\n%s", h.logs.String())
	}
	if got := rows(); got != beforeRows {
		t.Fatalf("the refused open left %d upload rows, want %d as before it", got, beforeRows)
	}
	if got := left(h.server.lim.postBytes, from); got != beforeBytes {
		t.Fatalf("the refused open left the post-bytes budget at %d, want %d as before it", got, beforeBytes)
	}

	// An hour on, an open is taken again.
	h.clock.advance(time.Hour)
	h.openOrFail(alice, to, size)
	if got := opensLeft(); got != opens-1 {
		t.Fatalf("an hour on, after one open, the sender has %d opens left, want %d", got, opens-1)
	}

	// An open refused at max_open_uploads reserved nothing either, and
	// gives its open back: at one open at once and two an hour, the open
	// refused at the cap and the one after the abort make three asks, and
	// the third is taken only if the refused one was not counted.
	t.Run("an open refused at the open-uploads cap spends no open", func(t *testing.T) {
		h := newHarness(t, Config{Limits: Limits{UploadOpensPerHour: 2, MaxOpenUploads: 1}})
		alice, bob := h.user(t, "alice"), h.user(t, "bob")
		first := h.openOrFail(alice, bob.Fingerprint(), size)
		status, _, body := h.openStream(alice, bob.Fingerprint(), size)
		if status != http.StatusTooManyRequests || !strings.HasPrefix(errorText(t, body), "rate limited: open uploads;") {
			t.Fatalf("an open at the cap of one open at once: %d %s; want 429 for open uploads", status, body)
		}
		if got := left(h.server.lim.uploadOpens, alice.Fingerprint()); got != 1 {
			t.Fatalf("after one open and one refused at the cap the sender has %d opens left, want 1", got)
		}
		if status, body, _ := h.sendRaw(alice, "DELETE", "/v1/uploads/"+first, nil, nil); status != http.StatusNoContent {
			t.Fatalf("abort: %d %s", status, body)
		}
		if status, _, body := h.openStream(alice, bob.Fingerprint(), size); status != http.StatusCreated {
			t.Fatalf("the open after the abort: %d %s; want 201, the refused open's token given back", status, body)
		}
	})
}

// chunks is a reader that delivers its bytes n at a time, so a test can
// say where each read ends.
type chunks struct {
	left, n int
}

func (c *chunks) Read(p []byte) (int, error) {
	if c.left == 0 {
		return 0, io.EOF
	}
	k := min(c.n, c.left, len(p))
	c.left -= k
	return k, nil
}

// TestLimitAHunkDeadlineCreditsEveryByte: what a read brings past a
// hunk's edge counts toward the next hunk, so an attempt's deadline moves
// once for every whole hunk it has delivered, wherever its reads end. A
// network's reads rarely end on the edge, and a reader that dropped the
// remainder would cut an honest sender at exactly the pace. Reads of
// 40,000 bytes cross the edge part way: 200,000 bytes are three hunks and
// move the deadline three times, where dropping the remainder moves it
// twice; reads of a whole hunk, of one byte and of a hunk and a half each
// move it once per hunk delivered.
func TestLimitAHunkDeadlineCreditsEveryByte(t *testing.T) {
	for _, tc := range []struct {
		total, read int
	}{
		{200000, 40000},
		{relayapi.HunkBytes * 4, relayapi.HunkBytes},
		{relayapi.HunkBytes*2 + 1, 1},
		{relayapi.HunkBytes * 3, relayapi.HunkBytes * 3 / 2},
		{relayapi.HunkBytes - 1, 7},
	} {
		moves := 0
		d := &deadlineReader{r: &chunks{left: tc.total, n: tc.read}, extend: func() { moves++ }, hunk: relayapi.HunkBytes}
		buf := make([]byte, 1<<20)
		for {
			if _, err := d.Read(buf); err != nil {
				break
			}
		}
		if want := tc.total / relayapi.HunkBytes; moves != want {
			t.Errorf("%d bytes read %d at a time moved the deadline %d times, want %d, one per whole hunk",
				tc.total, tc.read, moves, want)
		}
	}
}

// TestLimitStreamWindowDefaults: the shipped pace is the protocol's. A
// relay built from a Config that sets no stall timeout waits
// relayapi.HunkWindow for an upload attempt's next hunk and
// relayapi.ResumeWindow for a blob reader's next byte; every other test
// sets the timeout short on loopback, so without this the windows a relay
// really runs with would be proved by nothing. A timeout set is both
// windows.
func TestLimitStreamWindowDefaults(t *testing.T) {
	s := newHarness(t, Config{}).server
	if got := s.hunkWindow(); got != relayapi.HunkWindow {
		t.Errorf("with no stall timeout an attempt waits %s for a hunk, want relayapi.HunkWindow, %s", got, relayapi.HunkWindow)
	}
	if got := s.stallTimeout(); got != relayapi.ResumeWindow {
		t.Errorf("with no stall timeout a blob reader is waited %s, want relayapi.ResumeWindow, %s", got, relayapi.ResumeWindow)
	}
	const short = 250 * time.Millisecond
	s = newHarness(t, Config{StallTimeout: short}).server
	if got, got2 := s.hunkWindow(), s.stallTimeout(); got != short || got2 != short {
		t.Errorf("with a stall timeout of %s the windows are %s and %s, want it for both", short, got, got2)
	}
}
