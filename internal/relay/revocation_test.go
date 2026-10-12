package relay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// An upload is held to the allow list and the channel at the start of
// every attempt and once before placement, not at the open alone (R22,
// commit 1a). TestARevokedSenderCannotFinishPreviouslyOpenedUpload is the
// review's regression for a whole attempt after revocation; these are the
// rest of the plan's list: the refusal before a byte is read, the
// revocation while an attempt runs, the channel closed under the open, the
// honest case unchanged, and what a refused attempt spends.

// revocationCase is a relay with a sender the owner's allow list admits
// and a third identity to name in its place when the sender is revoked.
type revocationCase struct {
	h                    *harness
	sender, owner, other *identity.Identity
	issued               time.Time
	blob                 []byte
}

func newRevocationCase(t *testing.T, cfg Config) *revocationCase {
	t.Helper()
	h := newHarness(t, cfg)
	people := ids(t, "sender", "owner", "other")
	c := &revocationCase{h: h, sender: people[0], owner: people[1], other: people[2],
		issued: time.Now().Add(-time.Minute), blob: fakeStream(200, 3000)}
	for _, id := range people {
		h.register(id)
	}
	c.allow(c.sender)
	return c
}

// allow pushes a list naming who, each push issued a second after the
// last so the relay takes it as newer.
func (c *revocationCase) allow(who *identity.Identity) {
	c.h.t.Helper()
	c.issued = c.issued.Add(time.Second)
	if status, body, _ := c.h.pushAllow(c.owner, c.owner, c.issued, who.Fingerprint()); status != http.StatusNoContent {
		c.h.t.Fatalf("allow list naming %s: %d %s", who.Name, status, body)
	}
}

// revoke takes the sender off the list by naming another in its place,
// since an empty list reopens the mailbox, and checks the store agrees.
func (c *revocationCase) revoke() {
	c.h.t.Helper()
	c.allow(c.other)
	if allowed, err := c.h.store.MayPost(c.owner.Fingerprint(), c.sender.Fingerprint()); err != nil || allowed {
		c.h.t.Fatalf("the revocation did not take: allowed=%v err=%v", allowed, err)
	}
}

// open opens the blob to the owner on ch and returns the upload id.
func (c *revocationCase) open(ch string) string {
	c.h.t.Helper()
	status, opened, body := c.h.openStreamTo(c.sender, c.owner.Fingerprint(), int64(len(c.blob)), ch)
	if status != http.StatusCreated {
		c.h.t.Fatalf("open: %d %s", status, body)
	}
	return opened.Upload
}

// keep leaves a partial of upTo bytes kept for one resume.
func (c *revocationCase) keep(id string, upTo int) {
	c.h.t.Helper()
	if status, body, _ := c.h.putPartial(c.sender, id, c.blob, 0, upTo); status != http.StatusBadRequest {
		c.h.t.Fatalf("a first attempt cut at %d: %d %s", upTo, status, body)
	}
	if u, err := c.h.store.Upload(id); err != nil || u.Received != int64(upTo) {
		c.h.t.Fatalf("the partial was not kept at %d: %+v %v", upTo, u, err)
	}
}

// gone asserts the upload has no row and no file, and the counters agree.
func (c *revocationCase) gone(id, when string) {
	c.h.t.Helper()
	if row, file := c.h.uploadLeft(id); row || file != -1 {
		c.h.t.Errorf("%s: the upload is still held: row %v, file %d bytes; want neither", when, row, file)
	}
	c.h.assertCountersAgree()
}

// listed is how many messages the owner's own listing shows.
func (c *revocationCase) listed() []relayapi.StoredMessage {
	c.h.t.Helper()
	status, body, _ := c.h.send(c.owner, "GET", "/v1/mailbox/"+c.owner.Fingerprint(), nil, nil)
	if status != http.StatusOK {
		c.h.t.Fatalf("the owner's listing: %d %s", status, body)
	}
	var list relayapi.ListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		c.h.t.Fatal(err)
	}
	return list.Messages
}

// answerOf decodes an error answer whole: its sentence, code and time.
func answerOf(t *testing.T, body []byte) relayapi.ErrorResponse {
	t.Helper()
	var e relayapi.ErrorResponse
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("response is not an error object: %s", body)
	}
	return e
}

// putHeadOnly is an attempt written by hand whose head declares the body
// from offset to the end and whose body is withheld: nothing after the
// blank line, and the connection left open. The request does not ask for
// the connection to close, so a relay that answers without its own
// Connection: close would first wait to discard the body it never read,
// and that wait is what the deadline catches. took is from the head's
// write to the answer.
func (h *harness) putHeadOnly(from *identity.Identity, upload string, size, offset int, wait time.Duration) (status int, body []byte, closed bool, took time.Duration) {
	h.t.Helper()
	req, err := http.NewRequest("PUT", h.srv.URL+"/v1/uploads/"+upload, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.ContentLength = int64(size - offset)
	req.Header.Set(relayapi.UploadOffsetHeader, strconv.Itoa(offset))
	if err := relayapi.SignRequest(from, req, nil); err != nil {
		h.t.Fatal(err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		h.t.Fatal(err)
	}
	defer conn.Close()
	var head bytes.Buffer
	fmt.Fprintf(&head, "PUT %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n", req.URL.RequestURI(), req.Host, req.ContentLength)
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	head.WriteString("\r\n")
	start := time.Now()
	if _, err := conn.Write(head.Bytes()); err != nil {
		h.t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(wait))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		h.t.Fatalf("no answer within %s to an attempt whose body was withheld: %v", wait, err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	out.ReadFrom(resp.Body)
	return resp.StatusCode, out.Bytes(), resp.Close, time.Since(start)
}

// putBetween is one attempt written by hand that sends the body from
// offset up to upTo, calls between while the relay is inside the copy
// (the bytes are on its disk, so the start-of-attempt judgement has
// passed), and then sends the rest. It returns the relay's answer.
func (h *harness) putBetween(from *identity.Identity, upload string, blob []byte, offset, upTo int, between func()) (int, []byte) {
	h.t.Helper()
	req, err := http.NewRequest("PUT", h.srv.URL+"/v1/uploads/"+upload, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.ContentLength = int64(len(blob) - offset)
	req.Header.Set(relayapi.UploadOffsetHeader, strconv.Itoa(offset))
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
	head.Write(blob[offset:upTo])
	if _, err := conn.Write(head.Bytes()); err != nil {
		h.t.Fatal(err)
	}
	// Observe the relay, not the client: the bytes on its disk say the
	// attempt is past its start and inside the copy, with the lock held.
	h.waitOnDisk(upload, int64(upTo))
	between()
	if _, err := conn.Write(blob[upTo:]); err != nil {
		h.t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		h.t.Fatalf("reading the answer to an attempt interrupted at %d: %v", upTo, err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	out.ReadFrom(resp.Body)
	return resp.StatusCode, out.Bytes()
}

// 1. A sender revoked after its open is refused at the start of an attempt
// before a byte of the body is read: the head alone is answered, 403 in
// the allow list's words with the connection closed, and the upload is
// gone, its row and its file, kept partial and all.
func TestARevokedSendersAttemptIsRefusedBeforeItsBodyIsRead(t *testing.T) {
	const bound = 5 * time.Second
	for _, kept := range []int{0, 2500} {
		t.Run(fmt.Sprintf("offset %d", kept), func(t *testing.T) {
			// The stall window is longer than the bound, so a relay that
			// read the body would still be waiting when the bound ran out.
			c := newRevocationCase(t, Config{MaxBytes: 2048, StallTimeout: time.Minute})
			id := c.open("")
			if kept > 0 {
				c.keep(id, kept)
			}
			c.revoke()
			status, body, closed, took := c.h.putHeadOnly(c.sender, id, len(c.blob), kept, bound)
			if status != http.StatusForbidden || errorText(t, body) != msgNotAllowed {
				t.Fatalf("an attempt after revocation: %d %s; want 403 %q", status, body, msgNotAllowed)
			}
			if took >= bound {
				t.Fatalf("the refusal took %s; it should come before the body", took)
			}
			if !closed {
				t.Error("the refusal left the connection open over a body it did not read; want Connection: close")
			}
			c.gone(id, "after the refusal")
			if n := len(c.listed()); n != 0 {
				t.Errorf("the owner's listing has %d messages; want none", n)
			}
		})
	}
}

// 2. A sender revoked while an attempt runs, the attempt past its start and
// its bytes on the disk, places nothing: the copy runs to the end, the
// placement's judgement refuses it in the allow list's words, and the
// upload is gone. A first attempt and a resume each.
func TestARevocationDuringAnAttemptRefusesThePlacement(t *testing.T) {
	for _, kept := range []int{0, 2500} {
		t.Run(fmt.Sprintf("offset %d", kept), func(t *testing.T) {
			c := newRevocationCase(t, Config{MaxBytes: 2048})
			id := c.open("")
			if kept > 0 {
				c.keep(id, kept)
			}
			status, body := c.h.putBetween(c.sender, id, c.blob, kept, between(kept), c.revoke)
			if status != http.StatusForbidden || errorText(t, body) != msgNotAllowed {
				t.Fatalf("an attempt whose sender was revoked mid-copy: %d %s; want 403 %q", status, body, msgNotAllowed)
			}
			if n := len(c.listed()); n != 0 {
				t.Errorf("the revoked sender placed %d messages; want none", n)
			}
			c.gone(id, "after the placement was refused")
		})
	}
}

// 3. A channel closed under an open upload refuses it, at the start of an
// attempt and at the placement, with the code and the sentence a post to
// a closed channel gets. It closes two ways: the relay's clock passing
// not_after, and the owner pushing a directory whose not_after has passed.
func TestAChannelClosedUnderAnUploadRefusesIt(t *testing.T) {
	type closer struct {
		name  string
		close func(c *revocationCase)
	}
	closers := []closer{
		{"by the clock", func(c *revocationCase) { c.h.clock.advance(2 * time.Second) }},
		{"by a new directory", func(c *revocationCase) {
			past := c.h.clock.Now().Add(-time.Second)
			if status, body, _ := c.h.pushDirectory(c.owner, c.owner, c.h.clock.Now().Add(time.Second), dflt,
				channels.Channel{Name: "cfp", NotAfter: &past}); status != http.StatusNoContent {
				c.h.t.Fatalf("closing push: %d %s", status, body)
			}
		}},
	}
	setup := func(t *testing.T) (*revocationCase, string) {
		c := newRevocationCase(t, Config{MaxBytes: 2048, StallTimeout: time.Minute})
		closes := c.h.clock.Now().Add(time.Second)
		if status, body, _ := c.h.pushDirectory(c.owner, c.owner, c.h.clock.Now(), dflt,
			channels.Channel{Name: "cfp", NotAfter: &closes}); status != http.StatusNoContent {
			t.Fatalf("push: %d %s", status, body)
		}
		return c, c.open("cfp")
	}
	check := func(t *testing.T, c *revocationCase, status int, body []byte, wantSentence string) {
		t.Helper()
		e := refusal(t, body)
		if status != http.StatusForbidden || e.Code != relayapi.CodeChannelClosed || e.Error != wantSentence {
			t.Fatalf("an attempt on a closed channel: %d %s; want 403 %s %q", status, body, relayapi.CodeChannelClosed, wantSentence)
		}
		if n := len(c.listed()); n != 0 {
			t.Errorf("a closed channel took %d messages; want none", n)
		}
	}
	for _, cl := range closers {
		for _, kept := range []int{0, 2500} {
			t.Run(fmt.Sprintf("%s, at the start, offset %d", cl.name, kept), func(t *testing.T) {
				c, id := setup(t)
				if kept > 0 {
					c.keep(id, kept)
				}
				cl.close(c)
				want := closedSentence(c)
				status, body, closed, _ := c.h.putHeadOnly(c.sender, id, len(c.blob), kept, 5*time.Second)
				check(t, c, status, body, want)
				if !closed {
					t.Error("the refusal left the connection open; want Connection: close")
				}
				c.gone(id, "after the refusal")
			})
		}
		t.Run(cl.name+", during an attempt", func(t *testing.T) {
			c, id := setup(t)
			status, body := c.h.putBetween(c.sender, id, c.blob, 0, between(0), func() { cl.close(c) })
			check(t, c, status, body, closedSentence(c))
			c.gone(id, "after the placement was refused")
		})
	}
}

// closedSentence is the sentence for cfp closed, as channels.OpenAt words
// it against the bound the relay now holds.
func closedSentence(c *revocationCase) string {
	c.h.t.Helper()
	_, ch, err := c.h.store.ChannelState(c.owner.Fingerprint(), "cfp")
	if err != nil || ch.NotAfter == nil {
		c.h.t.Fatalf("the channel's state: %+v %v", ch, err)
	}
	return `channel "cfp" is not open: closed ` + ch.NotAfter.UTC().Format(time.RFC3339)
}

// 4. A sender still admitted, on a channel still open, places as before:
// a whole first attempt, and a kept partial resumed, each 201 with the
// message listed under its channel, and an allow-list push mid-copy that
// still names the sender does not refuse the placement.
func TestAnAdmittedUploadStillPlaces(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kept    int
		midPush bool
	}{
		{"one whole attempt", 0, false},
		{"a kept partial resumed", 2500, false},
		{"a push naming the sender during the attempt", 0, true},
		{"a push naming the sender during the resume", 2500, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newRevocationCase(t, Config{MaxBytes: 2048})
			closes := c.h.clock.Now().Add(time.Hour)
			if status, body, _ := c.h.pushDirectory(c.owner, c.owner, c.h.clock.Now(), dflt,
				channels.Channel{Name: "cfp", NotAfter: &closes}); status != http.StatusNoContent {
				t.Fatalf("push: %d %s", status, body)
			}
			id := c.open("cfp")
			if tc.kept > 0 {
				c.keep(id, tc.kept)
			}
			var status int
			var body []byte
			if tc.midPush {
				status, body = c.h.putBetween(c.sender, id, c.blob, tc.kept, between(tc.kept), func() { c.allow(c.sender) })
			} else {
				status, body, _ = c.h.putStream(c.sender, id, c.blob, tc.kept)
			}
			if status != http.StatusCreated {
				t.Fatalf("an admitted attempt: %d %s; want 201", status, body)
			}
			msgs := c.listed()
			if len(msgs) != 1 || msgs[0].Channel != "cfp" {
				t.Fatalf("the owner's listing: %+v; want one message under cfp", msgs)
			}
			c.gone(id, "after the placement")
		})
	}
}

// 5. A refused attempt spends what a refused post spends: the request
// that carried it, and nothing given back. The open charged one post and
// the stream's bytes against post_bytes_per_hour; a refused attempt, at
// its start or at its placement, first attempt or resume, leaves both
// charged, as a post the allow list refuses keeps its post and its bytes,
// and spends one request more.
func TestARefusedAttemptSpendsWhatARefusedPostSpends(t *testing.T) {
	limits := Limits{RequestsPerMinute: 1000, PostsPerMinute: 1000, PostBytesPerHour: 1 << 20}
	type spent struct{ requests, posts, bytes int64 }
	measure := func(c *revocationCase) spent {
		fp := c.sender.Fingerprint()
		return spent{left(c.h.server.lim.requests, fp), left(c.h.server.lim.posts, fp), left(c.h.server.lim.postBytes, fp)}
	}
	diff := func(a, b spent) spent { return spent{a.requests - b.requests, a.posts - b.posts, a.bytes - b.bytes} }

	// The yardstick: a post the allow list refuses keeps one request, one
	// post and its envelope's bytes; nothing is given back.
	c := newRevocationCase(t, Config{MaxBytes: 1 << 16, Limits: limits})
	c.revoke()
	post := sealedTo(t, c.sender, c.owner.Public(), "x", "")
	before := measure(c)
	if status, body := c.h.do(c.sender, "POST", "/v1/mailbox/"+c.owner.Fingerprint(), post, nil); status != http.StatusForbidden || errorText(t, body) != msgNotAllowed {
		t.Fatalf("a refused post: %d %s", status, body)
	}
	postCost := diff(before, measure(c))
	if want := (spent{1, 1, int64(len(post))}); postCost != want {
		t.Fatalf("a refused post spent %+v; want %+v", postCost, want)
	}

	for _, tc := range []struct {
		name string
		kept int
		mid  bool
	}{
		{"at the start of a first attempt", 0, false},
		{"at the start of a resume", 2500, false},
		{"at the placement of a first attempt", 0, true},
		{"at the placement of a resume", 2500, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newRevocationCase(t, Config{MaxBytes: 2048, StallTimeout: time.Minute, Limits: limits})
			start := measure(c)
			id := c.open("")
			if tc.kept > 0 {
				c.keep(id, tc.kept)
			}
			var status int
			var body []byte
			beforeAttempt := measure(c)
			if tc.mid {
				status, body = c.h.putBetween(c.sender, id, c.blob, tc.kept, between(tc.kept), c.revoke)
			} else {
				c.revoke()
				beforeAttempt = measure(c)
				status, body, _, _ = c.h.putHeadOnly(c.sender, id, len(c.blob), tc.kept, 5*time.Second)
			}
			if status != http.StatusForbidden || errorText(t, body) != msgNotAllowed {
				t.Fatalf("the refused attempt: %d %s", status, body)
			}
			got := diff(beforeAttempt, measure(c))
			// The revoking push in the middle case is the owner's request,
			// not the sender's; the attempt is the sender's one.
			if want := (spent{1, 0, 0}); got != want {
				t.Errorf("the refused attempt spent %+v; want %+v: one request and nothing given back", got, want)
			}
			// Open and refused attempt together keep what the refused post
			// kept: one post, and every byte offered, here the stream's size.
			whole := diff(start, measure(c))
			if whole.posts != postCost.posts || whole.bytes != int64(len(c.blob)) {
				t.Errorf("the open and the refused attempt kept %d posts and %d bytes; want %d post, as a refused post keeps, and the stream's %d bytes",
					whole.posts, whole.bytes, postCost.posts, len(c.blob))
			}
			c.gone(id, "after the refusal")
		})
	}
}

// between is where an interrupted attempt from offset pauses: past the
// stream's header, which a first attempt reads whole before it writes a
// byte (an ML-KEM encapsulation and a prefix), and short of the end.
func between(offset int) int {
	if offset == 0 {
		return 2000
	}
	return offset + 400
}

// A storage fault while the placement judges the upload again keeps it,
// as a placement that failed does: the answer is the storage refusal, the
// row stands at what it said before the attempt and the file is put back
// to it, nothing is given back, and once the fault clears an attempt from
// the row's received places the message. The fault is the allow list's
// table renamed away while the attempt is inside its copy, so MayPost,
// which reads it, fails at the placement and at nothing before it; it is
// renamed back before the next attempt. A first attempt and a resume.
func TestAStorageFaultAtThePlacementKeepsTheUpload(t *testing.T) {
	for _, kept := range []int{0, 2500} {
		t.Run(fmt.Sprintf("offset %d", kept), func(t *testing.T) {
			c := newRevocationCase(t, Config{MaxBytes: 2048})
			id := c.open("")
			if kept > 0 {
				c.keep(id, kept)
			}
			fp := c.sender.Fingerprint()
			bytesBefore := left(c.h.server.lim.postBytes, fp)
			status, body := c.h.putBetween(c.sender, id, c.blob, kept, between(kept), func() {
				if _, err := c.h.store.db.Exec(`ALTER TABLE allowlists RENAME TO allowlists_away`); err != nil {
					t.Fatal(err)
				}
			})
			if _, err := c.h.store.db.Exec(`ALTER TABLE allowlists_away RENAME TO allowlists`); err != nil {
				t.Fatal(err)
			}
			e := answerOf(t, body)
			if status != http.StatusInternalServerError || e.Code != relayapi.CodeStorageError || e.Error != relayapi.MsgStorageError {
				t.Fatalf("a storage fault at the placement: %d %s; want 500 %s %q", status, body, relayapi.CodeStorageError, relayapi.MsgStorageError)
			}
			u, err := c.h.store.Upload(id)
			if err != nil || u.Received != int64(kept) {
				t.Fatalf("the upload's row after the fault: %+v %v; want it kept at %d", u, err, kept)
			}
			if row, file := c.h.uploadLeft(id); !row || file != int64(kept) {
				t.Fatalf("after the fault: row %v, file %d bytes; want the row and a file of %d", row, file, kept)
			}
			if got := left(c.h.server.lim.postBytes, fp); got != bytesBefore {
				t.Errorf("post bytes left %d after the fault, %d before; want nothing given back", got, bytesBefore)
			}
			if n := len(c.listed()); n != 0 {
				t.Fatalf("the fault placed %d messages; want none", n)
			}
			if status, body, _ := c.h.putStream(c.sender, id, c.blob, kept); status != http.StatusCreated {
				t.Fatalf("an attempt from %d after the fault cleared: %d %s; want 201", kept, status, body)
			}
			if n := len(c.listed()); n != 1 {
				t.Fatalf("after the fault cleared the owner has %d messages; want 1", n)
			}
			c.gone(id, "after the placement")
		})
	}
}

// ReceiveUploadAdmitted itself, under the three answers mayPlace can give
// once the copy has reached the end: false is ErrNotAdmitted with the
// upload gone whole; an error is that error with the upload kept at its
// row's received, the file put back to it; true places.
func TestReceiveUploadAdmittedAtThePlacement(t *testing.T) {
	fault := errors.New("the judgement could not be made")
	for _, tc := range []struct {
		name     string
		kept     int
		admitted bool
		err      error
	}{
		{"refused, first attempt", 0, false, nil},
		{"refused, resume", 2500, false, nil},
		{"cannot judge, first attempt", 0, false, fault},
		{"cannot judge, resume", 2500, false, fault},
		{"admitted, first attempt", 0, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newRevocationCase(t, Config{MaxBytes: 2048})
			id := c.open("")
			if tc.kept > 0 {
				c.keep(id, tc.kept)
			}
			asked := 0
			copied := false
			got, err := c.h.store.ReceiveUploadAdmitted(id, int64(tc.kept), 2048, c.h.clock.Now, relayapi.ResumeWindow,
				func(f *os.File, want int64) (int64, error) {
					n, err := f.Write(c.blob[tc.kept:])
					copied = int64(n) == want
					return int64(n), err
				},
				func() (bool, error) {
					asked++
					if !copied {
						t.Error("mayPlace was asked before the copy reached the end")
					}
					return tc.admitted, tc.err
				})
			if asked != 1 {
				t.Errorf("mayPlace was asked %d times; want once", asked)
			}
			row, file := c.h.uploadLeft(id)
			switch {
			case tc.err != nil:
				if !errors.Is(err, fault) || got.Gone || got.Offset != int64(tc.kept) {
					t.Fatalf("got %+v, %v; want the fault, not gone, offset %d", got, err, tc.kept)
				}
				if u, uerr := c.h.store.Upload(id); uerr != nil || u.Received != int64(tc.kept) {
					t.Fatalf("the row: %+v %v; want received %d", u, uerr, tc.kept)
				}
				if !row || file != int64(tc.kept) {
					t.Fatalf("row %v, file %d bytes; want the row and a file of %d", row, file, tc.kept)
				}
			case !tc.admitted:
				if !errors.Is(err, ErrNotAdmitted) || !got.Gone {
					t.Fatalf("got %+v, %v; want gone, ErrNotAdmitted", got, err)
				}
				if row || file != -1 {
					t.Fatalf("row %v, file %d bytes; want neither", row, file)
				}
			default:
				if err != nil || got.Gone {
					t.Fatalf("got %+v, %v; want placed", got, err)
				}
				if n := len(c.listed()); n != 1 {
					t.Fatalf("%d messages listed; want 1", n)
				}
			}
			c.h.assertCountersAgree()
		})
	}
}
