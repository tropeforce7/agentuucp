package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// The stream endpoints. The relay stores bytes and never opens a chunk, so
// everything here is about who may write where, how much, and whether what
// arrived is structurally a stream at all.

// handleOpenStream reserves room for a stream and hands back an upload to
// append to.
//
// Every check happens before a byte is written, and the byte budget is
// charged with the whole declared size: a sender who cannot afford the
// stream is told so now rather than after uploading most of it. What the
// store then refuses — the mailbox or the relay full, no mailbox, the
// sender's count of open uploads at the cap, a storage error — is an
// upload the relay never made a row for, and the charge comes back, so a
// refused open costs a post and no bytes. An upload that was opened has
// its charge settled by returnUnheld when it goes unplaced.
func (s *Server) handleOpenStream(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	if !s.cfg.Streams {
		s.fail(w, http.StatusForbidden, "this relay does not accept streams; ask the operator to set streams")
		return
	}
	fp := r.PathValue("fp")
	var req relayapi.OpenStreamRequest
	if !s.decodeRequest(w, body, &req, "stream request") {
		return
	}
	// A copy of a message to several is held to max_recipients here,
	// before anything is looked up, stored or charged: the count is the
	// caller's own word about its own request and tells it nothing.
	if !s.holdRecipients(w, req.SectionList(), "stream request") {
		return
	}
	if req.Size <= 0 {
		s.fail(w, http.StatusBadRequest, "size must be positive")
		return
	}
	// A cap no setting lifts, well under MaxInt64: max_stream_bytes is
	// documented as 0 for unlimited, and unlimited must still be a number
	// the relay can add to what it holds without wrapping.
	if req.Size > MaxStreamSize {
		s.fail(w, http.StatusBadRequest, fmt.Sprintf(
			"stream is %d bytes; no relay accepts more than %d", req.Size, MaxStreamSize))
		return
	}
	if s.cfg.MaxStreamBytes > 0 && req.Size > s.cfg.MaxStreamBytes {
		s.fail(w, http.StatusForbidden, fmt.Sprintf(
			"stream is %d bytes; this relay's max_stream_bytes is %d", req.Size, s.cfg.MaxStreamBytes))
		return
	}
	if min := stream.HeaderSize + stream.MinChunk0 + stream.TagSize; req.Size < int64(min) {
		s.fail(w, http.StatusBadRequest, fmt.Sprintf(
			"stream is %d bytes; the smallest possible one is %d", req.Size, min))
		return
	}

	exists, blocked, err := s.store.MailboxState(fp)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if !exists {
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	}
	if blocked {
		s.fail(w, http.StatusForbidden, "recipient is blocked on this relay")
		return
	}
	// A courier's mailbox refuses every sender, in the allow list's own
	// words and at the allow list's own place in the order: the mailbox
	// exists and is not blocked, nothing is stored or charged, and nothing
	// on the wire says which of the two refused. The post route's comment
	// says why the two are one sentence.
	if s.isCourierMailbox(fp) {
		s.fail(w, http.StatusForbidden, msgNotAllowed)
		return
	}
	allowed, err := s.store.MayPost(fp, callerFP)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if !allowed {
		s.fail(w, http.StatusForbidden, msgNotAllowed)
		return
	}
	// The same place as a post's check: after the allow list, and before
	// the stream is charged, so a refused channel costs no budget.
	channel, ok := s.channelForPost(w, fp, req.Channel, req.Size, true, false)
	if !ok {
		return
	}

	// The whole stream is charged now, so a sender who has not the budget is
	// refused before uploading anything.
	if ok, retry := s.lim.posts.Allow(callerFP); !ok {
		s.rateLimited(w, limitPosts, retry, "")
		return
	}
	// An open is counted whatever becomes of the upload, since each one
	// reserves a recipient's room, and is given back below when the open
	// reserves nothing (D82).
	if ok, retry := s.lim.uploadOpens.Allow(callerFP); !ok {
		s.rateLimited(w, limitUploadOpens, retry, fmt.Sprintf(
			"; a sender may open %d uploads an hour on this relay", s.lim.uploadOpens.Burst()))
		return
	}
	if ok, retry := s.lim.postBytes.AllowN(callerFP, req.Size); !ok {
		s.lim.uploadOpens.Return(callerFP, 1)
		detail := ""
		if burst := s.lim.postBytes.Burst(); burst > 0 && req.Size > burst {
			// Named, because at the shipped defaults this is the refusal a
			// first user of streams meets, and the person who can do anything
			// about it needs to know which setting to raise.
			detail = fmt.Sprintf("; this stream is %d bytes and a sender's whole "+
				"post_bytes_per_hour budget is %d, so %s",
				req.Size, burst, relayapi.MsgWaitingWillNotHelp)
			s.rateLimitedCode(w, limitPostBytes, retry, detail, relayapi.CodeOverBudget)
			return
		}
		s.rateLimited(w, limitPostBytes, retry, detail)
		return
	}

	id, err := NewUploadID()
	if err != nil {
		s.lim.postBytes.Return(callerFP, req.Size)
		s.lim.uploadOpens.Return(callerFP, 1)
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	// The server's clock, which is also the one the expiry is read by: an
	// upload nobody starts an attempt on within the start window is gone.
	now := s.cfg.Now()
	expires := now.Add(relayapi.StartWindow)
	open := func() error {
		return s.store.OpenUpload(id, fp, callerFP, channel, req.Size, now, expires,
			s.cfg.Limits.Quotas(), s.cfg.MaxStreamBytes)
	}
	err = open()
	var capped *OpenUploadsError
	if errors.As(err, &capped) && !capped.Soonest.After(now) {
		// The sender's count is at the cap and its soonest expiry has
		// passed: an upload the relay still holds past its promised end,
		// untouched since and not yet purged, or mid-attempt with its
		// lock held. The open meets it the way every upload route meets
		// an expired upload, by letting it go: the purge, which skips a
		// locked row, and then the count once more. Without this a
		// sender who waited the Retry-After of the last refusal would be
		// refused again with a Retry-After of one second until the
		// hundredth request purged for it.
		s.purgeUploads(now)
		err = open()
	}
	if s.roomFreed(err) {
		err = open()
	}
	if err != nil {
		s.lim.postBytes.Return(callerFP, req.Size)
		s.lim.uploadOpens.Return(callerFP, 1)
	}
	switch {
	case err == nil:
	case errors.As(err, &capped):
		// Retry-After is the seconds to the sender's soonest expiry on
		// the relay's clock, rounded up so the sender is not invited
		// back a fraction early, and at least one: a row whose expiry
		// has passed is mid-attempt, its lock held, and the relay cannot
		// say when a transfer ends.
		wait := capped.Soonest.Sub(now)
		if part := wait % time.Second; part > 0 {
			wait += time.Second - part
		}
		s.rateLimited(w, limitOpenUploads, wait, fmt.Sprintf(
			"; you have %d uploads open, the most this relay allows one sender at once; "+
				"an upload goes %d seconds after its open unless an attempt has started, "+
				"an attempt is cut when %d KiB do not arrive within %d seconds, "+
				"and a kept partial goes %d seconds after it was kept",
			capped.Open, int64(relayapi.StartWindow/time.Second), relayapi.HunkBytes>>10,
			int64(relayapi.HunkWindow/time.Second), relayapi.ResumeWindowSeconds))
		return
	case errors.Is(err, ErrMailboxFull):
		setLimit(w, limitMailboxFull)
		s.refuse(w, http.StatusInsufficientStorage, relayapi.RefusalMailboxFull)
		return
	case errors.Is(err, ErrRelayFull):
		setLimit(w, limitRelayFull)
		s.refuse(w, http.StatusInsufficientStorage, relayapi.RefusalRelayFull)
		return
	case errors.Is(err, ErrNoMailbox):
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	default:
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}

	s.writeJSON(w, http.StatusCreated, relayapi.OpenStreamResponse{
		Upload:          id,
		Expires:         expires.UTC().Truncate(time.Second),
		ResumeThreshold: s.cfg.MaxBytes,
		ResumeWindow:    relayapi.ResumeWindowSeconds,
	})
}

// stallTimeout is how long the blob route waits for a reader to take its
// next byte: the resume window, unless a test set it shorter.
func (s *Server) stallTimeout() time.Duration {
	if s.cfg.StallTimeout > 0 {
		return s.cfg.StallTimeout
	}
	return relayapi.ResumeWindow
}

// hunkWindow is how long the stream route waits for an attempt's next
// hunk, and for its first from the attempt's start: relayapi.HunkWindow,
// unless a test set the stall timeout shorter.
func (s *Server) hunkWindow() time.Duration {
	if s.cfg.StallTimeout > 0 {
		return s.cfg.StallTimeout
	}
	return relayapi.HunkWindow
}

// refuseUnread answers a request whose body the handler will not read,
// and closes the connection after. What net/http does with the unread
// body is its own: whether or not the connection is to be closed, the
// server's finishRequest closes the body, which reads up to 256 KiB of
// what was declared before giving up, and a larger declaration is not
// drained at all; with the header the connection is not kept for another
// request. So a refusal here costs at most 256 KiB of read, by net/http,
// and no disk work.
func (s *Server) refuseUnread(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Connection", "close")
	s.fail(w, status, msg)
}

// refuseUnreadWith is refuseUnread for one of relayapi's fixed refusals.
func (s *Server) refuseUnreadWith(w http.ResponseWriter, status int, r relayapi.Refusal) {
	w.Header().Set("Connection", "close")
	s.refuse(w, status, r)
}

// msgNoUpload is the answer for an upload id the relay does not hold: never
// opened, aborted, completed, or purged.
const msgNoUpload = "no such upload"

// upload finds an upload and proves the caller owns it. Only the identity that
// opened it may touch it, so nobody can corrupt or finish somebody else's.
//
// An upload past its expiry is refused here, on every route, and aborted
// there and then: the expiry is when its reservation was promised to end,
// and until this only the purge read it, every hundredth request, so a
// sender who kept touching an expired upload kept its bytes landing and
// its reservation held for as long as they liked. The row goes under the
// upload's lock, as any abort does, so the reservation is released with
// the answer; the sender opens again, which is what the client's resume
// does on any error from HEAD.
func (s *Server) upload(w http.ResponseWriter, r *http.Request, callerFP string) (*Upload, bool) {
	id := r.PathValue("id")
	if !ValidUploadID(id) {
		s.fail(w, http.StatusBadRequest, "bad upload id")
		return nil, false
	}
	u, err := s.store.Upload(id)
	if errors.Is(err, ErrNoUpload) {
		s.fail(w, http.StatusNotFound, msgNoUpload)
		return nil, false
	}
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return nil, false
	}
	if u.From != callerFP {
		s.fail(w, http.StatusForbidden, "not your upload")
		return nil, false
	}
	// The edge is inclusive: at exactly expires the upload is still here.
	if now := s.cfg.Now(); now.After(u.Expires) {
		gone, err := s.store.AbortUpload(u.ID)
		if gone != nil {
			s.returnUnheld(gone)
		}
		if err != nil {
			s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
			return nil, false
		}
		s.fail(w, http.StatusGone, fmt.Sprintf(
			"this upload expired at %s and is gone; open a new stream and send it again",
			u.Expires.UTC().Format(time.RFC3339)))
		return nil, false
	}
	return u, true
}

// stillAdmitted judges an upload's sender and channel again as the open
// judged them, answering nil when the upload is still admitted (R22). A
// courier's mailbox refuses every sender: the store's placement has no
// business knowing which relays this one peers with, so it is judged here,
// in the allow list's words, as on the open, since what has changed under
// the sender is that the recipient now admits nobody.
func (s *Server) stillAdmitted(u *Upload) *judged {
	if s.isCourierMailbox(u.To) {
		return &judged{status: http.StatusForbidden, msg: msgNotAllowed}
	}
	allowed, err := s.store.MayPost(u.To, u.From)
	if err != nil {
		return &judged{storage: true}
	}
	if !allowed {
		return &judged{status: http.StatusForbidden, msg: msgNotAllowed}
	}
	_, refused := s.judgeChannel(u.To, u.Channel, u.Size, true, false)
	return refused
}

// handlePutStream is one attempt: the sealed stream from an offset to the
// end in one request, streamed onto the upload's file under the stall
// deadline, shape-checked as its first bytes pass, and placed in the
// mailbox when the last byte lands.
//
// The upload is admitted again before anything else (stillAdmitted, R22),
// and once more before its placement. Then the length is judged, still
// before a byte is read: an attempt with no
// Content-Length (a chunked body) cannot be judged and is 411; one whose
// offset and length do not reach the stream's size is 400, since an
// attempt runs to the end or is not an attempt; the body is not read for
// either, and the connection is closed after the answer, what net/http
// drains before closing being refuseUnread's to say. The offset must be
// where the relay's copy ends, or 409 carrying that offset, which is how
// a sender learns where to resume. Then the copy, under ReceiveUpload's
// rule for what an attempt that stops short leaves.
func (s *Server) handlePutStream(w http.ResponseWriter, r *http.Request, callerFP string) {
	u, ok := s.upload(w, r, callerFP)
	if !ok {
		return
	}
	// What the open judged is judged again before a byte of the attempt
	// is read (R22): a sender the recipient has since removed from the
	// allow list, or whose channel has since closed, or a recipient since
	// admitted as a courier, would otherwise land an upload opened before
	// it, for as long as it keeps the pace, hours for a large one. The
	// refusal is the open's, the upload goes with it, its file and its
	// reservation, and the open's charge stands, as a refused post's does.
	// No byte of the body has been read, and the wrapper's mark closes the
	// connection behind the answer.
	if refused := s.stillAdmitted(u); refused != nil {
		if !refused.storage {
			if _, err := s.store.AbortUpload(u.ID); err != nil && !errors.Is(err, ErrNoUpload) {
				refused = &judged{storage: true}
			}
		}
		s.writeRefusal(w, refused)
		return
	}
	offset, err := strconv.ParseInt(r.Header.Get(relayapi.UploadOffsetHeader), 10, 64)
	if err != nil || offset < 0 {
		s.refuseUnread(w, http.StatusBadRequest, "bad or missing "+relayapi.UploadOffsetHeader)
		return
	}
	if offset != u.Received {
		w.Header().Set(relayapi.UploadOffsetHeader, strconv.FormatInt(u.Received, 10))
		s.refuseUnread(w, http.StatusConflict, fmt.Sprintf(
			"upload is at offset %d, not %d; resume from there", u.Received, offset))
		return
	}
	length := r.ContentLength
	switch {
	case length < 0:
		s.refuseUnread(w, http.StatusLengthRequired, relayapi.MsgLengthRequired)
		return
	case length != u.Size-offset:
		// A difference of two values the relay holds (offset is
		// u.Received, at most u.Size), never a sum of two claimed ones.
		s.refuseUnread(w, http.StatusBadRequest, fmt.Sprintf(
			"%s: an attempt at offset %d with %d bytes does not reach %d", relayapi.MsgNotToTheEnd, offset, length, u.Size))
		return
	}

	// The hunk deadline (D82): the connection's read and write deadlines
	// are the relay's own for this request, now + the hunk window, and
	// they move by the window only when a whole hunk has arrived since
	// they last moved, so a transfer of any length completes while it
	// keeps the pace, a slower or stalled one ends inside a window as an
	// attempt that stopped short, and the answer at the end is always
	// writable within a window of the last hunk — the server's five-minute
	// write deadline, set when the headers were read, would otherwise fail
	// the 201 of a transfer longer than that after the message was placed.
	// A deadline every byte moved let a sender hold an upload's
	// reservation for ever on a byte a window.
	// The body is read from here: the connection may be kept after the
	// answer, and the refusals below that leave it unread say so again.
	w.Header().Del("Connection")
	rc := http.NewResponseController(w)
	stall := s.hunkWindow()
	extend := func() {
		rc.SetReadDeadline(time.Now().Add(stall))
		rc.SetWriteDeadline(time.Now().Add(stall))
	}
	extend()
	body := &deadlineReader{r: r.Body, extend: extend, hunk: relayapi.HunkBytes}
	var badShape error
	// The same judgement once more before the placement, under the
	// upload's lock, for a sender removed or a channel closed while this
	// attempt ran (R22).
	var lastRefusal *judged
	mayPlace := func() (bool, error) {
		refused := s.stillAdmitted(u)
		if refused != nil && refused.storage {
			return false, errors.New("relay: the upload's admission could not be judged at its placement")
		}
		lastRefusal = refused
		return refused == nil, nil
	}
	received, err := s.store.ReceiveUploadAdmitted(u.ID, offset, s.cfg.MaxBytes, s.cfg.Now, relayapi.ResumeWindow,
		func(f *os.File, want int64) (int64, error) {
			if offset == 0 {
				// The shape of the first bytes, before they are written:
				// the header's manifest length within its bounds and
				// leaving room for a final chunk, against the size the
				// open declared. A wrong shape is a body the relay will
				// not take a byte of.
				header := make([]byte, stream.HeaderSize)
				n, err := io.ReadFull(body, header)
				if err != nil {
					return 0, err
				}
				if err := checkStreamShape(header, u.Size); err != nil {
					badShape = err
					return 0, err
				}
				if _, err := f.Write(header); err != nil {
					return 0, err
				}
				rest, err := io.Copy(f, io.LimitReader(body, want-int64(n)))
				return int64(n) + rest, err
			}
			return io.Copy(f, io.LimitReader(body, want))
		}, mayPlace)
	if received.Gone && !errors.Is(err, ErrNotAdmitted) {
		// The attempt deleted the upload whole, with the row as it stood
		// before the attempt: received at the offset, since the row is
		// written only on the kept path, which keeps. One no longer
		// admitted at its placement keeps the open's charge, as a refused
		// post's charge stands.
		s.returnUnheld(&Upload{From: callerFP, Size: u.Size, Received: offset})
	}
	// The answer is written under a window of its own: the stall that
	// ended a read has spent the write's deadline too, and what the relay
	// kept is said to anyone still listening.
	rc.SetWriteDeadline(time.Now().Add(stall))
	if err != nil {
		// Whatever the refusal, once it is written: one judged after the
		// body began is answered while the body is still arriving, and
		// the close that follows could reset the connection before the
		// sender reads the answer (R42b).
		defer s.lingerAfterRefusal(rc, body)
		switch {
		case badShape != nil:
			s.refuseUnread(w, http.StatusBadRequest, badShape.Error())
			return
		case errors.Is(err, ErrNotAdmitted) && lastRefusal != nil:
			s.writeRefusal(w, lastRefusal)
			return
		case errors.Is(err, ErrUploadOffset):
			w.Header().Set(relayapi.UploadOffsetHeader, strconv.FormatInt(received.Offset, 10))
			s.refuseUnread(w, http.StatusConflict, "upload moved while this request was in flight")
			return
		case errors.Is(err, ErrNoUpload):
			// Aborted or purged between the look above and the lock: the
			// same answer as for an id never seen, which the sender does not
			// retry.
			s.refuseUnread(w, http.StatusNotFound, msgNoUpload)
			return
		case errors.Is(err, ErrRelayFull):
			setLimit(w, limitRelayFull)
			s.refuseUnreadWith(w, http.StatusInsufficientStorage, relayapi.RefusalRelayFull)
			return
		case errors.Is(err, ErrShortAttempt):
			// The sender stopped, or the hunk deadline ended it; either way
			// the sender is most likely gone, and the answer says what the
			// relay kept for anyone still listening.
			w.Header().Set(relayapi.UploadOffsetHeader, strconv.FormatInt(received.Offset, 10))
			if received.Kept {
				s.refuseUnread(w, http.StatusBadRequest, fmt.Sprintf(
					"the attempt stopped short at %d of %d bytes; kept for one resume until %s",
					received.Offset, u.Size, received.Expires.UTC().Format(time.RFC3339)))
				return
			}
			s.refuseUnread(w, http.StatusBadRequest, fmt.Sprintf(
				"the attempt stopped short at %d of %d bytes and nothing is kept; open a new stream", offset, u.Size))
			return
		}
		s.refuseUnreadWith(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	// The upload is a message now, and a listing held for the recipient
	// finds it: woken after the answer, as every wake is (R25).
	w.Header().Set(relayapi.UploadOffsetHeader, strconv.FormatInt(received.Offset, 10))
	s.writeJSON(w, http.StatusCreated, relayapi.PutStreamResponse{ID: received.Placed})
	s.notify.Wake(mailKey(u.To))
}

// lingerWait and lingerBytes bound what the relay reads of a refused
// attempt's body after its answer (R42b): two seconds, or sixteen hunks.
const (
	lingerWait  = 2 * time.Second
	lingerBytes = 16 * relayapi.HunkBytes
)

// lingerAfterRefusal is the close of an attempt refused after its body
// began (R42b). The connection is not kept, and closing it with the body
// still arriving resets it, which can reach the sender before the answer
// does; so the answer is flushed and the body read on and thrown away, for
// at most lingerWait or lingerBytes, giving the sender the time to read
// it. An attempt refused before a byte of its body was read is left
// alone: a sender that asked first (Expect) sends nothing once refused,
// and reading would wait out the whole bound for bytes that never come.
func (s *Server) lingerAfterRefusal(rc *http.ResponseController, body *deadlineReader) {
	if body.read == 0 {
		return
	}
	rc.Flush()
	rc.SetReadDeadline(time.Now().Add(lingerWait))
	io.CopyN(io.Discard, body.r, lingerBytes)
}

// deadlineReader is a request body that moves the hunk deadline on each
// time a whole hunk has been read since it last moved. What a read
// brought past a hunk's edge counts toward the next, so a sender at the
// pace is credited every byte; since stays under a hunk plus one read's
// length, both the relay's own.
type deadlineReader struct {
	r      io.Reader
	extend func()
	hunk   int64
	since  int64
	read   int64
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	d.read += int64(n)
	if d.since += int64(n); d.since >= d.hunk {
		d.since -= d.hunk
		d.extend()
	}
	return n, err
}

// deadlineWriter is a response whose every delivering write moves the
// stall deadline on: deadlineReader's twin, for the blob GET.
type deadlineWriter struct {
	http.ResponseWriter
	extend func()
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	n, err := d.ResponseWriter.Write(p)
	if n > 0 {
		d.extend()
	}
	return n, err
}

// Unwrap lets http.NewResponseController reach the connection through
// the wrapper, as statusRecorder's does.
func (d *deadlineWriter) Unwrap() http.ResponseWriter { return d.ResponseWriter }

// checkStreamShape applies to a stream's first bytes the whole of what the
// relay can say about it, holding no key and opening no chunk: the
// manifest chunk's declared length is within its bounds and leaves room
// for a final chunk within the size the open declared. It exists so that a
// recipient is never handed something that could not possibly be a stream.
func checkStreamShape(header []byte, size int64) error {
	if min := int64(stream.HeaderSize + stream.MinChunk0 + stream.TagSize); size < min {
		return fmt.Errorf("a stream is at least %d bytes; this one is %d", min, size)
	}
	length := int64(binary.BigEndian.Uint32(header[stream.EncSize:]))
	if length < stream.MinChunk0 || length > stream.MaxChunk0 {
		return fmt.Errorf("the manifest chunk claims %d bytes, outside [%d, %d]",
			length, stream.MinChunk0, stream.MaxChunk0)
	}
	if int64(stream.HeaderSize)+length+stream.TagSize > size {
		return errors.New("the manifest chunk does not leave room for a final chunk")
	}
	return nil
}

// handleAbortStream throws an upload away and releases its reservation.
func (s *Server) handleAbortStream(w http.ResponseWriter, r *http.Request, callerFP string) {
	u, ok := s.upload(w, r, callerFP)
	if !ok {
		return
	}
	gone, err := s.store.AbortUpload(u.ID)
	if gone != nil {
		s.returnUnheld(gone)
	}
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleBlob serves a stored stream, honouring Range so a client can resume a
// download and fetch a manifest without the payload behind it.
func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	if fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.fail(w, http.StatusBadRequest, "bad message id")
		return
	}
	kind, size, err := s.store.MessageKind(fp, id)
	if errors.Is(err, ErrNoMessage) {
		s.fail(w, http.StatusNotFound, "no such message")
		return
	}
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if kind != relayapi.KindStream {
		s.fail(w, http.StatusBadRequest, "this message is an envelope; fetch it from the mailbox")
		return
	}
	f, err := s.store.OpenMessage(fp, id)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		s.store.fault(f.Name(), err)
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if info.Size() != size {
		// A file that disagrees with its row is no better than a missing
		// one: the row is what the quotas were computed from, and a byte
		// range past the end of the file cannot be served by anybody. The
		// sweep at start drops it by this rule; this is the same rule met
		// while serving, and it is confined to this route, which only the
		// mailbox's owner reaches, after the signature. Nothing the client
		// can do would help, so it is told the message is gone rather than
		// left to ask for the same range at every fetch.
		f.Close()
		if _, err := s.store.Delete(fp, id); err != nil {
			s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
			return
		}
		// The owner is the caller on this route, and the minimal access log
		// promises to omit the caller, so the mailbox is named only in full
		// mode. The id is enough on its own: ids are one counter for the
		// whole relay, and the file is gone by the time this is written.
		whose := ""
		if !s.minimal {
			whose = " for " + fp
		}
		s.log.Warn(fmt.Sprintf("message %d%s is %d bytes on disk but %d in the database; "+
			"it is damaged and has been dropped", id, whose, info.Size(), size))
		s.fail(w, http.StatusGone, "message is damaged on the relay and has been dropped")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	// The write deadline is the PUT's read deadline turned round: the
	// relay's own, now + the stall timeout, moved by every write that
	// delivers bytes, so a blob of any size is served while the reader
	// keeps taking it and a reader that stops is cut inside the window.
	// The server's five-minute write timeout, set when the headers were
	// read, would otherwise cut a large blob on a slow link every five
	// minutes and leave the client to resume by Range each time.
	rc := http.NewResponseController(w)
	stall := s.stallTimeout()
	extend := func() { rc.SetWriteDeadline(time.Now().Add(stall)) }
	extend()
	// ServeContent does Range and If-Range, and streams the file rather than
	// reading it; it reaches the connection through the wrapper's Unwrap.
	http.ServeContent(&deadlineWriter{ResponseWriter: w, extend: extend}, r, "", info.ModTime(), f)
}

// callerAuthed is authed for the routes whose path carries no mailbox
// fingerprint: the upload routes, where who may touch an upload is
// decided from the row and the PUT's body is the payload itself and must
// not be read into memory, and the card listing, which is about no
// mailbox in particular and has no body. The signature therefore covers
// an empty body, which is what the client signs for these requests. The
// caller is still a registered, unblocked identity: a certificate alone,
// which the key lookup accepts, is not enough here, since "admitted to
// the relay" means a mailbox.
func (s *Server) callerAuthed(fn func(w http.ResponseWriter, r *http.Request, callerFP string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Nothing of the body has been read at this point, which is the
		// point: a caller without a certificate does not get to stream
		// sixteen megabytes into the relay before being refused. Every
		// refusal here is before the body, so the connection closes
		// behind it; the handler removes the mark when it reads the body.
		unread(w, r)
		fp, ok := s.verifyCaller(w, r, nil)
		if !ok {
			return
		}
		fn(w, r, fp)
	}
}

// callerAuthedBody is callerAuthed for a route that carries a body the
// signature must cover.
//
// The forward route needs both halves and no existing wrapper has them:
// authedWithCert, which authed and authedBody are, reads a mailbox
// fingerprint out of the path and refuses a request without one, and a
// forward names no mailbox — the recipient is inside the envelope and the
// next hop is in the path. callerAuthed has no fingerprint in the path and
// signs an empty body, which is right for the upload routes whose body is
// the payload and for the listing that has none, and wrong here: what the
// two lists say about where an envelope goes must be under the caller's
// signature like everything else this relay acts on.
//
// The order is the one order, authedWithCert's: the certificate, the header
// parsed, the body's declared length judged, the identity it names looked
// up, the body under this route's cap, then the signature over it.
// Everything that can be judged without the body is judged before it, so a
// caller the relay would refuse anyway never gets to send one.
func (s *Server) callerAuthedBody(limit int64, hint string, fn func(w http.ResponseWriter, r *http.Request, body []byte, callerFP string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Every refusal from here to the body closes the connection behind
		// its answer, as authedWithCert's do and for the same reason.
		unread(w, r)
		cert, ok := s.clientCert(w, r)
		if !ok {
			return
		}
		auth, err := relayapi.ParseAuth(r.Header.Get(relayapi.AuthHeader))
		if err != nil {
			s.authFailed(w, r, errUnauthorized)
			return
		}
		if !s.declaredLength(w, r, limit, hint) {
			return
		}
		caller, err := s.store.Mailbox(auth.FP)
		if err != nil {
			s.authFailed(w, r, errUnauthorized)
			return
		}
		pub, err := identity.ParseBundle(caller.Bundle)
		if err != nil {
			s.authFailed(w, r, errUnauthorized)
			return
		}
		body, ok := s.unsignedBody(w, r, limit, hint)
		if !ok {
			return
		}
		// The body is read: the connection may be kept after the answer.
		w.Header().Del("Connection")
		if err := s.checkSignature(auth, pub, r, body); err != nil {
			s.authFailed(w, r, err)
			return
		}
		verified(w, auth.FP)
		if !s.certMatches(w, r, cert, auth.FP) {
			return
		}
		if !s.chargeIdentity(w, auth.FP) {
			return
		}
		if caller.Blocked {
			s.fail(w, http.StatusForbidden, msgBlocked)
			return
		}
		// A courier is held to the minute (D83), once its signature has
		// verified and never before, so a stranger naming a courier's
		// fingerprint learns nothing from the answer. Refused 503 with a
		// minute's Retry-After, so the neighbour waits and asks again
		// rather than taking it for its enrolment, and said in the log once
		// a minute by this relay's name for the neighbour.
		if s.courier != nil {
			if name, ok := s.courier.Accepts(auth.FP); ok && !auth.FreshWithin(time.Now(), relayapi.CourierSkew) {
				s.store.faults.noteCourierClock(name)
				w.Header().Set("Retry-After", strconv.Itoa(int(relayapi.CourierSkew/time.Second)))
				s.refuse(w, http.StatusServiceUnavailable, relayapi.RefusalCourierClock)
				return
			}
		}
		fn(w, r, body, auth.FP)
	}
}

// verifyCaller is the shared tail of every authenticated route: parse, look
// the caller up, verify, charge, and refuse a blocked identity.
func (s *Server) verifyCaller(w http.ResponseWriter, r *http.Request, body []byte) (string, bool) {
	cert, ok := s.clientCert(w, r)
	if !ok {
		return "", false
	}
	auth, err := relayapi.ParseAuth(r.Header.Get(relayapi.AuthHeader))
	if err != nil {
		s.authFailed(w, r, errUnauthorized)
		return "", false
	}
	caller, err := s.store.Mailbox(auth.FP)
	if err != nil {
		s.authFailed(w, r, errUnauthorized)
		return "", false
	}
	pub, err := identity.ParseBundle(caller.Bundle)
	if err != nil {
		s.authFailed(w, r, errUnauthorized)
		return "", false
	}
	if err := s.checkSignature(auth, pub, r, body); err != nil {
		s.authFailed(w, r, err)
		return "", false
	}
	verified(w, auth.FP)
	if !s.certMatches(w, r, cert, auth.FP) {
		return "", false
	}
	if !s.chargeIdentity(w, auth.FP) {
		return "", false
	}
	if caller.Blocked {
		s.fail(w, http.StatusForbidden, msgBlocked)
		return "", false
	}
	return auth.FP, true
}
