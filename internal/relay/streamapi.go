package relay

import (
	"encoding/binary"
	"encoding/json"
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
// Every check happens before a byte is written, and the byte budget is charged
// with the whole declared size: a sender who cannot afford the stream is told
// so now rather than after uploading most of it.
func (s *Server) handleOpenStream(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	if !s.cfg.Streams {
		s.fail(w, http.StatusForbidden, "this relay does not accept streams; ask the operator to set streams")
		return
	}
	fp := r.PathValue("fp")
	var req relayapi.OpenStreamRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "malformed stream request")
		return
	}
	if req.Size <= 0 {
		s.fail(w, http.StatusBadRequest, "size must be positive")
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
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
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
	allowed, err := s.store.MayPost(fp, callerFP)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	if !allowed {
		s.fail(w, http.StatusForbidden, "sender is not on the recipient's allow list")
		return
	}
	// The same place as a post's check: after the allow list, and before
	// the stream is charged, so a refused channel costs no budget.
	channel, ok := s.channelForPost(w, fp, req.Channel)
	if !ok {
		return
	}

	// The whole stream is charged now, so a sender who has not the budget is
	// refused before uploading anything.
	if ok, retry := s.lim.posts.Allow(callerFP); !ok {
		s.rateLimited(w, limitPosts, retry, "")
		return
	}
	if ok, retry := s.lim.postBytes.AllowN(callerFP, req.Size); !ok {
		detail := ""
		if burst := s.lim.postBytes.Burst(); burst > 0 && req.Size > burst {
			// Named, because at the shipped defaults this is the refusal a
			// first user of streams meets, and the person who can do anything
			// about it needs to know which setting to raise.
			detail = fmt.Sprintf("; this stream is %d bytes and a sender's whole "+
				"post_bytes_per_hour budget is %d, so %s",
				req.Size, burst, relayapi.MsgWaitingWillNotHelp)
		}
		s.rateLimited(w, limitPostBytes, retry, detail)
		return
	}

	id, err := NewUploadID()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	now := time.Now()
	expires := now.Add(s.uploadTTL())
	switch err := s.store.OpenUpload(id, fp, callerFP, channel, req.Size, now, expires,
		s.cfg.Limits.Quotas(), s.cfg.MaxStreamBytes); {
	case err == nil:
	case errors.Is(err, ErrMailboxFull):
		setLimit(w, limitMailboxFull)
		s.fail(w, http.StatusInsufficientStorage, relayapi.MsgMailboxFull)
		return
	case errors.Is(err, ErrRelayFull):
		setLimit(w, limitRelayFull)
		s.fail(w, http.StatusInsufficientStorage, relayapi.MsgRelayFull)
		return
	case errors.Is(err, ErrNoMailbox):
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	default:
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}

	s.writeJSON(w, http.StatusCreated, relayapi.OpenStreamResponse{
		Upload:     id,
		Expires:    expires.UTC().Truncate(time.Second),
		MaxRequest: s.cfg.MaxBytes,
	})
}

func (s *Server) uploadTTL() time.Duration {
	if s.cfg.UploadTTL > 0 {
		return s.cfg.UploadTTL
	}
	return 24 * time.Hour
}

// upload finds an upload and proves the caller owns it. Only the identity that
// opened it may touch it, so nobody can corrupt or finish somebody else's.
func (s *Server) upload(w http.ResponseWriter, r *http.Request, callerFP string) (*Upload, bool) {
	id := r.PathValue("id")
	if !ValidUploadID(id) {
		s.fail(w, http.StatusBadRequest, "bad upload id")
		return nil, false
	}
	u, err := s.store.Upload(id)
	if errors.Is(err, ErrNoUpload) {
		s.fail(w, http.StatusNotFound, "no such upload")
		return nil, false
	}
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return nil, false
	}
	if u.From != callerFP {
		s.fail(w, http.StatusForbidden, "not your upload")
		return nil, false
	}
	return u, true
}

// handleAppendStream copies the next piece of a stream onto its file.
//
// The body is never read into memory: it is copied straight through, bounded
// both by the relay's max_bytes and by what the stream has left to send, so
// neither a large request nor a lying one can cost more than the smaller of
// the two.
func (s *Server) handleAppendStream(w http.ResponseWriter, r *http.Request, callerFP string) {
	u, ok := s.upload(w, r, callerFP)
	if !ok {
		return
	}
	offset, err := strconv.ParseInt(r.Header.Get(relayapi.UploadOffsetHeader), 10, 64)
	if err != nil || offset < 0 {
		s.fail(w, http.StatusBadRequest, "bad or missing "+relayapi.UploadOffsetHeader)
		return
	}
	if offset != u.Received {
		w.Header().Set(relayapi.UploadOffsetHeader, strconv.FormatInt(u.Received, 10))
		s.fail(w, http.StatusConflict, fmt.Sprintf(
			"upload is at offset %d, not %d; resume from there", u.Received, offset))
		return
	}

	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxBytes+relayapi.FramingAllowance)
	var overflow bool
	received, err := s.store.AppendUpload(u.ID, offset, func(f *os.File, limit int64) (int64, error) {
		n, err := io.Copy(f, io.LimitReader(body, limit))
		if err != nil {
			return n, err
		}
		// Anything still readable is more than the stream said it would send.
		var probe [1]byte
		if extra, _ := body.Read(probe[:]); extra > 0 {
			overflow = true
		}
		return n, nil
	})
	switch {
	case errors.Is(err, ErrUploadOffset):
		w.Header().Set(relayapi.UploadOffsetHeader, strconv.FormatInt(received, 10))
		s.fail(w, http.StatusConflict, "upload moved while this request was in flight")
		return
	case err != nil:
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.fail(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		if errors.Is(err, ErrRelayFull) {
			setLimit(w, limitRelayFull)
			s.fail(w, http.StatusInsufficientStorage, relayapi.MsgRelayFull)
			return
		}
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	if overflow {
		w.Header().Set(relayapi.UploadOffsetHeader, strconv.FormatInt(received, 10))
		s.fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
			"this upload declared %d bytes and has now been sent more", u.Size))
		return
	}

	w.Header().Set(relayapi.UploadOffsetHeader, strconv.FormatInt(received, 10))
	w.WriteHeader(http.StatusNoContent)
}

// handleHeadStream is how a client resumes: it asks where the relay got to.
func (s *Server) handleHeadStream(w http.ResponseWriter, r *http.Request, callerFP string) {
	u, ok := s.upload(w, r, callerFP)
	if !ok {
		return
	}
	w.Header().Set(relayapi.UploadOffsetHeader, strconv.FormatInt(u.Received, 10))
	w.Header().Set(relayapi.UploadLengthHeader, strconv.FormatInt(u.Size, 10))
	w.WriteHeader(http.StatusOK)
}

// handleCompleteStream turns a finished upload into a message.
//
// The structural checks are the whole of what the relay can say about a
// stream: it holds no key and cannot open a chunk. They exist so that a
// recipient is never handed something that could not possibly be a stream.
func (s *Server) handleCompleteStream(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	u, ok := s.upload(w, r, callerFP)
	if !ok {
		return
	}
	if u.Received != u.Size {
		w.Header().Set(relayapi.UploadOffsetHeader, strconv.FormatInt(u.Received, 10))
		s.fail(w, http.StatusConflict, fmt.Sprintf(
			"upload has %d of %d bytes; send the rest before completing it", u.Received, u.Size))
		return
	}
	if err := s.checkStreamShape(u); err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.store.CompleteUpload(u.ID)
	if err != nil {
		if errors.Is(err, ErrUploadOffset) {
			s.fail(w, http.StatusConflict, "upload is not complete")
			return
		}
		// Placing the file makes a directory and a directory entry, which
		// a full disk can refuse after every byte was accepted. The upload
		// is kept, and completing it again when there is room is enough.
		if errors.Is(err, ErrRelayFull) {
			setLimit(w, limitRelayFull)
			s.fail(w, http.StatusInsufficientStorage, relayapi.MsgRelayFull)
			return
		}
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	// The upload is a message now, and a listing held for the recipient
	// finds it.
	s.notify.Wake(mailKey(u.To))
	s.writeJSON(w, http.StatusOK, relayapi.CompleteStreamResponse{ID: id})
}

// checkStreamShape reads the first few bytes of a finished upload and applies
// the three inequalities the format guarantees. It opens nothing and decrypts
// nothing.
func (s *Server) checkStreamShape(u *Upload) error {
	if min := int64(stream.HeaderSize + stream.MinChunk0 + stream.TagSize); u.Size < min {
		return fmt.Errorf("a stream is at least %d bytes; this one is %d", min, u.Size)
	}
	f, err := s.store.OpenUploadFile(u.ID)
	if err != nil {
		return errors.New("upload could not be read")
	}
	defer f.Close()
	header := make([]byte, stream.HeaderSize)
	if _, err := io.ReadFull(f, header); err != nil {
		return errors.New("upload is shorter than a stream header")
	}
	length := int64(binary.BigEndian.Uint32(header[stream.EncSize:]))
	if length < stream.MinChunk0 || length > stream.MaxChunk0 {
		return fmt.Errorf("the manifest chunk claims %d bytes, outside [%d, %d]",
			length, stream.MinChunk0, stream.MaxChunk0)
	}
	if int64(stream.HeaderSize)+length+stream.TagSize > u.Size {
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
	if _, err := s.store.AbortUpload(u.ID); err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
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
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad message id")
		return
	}
	kind, size, err := s.store.MessageKind(fp, id)
	if errors.Is(err, ErrNoMessage) {
		s.fail(w, http.StatusNotFound, "no such message")
		return
	}
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	if kind != relayapi.KindStream {
		s.fail(w, http.StatusBadRequest, "this message is an envelope; fetch it from the mailbox")
		return
	}
	f, err := s.store.OpenMessage(fp, id)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		s.store.fault(f.Name(), err)
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
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
			s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
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
	// ServeContent does Range and If-Range, and streams the file rather than
	// reading it.
	http.ServeContent(w, r, "", info.ModTime(), f)
}

// authedNoMailbox is authed for a route whose path carries no mailbox
// fingerprint: the upload routes are addressed by upload id, and who may touch
// one is decided from the row rather than the path.
func (s *Server) authedNoMailbox(fn func(w http.ResponseWriter, r *http.Request, body []byte, callerFP string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readBody(w, r)
		if !ok {
			return
		}
		fp, ok := s.verifyCaller(w, r, body)
		if !ok {
			return
		}
		fn(w, r, body, fp)
	}
}

// uploadAuthed is the same for the routes whose body is the payload itself and
// must not be read into memory. The signature therefore covers an empty body,
// which is what the client signs for these requests.
func (s *Server) uploadAuthed(fn func(w http.ResponseWriter, r *http.Request, callerFP string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Nothing of the body has been read at this point, which is the
		// point: a caller without a certificate does not get to stream
		// sixteen megabytes into the relay before being refused.
		fp, ok := s.verifyCaller(w, r, nil)
		if !ok {
			return
		}
		fn(w, r, fp)
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
