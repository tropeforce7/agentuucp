package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The channel directory routes. An owner pushes a signed directory and any
// sender the allow list admits reads it back verbatim; the relay verifies the
// signature against the mailbox's registered bundle before storing anything
// and never edits what it stores, so it cannot invent a channel or change a
// description. The access log records the route and nothing from the body:
// a directory's names are the owner's to publish to senders, not to the
// operator.

// handleSetChannels is PUT /v1/mailbox/{fp}/channels, owner only.
//
// Order: the caller must be the owner, the body must decode, the signature
// must verify under the mailbox's own key, the document must pass every rule,
// its owner must be this mailbox, and only then is the store asked, which
// refuses a directory no newer than the one it holds.
func (s *Server) handleSetChannels(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	if fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	var req relayapi.ChannelsRequest
	if !s.decodeRequest(w, body, &req, "channels request") {
		return
	}
	// The caller has just authenticated as this mailbox, so the bundle is
	// there; anything else is the store's trouble.
	mb, err := s.store.Mailbox(fp)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	pub, err := identity.ParseBundle(mb.Bundle)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	d, err := channels.Verify(pub, req.Document, req.Signature)
	switch {
	case errors.Is(err, channels.ErrSignature):
		s.fail(w, http.StatusUnauthorized, "directory signature does not verify")
		return
	case errors.Is(err, channels.ErrOwner):
		s.fail(w, http.StatusBadRequest, "directory owner is not this mailbox")
		return
	case err != nil:
		// The validator's sentence, which names the channel and the rule,
		// or the decoder's, which names the field.
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	// The one rule that needs a clock, on the verified directory and before
	// anything is stored: issued no further ahead of this relay's clock
	// than a request may be, and every time in it within what this
	// program can write (CheckIssued says which).
	if err := channels.CheckIssued(d, time.Now()); err != nil {
		s.fail(w, http.StatusBadRequest, issuedRefusal(err))
		return
	}
	// A channel may be tighter than this relay and never looser (D90):
	// a max_bytes over the most this relay takes of any kind is refused
	// here, where the owner can act on it. The ceiling is the larger of
	// the two caps whether or not this relay takes streams now, so a
	// relay with streams off still takes a channel's number up to its
	// stream cap; each route judges its own cap before the channel's, so
	// a stored directory loosens nothing either way.
	ceiling := s.channelCeiling()
	for _, ch := range d.Channels {
		if ch.MaxBytes > ceiling {
			s.fail(w, http.StatusBadRequest, fmt.Sprintf(
				"channel %q: max_bytes %d is over the %d this relay takes", ch.Name, ch.MaxBytes, ceiling))
			return
		}
	}
	// Belt and braces: Verify has required the owner to be the key's
	// fingerprint, and the key is this mailbox's bundle, so this cannot
	// differ unless the two are looked up differently one day.
	if d.Owner != fp {
		s.fail(w, http.StatusBadRequest, "directory owner is not this mailbox")
		return
	}
	var older *DirectoryOlderError
	stored, err := s.store.SetDirectory(fp, d, req.Document, req.Signature)
	switch {
	case errors.As(err, &older):
		s.fail(w, http.StatusConflict, fmt.Sprintf("a newer directory is already there (issued %s)",
			older.Issued.UTC().Format(time.RFC3339)))
		return
	case errors.Is(err, ErrNoMailbox):
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	case err != nil:
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	// Only for a directory that replaced the stored one: a push of what
	// the relay already holds changes nothing anyone is waiting on. After
	// the answer, as every wake is (R25): the stored directory is what the
	// woken watcher reads, and it is written already.
	w.WriteHeader(http.StatusNoContent)
	if stored {
		s.notify.Wake(dirKey(fp))
	}
}

// handleGetChannels is GET /v1/mailbox/{fp}/channels, for anyone who may
// post to the mailbox.
//
// Order: the mailbox must exist and not be blocked, must not be a
// neighbouring relay's courier's, and the allow list must admit the
// caller, before anything about the directory is said — a refused
// sender gets the sentence a refused post gets, and learns nothing new. A
// mailbox with no directory is a 404 with a sentence of its own, since it
// has default and nothing else. The owner's own answer adds how many
// messages wait under each channel; nobody else's does.
func (s *Server) handleGetChannels(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
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
	// A courier's mailbox answers as a refusing one, in the post route's
	// words, so it looks the same on every route. Every caller here is
	// registered and may read GET /v1/couriers, so this hides nothing from
	// them; it keeps the contrast with this route from undercutting the
	// silence that matters, a forward's delivery, which a sender with no
	// mailbox here reads through its report.
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
	doc, sig, found, err := s.store.Directory(fp)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if !found {
		s.refuse(w, http.StatusNotFound, relayapi.RefusalNoDirectory)
		return
	}
	resp := relayapi.ChannelsResponse{Document: doc, Signature: sig}
	if callerFP == fp {
		counts, err := s.store.ChannelCounts(fp)
		if err != nil {
			s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
			return
		}
		// Every listed channel is in the map, at zero when nothing waits,
		// and so is any name mail still waits under after its channel was
		// removed. The document was verified when it was stored, and is
		// read here only for its names.
		var d channels.Directory
		if err := json.Unmarshal(doc, &d); err != nil {
			s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
			return
		}
		for _, ch := range d.Channels {
			if _, ok := counts[ch.Name]; !ok {
				counts[ch.Name] = 0
			}
		}
		resp.Queued = counts
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// channelCeiling is the most this relay takes of any kind, which a
// channel's max_bytes may not exceed: the larger of max_bytes and
// max_stream_bytes, with max_stream_bytes 0, unlimited, meaning the
// protocol's MaxStreamSize.
func (s *Server) channelCeiling() int64 {
	streams := s.cfg.MaxStreamBytes
	if streams <= 0 {
		streams = relayapi.MaxStreamSize
	}
	return max(s.cfg.MaxBytes, streams)
}

// channelForPost settles which channel a post, a stream being opened or a
// courier's delivery goes to: the name on the wire, or default when there
// is none. It runs after the allow list has admitted the sender, so a
// sender the owner has not admitted learns nothing about which channels
// exist, and before anything is stored or charged. The name must be one a
// directory could hold, must be in the mailbox's directory (default alone,
// for a mailbox with none), must be open at the relay's clock, both edges
// inclusive, and the channel must take a message of size wire bytes that
// is a stream or not and came by way of another relay or not. It reports
// whether the caller may go on; when not, the refusal has been written.
func (s *Server) channelForPost(w http.ResponseWriter, fp, name string, size int64, stream, forwarded bool) (string, bool) {
	name, refused := s.judgeChannel(fp, name, size, stream, forwarded)
	if refused != nil {
		s.writeRefusal(w, refused)
		return "", false
	}
	return name, true
}

// judged is a refusal the relay has judged and writes later: a status,
// the code a client acts on where there is one, the sentence, and the time
// a refusal about a time carries as data. storage marks the storage error's
// fixed refusal.
type judged struct {
	status  int
	code    string
	msg     string
	at      time.Time
	storage bool
}

// writeRefusal writes a judged refusal the way its kind is written.
func (s *Server) writeRefusal(w http.ResponseWriter, r *judged) {
	switch {
	case r.storage:
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
	case !r.at.IsZero():
		s.failAt(w, r.status, r.code, r.msg, r.at)
	case r.code != "":
		s.failCode(w, r.status, r.code, r.msg)
	default:
		s.fail(w, r.status, r.msg)
	}
}

// judgeChannel is channelForPost's judgement, the refusal answered rather
// than written, for the stream routes to judge an upload's channel again
// after its open (R22).
func (s *Server) judgeChannel(fp, name string, size int64, stream, forwarded bool) (string, *judged) {
	if name == "" {
		name = channels.Default
	}
	// Before the lookup, so the refusal never echoes a name longer than a
	// directory could hold.
	if err := channels.ValidName(name); err != nil {
		return "", &judged{status: http.StatusBadRequest, msg: "channel " + err.Error()}
	}
	exists, ch, err := s.store.ChannelState(fp, name)
	if err != nil {
		return "", &judged{storage: true}
	}
	if !exists {
		return "", &judged{status: http.StatusNotFound, code: relayapi.CodeNoSuchChannel, msg: fmt.Sprintf("no such channel %q", name)}
	}
	now := s.cfg.Now()
	if open, why := ch.OpenAt(now); !open {
		// The bound the sentence names, as data: the start for a channel
		// whose period has not begun, the end for one whose has ended.
		at := time.Time{}
		switch {
		case ch.NotBefore != nil && now.Before(*ch.NotBefore):
			at = *ch.NotBefore
		case ch.NotAfter != nil:
			at = *ch.NotAfter
		}
		return "", &judged{status: http.StatusForbidden, code: relayapi.CodeChannelClosed,
			msg: fmt.Sprintf("channel %q %s: %s", name, relayapi.MsgChannelClosed, why), at: at}
	}
	// The channel's own rules, after its period and in Refuses' order. The
	// route's own cap for this kind was judged before the channel was
	// looked up, so these only ever tighten it.
	rule, why := ch.Refuses(size, stream, forwarded)
	switch rule {
	case channels.RuleNoStreams:
		return "", &judged{status: http.StatusForbidden, code: relayapi.CodeChannelStreams, msg: fmt.Sprintf("channel %q %s", name, why)}
	case channels.RuleNoForwards:
		return "", &judged{status: http.StatusForbidden, code: relayapi.CodeChannelForwards, msg: fmt.Sprintf("channel %q %s", name, why)}
	case channels.RuleMaxBytes:
		return "", &judged{status: http.StatusRequestEntityTooLarge, code: relayapi.CodeChannelSize, msg: fmt.Sprintf("channel %q %s", name, why)}
	}
	return name, nil
}

// issuedRefusal is the sentence for an owner document CheckIssued refused:
// its own, and for issued ahead of now, whose clock it was.
func issuedRefusal(err error) string {
	if errors.Is(err, relayapi.ErrAheadOfNow) {
		return "by this relay's clock, " + err.Error()
	}
	return err.Error()
}
