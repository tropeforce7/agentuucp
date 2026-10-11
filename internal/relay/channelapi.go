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
	// the relay already holds changes nothing anyone is waiting on.
	if stored {
		s.notify.Wake(dirKey(fp))
	}
	w.WriteHeader(http.StatusNoContent)
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

// channelForPost settles which channel a post, or a stream being opened,
// goes to: the name on the wire, or default when there is none. It runs
// after the allow list has admitted the sender, so a sender the owner has
// not admitted learns nothing about which channels exist, and before
// anything is stored or charged. The name must be one a directory could
// hold, must be in the mailbox's directory (default alone, for a mailbox
// with none), and must be open at the relay's clock, both edges inclusive.
// It reports whether the caller may go on; when not, the refusal has been
// written.
func (s *Server) channelForPost(w http.ResponseWriter, fp, name string) (string, bool) {
	if name == "" {
		name = channels.Default
	}
	// Before the lookup, so the refusal never echoes a name longer than a
	// directory could hold.
	if err := channels.ValidName(name); err != nil {
		s.fail(w, http.StatusBadRequest, "channel "+err.Error())
		return "", false
	}
	exists, ch, err := s.store.ChannelState(fp, name)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return "", false
	}
	if !exists {
		s.failCode(w, http.StatusNotFound, relayapi.CodeNoSuchChannel, fmt.Sprintf("no such channel %q", name))
		return "", false
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
		s.failAt(w, http.StatusForbidden, relayapi.CodeChannelClosed,
			fmt.Sprintf("channel %q %s: %s", name, relayapi.MsgChannelClosed, why), at)
		return "", false
	}
	return name, true
}

// issuedRefusal is the sentence for an owner document CheckIssued refused:
// its own, and for issued ahead of now, whose clock it was.
func issuedRefusal(err error) string {
	if errors.Is(err, relayapi.ErrAheadOfNow) {
		return "by this relay's clock, " + err.Error()
	}
	return err.Error()
}
