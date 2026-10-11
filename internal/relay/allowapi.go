package relay

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The allow list routes. An owner pushes a signed list and reads it back
// verbatim; the relay verifies the signature against the mailbox's
// registered bundle before storing anything, and again every time it
// enforces the list, so it cannot admit a sender the owner did not name.
// The access log records the route and nothing from the body: who an
// owner admits is the owner's, not the operator's.

// handleSetAllow is PUT /v1/mailbox/{fp}/allow, owner only.
//
// Order: the caller must be the owner, the body must decode, the body must
// carry a document at all — one with none is told so in one sentence,
// before the mailbox or its bundle is read and with nothing stored — the
// signature must verify under the mailbox's own key, the document must
// pass every rule, its owner must be this mailbox, and only then is the
// store asked, which refuses a list no newer than the one it holds. The
// request carries the document, the signature and sections, and nothing
// else: a field it does not have is refused by name (P1), except the old
// "allow" key without a document, which is told it carries no document.
func (s *Server) handleSetAllow(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	if fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	// The shape an older client sent, an unsigned list under "allow" and
	// no document, keeps its sentence (R2), looked for before the strict
	// decode would refuse the key as a field the request does not have. A
	// body with a document as well is no older client's, and the strict
	// decode refuses the stray key by name.
	if hasOldKey(body, "allow") && !hasOldKey(body, "document") {
		s.fail(w, http.StatusBadRequest, relayapi.MsgNeedSignedAllowlist)
		return
	}
	var req relayapi.AllowRequest
	if !s.decodeRequest(w, body, &req, "allow request") {
		return
	}
	if len(req.Document) == 0 && len(req.Signature) == 0 {
		s.fail(w, http.StatusBadRequest, relayapi.MsgNeedSignedAllowlist)
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
	d, err := allowlist.Verify(pub, req.Document, req.Signature)
	switch {
	case errors.Is(err, allowlist.ErrSignature):
		s.fail(w, http.StatusUnauthorized, "allow list signature does not verify")
		return
	case errors.Is(err, allowlist.ErrOwner):
		s.fail(w, http.StatusBadRequest, "allow list owner is not this mailbox")
		return
	case err != nil:
		// The validator's sentence, which names the sender and the rule,
		// or the decoder's, which names the field.
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	// The one rule that needs a clock, on the verified list and before
	// anything is stored: issued no further ahead of this relay's clock
	// than a request may be, and every time in it within what this
	// program can write (CheckIssued says which).
	if err := allowlist.CheckIssued(d, time.Now()); err != nil {
		s.fail(w, http.StatusBadRequest, issuedRefusal(err))
		return
	}
	// Belt and braces, as the directory's push has it: Verify has required
	// the owner to be the key's fingerprint, and the key is this mailbox's
	// bundle.
	if d.Owner != fp {
		s.fail(w, http.StatusBadRequest, "allow list owner is not this mailbox")
		return
	}
	var older *AllowlistOlderError
	_, err = s.store.SetAllowlist(fp, d, req.Document, req.Signature)
	switch {
	case errors.As(err, &older):
		s.failAt(w, http.StatusConflict, relayapi.CodeNewerAllowList, fmt.Sprintf("a newer allow list is already there (issued %s)",
			older.Issued.UTC().Format(time.RFC3339)), older.Issued)
		return
	case errors.Is(err, ErrNoMailbox):
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	case err != nil:
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetAllow is GET /v1/mailbox/{fp}/allow, owner only: the pair as
// pushed, and the state the relay reads it as. A mailbox that has never
// pushed one answers with no document and the state none.
func (s *Server) handleGetAllow(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	if fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	doc, sig, state, _, err := s.store.Allowlist(fp)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	s.writeJSON(w, http.StatusOK, relayapi.AllowResponse{Document: doc, Signature: sig, State: state})
}
