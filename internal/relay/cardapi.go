package relay

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The card routes. An owner pushes a signed card and reads it back
// verbatim; the relay verifies the signature against the mailbox's
// registered bundle before storing anything, and again every time it lets
// a knock past the allow list on the card's word, so it cannot open a
// mailbox the owner did not open. The listing route serves stored cards
// to every registered identity, which verifies each for itself. The
// access log records the route and nothing from the body.

// handleSetCard is PUT /v1/mailbox/{fp}/card, owner only.
//
// Order: the caller must be the owner, the body must decode, the signature
// must verify under the mailbox's own key (a request with no document has
// none that does), the document must pass every rule, its owner must be
// this mailbox, and only then is the store asked, which refuses a card no
// newer than the one it holds. The body is read under the general cap, a
// card being a few hundred bytes.
func (s *Server) handleSetCard(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	if fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	var req relayapi.CardRequest
	if !s.decodeRequest(w, body, &req, "card request") {
		return
	}
	// The caller has just authenticated as this mailbox, so the bundle is
	// there; anything else is the store's trouble.
	mb, err := s.store.Mailbox(fp)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	pub, err := identity.ParseBundle(mb.Bundle)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	d, err := card.Verify(pub, req.Document, req.Signature)
	switch {
	case errors.Is(err, card.ErrSignature):
		s.fail(w, http.StatusUnauthorized, "card signature does not verify")
		return
	case errors.Is(err, card.ErrOwner):
		s.fail(w, http.StatusBadRequest, "card owner is not this mailbox")
		return
	case err != nil:
		// The validator's sentence, which names the rule, or the
		// decoder's, which names the field.
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	// Belt and braces, as the other two documents' pushes have it: Verify
	// has required the owner to be the key's fingerprint, and the key is
	// this mailbox's bundle.
	if d.Owner != fp {
		s.fail(w, http.StatusBadRequest, "card owner is not this mailbox")
		return
	}
	var older *CardOlderError
	_, err = s.store.SetCard(fp, d, req.Document, req.Signature)
	switch {
	case errors.As(err, &older):
		s.fail(w, http.StatusConflict, fmt.Sprintf("a newer card is already there (issued %s)",
			older.Issued.UTC().Format(time.RFC3339)))
		return
	case errors.Is(err, ErrNoMailbox):
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	case err != nil:
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetCard is GET /v1/mailbox/{fp}/card, owner only: the pair as
// pushed, and the state the relay reads it as. A mailbox that has never
// pushed one answers with no document and the state none.
func (s *Server) handleGetCard(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	if fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	doc, sig, state, _, err := s.store.Card(fp)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	s.writeJSON(w, http.StatusOK, relayapi.CardResponse{Document: doc, Signature: sig, State: state})
}

// handleListed is GET /v1/listed?after=FP&limit=N: a page of the cards
// whose owners chose to be listed, each with its bundle, for any
// registered and unblocked identity, which the wrapper has settled.
// after is a fingerprint or absent, refused by name otherwise before it
// reaches SQL; limit is held to [1, MaxListedLimit], the default the cap,
// and refused over it rather than served at the cap, since a client
// sizes what it holds of a page to the cap and would refuse more. The
// relay verifies nothing here; the reader verifies every entry.
func (s *Server) handleListed(w http.ResponseWriter, r *http.Request, callerFP string) {
	after := r.URL.Query().Get("after")
	if after != "" && !identity.ValidFingerprint(after) {
		s.fail(w, http.StatusBadRequest, "bad after parameter")
		return
	}
	limit, err := intParam(r, "limit", relayapi.MaxListedLimit)
	if err != nil || limit < 1 || limit > relayapi.MaxListedLimit {
		s.fail(w, http.StatusBadRequest, fmt.Sprintf("bad limit parameter: from 1 to %d", relayapi.MaxListedLimit))
		return
	}
	entries, total, err := s.store.ListedCards(after, int(limit))
	if err != nil {
		s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
		return
	}
	s.writeJSON(w, http.StatusOK, relayapi.ListedResponse{Entries: entries, Listed: total})
}
