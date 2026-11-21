package relay

import (
	"net/http"
	"strconv"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

// handleWithdraw is POST /v1/mailbox/{fp}/withdraw/{id}: a sender puts a
// note in the place of a message it posted, by the message's withdrawal key.
//
// Its body cap is a constant, relayapi.MaxWithdrawBytes and the framing
// allowance, never the operator's max_bytes, since the note is the
// client's own fixed shape; a note over max_bytes is refused here as a
// post over it is.
//
// It runs in the post's order, each step refusing before the next. The
// wrapper has held the certificate, the header, the declared length, the
// caller, the body under the cap and the signature. Then the id, as a
// deletion holds one; the post's two budgets for the body's size, before
// anything is parsed, since a route that cost nothing would be a free
// question (D192); the request through decodeRequest, the key's shape,
// and the note as every route reads an outer envelope, addressed to this
// mailbox and no larger than a post may be; the mailbox, the caller's
// admission and the note's channel in the post's own words, the channel
// without its period or its streams rule (D195); and only then the store,
// where the key is compared and the note takes the row's place in one
// transaction, through the post's storing sequence, so a repeat is
// answered as a repeated post is.
//
// Every row the key does not open is the one 404 with
// CodeNotWithdrawable, whatever the reason, so nobody without the key
// learns anything about a mailbox. The holder of the right key learns one
// thing: whether the relay still held the message (D191).
func (s *Server) handleWithdraw(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.fail(w, http.StatusBadRequest, "bad message id")
		return
	}
	if !s.chargePost(w, callerFP, int64(len(body))) {
		return
	}
	var req relayapi.WithdrawRequest
	if !s.decodeRequest(w, body, &req, "withdrawal request") {
		return
	}
	// The key is never echoed: it is a credential.
	if !withdraw.Valid(req.Key) {
		s.fail(w, http.StatusBadRequest, "withdrawal key is not 64 lowercase hex characters")
		return
	}
	note := []byte(req.Note)
	if size := int64(len(note)); size > s.inlineMax() || size > relayapi.MaxWithdrawBytes {
		s.fail(w, http.StatusRequestEntityTooLarge, "withdrawal note too large")
		return
	}
	env, err := parseCarried(note)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "note: "+err.Error())
		return
	}
	if env.To != fp {
		s.fail(w, http.StatusBadRequest, "envelope is not addressed to this mailbox")
		return
	}
	if !s.admitPoster(w, fp, callerFP) {
		return
	}
	channel, open, refused := s.judgeNote(fp, env.Ch, int64(len(note)))
	if refused != nil {
		s.writeRefusal(w, refused)
		return
	}
	key := withdraw.Stored(req.Key)
	// The note keeps a key of its own, as any envelope posted here does,
	// but only on a channel that is open: one stored outside its period
	// keeps none, so a withdrawal is spared the period once per message
	// and never chained into new mail on a closed channel.
	noteStored := ""
	if open {
		noteStored = withdraw.Stored(withdraw.EnvelopeKey(env.To, env.CT))
	}
	s.storeOnce(w, fp, callerFP, env, func(f Forwarded) (int64, error) {
		return s.store.Replace(fp, id, key, noteStored, channel, open, note, s.cfg.Limits.Quotas(), f)
	})
}
