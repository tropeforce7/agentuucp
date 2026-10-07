package relay

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The knock route: a stranger's one message to a mailbox whose owner has
// said, on a signed card, that they take knocks. It is a route and not a
// field of the post because everything that can be judged without the
// body is judged before it, and a kind inside the body would have the
// relay read a whole post before learning it was a knock; so the route
// has a cap of its own, knock_max_bytes, and a body that declares itself
// over it is refused before a byte is read.

// handleKnock shares handlePost's shape and its helpers, and never calls
// MayPost: the knock is the one message that goes past the allow list,
// and it goes past it only where the recipient's card, verified here and
// now, says knocks. After the wrapper's certificate, header, identity,
// body under the knock cap, signature and block, in order: the knock's
// own size cap; the post budgets, charged as for any post; the envelope
// parsed and held to be addressed to the mailbox and to name no channel;
// the mailbox's existence and block; the card; the sender's knock bucket;
// then Put, which holds the mailbox's knock cap inside its transaction
// and gives the knock token back when it refuses. The post budgets are
// not given back on a refused Put, exactly as handlePost keeps them.
func (s *Server) handleKnock(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	size := int64(len(body))
	if size > s.knockMax() {
		s.fail(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("knock too large: at most %d bytes (knock_max_bytes)", s.knockMax()))
		return
	}
	if ok, retry := s.lim.posts.Allow(callerFP); !ok {
		s.rateLimited(w, limitPosts, retry, "")
		return
	}
	if ok, retry := s.lim.postBytes.AllowN(callerFP, size); !ok {
		s.rateLimited(w, limitPostBytes, retry, "")
		return
	}

	// The outer envelope as every route reads it (parseCarried): strictly,
	// any version from 1, so that this relay never refuses mail for a
	// version that is the two ends' business.
	env, err := parseCarried(body)
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if env.To != fp {
		s.fail(w, http.StatusBadRequest, "envelope is not addressed to this mailbox")
		return
	}
	// A knock is filed under the default channel: which channels exist is
	// the owner's to publish to the senders they admit, and a knocker is
	// not one yet.
	if env.Ch != "" {
		s.fail(w, http.StatusBadRequest, "a knock names no channel")
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
	// A courier's mailbox takes no knocks either — in the words every
	// mailbox that takes none gets, not words of its own.
	//
	// The sentence below is deliberately the same for no card, a card that
	// says no, and a card that does not verify, because the state of
	// somebody else's card is not a stranger's to learn. A courier pushes
	// no card, so this is what it answered before this commit and what it
	// answers now. The post and the stream do the same thing with the
	// sentence they have: a courier's mailbox refuses every sender exactly
	// as a mailbox whose allow list named nobody would, so on none of the
	// four routes does an answer say which relays this one peers with.
	if s.isCourierMailbox(fp) {
		s.refuse(w, http.StatusForbidden, relayapi.RefusalNoKnocks)
		return
	}
	takes, err := s.store.TakesKnocks(fp)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	// One sentence for no card, a card that says no and a card that does
	// not verify: the state of somebody else's card is not a stranger's
	// to learn.
	if !takes {
		s.refuse(w, http.StatusForbidden, relayapi.RefusalNoKnocks)
		return
	}
	if ok, retry := s.lim.knocks.Allow(callerFP); !ok {
		s.rateLimited(w, limitKnocks, retry, "")
		return
	}
	// The knocker is the fingerprint the signature proved, never anything
	// the envelope claims: what the sender wrote inside is sealed and is
	// the recipient's to judge, and the column is the relay's own.
	id, err := s.store.Put(fp, channels.Default, relayapi.KindKnock, callerFP, body, s.cfg.Limits.Quotas(), Forwarded{})
	switch {
	case errors.Is(err, ErrKnocksWaiting):
		// The recipient's cap, not the sender's: the token is given back,
		// and there is no Retry-After, since the relay cannot say when
		// the recipient will fetch. A client treats the answer as final.
		s.lim.knocks.Return(callerFP, 1)
		setLimit(w, limitKnocksWaiting)
		s.fail(w, http.StatusTooManyRequests, relayapi.MsgKnocksWaiting)
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
	case err != nil:
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	s.notify.Wake(mailKey(fp))
	s.writeJSON(w, http.StatusOK, relayapi.PostResponse{ID: id})
}
