package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// handleForward takes an envelope this relay is to carry to a neighbour.
//
// The order is the whole of what this route is, and every step of it is
// before the one after for a reason:
//
//   - the certificate, the header, the identity and the signature over the
//     body, in callerAuthedBody, which is the one order every authenticated
//     route takes;
//   - whether this relay forwards at all, which costs nothing and is the
//     answer for most relays;
//   - the caller's budgets, a user's or a courier's, keyed by the
//     fingerprint the signature proved;
//   - the two lists to their rules, and the address rule over both together
//     after this relay has appended its own name for the courier, so that a
//     path nobody could route costs no parse;
//   - the envelope parsed, so that nothing is stored for a body that is not
//     an envelope;
//   - the hash against the carried table, so that an envelope this relay has
//     already taken is refused before anything is stored and before any
//     bound is spent on it;
//   - then the neighbour, the carried ceiling and the queue's room, or the
//     delivery.
//
// Everything that can be judged without storing is judged before anything is
// stored or charged to anybody.
func (s *Server) handleForward(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	if s.courier == nil {
		s.fail(w, http.StatusForbidden, relayapi.MsgForwardsNothing)
		return
	}
	// Who the caller is decides which budgets it spends and whether it may
	// write a return path at all.
	courierName, isCourier := s.courier.Accepts(callerFP)
	if !s.chargeForward(w, callerFP, int64(len(body)), isCourier) {
		return
	}

	var req relayapi.ForwardRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "malformed forward request")
		return
	}
	// A user writing via would be forging a return path, and a user with an
	// empty path has a recipient on this relay and a mailbox route to post
	// to. Both are the caller's own doing and are said plainly.
	if !isCourier {
		if len(req.Via) > 0 {
			s.fail(w, http.StatusBadRequest, relayapi.MsgViaIsACouriers)
			return
		}
		if len(req.Path) == 0 {
			s.fail(w, http.StatusBadRequest, relayapi.MsgPathNamesARelay)
			return
		}
	}
	// This relay's own name for the courier goes on before the address rule
	// runs, so that a courier cannot leave its own hop out to make room for
	// another, and so that what the rule sees is the address as it now is.
	via := req.Via
	if isCourier {
		via = append(append([]string{}, req.Via...), courierName)
	}
	if err := s.checkAddress(req.Path, via); err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}

	env, err := parseForwarded(req.Envelope)
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}

	// The hash is over the envelope and not over the request's bytes, so a
	// hop that re-spaced the JSON cannot make one envelope look like two.
	hash := CarriedHash(env)

	// An envelope this relay has already taken is refused here, before the
	// neighbour is looked up and before anything is written: a retry whose
	// answer was lost and a loop coming back are the two expected callers of
	// this route, and both should cost a read rather than a file written and
	// unlinked. Enqueue checks it again inside its own transaction, which is
	// the one that decides; this is the cheap answer, not the authority.
	// Asking first also means a retry is answered the same way after the
	// neighbour it named has been taken out of the courier home, where the
	// lookup below would say the address was wrong about an envelope this
	// relay is holding.
	if carried, err := s.store.Carried(hash); err != nil {
		s.storageFault(w, r, err)
		return
	} else if carried {
		s.alreadyCarried(w, callerFP, hash, courierName, isCourier)
		return
	}

	if len(req.Path) == 0 {
		// Delivery into a mailbox here is the next commit's. Nothing
		// between this commit and that one is released, so the sentence is
		// the honest one for the state the tree is in rather than a
		// promise: a courier that meets it has done nothing wrong and its
		// row stays waiting.
		s.fail(w, http.StatusNotImplemented, "delivery to a mailbox on this relay is not implemented yet")
		return
	}

	next := req.Path[0]
	neighbour, ok := s.courier.Neighbour(next)
	if !ok {
		s.fail(w, http.StatusNotFound, fmt.Sprintf("%s %q on this relay", relayapi.MsgNoNeighbour, next))
		return
	}
	now := s.cfg.Now()
	row := &Outbound{
		PosterFP:  callerFP,
		Neighbour: neighbour.Name,
		Path:      JoinPath(req.Path[1:]),
		Via:       JoinPath(via),
		ToFP:      env.To,
		Hash:      hash,
		Kind:      relayapi.KindEnvelope,
		Received:  now,
		GivesUp:   now.Add(s.cfg.CourierLimits.ForwardTTL),
	}
	quotas := s.cfg.CourierLimits.Quotas()
	if isCourier {
		quotas = s.cfg.CourierLimits.CourierQuotasFor()
	}
	expires := now.Add(s.cfg.CourierLimits.CarriedWindow(len(req.Path) - 1))
	id, err := s.store.Enqueue(row, req.Envelope, quotas, expires)
	switch {
	case errors.Is(err, ErrCarried):
		// A retry after a lost answer, or a loop dying. The id goes back
		// only to the poster of the row that holds it: a second courier
		// posting the same envelope learns nothing about another's row.
		s.alreadyCarried(w, callerFP, hash, courierName, isCourier)
		return
	case errors.Is(err, ErrCarriedFull):
		s.fail(w, http.StatusInsufficientStorage, relayapi.MsgCarriedFull)
		return
	case errors.Is(err, ErrQueueFull):
		// Bare: the client tells this refusal from the mailbox's and the
		// relay's by the sentence, and the bound that was reached is the
		// relay's own or the poster's and never the neighbour's, so naming
		// one would say something untrue as well as breaking the match.
		s.fail(w, http.StatusInsufficientStorage, relayapi.MsgQueueFull)
		return
	case errors.Is(err, ErrRelayFull):
		// A full disk is the operator's and is answered as such, as every
		// other route that writes answers it; a 500 would send the sender
		// looking for a fault of their own.
		setLimit(w, limitRelayFull)
		s.fail(w, http.StatusInsufficientStorage, relayapi.MsgRelayFull)
		return
	case err != nil:
		s.storageFault(w, r, err)
		return
	}
	// The worker for that neighbour is woken, and never waited for: the
	// wake is a send on a channel that holds one and cannot block, so no
	// request waits on the queue and the queue waits on no request.
	s.wake(neighbour.Name)
	s.writeJSON(w, http.StatusCreated, relayapi.ForwardResponse{ID: id})
}

// chargeForward spends the caller's budgets for one forward: a courier's
// own pair, or a user's post budgets, keyed by the verified fingerprint
// either way so nobody can spend somebody else's.
func (s *Server) chargeForward(w http.ResponseWriter, callerFP string, size int64, isCourier bool) bool {
	posts, bytes, which := s.lim.posts, s.lim.postBytes, limitPosts
	if isCourier {
		posts, bytes, which = s.lim.courierPosts, s.lim.courierPostBytes, limitCourierPosts
	}
	if ok, retry := posts.Allow(callerFP); !ok {
		s.rateLimited(w, which, retry, "")
		return false
	}
	if ok, retry := bytes.AllowN(callerFP, size); !ok {
		s.rateLimited(w, which, retry, "")
		return false
	}
	return true
}

// alreadyCarried answers a 409 for an envelope this relay has taken before,
// carrying the row's id when the caller is that row's own poster.
//
// The id is what an undeliverable coming back will name, so a retry whose
// first answer was lost needs it; a caller who is not the poster of the row
// has no business learning another poster's row id, and gets the bare
// refusal. Either way nothing is stored and no mailbox is charged.
func (s *Server) alreadyCarried(w http.ResponseWriter, callerFP, hash, courierName string, isCourier bool) {
	if isCourier {
		s.store.faults.noteCarriedAgain(courierName)
	}
	id, err := s.store.OutboundIDFor(callerFP, hash)
	if err != nil {
		// The refusal stands whatever the lookup did: the envelope is
		// carried, which is what the caller needs to know.
		s.fail(w, http.StatusConflict, relayapi.MsgAlreadyCarried)
		return
	}
	if id == 0 {
		s.fail(w, http.StatusConflict, relayapi.MsgAlreadyCarried)
		return
	}
	s.writeJSON(w, http.StatusConflict, relayapi.ForwardResponse{ID: id})
}

// checkAddress holds the two lists to their rules and the address rule to
// both of them together.
//
// Every name is a relay name — a path element a sender wrote and a directory
// under a courier home — so every name is held to the rule that makes it
// one, which is the same rule the couriers file and the home run. The two
// lists are counted together against max_hops, since what the cap is about
// is how far one address reaches. And a name appearing twice across them is
// refused: with relative names that is conservative, refusing an address
// where two different hosts happen to share a name at different hops, and
// that is the right trade, because the sender cannot tell those two cases
// apart either.
func (s *Server) checkAddress(path, via []string) error {
	// The rule is store.CheckAddress, which `auu send` runs too: a name has
	// one rule and both ends run it. What is this relay's own is the
	// ceiling, clamped here because a zero or a nonsense max_hops is the
	// zero value of the settings struct, which an embedder can hand over
	// and auu-relay never does.
	hops := s.cfg.CourierLimits.MaxHops
	if hops <= 0 || hops > relayapi.MaxHops {
		hops = relayapi.MaxHops
	}
	err := store.CheckAddress(path, via, hops)
	if errors.Is(err, store.ErrAddressHops) {
		// The one sentence this relay finishes, since the ceiling is its
		// operator's and the setting's name is what they would change.
		return fmt.Errorf("%v (courier.max_hops)", err)
	}
	return err
}

// parseForwarded reads the envelope out of a forward request and holds it to
// what this relay knows about one: its version, and a recipient that is a
// fingerprint.
//
// It is a strict decode of the bytes as they arrived, and those same bytes
// are what is stored and forwarded, so a relay never passes on something
// other than what it was given.
func parseForwarded(raw []byte) (*envelope.Envelope, error) {
	// An absent field and a null one are both no envelope. The second
	// decodes to four bytes rather than none, and without this it would
	// reach the strict decode and come back as an envelope whose version is
	// zero, which is a sentence about a field nobody sent.
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("forward request carries no envelope")
	}
	var env envelope.Envelope
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("malformed envelope: %v", err)
	}
	if env.V != envelope.Version {
		return nil, fmt.Errorf("envelope v is %d; this relay carries %d", env.V, envelope.Version)
	}
	if !identity.ValidFingerprint(env.To) {
		return nil, errors.New("envelope to is not a fingerprint")
	}
	if len(env.CT) == 0 {
		return nil, errors.New("envelope carries no ciphertext")
	}
	return &env, nil
}

// forwardCap is what the forward route reads: a post's cap and the framing
// allowance, as the post route reads, since what it carries is a post's
// envelope with two short lists beside it. max_hops names of 64 bytes and
// their JSON fit inside the allowance many times over.
func (s *Server) forwardCap() int64 { return s.cfg.MaxBytes + relayapi.FramingAllowance }

// wake nudges the worker for one neighbour. A nil set of workers is a relay
// that dials nobody, which is every relay without a courier home and every
// harness that has not been given one.
func (s *Server) wake(neighbour string) { s.workers.wake(neighbour) }

// storageFault answers a fault that is the relay's own, noting it once a
// minute per path for the operator, as every storage fault is answered.
func (s *Server) storageFault(w http.ResponseWriter, r *http.Request, err error) {
	s.store.faults.note(r.URL.Path, err)
	s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
}
