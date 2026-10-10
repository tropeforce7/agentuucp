package relay

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/wire"
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
//   - then the neighbour, the poster's carried share, the carried ceiling
//     and the queue's room; or the delivery, which takes the carried share
//     after its own checks.
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
	if !s.decodeRequest(w, body, &req, "forward request") {
		return
	}
	// A user's copy of a message to several is held to max_recipients
	// here, where the request was read: after the forward's charge, as
	// every refusal of a forward's body is, and before anything is
	// stored. This relay is the first one only for a user; a courier's
	// onward request is a relay's, whose first relay held its sender
	// already, and a count on it is not read.
	if !isCourier && !s.holdRecipients(w, req.SectionList(), "forward request") {
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
		s.deliver(w, r, env, req.Envelope, JoinPath(via), hash, callerFP, courierName, isCourier)
		return
	}

	next := req.Path[0]
	neighbour, ok := s.courier.Neighbour(next)
	if !ok {
		s.failCode(w, http.StatusNotFound, relayapi.CodeNoNeighbour, fmt.Sprintf("%s %q on this relay", relayapi.MsgNoNeighbour, next))
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
	// The hash this row writes is charged to its poster here, after every
	// check made before the store and immediately before the one write,
	// one token for each ForwardTTL it will be kept. Every store answer but
	// success wrote no hash, so each gives the tokens back.
	tokens := s.cfg.CourierLimits.carriedHops(len(req.Path) - 1)
	if !s.chargeCarried(w, callerFP, tokens, isCourier) {
		return
	}
	id, err := s.store.Enqueue(row, req.Envelope, quotas, expires)
	if err != nil {
		s.returnCarried(callerFP, tokens, isCourier)
	}
	switch {
	case errors.Is(err, ErrCarried):
		// A retry after a lost answer, or a loop dying. A row's id and how
		// it ended go back only to its poster: a second courier posting the
		// same envelope learns nothing about another's row.
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
		s.refuse(w, http.StatusInsufficientStorage, relayapi.RefusalRelayFull)
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

// deliver puts a forwarded envelope into a mailbox on this relay, which is
// the end of its journey: the path is spent, so the recipient is here.
//
// The order is the post route's order, and for the post route's reasons —
// the mailbox exists, it is not blocked, it is not a courier's, the sender
// is admitted, the channel is one the owner published — with one thing
// different at the sender. The sender the allow list is asked about is the
// courier that posted, not whoever sealed the envelope: a relay cannot read
// the envelope, so it cannot know who wrote it, and the identity it can
// prove is the neighbour that handed it over. So a recipient with a
// restricted list admits a relay rather than a person, and admits everybody
// behind that relay with it, which the security document says in those
// words because it is the one place a list means something coarser than the
// fingerprints in it.
//
// The answer goes back to the courier on this request: a delivery is done
// when it is done, and the neighbour holding the row wants to know that it
// may let go of it.
func (s *Server) deliver(w http.ResponseWriter, r *http.Request, env *relayapi.Carried,
	raw []byte, via, hash, callerFP, courierName string, isCourier bool) {

	fp := env.To
	// The operator's own cap on a message, which the post route refuses at
	// and this must too: the forward route's body cap is max_bytes plus the
	// framing a request costs, so without this a neighbour's courier could
	// place a message that much over the setting into a mailbox here, and
	// an operator's number would mean one thing for their own users and
	// another for everybody reached through a peer.
	if int64(len(raw)) > s.cfg.MaxBytes {
		s.fail(w, http.StatusRequestEntityTooLarge, "envelope too large")
		return
	}
	exists, blocked, err := s.store.MailboxState(fp)
	if err != nil {
		s.storageFault(w, r, err)
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
	// A courier's mailbox refuses every sender, as it does on every other
	// route that carries something into one, and in the same words. A
	// neighbour forwarding mail to another neighbour's courier is a loop
	// somebody built by hand; it ends here and says nothing about who this
	// relay peers with.
	if s.isCourierMailbox(fp) {
		s.fail(w, http.StatusForbidden, msgNotAllowed)
		return
	}
	allowed, err := s.store.MayPost(fp, callerFP)
	if err != nil {
		s.storageFault(w, r, err)
		return
	}
	if !allowed {
		s.fail(w, http.StatusForbidden, msgNotAllowed)
		return
	}
	channel, ok := s.channelForPost(w, fp, env.Ch)
	if !ok {
		return
	}
	// The hash this delivery writes is charged to the courier here, after
	// every check made before the store and immediately before the write:
	// one token, since a hash for an envelope at its last hop is kept one
	// ForwardTTL. Every store answer but success wrote no hash, so each
	// gives it back.
	if !s.chargeCarried(w, callerFP, 1, isCourier) {
		return
	}
	put := func() (int64, error) {
		return s.store.Put(fp, channel, relayapi.KindEnvelope, "", raw, s.cfg.Limits.Quotas(),
			Forwarded{
				Via:     via,
				Hash:    hash,
				Expires: s.cfg.Now().Add(s.cfg.CourierLimits.CarriedWindow(0)),
				Quotas:  s.cfg.CourierLimits.Quotas(),
			})
	}
	id, err := put()
	if s.roomFreed(err) {
		id, err = put()
	}
	if err != nil {
		s.returnCarried(callerFP, 1, isCourier)
	}
	switch {
	case errors.Is(err, ErrCarried):
		// The same envelope arriving twice, which the cheap check above
		// catches in the ordinary case; this is the one that decides,
		// inside the transaction, and is what makes a delivery idempotent
		// for a neighbour whose answer was lost.
		s.alreadyCarried(w, callerFP, hash, courierName, isCourier)
		return
	case errors.Is(err, ErrCarriedFull):
		s.fail(w, http.StatusInsufficientStorage, relayapi.MsgCarriedFull)
		return
	case errors.Is(err, ErrMailboxFull):
		// The recipient has to collect their mail, which is neither the
		// courier's doing nor something it can retry around; its row waits
		// and its own forward_ttl ends it if nobody does.
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
		s.storageFault(w, r, err)
		return
	}
	// After the store has the row, so a listing woken by this finds it.
	s.notify.Wake(mailKey(fp))
	s.writeJSON(w, http.StatusCreated, relayapi.ForwardResponse{ID: id})
}

// handleFailed takes an undeliverable coming back from a neighbour: the first
// control message, and the one route on which a relay tells another relay
// something rather than handing it something.
//
// The order is this route's whole content, as every route's is:
//
//   - the certificate, the header, the identity and the signature over the
//     body, in callerAuthedBody;
//   - the caller is a courier this relay accepts from, which is what a report
//     is between, and any other caller is refused before the body is looked
//     at;
//   - the courier's request budget and its reports_per_minute, beside each
//     other and both keyed by the fingerprint the signature proved;
//   - the three fields to their rules, so nothing is looked up for a body
//     that is not a report;
//   - then the row.
//
// A report is never stored as a file, never hashed into the carried table and
// never turned into a message: what it costs this relay is one row's state
// and, when the row's poster is itself a courier, one more row in the queue.
func (s *Server) handleFailed(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	if s.courier == nil {
		s.fail(w, http.StatusForbidden, relayapi.MsgForwardsNothing)
		return
	}
	courierName, isCourier := s.courier.Accepts(callerFP)
	if !isCourier {
		s.fail(w, http.StatusForbidden, relayapi.MsgNotACourier)
		return
	}
	if ok, retry := s.lim.courierReports.Allow(callerFP); !ok {
		s.rateLimited(w, limitCourierReports, retry, "")
		return
	}
	var req relayapi.ForwardFailedRequest
	if !s.decodeRequest(w, body, &req, "report") {
		return
	}
	if req.ID <= 0 {
		s.fail(w, http.StatusBadRequest, "a report names the id this relay was answered with")
		return
	}
	if req.Code != relayapi.CodeRefused && req.Code != relayapi.CodeGaveUp {
		s.fail(w, http.StatusBadRequest, fmt.Sprintf("code is %q or %q",
			relayapi.CodeRefused, relayapi.CodeGaveUp))
		return
	}
	if len(req.Said) > relayapi.MaxSaid {
		s.fail(w, http.StatusBadRequest, fmt.Sprintf("said is %d bytes; at most %d",
			len(req.Said), relayapi.MaxSaid))
		return
	}
	if err := message.ValidOneLine("said", req.Said); err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}

	// The name a row was handed under is the courier home's spelling, since
	// that is what handleForward and reportBack write into the row. The
	// couriers file's spelling is what Accepts answers, and the two may differ
	// in case: both halves of a peering fold internally, so a file saying Bar
	// against a home saying bar is one neighbour and not a pair of one-way
	// ones, and this relay says so in as many words where it reads them. The
	// column has no COLLATE, so looking a row up by the file's spelling found
	// nothing and every report from such a peering was refused 404 for ever —
	// with the reporting relay reading a 404 as final and dropping the news,
	// and nothing logged at the end that could have fixed it. One name, one
	// spelling, resolved through the home exactly as reportBack resolves it.
	neighbour, dialable := s.courier.Neighbour(courierName)
	if !dialable {
		// A courier this relay accepts from under a name its home does not
		// know. Either nothing was ever handed to it — a one-way peering,
		// which the relay names at its start — or the operator gave it two
		// different names rather than two spellings of one, which the start
		// also names, and rows for it were written under the home's name.
		// Neither is answerable here: this route is given a fingerprint and
		// an id, and the one name it can reach from them is this one. So the
		// answer is the same as for a row that is not there, and the operator
		// has already been told at the start which names appear in one file
		// and not the other, that being the only place the two can be
		// compared.
		s.fail(w, http.StatusNotFound, relayapi.MsgNoSuchRow)
		return
	}
	row, found, err := s.store.HandedTo(neighbour.Name, req.ID)
	if err != nil {
		s.storageFault(w, r, err)
		return
	}
	if !found {
		s.fail(w, http.StatusNotFound, relayapi.MsgNoSuchRow)
		return
	}
	if row == nil {
		s.fail(w, http.StatusConflict, relayapi.MsgRowNotHanded)
		return
	}

	// The row ends, with this relay's own name for the hop that reported in
	// front of the sentence, so that what the sender eventually reads names
	// each relay by a name their own relay chose. said also cuts and escapes
	// it, as it does a refusal met on a dial.
	//
	// The ending is guarded on the row still being handed, in the UPDATE's own
	// WHERE, because the read above and this write are two statements: two
	// reports naming one id both read handed, and without the guard both took
	// it. A report is taken once, which both documents say, and a caller that
	// lost the race gets the answer it would have got had it arrived second.
	took, err := s.store.FailHandedOnce(row.ID, req.Code, said(neighbour.Name, req.Said), s.cfg.Now())
	if err != nil {
		s.storageFault(w, r, err)
		return
	}
	if !took {
		s.fail(w, http.StatusConflict, relayapi.MsgRowNotHanded)
		return
	}
	// And one hop further back, when the row was not this relay's own user's
	// but a neighbour's. Never for a report: the chain ends where it started.
	//
	// Whatever that does, this request succeeded. The report has been taken
	// and the row is final, which is everything the relay that reported
	// needed: it may let its own row go. Passing a failure back to it would
	// invite it to retry a report this relay has already acted on, and a
	// second report on a final row is refused, so the retry would be a
	// request nobody can answer usefully. So the news failing to travel
	// further is a line in this relay's log keyed by the neighbour it was
	// for — the same line as a neighbour refusing one — and that line is the
	// only trace there will be.
	//
	// Nothing tells the hop behind later, which is worth saying plainly
	// because it is the one place news is lost rather than delayed: the row
	// that would have to notice is one that relay has already handed over,
	// and a handed row that hears nothing is the ordinary shape of success,
	// a delivered message producing no report at all. So no relay can tell a
	// delivery from news that never arrived, and ending handed rows on a
	// timer would tell every sender that every delivered message had failed.
	// forward_ttl ends a row that is still waiting, which is a relay that
	// never got the message away, and is a different thing.
	//
	// That includes the case where this relay's queue has no room for the
	// report: a report row is counted against the row bounds because it is a
	// row, so a courier at its share can be refused one.
	if name := reportBack(s.store, s.courier, s.cfg.CourierLimits, s.cfg.Now(),
		row, req.Code, said(neighbour.Name, req.Said)); name != "" {
		s.wake(name)
	}
	w.WriteHeader(http.StatusNoContent)
}

// reportBack queues an undeliverable for the courier that posted the row just
// failed, so that the news travels one hop at a time back to whoever sent the
// message. It answers the neighbour to wake, or the empty string.
//
// Both ways a row can end come here, and they are the two halves of the same
// thing. The last hop refuses a delivery synchronously, so the relay before it
// learns at its own worker and fails the row there; a hop further out learns
// by a report on the route. Either way the row is final and either way the
// poster may be a neighbour rather than one of this relay's own users, and a
// poster that is a neighbour is owed the news. Wiring only the route would
// have left the commonest failure of all — the last hop refusing — unwinding
// exactly one hop and stopping.
//
// The id it carries is this relay's own row id, because that is the number the
// courier being told holds: it took this relay's answer when it handed the
// envelope over and wrote it into its own row as their_id.
//
// A report is never made for a report: the chain ends where it started. And a
// failure to queue one is a line in the log and nothing more — the row is
// already final, which is what its own poster needs, and nobody further back is
// told, then or later. The note at the call in handleFailed says why there is no
// timer that could tell them: a handed row hearing nothing is success, so a
// timer would tell every sender their delivered mail had failed.
func reportBack(st *Store, c *Courier, limits CourierLimits, now time.Time,
	row *Outbound, code, said string) string {

	if c == nil || row.Kind == KindReport {
		return ""
	}
	name, ok := c.Accepts(row.PosterFP)
	if !ok {
		// The poster is one of this relay's own users. Their row says
		// everything, and they read it in their own queue.
		return ""
	}
	neighbour, ok := c.Neighbour(name)
	if !ok {
		// A courier this relay accepts from that it cannot dial: a one-way
		// peering, which the start says out loud. The news stops here.
		st.faults.noteUndialable(name)
		return ""
	}
	if err := st.EnqueueReport(&Outbound{
		PosterFP:  row.PosterFP,
		Neighbour: neighbour.Name,
		Kind:      KindReport,
		TheirID:   row.ID,
		Code:      code,
		Said:      said,
		Received:  now,
		GivesUp:   now.Add(limits.ForwardTTL),
		// A courier's own quotas and not a user's: the poster of this row is
		// the courier being told, so its share of the queue is the share
		// this row spends.
	}, limits.CourierQuotasFor()); err != nil {
		st.faults.noteReportNotQueued(neighbour.Name, err)
		return ""
	}
	return neighbour.Name
}

// handleCouriers answers every neighbour this relay accepts forwarded mail
// from, this relay's own name for each and the fingerprint its couriers file
// admits.
//
// It is for this relay's own users, and what they need it for is the allow
// list. Delivery of a forwarded message asks the recipient's allow list about
// the *courier* that handed the envelope over, because a relay cannot open one
// and the only sender it can prove is its neighbour — so a recipient who has
// pushed a list at all is unreachable from every other relay until they admit
// these fingerprints by name. Somebody who cannot read this cannot be written
// to from off this relay, so an operator who withheld it would be breaking
// forwarding for their own users rather than keeping a secret.
//
// callerAuthed and not adminAuthed, and not open: any registered identity here,
// nobody else. That is narrower than it looks and it does not reopen what a
// courier's mailbox was made silent to close. That mailbox answers exactly as
// every refusing mailbox does, so a stranger holding a fingerprint cannot learn
// whether this relay accepts from it by posting at it; this route answers only
// identities that have a mailbox here, which the same stranger does not have.
//
// There is no paging and no parameter. The whole list is at most
// relayapi.MaxCouriers entries, which is also the most lines the couriers file
// may hold, so a relay that loaded its file cannot answer more than a client
// will accept; and a list of relay names is small enough that a page would be
// an interface nobody needs. A relay with no courier block answers an empty
// list rather than a 404: it forwards nothing, which is an answer.
func (s *Server) handleCouriers(w http.ResponseWriter, r *http.Request, callerFP string) {
	// Always a list and never null: absent and empty are one value after a
	// decode, and empty is the honest one for a relay that peers with nobody.
	list := s.courier.Accepted()
	if list == nil {
		list = []relayapi.Courier{}
	}
	s.writeJSON(w, http.StatusOK, relayapi.CouriersResponse{Couriers: list})
}

// handleQueue answers the caller their own rows in this relay's forwarding
// queue: the mail they addressed to somebody on another relay and this relay
// has still to hand over, or has handed over, or has given up on.
//
// For a caller that is a neighbour's courier the rows include the reports this
// relay owes it, a report row's poster being that courier. They are its own
// rows and belong on its page, but they are rows about its mail rather than its
// mail, so a courier's page can hold both; nothing reads that page to learn
// about a report, the report route being how a courier is told, so this is a
// thing to know rather than a thing to work around.
//
// It is the owner's own, by the fingerprint the signature proved, and a
// mailbox that is not the caller's is refused as it is on every other route
// that reads a mailbox's private state. The rows name a poster and nobody
// else — a recipient is blanked the moment a neighbour takes the envelope —
// so there is nothing here that is anybody's but the caller's.
//
// A relay that forwards nothing has no such queue and says so, in the same
// sentence the forward route gives, because the answer to "what is waiting"
// on such a relay is not an empty list but that there is nowhere for
// anything to wait.
func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	if fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	if s.courier == nil {
		s.fail(w, http.StatusForbidden, relayapi.MsgForwardsNothing)
		return
	}
	rows, err := s.store.OutboundFor(callerFP, relayapi.MaxQueueLimit)
	if err != nil {
		s.storageFault(w, r, err)
		return
	}
	out := relayapi.QueueResponse{Queued: make([]relayapi.QueuedMessage, 0, len(rows))}
	for _, o := range rows {
		out.Queued = append(out.Queued, relayapi.QueuedMessage{
			ID: o.ID, Neighbour: o.Neighbour, Path: o.Path, State: o.State,
			Tries: o.Tries, LastTry: o.LastTry, NextTry: o.NextTry, GivesUp: o.GivesUp,
			Code: o.Code, Said: o.Said,
		})
	}
	s.writeJSON(w, http.StatusOK, out)
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

// chargeCarried spends a poster's share of the carried hashes, a user's or
// a courier's, keyed by the fingerprint the signature proved, and answers
// 429 with Retry-After when the share is spent. It is the last check before
// the write of a forward or a delivery, so a refusal here stores nothing.
// The share is spent only on a write that is tried, and returnCarried
// gives it back when the write fails.
func (s *Server) chargeCarried(w http.ResponseWriter, callerFP string, tokens int64, isCourier bool) bool {
	bucket, setting := s.lim.carried, "courier.carried_rows_per_poster"
	if isCourier {
		bucket, setting = s.lim.courierCarried, "courier.carried_rows_per_courier"
	}
	ok, retry := bucket.AllowN(callerFP, tokens)
	if !ok {
		s.rateLimited(w, limitCarried, retry, fmt.Sprintf(
			"; this relay keeps a hash of every envelope it carries, and %s bounds "+
				"how many one poster's may stand", setting))
	}
	return ok
}

// returnCarried gives back what chargeCarried spent, for a write that wrote
// no hash.
func (s *Server) returnCarried(callerFP string, tokens int64, isCourier bool) {
	bucket := s.lim.carried
	if isCourier {
		bucket = s.lim.courierCarried
	}
	bucket.Return(callerFP, tokens)
}

// alreadyCarried answers a 409 for an envelope this relay has taken before,
// with what Store.CarriedAnswerFor finds: the caller's own row's id, and for
// an ended row its code and sentence; or the id of the message it became; or
// nothing. The caller reads the first and third as taken, the second as its
// own row ending the same way, and a bare 409 as refused (rulings 44 and 45).
// Nothing is stored and no mailbox is charged.
func (s *Server) alreadyCarried(w http.ResponseWriter, callerFP, hash, courierName string, isCourier bool) {
	if isCourier {
		s.store.faults.noteCarriedAgain(courierName)
	}
	answer, err := s.store.CarriedAnswerFor(callerFP, hash)
	if err != nil || answer.ID == 0 {
		// Bare: nothing of the caller's here and nothing delivered, which
		// is a loop coming back, and the caller reads it as refused. On a
		// lookup that failed the refusal stands too, the envelope being
		// carried whatever the lookup did.
		s.fail(w, http.StatusConflict, relayapi.MsgAlreadyCarried)
		return
	}
	s.writeJSON(w, http.StatusConflict, relayapi.ForwardResponse{ID: answer.ID, Code: answer.Code, Said: answer.Said})
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

// parseForwarded reads the envelope out of a forward request. An absent
// field and a null one are both no envelope: the second decodes to four
// bytes rather than none, and without this it would reach the strict decode
// and come back as an envelope whose version is zero, which is a sentence
// about a field nobody sent.
func parseForwarded(raw []byte) (*relayapi.Carried, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("forward request carries no envelope")
	}
	return parseCarried(raw)
}

// parseCarried is how every route reads the outer envelope it is given:
// strictly, the four fields of relayapi.Carried and no other, a version of 1
// or more, a recipient that is a fingerprint and a ciphertext that is not
// empty. It is the bytes as they arrived that are stored and passed on, never
// these fields, so a relay never hands on something other than what it was
// given, and the version is the two ends' business: this relay carries one
// it has never heard of (D38).
func parseCarried(raw []byte) (*relayapi.Carried, error) {
	var env relayapi.Carried
	if err := wire.Decode(raw, &env); err != nil {
		return nil, fmt.Errorf("malformed envelope: %v", err)
	}
	if env.V < 1 {
		return nil, fmt.Errorf("envelope v is %d; a relay carries any version from 1", env.V)
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
	s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
}
