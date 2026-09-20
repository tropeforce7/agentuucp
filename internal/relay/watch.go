package relay

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The listing's hold. GET /v1/mailbox/{fp}?wait=D asks the relay to hold
// the listing open until a message arrives after the id asked from, or a
// directory the listing watches (peers=FP:ISSUED,...) is replaced, or D
// elapses, and then to answer the ordinary listing. A client that does
// not ask sees no change. Over either cap on holds the relay answers at
// once: the hold degrades and never refuses, and the client cannot tell a
// listing answered at once from one whose hold ended with nothing.

// holds counts the listings held open, across the relay and per identity,
// so both caps are checked and a hold taken in one step.
type holds struct {
	mu    sync.Mutex
	max   int64 // across the relay; zero is unlimited
	total int64
	perFP map[string]int
}

func newHolds(max int64) *holds {
	return &holds{max: max, perFP: map[string]int{}}
}

// take reports whether one more hold for fp is within both caps, and
// counts it when it is.
func (h *holds) take(fp string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.max > 0 && h.total >= h.max {
		return false
	}
	if h.perFP[fp] >= maxWaitingPerIdentity {
		return false
	}
	h.total++
	h.perFP[fp]++
	return true
}

func (h *holds) release(fp string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.total--
	if h.perFP[fp]--; h.perFP[fp] <= 0 {
		delete(h.perFP, fp)
	}
}

// held is how many listings are held open now.
func (h *holds) held() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.total
}

// Held is how many listings the relay is holding open now, so a test
// outside this package can see a hold is under way before it acts on it.
func (s *Server) Held() int64 { return s.holds.held() }

// watchParams reads wait and peers from a listing's query. wait is a Go
// duration, absent or zero for no hold, clamped to the ceiling rather than
// refused above it. peers is FP:ISSUED entries separated by commas, ISSUED
// the Unix nanoseconds of the directory issue the watcher holds; the count
// is checked before any entry is read, and every entry's form before any
// is looked up, so a malformed list touches nothing. A peer with no
// mailbox, or one the caller may not post to, is dropped without a word:
// the caller has already been told 403 by the directory fetch it made
// first, and a wait that never ends must not be a way to learn anything
// about a mailbox its owner has not admitted the caller to.
func (s *Server) watchParams(w http.ResponseWriter, r *http.Request, callerFP string) (wait time.Duration, peers map[string]time.Time, ok bool) {
	q := r.URL.Query()
	if raw := q.Get("wait"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < 0 {
			s.fail(w, http.StatusBadRequest, "bad wait parameter")
			return 0, nil, false
		}
		wait = min(d, s.maxWait)
	}
	raw := q.Get("peers")
	if raw == "" {
		return wait, nil, true
	}
	if strings.Count(raw, ",")+1 > relayapi.MaxWatchPeers {
		s.fail(w, http.StatusBadRequest, "too many peers to watch; narrow with --peer")
		return 0, nil, false
	}
	type entry struct {
		fp     string
		issued time.Time
	}
	var entries []entry
	for _, e := range strings.Split(raw, ",") {
		fp, issued, found := strings.Cut(e, ":")
		nanos, err := strconv.ParseInt(issued, 10, 64)
		if !found || !identity.ValidFingerprint(fp) || err != nil {
			s.fail(w, http.StatusBadRequest, "bad peers parameter")
			return 0, nil, false
		}
		entries = append(entries, entry{fp, time.Unix(0, nanos)})
	}
	peers = make(map[string]time.Time, len(entries))
	for _, e := range entries {
		exists, blocked, err := s.store.MailboxState(e.fp)
		if err != nil {
			s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
			return 0, nil, false
		}
		if !exists || blocked {
			continue
		}
		allowed, err := s.store.MayPost(e.fp, callerFP)
		if err != nil {
			s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
			return 0, nil, false
		}
		if !allowed {
			continue
		}
		peers[e.fp] = e.issued
	}
	return wait, peers, true
}

// listing answers GET /v1/mailbox/{fp}, holding it open for wait when there
// is nothing to say yet.
//
// The order: the hold is taken against the caps, or not; the notifier is
// subscribed to under the mailbox's mail key and every watched peer's
// directory key; then the look. A row or a directory that lands between
// the look and the wait has already closed the wake channel, so nothing is
// missed, and there is no loop: one wake, one more look, one answer, which
// may be empty when the wake was for something the look does not report.
// A caller that goes away is not answered; the hold ends with its context.
func (s *Server) listing(w http.ResponseWriter, r *http.Request, fp string, after int64, limit int, stubs bool, wait time.Duration, peers map[string]time.Time) {
	hold := wait > 0
	if hold && !s.holds.take(fp) {
		// Over a cap the answer is the ordinary listing, at once, as a
		// relay without the hold would give; the access log says why a
		// request that asked to be held was not.
		setLimit(w, limitWaiting)
		hold = false
	}
	var wake <-chan struct{}
	if hold {
		defer s.holds.release(fp)
		keys := make([]string, 0, 1+len(peers))
		keys = append(keys, mailKey(fp))
		for peer := range peers {
			keys = append(keys, dirKey(peer))
		}
		var cancel func()
		wake, cancel = s.notify.Subscribe(keys...)
		defer cancel()
	}
	resp, found, err := s.look(fp, after, limit, stubs, peers)
	if err != nil {
		s.listingFailed(w, err)
		return
	}
	if hold && !found {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-wake:
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
		if resp, _, err = s.look(fp, after, limit, stubs, peers); err != nil {
			s.listingFailed(w, err)
			return
		}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// look is one listing: the rows after the id asked from, the count of
// everything held, and which watched peers hold a directory issued later
// than the watcher said. found reports whether there is anything to
// answer with rather than hold for.
func (s *Server) look(fp string, after int64, limit int, stubs bool, peers map[string]time.Time) (resp relayapi.ListResponse, found bool, err error) {
	// A page follows max_bytes: as many envelopes as fit the budget, and
	// one at least, so a client sized to the relay's max_bytes holds it.
	listing, err := s.store.ListingWithin(fp, after, limit, stubs, s.cfg.MaxBytes)
	if err != nil {
		return resp, false, err
	}
	// The owner is told, on every listing, what state their allow list
	// is in: a list that no longer verifies refuses every sender, and
	// the owner would otherwise learn that only from the silence.
	allow, err := s.store.AllowState(fp)
	if err != nil {
		return resp, false, err
	}
	resp = relayapi.ListResponse{
		Messages: make([]relayapi.StoredMessage, 0, len(listing.Rows)),
		Queued:   listing.Queued,
		Allow:    allow,
	}
	for _, row := range listing.Rows {
		msg := relayapi.StoredMessage{
			ID: row.ID, Received: row.Received, Kind: row.Kind, Size: row.Size, Channel: row.Channel,
		}
		if row.Envelope != nil {
			msg.Envelope = json.RawMessage(row.Envelope)
		}
		resp.Messages = append(resp.Messages, msg)
	}
	for peer, held := range peers {
		issued, stored, err := s.store.DirectoryIssued(peer)
		if err != nil {
			return resp, false, err
		}
		if stored && issued.After(held) {
			resp.DirectoriesChanged = append(resp.DirectoriesChanged, peer)
		}
	}
	// The map's order is nobody's; the answer's is fixed.
	sort.Strings(resp.DirectoriesChanged)
	return resp, len(resp.Messages) > 0 || len(resp.DirectoriesChanged) > 0, nil
}

func (s *Server) listingFailed(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNoMailbox) {
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	}
	s.fail(w, http.StatusInternalServerError, relayapi.MsgStorageError)
}
