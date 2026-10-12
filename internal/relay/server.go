package relay

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// Config configures a relay server.
type Config struct {
	// MaxBytes caps one posted envelope, never above relayapi.MaxPageBytes
	// (inlineMax), and is a stream's resume threshold. Zero means
	// relayapi.DefaultMaxBytes.
	MaxBytes int64
	// Registration is open, token, or closed. Empty means open.
	Registration string
	// PublicURL is the URL users reach this relay at, and the audience every
	// enrolment token must name. Empty skips the audience check.
	PublicURL string
	// AdminFile holds the export lines of this relay's administrators. Empty
	// means the relay has none and the whole admin API answers 403.
	AdminFile string
	// Admins is AdminFile as the caller loaded it at start, so the relay
	// serves its first request from the set start logged. Nil with AdminFile
	// set means the relay loads the file itself when it is built.
	Admins *Admins
	// TokenMaxAge is the longest lifetime a token may be registered with.
	TokenMaxAge time.Duration
	// Streams says whether the relay accepts stream uploads at all. The zero
	// value is off: it is a new capability, and a library embedder should ask
	// for it. auu-relay asks by default.
	Streams bool
	// streamsSet lets the tests tell "off" from "not mentioned".
	streamsSet bool
	// MaxStreamBytes is the largest declared stream. Zero is unlimited.
	MaxStreamBytes int64
	// StallTimeout is the stream routes' window: how long an upload
	// attempt waits for its next hunk of relayapi.HunkBytes, moved only
	// when a whole hunk has arrived, before ending it as one that stopped
	// short, and how long the blob route waits for a reader to take its
	// next byte, moved on every write that delivers bytes. Zero means
	// relayapi.HunkWindow for the first and relayapi.ResumeWindow for the
	// second. It is a field so a test can set it short on a loopback
	// connection: the deadline is the wall clock's, not Now's.
	StallTimeout time.Duration
	// Logger receives one line per request. Never receives request bodies.
	Logger *slog.Logger
	// Limits is the rate limit and quota policy. The zero value is unlimited;
	// DefaultLimits is what auu-relay starts from.
	Limits Limits
	// AccessLog is AccessLogFull or AccessLogMinimal. Empty means full.
	AccessLog string
	// ClientCerts, when set, requires a live client certificate on every
	// mailbox route and issues one at enrolment. Nil is off, which is the
	// zero value: client certificates are a new requirement, and a library
	// embedder must ask for them.
	ClientCerts *ClientCertPolicy
	// TrustAnchor is the root this relay's own certificate chains to, when
	// it serves from an auu-ca bundle: what a machine pins, and what the
	// trust anchor route hands out. It is set whenever a bundle is loaded,
	// whether or not client certificates are required. The two are separate
	// settings: a relay serves its own certificate without asking for
	// anyone else's, and a machine must be able to pin it either way.
	TrustAnchor *x509.Certificate
	// Now is the clock the rate limiters read. Nil means time.Now. Tests
	// inject one so they need not sleep; request freshness and nonce expiry
	// always use the real clock, because those are agreements with a client.
	Now func() time.Time
	// CourierLimits is what this relay's forwarding is bounded by. The zero
	// value is unlimited where a zero is honest and refuses nothing where
	// it is not: a relay with no Courier never reads it, and auu-relay
	// starts from DefaultCourierLimits.
	CourierLimits CourierLimits
	// Courier is this relay's side of its peerings with other relays: the
	// identity it posts to a neighbour as, the neighbours it can dial, and
	// the neighbours it accepts forwarded mail from. Nil is a relay that
	// forwards nothing and accepts nothing forwarded, which is the zero
	// value and what every relay was until this existed: the caller builds
	// one with NewCourier, so that a configuration which cannot work is a
	// relay that does not start.
	Courier *Courier
}

// Server is the relay's HTTP surface.
type Server struct {
	store    *Store
	cfg      Config
	log      *slog.Logger
	mux      *http.ServeMux
	requests atomic.Int64
	// routes is every pattern registered on mux, in order, for the test
	// that holds the key agent's receive set to the route table.
	routes []string

	lim      limiters
	inflight chan struct{}
	minimal  bool
	admins   *adminSet
	// courier is nil on a relay that neither forwards nor accepts forwarded
	// mail, which is every relay that has not been given a courier block.
	courier *Courier
	// workers empties the forwarding queue, one goroutine per neighbour.
	// Nil on a relay that dials nobody, and every method on it takes a nil
	// receiver, so no caller has to ask first.
	workers *workers
	started time.Time
	// notify wakes a listing held open for a mailbox when a row arrives in
	// it, or a directory it watches is replaced; holds counts the listings
	// held, against the caps; maxWait is the longest hold, relayapi.MaxWait
	// unless a test shortens it.
	notify  *notifier
	holds   *holds
	maxWait time.Duration
}

// Refusals whose exact words two packages depend on.
const (
	msgBlocked = "this identity is blocked on this relay"
	// msgNotAllowed is what a sender the recipient has not admitted is
	// told, on every route that carries something into a mailbox.
	//
	// It is a constant rather than three spellings because a second thing
	// now answers with it: a mailbox belonging to a neighbouring relay's
	// courier refuses every sender, exactly as a mailbox whose allow list
	// named nobody would, and the whole value of that is in the two being
	// one sentence. Ruling 10 wanted a list that admits nobody; the signed
	// format cannot spell one, since an empty list admits everybody and
	// Validate refuses a list naming only the owner. So the relay keeps
	// that list for a courier's mailbox itself, and says what it would
	// say. Nothing on the wire tells the two apart, which is the point: a
	// refusal of its own would make these routes the place a stranger
	// holding a fingerprint could ask which relays this one peers with.
	msgNotAllowed        = "sender is not on the recipient's allow list"
	msgNotAccepting      = "this relay is not accepting new registrations"
	msgTokenNotFromAdmin = "enrolment token was not issued by an administrator of this relay"
	msgTokenWrongUse     = "enrolment token does not authorise this"
	msgNeedCertToken     = "a certificate for another machine needs a certificate token bound to this identity"
	msgNeedAnyToken      = "this relay requires client certificates and this identity has no live one: enrol again with a token from an administrator"
)

// msgCertTokenForNew is a certificate token presented where a mailbox has
// yet to be made.
const msgCertTokenForNew = "enrolment token is a certificate token, which adds a machine to an identity " +
	"already on this relay, and this identity has no mailbox here: ask the administrator for a registration token"

// finalRowRetention is how long a queue row that failed is kept, so that the
// person who posted it can read what happened to their mail. A day, which is
// long enough for somebody who reads their mail once a day.
const finalRowRetention = 24 * time.Hour

// expiredTokenRetention is how long a spent or expired token is kept so an
// administrator can still see what happened.
const expiredTokenRetention = 30 * 24 * time.Hour

// healthPath is exempt from every limit, so monitoring does not flap during an
// attack and an operator can still tell a busy relay from a dead one.
const healthPath = "/v1/health"

// trustAnchorPath serves the root a machine pins. Like health it is reachable
// before a machine holds anything at all.
const trustAnchorPath = "/v1/trust-anchor"

// legacyTokenHeader is the header an enrolment token used to travel in. It is
// never read: the token is inside the certificate request now, where the
// signature covers it. It is named only so a client still sending one is told
// what changed instead of being refused for a missing token.
const legacyTokenHeader = "X-CCX-Token"

// NewServer wires up the routes.
func NewServer(store *Store, cfg Config) *Server {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = relayapi.DefaultMaxBytes
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Registration == "" {
		cfg.Registration = relayapi.RegistrationOpen
	}
	store.SetFaultLog(cfg.Logger, cfg.Now)
	s := &Server{
		store:   store,
		cfg:     cfg,
		log:     cfg.Logger,
		mux:     http.NewServeMux(),
		lim:     newLimiters(cfg.Limits, cfg.CourierLimits, cfg.Now),
		minimal: cfg.AccessLog == AccessLogMinimal,
		admins:  newAdminSet(cfg.AdminFile, cfg.Admins, cfg.Logger),
		courier: cfg.Courier,
		started: time.Now(),
		notify:  &notifier{},
		holds:   newHolds(cfg.Limits.MaxWaiting),
		maxWait: relayapi.MaxWait,
	}
	if cfg.Limits.MaxInflight > 0 {
		s.inflight = make(chan struct{}, cfg.Limits.MaxInflight)
	}
	// The workers start with the relay and stop with it, and are started
	// after the server is built so a wake from a request can never reach a
	// half-built one. The first thing each does is look at what the last run
	// left waiting, so a relay that was stopped mid-outage picks the queue
	// up where it was.
	s.workers = startWorkers(store, cfg.Courier, cfg.CourierLimits, cfg.Logger, cfg.Now)

	s.route("GET "+healthPath, s.handleHealth)
	s.route("POST /v1/register", s.handleRegister)
	s.route("GET /v1/keys/{fp}", s.handleKeys)
	s.route("GET "+trustAnchorPath, s.handleTrustAnchor)
	s.route("PUT /v1/mailbox/{fp}/allow", s.authedBody(relayapi.MaxDocumentBytes, hintCompact, s.handleSetAllow))
	s.route("GET /v1/mailbox/{fp}/allow", s.authed(s.handleGetAllow))
	s.route("GET /v1/mailbox/{fp}/queue", s.authed(s.handleQueue))
	s.route("PUT /v1/mailbox/{fp}/channels", s.authedBody(relayapi.MaxDocumentBytes, hintCompact, s.handleSetChannels))
	s.route("GET /v1/mailbox/{fp}/channels", s.authed(s.handleGetChannels))
	s.route("PUT /v1/mailbox/{fp}/card", s.authedBody(relayapi.FramingAllowance, hintCompact, s.handleSetCard))
	s.route("GET /v1/mailbox/{fp}/card", s.authed(s.handleGetCard))
	s.route("POST /v1/mailbox/{fp}", s.authedBody(s.postCap(), "", s.handlePost))
	s.route("POST /v1/mailbox/{fp}/knock", s.authedBody(s.knockCap(), "", s.handleKnock))
	s.route("GET /v1/mailbox/{fp}", s.authed(s.handleList))
	s.route("DELETE /v1/mailbox/{fp}/{id}", s.authed(s.handleDelete))

	s.route("POST /v1/mailbox/{fp}/certs", s.authedWithCert(relayapi.FramingAllowance, "", s.handleIssueCert))
	s.route("GET /v1/mailbox/{fp}/certs", s.authedWithCert(relayapi.FramingAllowance, "", s.handleListCerts))

	s.route("POST /v1/mailbox/{fp}/streams", s.authed(s.handleOpenStream))
	s.route("GET /v1/mailbox/{fp}/{id}/blob", s.authed(s.handleBlob))
	s.route("PUT /v1/uploads/{id}", s.callerAuthed(s.handlePutStream))
	s.route("DELETE /v1/uploads/{id}", s.callerAuthed(s.handleAbortStream))
	s.route("GET /v1/listed", s.callerAuthed(s.handleListed))
	// Any registered identity of this relay, which is what decision 14 asks
	// for: its own users must know these names to be reachable from off it.
	s.route("GET /v1/couriers", s.callerAuthed(s.handleCouriers))

	// The forward route names no mailbox: the recipient is inside the
	// envelope and the next hop is the first name of the path, so it is
	// caller-authenticated with a body the signature covers.
	s.route("POST /v1/forward", s.callerAuthedBody(s.forwardCap(), "", s.handleForward))
	// A control message, read under its own small cap and not under a post's:
	// nothing about a report is a message, and a body over a kibibyte is not
	// one whatever it says.
	s.route("POST /v1/forward/failed", s.callerAuthedBody(relayapi.MaxReportBytes, "", s.handleFailed))

	s.route("GET /v1/admin/status", s.adminAuthed(s.handleAdminStatus))
	s.route("GET /v1/admin/mailboxes", s.adminAuthed(s.handleAdminMailboxes))
	s.route("GET /v1/admin/mailboxes/{fp}", s.adminAuthed(s.handleAdminMailbox))
	s.route("DELETE /v1/admin/mailboxes/{fp}", s.adminAuthed(s.handleAdminDeregister))
	s.route("DELETE /v1/admin/mailboxes/{fp}/messages", s.adminAuthed(s.handleAdminPurge))
	s.route("GET /v1/admin/blocks", s.adminAuthed(s.handleAdminBlocks))
	s.route("PUT /v1/admin/blocks/{fp}", s.adminAuthed(s.handleAdminBlock))
	s.route("DELETE /v1/admin/blocks/{fp}", s.adminAuthed(s.handleAdminUnblock))
	s.route("GET /v1/admin/certs", s.adminAuthed(s.handleAdminCerts))
	s.route("DELETE /v1/admin/certs/{serial}", s.adminAuthed(s.handleAdminRevokeCert))
	s.route("POST /v1/admin/tokens", s.adminAuthed(s.handleAdminAddToken))
	s.route("GET /v1/admin/tokens", s.adminAuthed(s.handleAdminTokens))
	s.route("DELETE /v1/admin/tokens/{id}", s.adminAuthed(s.handleAdminRevokeToken))
	return s
}

// Close wakes every request the relay is holding open, so each answers with
// what it has, and holds no more. The relay calls it before its listener is
// shut down: a shutdown drains the requests in flight, and one held for a
// minute would otherwise be waited on for a minute.
func (s *Server) Close() {
	s.notify.Close()
	// The workers stop with the relay. An attempt in flight is abandoned
	// rather than waited out — its context is this one — and the row stays
	// waiting, which is safe because the neighbour may have taken the
	// envelope: the retry after the restart is answered already-carried and
	// read as handed. Stopping here rather than in the drain means a stop
	// does not wait on a neighbour that is not answering.
	s.workers.Stop()
}

// route registers a handler and records which route matched, so the access log
// can name the route without naming the mailbox in the path.
//
// ServeMux does set Request.Pattern, but on the copy it hands the handler,
// which the outermost middleware never sees. The registered string is the same
// thing. The method is dropped from it because it is logged in its own field.
func (s *Server) route(pattern string, h http.HandlerFunc) {
	_, routePath, _ := strings.Cut(pattern, " ")
	// Recorded for TestTheClassifierAgreesWithTheRelay, which holds the
	// agent's receive set to what is registered here.
	s.routes = append(s.routes, pattern)
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if rec, ok := w.(*statusRecorder); ok {
			rec.pattern = routePath
		}
		h(w, r)
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	if r.Method == http.MethodGet && r.URL.Path == healthPath {
		s.mux.ServeHTTP(rec, r)
		s.logRequest(rec, r, start)
		return
	}

	if !s.acquire() {
		// Nothing has been read or looked up yet, which is the point: the cap
		// exists to stop slow callers from occupying the process. The
		// connection closes behind the answer, as after every refusal
		// before the body: net/http would otherwise read up to 256 KiB
		// of a body the handler never asked for before writing the 503,
		// and wait for it if it never came.
		rec.Header().Set("Connection", "close")
		rec.Header().Set("Retry-After", "1")
		rec.limit = limitInflight
		s.fail(rec, http.StatusServiceUnavailable, "relay is busy")
		s.logRequest(rec, r, start)
		return
	}
	// Deferred: a handler that panics is recovered by net/http per connection,
	// and a slot leaked there would never come back.
	defer s.release()

	s.mux.ServeHTTP(rec, r)
	s.logRequest(rec, r, start)

	if s.requests.Add(1)%100 == 0 {
		now := time.Now()
		if err := s.store.PurgeNonces(now); err != nil {
			s.log.Warn("nonce purge failed", "err", err)
		}
		// The envelopes this relay remembers carrying, on the nonce purge's
		// timer because they are the same shape of thing: a hash and an
		// expiry, kept so that something cannot happen twice. It must run,
		// and only here: a hash is the one thing the relay stores that
		// nobody comes back for, so without a purge the ceiling on them is
		// reached once and never left, and a relay at it forwards nothing
		// ever again.
		// By the relay's own clock and not the wall clock, because that is
		// the clock the expiry was written with: a nonce's expiry is an
		// agreement with a client and stays on the real one, and this is
		// the relay's bookkeeping about itself. Two clocks for one number
		// is a purge that cannot be driven and, where a test injects one,
		// cannot be shown to run at all.
		if err := s.store.PurgeCarried(s.cfg.Now()); err != nil {
			s.log.Warn("carried purge failed", "err", err)
		}
		// The queue's own dead rows: a failed one a day after it failed, so
		// its poster has had a chance to read what happened, and a handed
		// one once the window an undeliverable could arrive in has passed.
		// A waiting row is never taken here — its own gives_up ends it, and
		// that is the worker's, so that the poster is told rather than
		// finding their mail gone.
		if n, err := s.store.PurgeOutbound(s.cfg.Now(), finalRowRetention,
			s.cfg.CourierLimits.CarriedWindow); err != nil {
			s.log.Warn("outbound purge failed", "err", err)
		} else if n > 0 {
			s.log.Info("courier: queue rows purged", "rows", n)
		}
		// Long-dead tokens. Anything an administrator could still act on,
		// including one that expired yesterday, stays.
		if err := s.store.PurgeTokens(now.Add(-expiredTokenRetention)); err != nil {
			s.log.Warn("token purge failed", "err", err)
		}
		// Certificates long dead. One revoked yesterday stays, so an
		// administrator can still see what happened.
		if err := s.store.PurgeCerts(now.Add(-expiredTokenRetention)); err != nil {
			s.log.Warn("certificate purge failed", "err", err)
		}
		s.purgeUploads(now)
	}
}

// purgeUploads lets go of every upload past its expiry whose lock is not
// held, settles each sender's budget for its rows by returnUnheld, and
// says how many it let go. It runs every hundredth request; at an open
// refused for the sender's count when the soonest of that sender's
// expiries has passed, so that the count the refusal promised would fall
// by then has; and at a refusal for a full mailbox or relay, in roomFreed.
// Failures are logged and not answered: it runs inside an unrelated
// caller's request, or one that will be answered by its own count or room.
func (s *Server) purgeUploads(now time.Time) int {
	purged, skipped, err := s.store.PurgeUploads(now)
	if err != nil {
		s.log.Warn("upload purge failed", "err", err)
	}
	for i := range purged {
		s.returnUnheld(&purged[i])
	}
	if len(purged) > 0 {
		s.log.Info("abandoned uploads removed", "count", len(purged))
	}
	if skipped > 0 {
		// Mid-append, or being completed or aborted as the purge ran:
		// met again at the next one.
		s.log.Debug("expired uploads left for the next purge, their locks held", "count", skipped)
	}
	return len(purged)
}

// roomFreed reports whether a store's refusal for a full mailbox or a
// full relay may be asked again: it purged the relay's expired uploads and
// let at least one go, whichever mailbox that one held room in. roomFor
// counts every upload's reservation whatever its expiry, since an attempt
// that runs past the expiry the open wrote is still landing bytes and only
// the purge, under the upload's lock, can tell it from an abandoned one; so
// an expired reservation nobody fed would hold a recipient's room until its
// sender's next request on it, its sender's open at the max_open_uploads
// cap, or the hundredth request's purge, which on a quiet relay is a long
// time after the ten seconds an unfed open is given. Each route that answers 507
// from roomFor asks here first and, when this says yes, asks the store once
// more; if what went held room elsewhere, that second ask is a 507 again.
// So for the quotas roomFor keeps, a 507 is answered only when the room is
// taken by what still counts. A full disk is refused the same way, and the
// purge frees only what kept partials held there. An upload whose lock is
// held, an attempt in flight, is passed over and keeps its room. Any other
// answer, and a purge that let nothing go, leave the refusal as it was,
// with no second ask.
func (s *Server) roomFreed(err error) bool {
	if !errors.Is(err, ErrMailboxFull) && !errors.Is(err, ErrRelayFull) {
		return false
	}
	return s.purgeUploads(s.cfg.Now()) > 0
}

// returnUnheld settles a sender's post bytes when an upload's row goes
// unplaced, by abort, by expiry at a route or the purge, or by an attempt
// that deleted it whole, as the row stood when it went.
//
// An upload the relay never fed, its row holding no byte, gives nothing
// back: it cost the relay a reservation of the recipient's room and the
// sender nothing, and the open's charge is what it costs. Refunded, it
// made holding a mailbox full free, opened, dropped and opened again at
// once. That includes a first attempt that ended short of the resume
// threshold, and one the relay's own disk failed, which are charged the
// declared size for the hour; an open the budget then cannot afford is
// refused 429 "rate limited: post bytes", with Retry-After saying when
// the budget allows it. An upload with kept bytes is given back what it
// declared above them: those bytes were held, so they stay charged, and
// a placed stream gives nothing back. n is a difference of two values
// the relay wrote, and a return never fills a bucket past its burst.
func (s *Server) returnUnheld(u *Upload) {
	if u.Received == 0 {
		s.store.faults.noteUnfed(u.From, u.Size, s.minimal)
		return
	}
	s.lim.postBytes.Return(u.From, u.Size-u.Received)
}

// acquire takes an in-flight slot without waiting for one.
func (s *Server) acquire() bool {
	if s.inflight == nil {
		return true
	}
	select {
	case s.inflight <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) release() {
	if s.inflight != nil {
		<-s.inflight
	}
}

// logRequest writes the one line per request the relay keeps.
//
// Bodies are never logged: they are the only thing the relay is trusted not to
// spread around. The fingerprint is logged only once a signature has proven it,
// so the log cannot be seeded with an identity anyone can claim, and in minimal
// mode it is not logged at all.
func (s *Server) logRequest(rec *statusRecorder, r *http.Request, start time.Time) {
	attrs := []any{"method", r.Method}
	if s.minimal {
		// The route, not the path. A path names the recipient's mailbox, and
		// the caller plus the recipient is the social graph this relay is
		// otherwise built not to hold.
		attrs = append(attrs, "path", orDash(rec.pattern))
	} else {
		// Truncated: a log line is an allocation and a log file is a disk,
		// and the path arrives from the caller.
		attrs = append(attrs, "path", truncateForLog(r.URL.Path))
	}
	attrs = append(attrs, "status", rec.status)
	if !s.minimal {
		attrs = append(attrs, "fp", orDash(rec.fp))
	}
	if rec.limit != "" {
		attrs = append(attrs, "limit", rec.limit)
	}
	attrs = append(attrs, "dur", time.Since(start).Round(time.Millisecond).String())
	s.log.Info("request", attrs...)
}

// maxLoggedPath bounds a path taken from the wire before it reaches a log.
const maxLoggedPath = 256

func truncateForLog(s string) string {
	if len(s) <= maxLoggedPath {
		return s
	}
	return s[:maxLoggedPath] + "…"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	fp      string // set only once the caller's signature has been verified
	pattern string // the route that matched, for the minimal access log
	limit   string // which limit refused this request, if any
}

// verified records who the caller turned out to be, for the access log.
func verified(w http.ResponseWriter, fp string) {
	if rec, ok := w.(*statusRecorder); ok {
		rec.fp = fp[:16]
	}
}

// setLimit records which limit refused a request, for the access log.
func setLimit(w http.ResponseWriter, name string) {
	if rec, ok := w.(*statusRecorder); ok {
		rec.limit = name
	}
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.NewResponseController reach the connection through
// the recorder, for the stream route's deadlines.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Warn("write failed", "err", err)
	}
}

// fail writes a refusal of no particular kind: a sentence and an empty
// code. A refusal a client acts on goes through refuse, failCode or failAt,
// so that its code travels with it.
func (s *Server) fail(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, relayapi.ErrorResponse{Error: msg})
}

// refuse writes one of relayapi's fixed refusals, its sentence and its code
// as the one value they are (ruling 68).
func (s *Server) refuse(w http.ResponseWriter, status int, r relayapi.Refusal) {
	s.writeJSON(w, status, relayapi.ErrorResponse{Error: r.Msg, Code: r.Code})
}

// failCode writes a refusal a client acts on whose sentence carries a value,
// with its code beside it at its one site.
func (s *Server) failCode(w http.ResponseWriter, status int, code, msg string) {
	s.writeJSON(w, status, relayapi.ErrorResponse{Error: msg, Code: code})
}

// failAt is failCode for the refusals about a time, which the answer
// carries as data beside the sentence that also names it.
func (s *Server) failAt(w http.ResponseWriter, status int, code, msg string, at time.Time) {
	s.writeJSON(w, status, relayapi.ErrorResponse{Error: msg, Code: code, At: at.UTC()})
}

// hasOldKey reports whether a body is a JSON object with key at its top,
// for the allow route, which keeps a named sentence for the unsigned list
// an older client sent (R2, ruling 67): it looks for the old key before the
// strict decode would refuse it as a field the request does not have. It
// reads nothing but the key's presence.
func hasOldKey(body []byte, key string) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return false
	}
	_, ok := top[key]
	return ok
}

// decodeRequest is the one way a route reads a request body (D37, P1): the
// strict decode, so a field the request does not have is refused by name,
// then the body's sections held to wire.CheckBody. A section this relay does
// not know is ignored; one marked critical is refused with the code and
// sentence a client acts on, naming the section and this relay's wire level.
// It writes the 400 itself and reports whether the route may go on. what
// names the request in the sentence.
//
// It runs where each route decoded before, so the order of checks is as it
// was: on every authenticated route after the signature, the nonce and the
// charge, exactly where a malformed body was refused; on register before
// the signature, since the key that verifies it is in the body, so that
// refusal spends no nonce and tells an unauthenticated caller only the wire
// level, which the health answer tells everyone. Nothing is written first.
func (s *Server) decodeRequest(w http.ResponseWriter, body []byte, req interface{ SectionList() []wire.Section }, what string) bool {
	if err := wire.Decode(body, req); err != nil {
		s.fail(w, http.StatusBadRequest, fmt.Sprintf("malformed %s: %v", what, err))
		return false
	}
	err := wire.CheckBody(req.SectionList())
	var newer *wire.NeedsNewerError
	switch {
	case err == nil:
		return true
	case errors.As(err, &newer):
		s.writeJSON(w, http.StatusBadRequest, relayapi.ErrorResponse{
			Error: fmt.Sprintf(relayapi.MsgNeedsNewer, relayapi.WireLevel, newer.Name),
			Code:  relayapi.CodeNeedsNewer,
		})
	default:
		s.fail(w, http.StatusBadRequest, fmt.Sprintf("malformed %s: %v", what, err))
	}
	return false
}

// rateLimited answers a request that ran out of budget. detail is appended to
// the error text when there is something useful to say beyond the limit's name.
func (s *Server) rateLimited(w http.ResponseWriter, which string, retryAfter time.Duration, detail string) {
	s.rateLimitedCode(w, which, retryAfter, detail, "")
}

// rateLimitedCode is rateLimited with a code, for the one 429 a client acts
// on beyond waiting: a post or a stream bigger than a sender's whole budget,
// which no wait lets through (CodeOverBudget).
func (s *Server) rateLimitedCode(w http.ResponseWriter, which string, retryAfter time.Duration, detail, code string) {
	setLimit(w, which)
	seconds := int64(retryAfter / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	// Always an integer number of seconds, never a date: the client turns this
	// straight into a sleep.
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	s.failCode(w, http.StatusTooManyRequests, code, "rate limited: "+which+detail)
}

// readBody drains the request under the route's cap, so an oversize body
// cannot consume memory before it is rejected. A body that declares itself
// over the cap is refused before a byte of it is read, with the connection
// closed behind the answer as refuseUnread has it; one that arrives without
// a length, or lies about it, is cut by MaxBytesReader at the same cap.
// The 413 names the cap in bytes, and hint, when given, says what to do
// about it.
//
// The caps are per route and are the wire's constants: the post route
// takes inlineMax, max_bytes and never above relayapi.MaxPageBytes, plus
// relayapi.FramingAllowance, the knock route knockMax plus it, two of the three owner-signed documents
// relayapi.MaxDocumentBytes, and every other body route
// relayapi.FramingAllowance alone, the card among them, since a card
// is a few hundred bytes. The stream PUT never comes here: its
// body is judged by Content-Length against the size the open declared
// and streamed to disk, in handlePutStream.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request, limit int64, hint string) ([]byte, bool) {
	return s.readBodyCharged(w, r, limit, hint, nil)
}

// unsignedBody is readBody for a body read before its signature is
// checked, on the three authenticated wrappers: a body refused there, for
// its declared length, its read length or a read that failed, is charged
// to the address's unauthenticated budget as a refused signature is, and
// answered 429 when that is spent. A refusal of the body then costs what a
// refused signature costs whoever is named; without the charge the free
// 413 said, as often as anyone liked, which fingerprints the relay knows.
func (s *Server) unsignedBody(w http.ResponseWriter, r *http.Request, limit int64, hint string) ([]byte, bool) {
	return s.readBodyCharged(w, r, limit, hint, s.chargeUnauthenticated)
}

// readBodyCharged is readBody with charge, when given, run before any
// refusal is written; a charge that answers itself refuses in its place.
func (s *Server) readBodyCharged(w http.ResponseWriter, r *http.Request, limit int64, hint string,
	charge func(w http.ResponseWriter, r *http.Request) bool) ([]byte, bool) {

	charged := func() bool { return charge == nil || charge(w, r) }
	if r.ContentLength > limit {
		if charged() {
			s.refuseUnread(w, http.StatusRequestEntityTooLarge, tooLarge(limit, hint))
		}
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if !charged() {
			return nil, false
		}
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.fail(w, http.StatusRequestEntityTooLarge, tooLarge(limit, hint))
			return nil, false
		}
		s.fail(w, http.StatusBadRequest, "could not read request body")
		return nil, false
	}
	return body, true
}

// unread marks the answer to a request whose body the handler has not
// read and will not: the connection closes behind it. Without this net/http,
// keeping the connection for the next request, reads up to 256 KiB of the
// body before it writes the answer and waits for a body that never comes;
// a caller refused before the body cannot expect the connection back. A
// request that declares no body has nothing to leave unread, and keeps
// its connection. A handler that goes on to read the body removes the
// mark.
func unread(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 {
		w.Header().Set("Connection", "close")
	}
}

// tooLarge is the 413's sentence: the cap in bytes, and the hint after it.
func tooLarge(limit int64, hint string) string {
	msg := fmt.Sprintf("%s: at most %d bytes", relayapi.MsgBodyTooLarge, limit)
	if hint != "" {
		msg += "; " + hint
	}
	return msg
}

// hintCompact is the hint on a document refused for its size: the cap
// leaves room above the documents' own maxima for whitespace, so one that
// is refused was indented past it.
const hintCompact = "send the document compact, without indentation"

// inlineMax is the largest envelope this relay stores in a mailbox row:
// max_bytes, and never more than relayapi.MaxPageBytes. A row over that
// is one no client of this release lists, since its page would pass the
// client's MaxListingHold whatever else it held, so the post, a courier's
// delivery, the forward and the knock refuse it rather than store what
// would stop every fetch of the mailbox. A max_bytes above it still sets
// a stream's resume threshold, and the health answer still says it.
func (s *Server) inlineMax() int64 { return min(s.cfg.MaxBytes, relayapi.MaxPageBytes) }

// postCap is the post route's body cap: an envelope of inlineMax with the
// framing allowance for its JSON.
func (s *Server) postCap() int64 { return s.inlineMax() + relayapi.FramingAllowance }

// knockMax is the largest knock envelope: knock_max_bytes, or max_bytes
// when that is zero, since zero is unlimited everywhere and a knock is a
// post, so unlimited is the post's cap; and either way never more than
// inlineMax, since a knock is a row like any other.
func (s *Server) knockMax() int64 {
	if s.cfg.Limits.KnockMaxBytes > 0 {
		return min(s.cfg.Limits.KnockMaxBytes, s.inlineMax())
	}
	return s.inlineMax()
}

// knockCap is the knock route's body cap: knockMax with the framing
// allowance, as postCap is max_bytes with it.
func (s *Server) knockCap() int64 { return s.knockMax() + relayapi.FramingAllowance }

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// The registration mode is what admission to this relay means, and
	// so what a name listed on it rests on; a client says it wherever it
	// asks a person to trust a listed name.
	// The most recipients a message to several may name travels as a
	// section, not a field: a client from before it ignores it, and one
	// that knows it reads its absence as a relay that holds only the
	// protocol's ceiling.
	resp := relayapi.HealthResponse{OK: true, MaxBytes: s.cfg.MaxBytes, KnockMaxBytes: s.knockMax(),
		Registration: s.cfg.Registration, WireLevel: relayapi.WireLevel}
	resp.Sections.Sections = s.maxRecipientsSection()
	if s.clientCerts() {
		resp.MLDSA = clientca.ParameterNumber(s.cfg.ClientCerts.Issuer.Parameters())
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// checkSignature applies the timestamp window, verifies the signature, and only
// then consumes the nonce.
//
// The ordering matters. Consuming first would let anyone on the internet write
// rows into the relay's nonce table without holding any key at all. Verifying
// first means a database write requires a signature, and replay protection is
// unaffected: a replayed request has a good signature but a spent nonce.
func (s *Server) checkSignature(auth *relayapi.Auth, pub *identity.Public, r *http.Request, body []byte) error {
	if !auth.FreshAt(time.Now()) {
		return errUnauthorized
	}
	if !auth.Verify(pub, r.Method, relayapi.RequestPath(r), body) {
		return errUnauthorized
	}
	if err := s.store.UseNonce(auth.Nonce, time.Now().Add(relayapi.NonceTTL)); err != nil {
		if errors.Is(err, ErrReplay) {
			return errUnauthorized
		}
		return err // a real storage fault, which must not masquerade as a 401
	}
	return nil
}

// errUnauthorized is the single reason given for every authentication failure,
// so a caller cannot learn which check it tripped.
var errUnauthorized = errors.New("unauthorized")

// authFailed writes the response for a failed authentication.
//
// A genuine rejection is charged to the source address and answered 401, or 429
// once that address has spent its budget. A storage fault is neither: it is the
// relay's problem, and must not masquerade as a 401 or cost the caller a token.
func (s *Server) authFailed(w http.ResponseWriter, r *http.Request, err error) {
	if !errors.Is(err, errUnauthorized) {
		s.log.Error("authentication could not be completed", "err", err)
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if !s.chargeUnauthenticated(w, r) {
		return
	}
	s.fail(w, http.StatusUnauthorized, "unauthorized")
}

// chargeUnauthenticated spends one token of the source address's
// unauthenticated budget, for a refusal made before any signature is
// verified, and answers 429 itself when the budget is spent. It reports
// whether the caller may still be answered with the refusal.
func (s *Server) chargeUnauthenticated(w http.ResponseWriter, r *http.Request) bool {
	if ok, retry := s.lim.unauthenticated.Allow(s.clientIP(r)); !ok {
		s.rateLimited(w, limitUnauthenticated, retry, "")
		return false
	}
	return true
}

// chargeIdentity spends one request token against a caller who has proved who
// they are. It reports whether the request may continue.
//
// The key is always the verified fingerprint, never the claimed one, so nobody
// can spend somebody else's budget by naming them.
func (s *Server) chargeIdentity(w http.ResponseWriter, fp string) bool {
	ok, retry := s.lim.requests.Allow(fp)
	if !ok {
		s.rateLimited(w, limitRequests, retry, "")
	}
	return ok
}

// authed wraps a handler that requires a registered caller. The wrapped handler
// receives the verified caller fingerprint and the already-read body.
func (s *Server) authed(fn func(w http.ResponseWriter, r *http.Request, body []byte, callerFP string)) http.HandlerFunc {
	return s.authedBody(relayapi.FramingAllowance, "", fn)
}

// authedBody is authed with the route's body cap and the hint its 413
// carries: the post route and the two documents have caps of their own.
func (s *Server) authedBody(limit int64, hint string, fn func(w http.ResponseWriter, r *http.Request, body []byte, callerFP string)) http.HandlerFunc {
	return s.authedWithCert(limit, hint, func(w http.ResponseWriter, r *http.Request, body []byte, callerFP string, _ *CertRow) {
		fn(w, r, body, callerFP)
	})
}

// authedWithCert is authed for the handlers that need to know which
// certificate the request arrived on.
//
// The order is one order on every authenticated route but the admin
// routes, which read the body before the administrator (adminAuthed): the
// certificate, the auth header parsed, the identity it names looked up,
// then the body under the route's cap, then the signature over it. Everything that can
// be judged without the body is judged before it, so a caller the relay
// would refuse anyway — no honoured certificate, a header that will not
// parse, a fingerprint no mailbox has — is refused without the relay
// accepting what they wanted to send, which is most of what the cap and
// the credential buy. The signature cannot come first: it is over the
// body, so the body must be read to check it. A stranger with a valid
// certificate therefore costs one mailbox lookup before the body rather
// than after it, the same read earlier, bounded by the in-flight cap as
// it was.
func (s *Server) authedWithCert(limit int64, hint string, fn func(w http.ResponseWriter, r *http.Request, body []byte, callerFP string, cert *CertRow)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fp := r.PathValue("fp")
		if !identity.ValidFingerprint(fp) {
			s.fail(w, http.StatusBadRequest, "bad mailbox fingerprint")
			return
		}
		// Every refusal from here to the body closes the connection behind
		// its answer, as readBody's own does: net/http reads up to 256 KiB
		// of an unread body before it writes a response on a connection it
		// will keep, and waits for a body that never comes, so a refusal
		// meant to leave the body unread must not keep the connection.
		unread(w, r)
		cert, ok := s.clientCert(w, r)
		if !ok {
			return
		}
		auth, err := relayapi.ParseAuth(r.Header.Get(relayapi.AuthHeader))
		if err != nil {
			// A header that will not parse cannot have come from a working
			// client, so it is refused without touching the database at all.
			s.authFailed(w, r, errUnauthorized)
			return
		}
		caller, err := s.store.Mailbox(auth.FP)
		if err != nil {
			s.authFailed(w, r, errUnauthorized)
			return
		}
		pub, err := identity.ParseBundle(caller.Bundle)
		if err != nil {
			s.authFailed(w, r, errUnauthorized)
			return
		}
		body, ok := s.unsignedBody(w, r, limit, hint)
		if !ok {
			return
		}
		// The body is read: the connection may be kept after the answer.
		w.Header().Del("Connection")
		// A well-formed but wrong signature is verified before it is charged,
		// deliberately. Charging first would let a neighbour behind the same
		// address empty the bucket and lock a legitimate user out of
		// authenticating. That neighbour costs one signature check a request,
		// which the in-flight cap bounds.
		if err := s.checkSignature(auth, pub, r, body); err != nil {
			s.authFailed(w, r, err)
			return
		}
		verified(w, auth.FP)
		if !s.certMatches(w, r, cert, auth.FP) {
			return
		}
		if !s.chargeIdentity(w, auth.FP) {
			return
		}
		// After verification, deliberately: answering this before the
		// signature has proved who the caller is would turn the block list
		// into something anyone could read a fingerprint out of.
		if caller.Blocked {
			s.fail(w, http.StatusForbidden, msgBlocked)
			return
		}
		fn(w, r, body, auth.FP, cert)
	}
}

// handleRegister is the one authenticated route where the caller is not yet
// known: the key that signs the request is the key being registered.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if ok, retry := s.lim.unauthenticated.Allow(ip); !ok {
		s.rateLimited(w, limitUnauthenticated, retry, "")
		return
	}
	if ok, retry := s.lim.registrations.Allow(ip); !ok {
		s.rateLimited(w, limitRegistrations, retry, "")
		return
	}
	// The header before the body, as on every route; there is no identity
	// to look up, since the key that signs is the one being registered.
	// A refusal before the body closes the connection behind it.
	unread(w, r)
	auth, err := relayapi.ParseAuth(r.Header.Get(relayapi.AuthHeader))
	if err != nil {
		s.fail(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// A client of the earlier protocol, whose token was a header outside the
	// signature. Told plainly rather than refused for a missing token.
	if r.Header.Get(legacyTokenHeader) != "" {
		s.fail(w, http.StatusBadRequest, relayapi.MsgTokenInHeader)
		return
	}
	body, ok := s.readBody(w, r, relayapi.FramingAllowance, "")
	if !ok {
		return
	}
	w.Header().Del("Connection")
	var req relayapi.RegisterRequest
	if !s.decodeRequest(w, body, &req, "register request") {
		return
	}
	pub, err := identity.ParseBundle(req.Bundle)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "malformed key bundle")
		return
	}
	// The display name is served to every enrolled machine and printed on
	// their terminals and the administrator's, so it is held to the
	// export line's rule, the one the client's own name is under: a
	// terminal escape or a megabyte is refused here, not stored. Empty is
	// no name, and nothing to print.
	if req.Name != "" {
		if err := identity.ValidName(req.Name); err != nil {
			s.fail(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), "identity: "))
			return
		}
	}
	// The address is derived from the submitted key material, never taken from
	// the header, so nobody can claim someone else's fingerprint.
	fp := pub.Fingerprint()
	if fp != auth.FP {
		s.fail(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := s.checkSignature(auth, pub, r, body); err != nil {
		s.authFailed(w, r, err)
		return
	}
	verified(w, fp)
	if !s.chargeIdentity(w, fp) {
		return
	}

	exists, blocked, err := s.store.MailboxState(fp)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	// Blocks and the mailbox cap apply in every registration mode, and both
	// are settled before a token is looked at, so a refusal here costs the
	// holder no part of their token.
	if blocked {
		s.fail(w, http.StatusForbidden, msgBlocked)
		return
	}

	// The certificate request, always: it is where the enrolment token
	// lives, so a relay that issues no certificates still reads one. Checked
	// before the token, because the token is inside it.
	csr, ok := s.parseCSR(w, req.CSR, true)
	if !ok {
		return
	}

	opt := RegisterOptions{MaxMailboxes: s.cfg.Limits.MaxMailboxes, Now: time.Now()}
	var enrolling *token.Claims
	switch {
	case !exists:
		// A new mailbox. What it costs is the registration mode's business.
		switch s.cfg.Registration {
		case relayapi.RegistrationClosed:
			s.fail(w, http.StatusForbidden, msgNotAccepting)
			return
		case relayapi.RegistrationToken:
			claims, ok := s.enrolmentToken(w, r, fp, csrToken(csr), token.UseRegister)
			if !ok {
				return
			}
			enrolling = claims
			opt.TokenID, opt.TokenUse = claims.ID, claims.Use
		}
	case s.clientCerts() && s.cfg.Registration != relayapi.RegistrationOpen:
		// An existing mailbox asking for a certificate. With a live one on
		// record this is another machine, and it costs a certificate token
		// bound to this identity, which is the whole point of the feature:
		// without that cost, a copied identity could mint itself a
		// certificate and the certificate would add nothing against exactly
		// the attacker it exists for. With none live it is the identity
		// enrolling, not adding a machine: the relay began requiring
		// certificates after it registered, or its only certificate expired
		// or was revoked. That costs an enrolment token, as joining does,
		// and a certificate token bound to it is accepted too. Either way
		// there is no token-free path.
		live, err := s.store.Certs(fp, false, opt.Now)
		if err != nil {
			s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
			return
		}
		uses := []string{token.UseCert}
		if len(live) == 0 {
			uses = []string{token.UseRegister, token.UseCert}
		}
		claims, ok := s.enrolmentToken(w, r, fp, csrToken(csr), uses...)
		if !ok {
			return
		}
		enrolling = claims
		opt.TokenID, opt.TokenUse = claims.ID, claims.Use
	}

	// Signed before the transaction, so a failure to issue costs no token,
	// and inserted inside it, so a mailbox and its first certificate arrive
	// together or not at all.
	var issued *clientca.Issued
	if s.clientCerts() {
		if issued, err = s.issueCert(csr, fp, opt.Now); err != nil {
			s.log.Error("issuing a client certificate", "err", err)
			s.fail(w, http.StatusInternalServerError, "could not issue a certificate")
			return
		}
		row := NewCertRow(issued, fp, opt.Now)
		opt.Cert = &row
	}

	if err := s.store.Register(fp, req.Bundle, req.Name, opt); err != nil {
		outcome := "refused"
		switch {
		case errors.Is(err, ErrTooManyMailboxes):
			s.fail(w, http.StatusForbidden, msgNotAccepting)
		case errors.Is(err, ErrTokenUnknown):
			s.fail(w, http.StatusForbidden, "enrolment token is unknown to this relay")
		case errors.Is(err, ErrTokenRevoked):
			s.fail(w, http.StatusForbidden, "enrolment token has been revoked")
		case errors.Is(err, ErrTokenSpent):
			s.fail(w, http.StatusForbidden, "enrolment token has already been used")
		case errors.Is(err, ErrTokenWrongUse):
			s.fail(w, http.StatusForbidden, msgTokenWrongUse)
		default:
			s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
			outcome = "error"
		}
		if enrolling != nil {
			s.audit("enrol", "", fp, outcome, "token", enrolling.ID)
		}
		return
	}
	if enrolling != nil {
		s.audit("enrol", "", fp, "ok", "token", enrolling.ID, "use", enrolling.Use)
	}
	resp := relayapi.RegisterResponse{FP: fp}
	if issued != nil {
		notAfter := issued.NotAfter
		resp.Cert, resp.NotAfter = issued.Cert, &notAfter
		// The anchor, which is what the machine pins and what a token names.
		resp.CA = s.cfg.ClientCerts.Verifier.Anchor().Raw
		s.audit("cert issue", "", fp, "ok", "serial", issued.Serial, "label", issued.Label)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// csrToken is the enrolment token a certificate request carried, if any.
func csrToken(csr *clientca.Request) string {
	if csr == nil {
		return ""
	}
	return csr.Token
}

// enrolmentToken applies every check that can be made before the database is
// touched, and writes its own refusal.
//
// The order is deliberate. Nothing about the relay's token table is revealed
// until the signature has proved the token came from one of this relay's
// administrators, and the cheap checks come before the transaction, so a
// failed enrolment consumes nothing.
func (s *Server) enrolmentToken(w http.ResponseWriter, r *http.Request, fp, raw string, uses ...string) (*token.Claims, bool) {
	if raw == "" {
		s.fail(w, http.StatusForbidden, needTokenMessage(uses))
		return nil, false
	}
	u, err := token.Parse(raw)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "malformed enrolment token")
		return nil, false
	}
	issuer, ok := s.admins.lookup(u.IssuerFingerprint())
	if !ok {
		s.fail(w, http.StatusForbidden, msgTokenNotFromAdmin)
		return nil, false
	}
	claims, err := u.Verify(issuer, time.Now(), relayapi.MaxSkew)
	switch {
	case err == nil:
	case errors.Is(err, token.ErrForm):
		s.fail(w, http.StatusBadRequest, "malformed enrolment token")
		return nil, false
	case errors.Is(err, token.ErrUse):
		s.fail(w, http.StatusForbidden, "enrolment token is not for registration")
		return nil, false
	case errors.Is(err, token.ErrExpired):
		s.fail(w, http.StatusForbidden, "enrolment token has expired")
		return nil, false
	case errors.Is(err, token.ErrNotYetValid):
		s.fail(w, http.StatusForbidden, "enrolment token is not yet valid")
		return nil, false
	default:
		// Signature, or a key that is not the claimed issuer's.
		s.fail(w, http.StatusForbidden, msgTokenNotFromAdmin)
		return nil, false
	}
	if s.cfg.PublicURL != "" &&
		token.NormaliseRelay(claims.Relay) != token.NormaliseRelay(s.cfg.PublicURL) {
		s.fail(w, http.StatusForbidden, "enrolment token is for a different relay")
		return nil, false
	}
	if claims.Subject != "" && claims.Subject != fp {
		s.fail(w, http.StatusForbidden, "enrolment token was issued to a different identity")
		return nil, false
	}
	// The use is checked here and again inside the transaction that spends
	// it, so a token cannot be redeemed for something it does not authorise
	// even if the two checks were ever to race.
	if !slices.Contains(uses, claims.Use) {
		s.fail(w, http.StatusForbidden, wrongUseMessage(uses, fp))
		return nil, false
	}
	return claims, true
}

// wrongUseMessage says which token would have done, when the one presented
// does not authorise this. There are two uses, so a token refused for its
// use is the other one: a register token where a certificate token is
// needed — the identity has a live certificate on another machine, and the
// person holding a fresh enrolment token is told what to ask for instead,
// with their own fingerprint filled in, since the signature proved it — or
// a certificate token where a mailbox has yet to be made. The container
// suite's K21 found the first refused as "does not authorise this".
func wrongUseMessage(uses []string, fp string) string {
	switch {
	case slices.Contains(uses, token.UseCert) && !slices.Contains(uses, token.UseRegister):
		return fmt.Sprintf("this identity already holds a live certificate on another machine, so adding this one "+
			"needs a certificate token: ask the administrator for one issued with --use cert --for %s", fp)
	case slices.Contains(uses, token.UseRegister) && !slices.Contains(uses, token.UseCert):
		return msgCertTokenForNew
	}
	return msgTokenWrongUse
}

// needTokenMessage says what kind of token is missing, because they are
// obtained differently: a register token invites someone onto the relay, a
// cert token adds a machine to an identity already on it, and an identity
// with a mailbox but no live certificate takes either.
func needTokenMessage(uses []string) string {
	switch {
	case slices.Contains(uses, token.UseRegister) && slices.Contains(uses, token.UseCert):
		return msgNeedAnyToken
	case slices.Contains(uses, token.UseCert):
		return msgNeedCertToken
	}
	return "this relay requires an enrolment token"
}

// handleKeys is a convenience lookup, by a whole fingerprint or by the
// 16-character short id that listings print. It is not a trust anchor: the
// human still confirms the fingerprint out of band before adding a peer.
func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	// A certificate for any identity, not this one: looking a peer up is
	// something every enrolled machine does, and nothing about it is the
	// caller's own mailbox.
	if _, ok := s.clientCert(w, r); !ok {
		return
	}
	if ok, retry := s.lim.unauthenticated.Allow(s.clientIP(r)); !ok {
		s.rateLimited(w, limitUnauthenticated, retry, "")
		return
	}
	query := r.PathValue("fp")
	var mb *Mailbox
	var err error
	switch {
	case identity.ValidFingerprint(query):
		mb, err = s.store.Mailbox(query)
	case identity.ValidShortID(query):
		mb, err = s.store.MailboxByShort(query)
	default:
		s.fail(w, http.StatusBadRequest, "bad fingerprint")
		return
	}
	switch {
	case errors.Is(err, ErrNoMailbox):
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	case errors.Is(err, ErrAmbiguousShort):
		s.fail(w, http.StatusBadRequest, "more than one mailbox begins with that short id; use the full fingerprint")
		return
	case err != nil:
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	s.writeJSON(w, http.StatusOK, relayapi.KeysResponse{Bundle: mb.Bundle, Name: mb.Name, Created: mb.Created})
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	size := int64(len(body))
	if size > s.inlineMax() {
		s.fail(w, http.StatusRequestEntityTooLarge, "envelope too large")
		return
	}
	// Both post budgets are spent before the envelope is parsed or the
	// recipient looked up, so a refused post costs the relay as little as
	// possible.
	if ok, retry := s.lim.posts.Allow(callerFP); !ok {
		s.rateLimited(w, limitPosts, retry, "")
		return
	}
	if ok, retry := s.lim.postBytes.AllowN(callerFP, size); !ok {
		detail := ""
		if burst := s.lim.postBytes.Burst(); burst > 0 && size > burst {
			detail = fmt.Sprintf("; this message is %d bytes and a sender's whole "+
				"post_bytes_per_hour budget is %d, so %s",
				size, burst, relayapi.MsgWaitingWillNotHelp)
			s.rateLimitedCode(w, limitPostBytes, retry, detail, relayapi.CodeOverBudget)
			return
		}
		s.rateLimited(w, limitPostBytes, retry, detail)
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
	// A mailbox that belongs to a neighbouring relay's courier refuses
	// every sender, as a mailbox whose allow list named nobody would. The
	// courier enrolled here only so that its relay could forward through
	// this one, and nothing on either side reads what arrives in it;
	// without this it is an ordinary mailbox that any registered identity
	// can fill, and the storage it spends is this relay's.
	//
	// The refusal is after the mailbox exists and is not blocked, and
	// before the allow list, so nothing is stored or charged; and it is the
	// allow list's own sentence, so nothing on the wire says which of the
	// two refused. This relay knows which mailboxes they are from its own
	// couriers file, and from nothing else: the mailbox that needs it is
	// always at the relay whose file names its owner, since a courier's
	// forwards only work where it is listed.
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
	// After the allow list, deliberately: which channels exist is the
	// owner's to publish to the senders they admit, and nobody else.
	channel, ok := s.channelForPost(w, fp, env.Ch)
	if !ok {
		return
	}
	put := func() (int64, error) {
		return s.store.Put(fp, channel, relayapi.KindEnvelope, "", body, s.cfg.Limits.Quotas(), Forwarded{})
	}
	id, err := put()
	if s.roomFreed(err) {
		id, err = put()
	}
	switch {
	case errors.Is(err, ErrMailboxFull):
		// Not the sender's fault and not something they can retry around: the
		// recipient has to collect their mail.
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
	// After the store has the row, so a listing woken by this finds it.
	s.notify.Wake(mailKey(fp))
	s.writeJSON(w, http.StatusOK, relayapi.PostResponse{ID: id})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	if fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	after, err := intParam(r, "after", 0)
	if err != nil || after < 0 {
		s.fail(w, http.StatusBadRequest, "bad after parameter")
		return
	}
	limit, err := intParam(r, "limit", relayapi.DefaultListLimit)
	if err != nil || limit <= 0 {
		s.fail(w, http.StatusBadRequest, "bad limit parameter")
		return
	}
	if limit > relayapi.MaxListLimit {
		limit = relayapi.MaxListLimit
	}
	// stubs answers every row without its envelope, whatever its kind: a
	// client checking which of the messages it kept are still queued needs
	// the ids and nothing else, and a mailbox of kept mail would otherwise
	// be downloaded again on every check; such a client refuses a stubs
	// listing that carries an envelope.
	stubs, err := boolParam(r, "stubs")
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad stubs parameter")
		return
	}
	wait, peers, ok := s.watchParams(w, r, callerFP)
	if !ok {
		return
	}
	s.listing(w, r, fp, after, int(limit), stubs, wait, peers)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, body []byte, callerFP string) {
	fp := r.PathValue("fp")
	if fp != callerFP {
		s.fail(w, http.StatusForbidden, "not your mailbox")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.fail(w, http.StatusBadRequest, "bad message id")
		return
	}
	deleted, err := s.store.Delete(fp, id)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if !deleted {
		s.fail(w, http.StatusNotFound, "no such message")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// boolParam reads a flag parameter: absent or empty is false, 1 and true
// are true, and anything else is the caller's mistake, said rather than
// taken for either.
func boolParam(r *http.Request, name string) (bool, error) {
	switch raw := r.URL.Query().Get(name); raw {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	default:
		return false, fmt.Errorf("relay: %s=%q is neither 1 nor 0", name, raw)
	}
}

func intParam(r *http.Request, name string, def int64) (int64, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	return strconv.ParseInt(raw, 10, 64)
}
