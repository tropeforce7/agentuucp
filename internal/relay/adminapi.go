package relay

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// adminAuthed wraps a handler that only an administrator may reach.
//
// It mirrors authed with one difference that is the whole point: the caller's
// public key comes from the relay host's authorized file, not from a mailbox.
// An administrator therefore need not be a user of the relay at all.
func (s *Server) adminAuthed(fn func(w http.ResponseWriter, r *http.Request, body []byte, adminFP string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Every refusal before the body closes the connection behind it,
		// and every refusal before the signature costs the source address
		// one token of its unauthenticated budget, whoever is named, so that nothing on these routes says
		// who administers the relay, or whether anybody does, for less than
		// a refused signature costs.
		unread(w, r)
		if !s.admins.enabled() {
			if s.chargeUnauthenticated(w, r) {
				s.refuse(w, http.StatusForbidden, relayapi.RefusalNoAdministrators)
			}
			return
		}
		auth, err := relayapi.ParseAuth(r.Header.Get(relayapi.AuthHeader))
		if err != nil {
			s.authFailed(w, r, errUnauthorized)
			return
		}
		// The body before the administrator, here alone of the three
		// wrappers, so every byte is bounded and read alike before the
		// administrator is known (R12). Read after the lookup, a body
		// declared and not sent was waited for under an administrator's
		// fingerprint and refused 401 at once under anybody else's; judged
		// after it, one declared over the cap was 413 for an administrator
		// and 401 for the rest (T11). So a body of no declared length is
		// refused 411 for every caller alike, which auu-admin never meets
		// since it always declares one (R11), one declared over the cap
		// 413, and the rest is read whole, each refusal charged as a
		// refused signature is.
		if r.ContentLength < 0 {
			if s.chargeUnauthenticated(w, r) {
				s.refuseUnread(w, http.StatusLengthRequired, "a request to an admin route declares its body's length")
			}
			return
		}
		body, ok := s.unsignedBody(w, r, relayapi.FramingAllowance, "")
		if !ok {
			return
		}
		// The body is read: the connection may be kept after the answer,
		// whoever is named, so the 401 below and a refused signature's look
		// alike down to that header.
		w.Header().Del("Connection")
		// 401 and not 403: an outsider must not learn who administers a relay
		// by watching which fingerprints are told they are not one.
		pub, ok := s.admins.lookup(auth.FP)
		if !ok {
			s.authFailed(w, r, errUnauthorized)
			return
		}
		if err := s.checkSignature(auth, pub, r, body); err != nil {
			s.authFailed(w, r, err)
			return
		}
		verified(w, auth.FP)
		if !s.chargeIdentity(w, auth.FP) {
			return
		}
		// Blocks do not apply here. Admin authority comes from the file on the
		// relay's host and from nothing else.
		fn(w, r, body, auth.FP)
	}
}

// audit records one privileged action: an administrator's change, or an
// enrolment.
//
// It is written in both access log modes. This is the operator's record of
// what their own administrators did, not a record of users' traffic, and an
// operator who cannot answer "who deleted that mailbox" has no business having
// administrators at all.
func (s *Server) audit(action, adminFP, target, outcome string, extra ...any) {
	attrs := []any{
		"action", action,
		"admin", orDash(shortFP(adminFP)),
		"target", orDash(shortFP(target)),
		"outcome", outcome,
	}
	s.log.Info("admin", append(attrs, extra...)...)
}

// shortFP trims a fingerprint for logging and leaves anything else alone, so
// a token id or a name passes through whole.
func shortFP(v string) string {
	if identity.ValidFingerprint(v) {
		return v[:16]
	}
	return v
}

// adminFP pulls a validated fingerprint out of the path.
func (s *Server) adminFP(w http.ResponseWriter, r *http.Request) (string, bool) {
	fp := r.PathValue("fp")
	if !identity.ValidFingerprint(fp) {
		s.fail(w, http.StatusBadRequest, "bad fingerprint")
		return "", false
	}
	return fp, true
}

// clientCertMode is what an administrator sees in status.
func (s *Server) clientCertMode() string {
	if s.clientCerts() {
		return relayapi.ClientCertsRequired
	}
	return relayapi.ClientCertsOff
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	now := time.Now()
	counts, err := s.store.Counts(now)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	usage, err := s.store.RelayUsage()
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	// The authority an operator would have to rotate, and when. Rotating it
	// means re-enrolling every machine, so they want the date in front of
	// them rather than in a directory listing.
	var caFingerprint string
	var caNotAfter *time.Time
	var certLifetime int64
	var mldsaSet int
	if s.cfg.TrustAnchor != nil {
		// The anchor, not the signing intermediate: it is what tokens carry
		// and what survives a rotation of the relay's own key. Reported
		// whether or not client certificates are required, because a
		// machine pins it either way.
		caFingerprint = pki.SPKI(s.cfg.TrustAnchor)
	}
	if s.clientCerts() {
		caFingerprint = s.cfg.ClientCerts.Verifier.AnchorSPKI()
		expires := s.cfg.ClientCerts.Issuer.NotAfter()
		caNotAfter = &expires
		certLifetime = int64(s.cfg.ClientCerts.Lifetime / time.Second)
		mldsaSet = clientca.ParameterNumber(s.cfg.ClientCerts.Issuer.Parameters())
	}
	l := s.cfg.Limits
	// max_recipients goes in a section and not in LimitsView: a field
	// LimitsView does not have would be refused by an auu-admin from
	// before it, which reads the answer strictly.
	s.writeJSON(w, http.StatusOK, relayapi.AdminStatusResponse{
		Sections:         relayapi.Sections{Sections: s.maxRecipientsSection()},
		Registration:     s.cfg.Registration,
		PublicURL:        s.cfg.PublicURL,
		Uptime:           now.Sub(s.started).Round(time.Second).String(),
		Started:          s.started.UTC().Truncate(time.Second),
		Administrators:   s.admins.count(),
		Mailboxes:        counts.Mailboxes,
		QueuedMessages:   usage.Messages,
		QueuedBytes:      usage.Bytes,
		LiveTokens:       counts.LiveTokens,
		Blocks:           counts.Blocks,
		ClientCerts:      s.clientCertMode(),
		LiveCerts:        counts.LiveCerts,
		AccessLog:        s.accessLogMode(),
		MaxBytes:         s.cfg.MaxBytes,
		CAFingerprint:    caFingerprint,
		CANotAfter:       caNotAfter,
		CertLifetimeSecs: certLifetime,
		MLDSA:            mldsaSet,
		Limits: relayapi.LimitsView{
			RequestsPerMinute:        l.RequestsPerMinute,
			PostsPerMinute:           l.PostsPerMinute,
			PostBytesPerHour:         l.PostBytesPerHour,
			UnauthenticatedPerMinute: l.UnauthenticatedPerMinute,
			RegistrationsPerHour:     l.RegistrationsPerHour,
			MaxMailboxes:             l.MaxMailboxes,
			MailboxMaxMessages:       l.MailboxMaxMessages,
			MailboxMaxBytes:          l.MailboxMaxBytes,
			RelayMaxBytes:            l.RelayMaxBytes,
			MaxOpenUploads:           l.MaxOpenUploads,
			MaxInflight:              l.MaxInflight,
			MaxWaiting:               l.MaxWaiting,
			KnockMaxBytes:            l.KnockMaxBytes,
			MaxKnocksWaiting:         l.MaxKnocksWaiting,
			KnocksPerHour:            l.KnocksPerHour,
		},
		TokenMaxAgeSecs: int64(s.cfg.TokenMaxAge / time.Second),
	})
}

func (s *Server) accessLogMode() string {
	if s.minimal {
		return AccessLogMinimal
	}
	return AccessLogFull
}

func (s *Server) handleAdminMailboxes(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	after := r.URL.Query().Get("after")
	if after != "" && !identity.ValidFingerprint(after) {
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
	boxes, err := s.store.Mailboxes(after, int(limit))
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	resp := relayapi.MailboxListResponse{Mailboxes: boxes}
	if resp.Mailboxes == nil {
		resp.Mailboxes = []relayapi.MailboxRecord{}
	}
	// A full page means there may be more; anything shorter is the end.
	if int64(len(boxes)) == limit {
		resp.Next = boxes[len(boxes)-1].FP
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAdminMailbox(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	fp, ok := s.adminFP(w, r)
	if !ok {
		return
	}
	record, err := s.store.MailboxRecord(fp)
	if errors.Is(err, ErrNoMailbox) {
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	}
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	s.writeJSON(w, http.StatusOK, relayapi.MailboxAnswer{Mailbox: *record})
}

func (s *Server) handleAdminDeregister(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	fp, ok := s.adminFP(w, r)
	if !ok {
		return
	}
	removed, err := s.store.Deregister(fp)
	if err != nil {
		s.audit("mailbox.remove", adminFP, fp, "error")
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if !removed {
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	}
	s.audit("mailbox.remove", adminFP, fp, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminPurge(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	fp, ok := s.adminFP(w, r)
	if !ok {
		return
	}
	purged, err := s.store.PurgeMailbox(fp)
	if err != nil {
		s.audit("mailbox.purge", adminFP, fp, "error")
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if !purged {
		s.fail(w, http.StatusNotFound, "no such mailbox")
		return
	}
	s.audit("mailbox.purge", adminFP, fp, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminBlocks(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	blocks, err := s.store.Blocks()
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	resp := relayapi.BlocksResponse{Blocks: make([]relayapi.BlockRecord, 0, len(blocks))}
	for _, b := range blocks {
		resp.Blocks = append(resp.Blocks, relayapi.BlockRecord{
			FP: b.FP, Reason: b.Reason, Created: b.Created, ByFP: b.ByFP,
		})
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAdminBlock(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	fp, ok := s.adminFP(w, r)
	if !ok {
		return
	}
	var req relayapi.BlockRequest
	if !s.decodeRequest(w, body, &req, "block request") {
		return
	}
	reason := strings.TrimSpace(req.Reason)
	// The reason reaches an administrator's terminal and the operator's log.
	if err := token.ValidateNote(reason); err != nil {
		s.fail(w, http.StatusBadRequest, "reason "+err.Error())
		return
	}
	if err := s.store.SetBlock(fp, reason, adminFP, time.Now()); err != nil {
		s.audit("block.add", adminFP, fp, "error")
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	s.audit("block.add", adminFP, fp, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminUnblock(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	fp, ok := s.adminFP(w, r)
	if !ok {
		return
	}
	removed, err := s.store.RemoveBlock(fp)
	if err != nil {
		s.audit("block.remove", adminFP, fp, "error")
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if !removed {
		s.fail(w, http.StatusNotFound, "no such block")
		return
	}
	s.audit("block.remove", adminFP, fp, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminAddToken registers a token the calling administrator signed.
//
// You register your own tokens. Accepting another administrator's would let
// anyone with admin access put a colleague's name on an invitation.
func (s *Server) handleAdminAddToken(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	var req relayapi.RegisterTokenRequest
	if !s.decodeRequest(w, body, &req, "token request") {
		return
	}
	u, err := token.Parse(req.Token)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "malformed token")
		return
	}
	if u.IssuerFingerprint() != adminFP {
		s.fail(w, http.StatusForbidden, "a token may only be registered by the administrator who signed it")
		return
	}
	issuer, ok := s.admins.lookup(adminFP)
	if !ok {
		s.refuse(w, http.StatusForbidden, relayapi.RefusalNoAdministrators)
		return
	}
	now := time.Now()
	// Not yet valid is fine here: an administrator may register a token that
	// starts later. Expired is not, since it could never be redeemed.
	claims, err := u.Verify(issuer, now, 0)
	switch {
	case err == nil, errors.Is(err, token.ErrNotYetValid):
	case errors.Is(err, token.ErrForm):
		s.fail(w, http.StatusBadRequest, "malformed token")
		return
	case errors.Is(err, token.ErrUse):
		s.fail(w, http.StatusBadRequest, "unsupported token use")
		return
	case errors.Is(err, token.ErrExpired):
		s.fail(w, http.StatusBadRequest, "token has already expired")
		return
	default:
		s.fail(w, http.StatusForbidden, "token signature does not verify")
		return
	}
	if claims.NotAfter <= now.Unix() {
		s.fail(w, http.StatusBadRequest, "token has already expired")
		return
	}
	if s.cfg.TokenMaxAge > 0 {
		// Compared in seconds, never converted to nanoseconds: a span over
		// about 292 years overflows a time.Duration into a negative number,
		// which compares as shorter than the cap and so bypasses it. Validate
		// has already proved both bounds positive and ordered, so this
		// subtraction cannot overflow.
		maxSeconds := int64(s.cfg.TokenMaxAge / time.Second)
		if claims.NotAfter-claims.NotBefore > maxSeconds {
			s.fail(w, http.StatusBadRequest,
				"token lifetime is longer than this relay's token_max_age of "+s.cfg.TokenMaxAge.String())
			return
		}
	}
	if s.cfg.PublicURL != "" &&
		token.NormaliseRelay(claims.Relay) != token.NormaliseRelay(s.cfg.PublicURL) {
		s.fail(w, http.StatusBadRequest, "token names a different relay")
		return
	}
	// Verify already applied this, but the note is about to be stored and
	// handed back to administrators, so it is checked where it lands.
	if err := token.ValidateNote(claims.Note); err != nil {
		s.fail(w, http.StatusBadRequest, "note "+err.Error())
		return
	}

	if err := s.store.AddToken(*claims, now); err != nil {
		if errors.Is(err, ErrDuplicateToken) {
			s.fail(w, http.StatusConflict, "a token with that id is already registered")
			return
		}
		s.audit("token.issue", adminFP, claims.ID, "error")
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	s.audit("token.issue", adminFP, claims.ID, "ok",
		"uses", claims.Uses, "not_after", claims.NotAfterTime().UTC().Format(time.RFC3339))

	record, err := s.store.Token(claims.ID)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	s.writeJSON(w, http.StatusCreated, relayapi.TokenAnswer{Token: record.Wire(now)})
}

func (s *Server) handleAdminTokens(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	all := r.URL.Query().Get("all") != ""
	now := time.Now()
	records, err := s.store.Tokens(all, now)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	resp := relayapi.TokenListResponse{Tokens: make([]relayapi.TokenRecord, 0, len(records))}
	for _, t := range records {
		resp.Tokens = append(resp.Tokens, t.Wire(now))
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAdminRevokeToken(w http.ResponseWriter, r *http.Request, body []byte, adminFP string) {
	id := r.PathValue("id")
	if !token.ValidID(id) {
		s.fail(w, http.StatusBadRequest, "bad token id")
		return
	}
	revoked, err := s.store.RevokeToken(id)
	if err != nil {
		s.audit("token.revoke", adminFP, id, "error")
		s.refuse(w, http.StatusInternalServerError, relayapi.RefusalStorageError)
		return
	}
	if !revoked {
		s.fail(w, http.StatusNotFound, "no such token")
		return
	}
	s.audit("token.revoke", adminFP, id, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
