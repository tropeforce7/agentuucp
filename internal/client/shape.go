package client

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// What a relay lists is checked for shape before it is used.
//
// A relay is in this package's model as something that may not be honest:
// the client caps what it reads from one, refuses a bundle for the wrong
// fingerprint, and escapes its sentences. Its listings were the one thing
// it said that nothing looked at: auu-admin and auu print a fingerprint,
// a serial or a token id from a listing by its first sixteen characters,
// and a Go slice past the end of a string is a panic, so a relay that
// answered a two-byte fingerprint crashed the tool. Every id-shaped field
// in an answer is checked here, in one place per answer type, as it comes
// off the wire; a field that fails makes the whole answer ErrMalformedAnswer,
// naming the field and the relay, and nothing of it reaches a caller. A
// seconds field is bounded the same way, before anything multiplies it.
// Commands then slice what they were given.

// ErrMalformedAnswer is an answer from the relay with a field of the wrong
// shape. Every such error wraps it, so a caller can tell a relay that is
// not speaking the protocol from one that refused.
var ErrMalformedAnswer = errors.New("malformed answer")

// malformed names the answer, the field and the relay. The value is not
// repeated: it is the thing that could not be trusted.
func (c *Client) malformed(answer, field, want string) error {
	return fmt.Errorf("%w from the relay at %s: in %s, %s is not %s; nothing of the answer was used",
		ErrMalformedAnswer, c.base, answer, field, want)
}

const (
	wantMaxBytes    = "the relay's max_bytes (from 1 to 1073741824; a health answer without it is refused)"
	wantFingerprint = "a fingerprint (64 lowercase hex characters)"
	wantSerial      = "a certificate serial"
	wantTokenID     = "a token id (32 lowercase hex characters)"
	wantSeconds     = "a number of seconds within a hundred years"
	wantCount       = "a count (zero or more)"
	wantID          = "a message id (one or more)"
	wantMLDSA       = "an ML-DSA parameter set (44, 65 or 87, or 0 for none)"
	wantKind        = "a message kind (envelope, stream or knock)"
	wantChannelName = "a channel name"
	wantTime        = "a time"
)

// The enumerated fields of an answer, each held to the set the protocol
// defines, so that a command prints a word it knows rather than whatever
// the relay sent. Nothing on the wire is from before: a field the relay
// always sends is refused by name when it is absent, which for a word is
// the empty string. The one empty word that is a value is a mailbox
// record's allow, empty for a mailbox that has never pushed a list.
var (
	registrations     = []string{relayapi.RegistrationOpen, relayapi.RegistrationToken, relayapi.RegistrationClosed}
	certModes         = []string{relayapi.ClientCertsOff, relayapi.ClientCertsRequired}
	allowWords        = []string{relayapi.AllowSigned, relayapi.AllowNone, relayapi.AllowBroken}
	mailboxAllowWords = []string{"", relayapi.AllowSigned, relayapi.AllowNone, relayapi.AllowBroken}
	cardWords         = []string{relayapi.CardSigned, relayapi.CardNone, relayapi.CardBroken}
	mailboxCardWords  = []string{"", relayapi.CardSigned, relayapi.CardNone, relayapi.CardBroken}
	kinds             = []string{relayapi.KindEnvelope, relayapi.KindStream, relayapi.KindKnock}
	tokenUses         = []string{token.UseRegister, token.UseCert}
	tokenStates       = []string{relayapi.TokenLive, relayapi.TokenSpent, relayapi.TokenRevoked, relayapi.TokenExpired}
)

// oneOf reports whether v is in the set.
func oneOf(v string, set []string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// wantOneOf is the sentence for an enumerated field.
func wantOneOf(set []string) string {
	var words []string
	for _, s := range set {
		if s != "" {
			words = append(words, s)
		}
	}
	return "one of " + strings.Join(words, ", ")
}

// checkStatus is the shape of a relay's status: the authority's fingerprint
// when it has one, and the two lifetimes, which auu-admin prints as
// durations after multiplying by time.Second.
func (c *Client) checkStatus(st *relayapi.AdminStatusResponse) error {
	const answer = "the status"
	if st.CAFingerprint != "" && !identity.ValidFingerprint(st.CAFingerprint) {
		return c.malformed(answer, "ca_fingerprint", wantFingerprint)
	}
	if !oneOf(st.Registration, registrations) {
		return c.malformed(answer, "registration", wantOneOf(registrations))
	}
	if !oneOf(st.ClientCerts, certModes) {
		return c.malformed(answer, "client_certs", wantOneOf(certModes))
	}
	if !validSeconds(st.TokenMaxAgeSecs) {
		return c.malformed(answer, "token_max_age_seconds", wantSeconds)
	}
	if !validSeconds(st.CertLifetimeSecs) {
		return c.malformed(answer, "cert_lifetime_seconds", wantSeconds)
	}
	if !validMLDSA(st.MLDSA) {
		return c.malformed(answer, "mldsa", wantMLDSA)
	}
	l := st.Limits
	return c.counts(answer,
		count{"max_bytes", st.MaxBytes},
		count{"administrators", int64(st.Administrators)}, count{"mailboxes", st.Mailboxes},
		count{"queued_messages", st.QueuedMessages}, count{"queued_bytes", st.QueuedBytes},
		count{"live_tokens", st.LiveTokens}, count{"blocks", st.Blocks}, count{"live_certs", st.LiveCerts},
		count{"limits.requests_per_minute", l.RequestsPerMinute}, count{"limits.posts_per_minute", l.PostsPerMinute},
		count{"limits.post_bytes_per_hour", l.PostBytesPerHour}, count{"limits.unauthenticated_per_minute", l.UnauthenticatedPerMinute},
		count{"limits.registrations_per_hour", l.RegistrationsPerHour}, count{"limits.max_mailboxes", l.MaxMailboxes},
		count{"limits.mailbox_max_messages", l.MailboxMaxMessages}, count{"limits.mailbox_max_bytes", l.MailboxMaxBytes},
		count{"limits.relay_max_bytes", l.RelayMaxBytes}, count{"limits.max_open_uploads", l.MaxOpenUploads},
		count{"limits.max_inflight", l.MaxInflight}, count{"limits.max_waiting", l.MaxWaiting},
		count{"limits.knock_max_bytes", l.KnockMaxBytes}, count{"limits.max_knocks_waiting", l.MaxKnocksWaiting},
		count{"limits.knocks_per_hour", l.KnocksPerHour})
}

// checkHealth is the shape of a relay's health: the parameter set it
// names for client certificates, if any.
func (c *Client) checkHealth(h *relayapi.HealthResponse) error {
	if !validMLDSA(h.MLDSA) {
		return c.malformed("the health answer", "mldsa", wantMLDSA)
	}
	// max_bytes is what the client sizes a listing page to; a relay's own
	// is positive and under the ceiling, and a health answer without it
	// is refused by name.
	if h.MaxBytes < 1 || h.MaxBytes > relayapi.MaxBytesCeiling {
		return c.malformed("the health answer", "max_bytes", wantMaxBytes)
	}
	// The registration mode is what a listed name rests on, said wherever
	// a command asks a person to trust one; a health answer without it,
	// or with a fourth word, is refused by name.
	if !oneOf(h.Registration, registrations) {
		return c.malformed("the health answer", "registration", wantOneOf(registrations))
	}
	return nil
}

// checkListed is a page of the card listing: entries always sent, empty
// past the end, and never more of them than the page asked for, since a
// relay that ignored the limit is not one this client sizes its hold
// to; the count of listed cards in all, a number the relay sends whose
// zero is a value; each entry's three byte fields are the reader's to
// verify, not to check for shape.
func (c *Client) checkListed(page *relayapi.ListedResponse) error {
	const answer = "the card listing"
	if page.Entries == nil {
		return c.malformed(answer, "entries", "present: a page carries its entries, [] past the end")
	}
	if len(page.Entries) > relayapi.MaxListedLimit {
		return c.malformed(answer, "entries", fmt.Sprintf("at most the %d asked for", relayapi.MaxListedLimit))
	}
	return c.counts(answer, count{"listed", page.Listed})
}

// checkCard is the owner's own card as the relay serves it: the state as
// one of its three words, which the relay always sends.
func (c *Client) checkCard(r *relayapi.CardResponse) error {
	if !oneOf(r.State, cardWords) {
		return c.malformed("the card answer", "state", wantOneOf(cardWords))
	}
	return nil
}

// checkListing is a page of a mailbox: how much is queued, the state of
// the allow list and of the card each as one of its words, and each
// message's id, size, kind
// as one of its two words and channel held to the name rule, every one
// of which the relay always sends and is refused by name when absent. A
// page asked for as stubs carries no envelope: a row with one is a relay
// that ignored the parameter, refused by name.
func (c *Client) checkListing(page *relayapi.ListResponse, stubs bool) error {
	const answer = "the listing"
	if err := c.counts(answer, count{"queued", page.Queued}); err != nil {
		return err
	}
	if !oneOf(page.Allow, allowWords) {
		return c.malformed(answer, "allow", wantOneOf(allowWords))
	}
	if !oneOf(page.Card, cardWords) {
		return c.malformed(answer, "card", wantOneOf(cardWords))
	}
	for i := range page.Messages {
		m := &page.Messages[i]
		if m.ID <= 0 {
			return c.malformed(answer, "id", wantID)
		}
		if m.Size < 0 {
			return c.malformed(answer, "size", wantCount)
		}
		if !oneOf(m.Kind, kinds) {
			return c.malformed(answer, "kind", wantKind)
		}
		if err := channels.ValidName(m.Channel); err != nil {
			return c.malformed(answer, "channel", wantChannelName)
		}
		if stubs && len(m.Envelope) != 0 {
			return c.malformed(answer, "envelope", "absent: a stubs listing carries no envelope")
		}
	}
	return nil
}

// checkKeys is a lookup's answer: when the mailbox was registered, which
// the relay always says. The bundle is the caller's to parse, since what
// it parses to is the answer.
func (c *Client) checkKeys(k *relayapi.KeysResponse) error {
	if k.Created.IsZero() {
		return c.malformed("the lookup", "created", wantTime)
	}
	return nil
}

// checkDirectory is a directory answer: how many messages are queued
// under each channel, each zero or more.
func (c *Client) checkDirectory(resp *relayapi.ChannelsResponse) error {
	for name, n := range resp.Queued {
		if n < 0 {
			return c.malformed("the directory answer", "queued["+identity.Printable(name)+"]", wantCount)
		}
	}
	return nil
}

// checkID is the id a relay gives a message it accepted, from a post or
// a completed stream.
func (c *Client) checkID(answer string, id int64) error {
	if id <= 0 {
		return c.malformed(answer, "id", wantID)
	}
	return nil
}

// checkOpenStream is an opened upload: the threshold past which a first
// attempt that stops short is kept, zero or more, and the window a kept
// partial lives, in seconds within the bound every seconds field has.
func (c *Client) checkOpenStream(out *relayapi.OpenStreamResponse) error {
	const answer = "the opened stream"
	if err := c.counts(answer, count{"resume_threshold", out.ResumeThreshold}); err != nil {
		return err
	}
	if !validSeconds(out.ResumeWindow) {
		return c.malformed(answer, "resume_window", wantSeconds)
	}
	return nil
}

// parseOffset is the byte count a relay reports for an upload, from the
// header the upload routes answer with.
func (c *Client) parseOffset(raw string) (int64, error) {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, c.malformed("the upload answer", relayapi.UploadOffsetHeader, wantCount)
	}
	return n, nil
}

func validSeconds(n int64) bool { return n >= 0 && n <= relayapi.MaxDurationSeconds }

// validMLDSA is the parameter set a relay names for client certificates:
// one of the three, or zero for a relay that names none.
func validMLDSA(n int) bool { return n == 0 || n == 44 || n == 65 || n == 87 }

// count is one counted field of an answer, by its wire name.
type count struct {
	name string
	n    int64
}

// counts holds every count in an answer to zero or more, in one place per
// answer, naming the first field that is not.
func (c *Client) counts(answer string, fields ...count) error {
	for _, f := range fields {
		if f.n < 0 {
			return c.malformed(answer, f.name, wantCount)
		}
	}
	return nil
}

// checkMailbox is the shape of one mailbox record, in a listing or alone.
func (c *Client) checkMailbox(answer string, m *relayapi.MailboxRecord) error {
	if !identity.ValidFingerprint(m.FP) {
		return c.malformed(answer, "fp", wantFingerprint)
	}
	if !oneOf(m.Allow, mailboxAllowWords) {
		return c.malformed(answer, "allow", wantOneOf(mailboxAllowWords))
	}
	if !oneOf(m.Card, mailboxCardWords) {
		return c.malformed(answer, "card", wantOneOf(mailboxCardWords))
	}
	return c.counts(answer, count{"queued_messages", m.QueuedMessages}, count{"queued_bytes", m.QueuedBytes},
		count{"channels", m.Channels}, count{"allowlist_size", m.AllowlistSize})
}

// checkMailboxes is a page of mailboxes and the cursor for the next, which
// the next request sends back as a fingerprint.
func (c *Client) checkMailboxes(page *relayapi.MailboxListResponse) error {
	const answer = "the mailbox listing"
	for i := range page.Mailboxes {
		if err := c.checkMailbox(answer, &page.Mailboxes[i]); err != nil {
			return err
		}
	}
	if page.Next != "" && !identity.ValidFingerprint(page.Next) {
		return c.malformed(answer, "next", wantFingerprint)
	}
	return nil
}

// checkBlocks is the block listing: who is blocked, and by whom.
func (c *Client) checkBlocks(blocks []relayapi.BlockRecord) error {
	const answer = "the block listing"
	for i := range blocks {
		if !identity.ValidFingerprint(blocks[i].FP) {
			return c.malformed(answer, "fp", wantFingerprint)
		}
		if !identity.ValidFingerprint(blocks[i].ByFP) {
			return c.malformed(answer, "by_fp", wantFingerprint)
		}
	}
	return nil
}

// checkToken is one token record: its id, the administrator who issued
// it, and the identity it is bound to when it is bound.
func (c *Client) checkToken(answer string, t *relayapi.TokenRecord) error {
	if !token.ValidID(t.ID) {
		return c.malformed(answer, "id", wantTokenID)
	}
	if !identity.ValidFingerprint(t.Issuer) {
		return c.malformed(answer, "issuer", wantFingerprint)
	}
	if t.Subject != "" && !identity.ValidFingerprint(t.Subject) {
		return c.malformed(answer, "subject", wantFingerprint)
	}
	if !oneOf(t.Use, tokenUses) {
		return c.malformed(answer, "use", wantOneOf(tokenUses))
	}
	if !oneOf(t.State, tokenStates) {
		return c.malformed(answer, "state", wantOneOf(tokenStates))
	}
	if t.Uses < 0 {
		return c.malformed(answer, "uses", wantCount)
	}
	if t.UsesLeft < 0 || t.UsesLeft > t.Uses {
		return c.malformed(answer, "uses_left", "between 0 and uses")
	}
	return nil
}

func (c *Client) checkTokens(tokens []relayapi.TokenRecord) error {
	for i := range tokens {
		if err := c.checkToken("the token listing", &tokens[i]); err != nil {
			return err
		}
	}
	return nil
}

// checkCerts is a certificate listing: every serial, and every fingerprint
// where the listing carries one. An administrator's listing names the
// identity of each; a mailbox's own leaves the field out, since every row
// is the caller's, so there it is checked only when present.
func (c *Client) checkCerts(answer string, certs []relayapi.CertRecord, ownListing bool) error {
	for i := range certs {
		if !clientca.ValidSerial(certs[i].Serial) {
			return c.malformed(answer, "serial", wantSerial)
		}
		if certs[i].FP == "" && ownListing {
			continue
		}
		if !identity.ValidFingerprint(certs[i].FP) {
			return c.malformed(answer, "fp", wantFingerprint)
		}
	}
	return nil
}
