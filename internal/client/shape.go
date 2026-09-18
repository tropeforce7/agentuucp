package client

import (
	"errors"
	"fmt"
	"strings"

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
	wantFingerprint = "a fingerprint (64 lowercase hex characters)"
	wantSerial      = "a certificate serial"
	wantTokenID     = "a token id (32 lowercase hex characters)"
	wantSeconds     = "a number of seconds within a hundred years"
)

// The enumerated fields of an answer, each held to the set the protocol
// defines, so that a command prints a word it knows rather than whatever
// the relay sent. The empty string is allowed where a relay from before
// the field sends nothing.
var (
	registrations = []string{"", relayapi.RegistrationOpen, relayapi.RegistrationToken, relayapi.RegistrationClosed}
	certModes     = []string{"", relayapi.ClientCertsOff, relayapi.ClientCertsRequired}
	allowWords    = []string{"", relayapi.AllowSigned, relayapi.AllowNone, relayapi.AllowBroken}
	tokenUses     = []string{token.UseRegister, token.UseCert}
	tokenStates   = []string{relayapi.TokenLive, relayapi.TokenSpent, relayapi.TokenRevoked, relayapi.TokenExpired}
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
	return nil
}

func validSeconds(n int64) bool { return n >= 0 && n <= relayapi.MaxDurationSeconds }

// checkMailbox is the shape of one mailbox record, in a listing or alone.
func (c *Client) checkMailbox(answer string, m *relayapi.MailboxRecord) error {
	if !identity.ValidFingerprint(m.FP) {
		return c.malformed(answer, "fp", wantFingerprint)
	}
	if !oneOf(m.Allow, allowWords) {
		return c.malformed(answer, "allow", wantOneOf(allowWords))
	}
	return nil
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
