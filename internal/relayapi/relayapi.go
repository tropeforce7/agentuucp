// Package relayapi holds the types on the wire between an auu client and a relay,
// plus the one implementation of request signing that both sides use.
//
// The relay is untrusted: it stores ciphertext, and what it enforces is who
// may have a mailbox and who may drop mail in whose, never anything about the
// contents. Request signing exists to stop the relay being an open spool for
// anyone on the internet, not to protect message contents.
package relayapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

const (
	// AuthHeader carries the per-request signature.
	AuthHeader = "X-CCX-Auth"

	// MsgTokenInHeader is the refusal for a client still sending an enrolment
	// token as a header. The token now travels inside the certificate
	// request, where the signature covers it.
	MsgTokenInHeader = "enrolment tokens travel inside the certificate request"

	authVersion = "v1"
	httpDomain  = "ccx-http-v1"

	// MaxSkew is how far a request timestamp may be from the relay's clock.
	MaxSkew = 5 * time.Minute
	// NonceTTL is how long a used nonce is remembered. It must exceed MaxSkew.
	NonceTTL = 10 * time.Minute

	nonceBytes = 16

	// MaxAuthHeader is the longest a ccx-auth-v1 header can be: the
	// version, a fingerprint, a timestamp, a nonce and a signature, and
	// the four spaces between them. Each field has one shape — 64 hex
	// characters, at most 20 digits for an int64 with its sign, 16 nonce
	// bytes and a 64-byte Ed25519 signature in standard base64 — so a
	// header longer than their sum cannot be one, and ParseAuth refuses
	// it before it splits a field. A later auth version with another
	// signature is its own shape with its own constant; this one is
	// 2 + 1 + 64 + 1 + 20 + 1 + 24 + 1 + 88 = 202.
	MaxAuthHeader = len(authVersion) + 1 + 64 + 1 + 20 + 1 + (nonceBytes+2)/3*4 + 1 + (64+2)/3*4

	// Client certificate modes. There is no "optional": a mode that issued
	// and checked certificates but still admitted requests without one would
	// be a migration aid, and there is nothing to migrate.
	ClientCertsOff      = "off"
	ClientCertsRequired = "required"

	// DefaultMaxBytes is the default ceiling on a posted envelope.
	DefaultMaxBytes int64 = 16 << 20
)

// Wire types.
type (
	ErrorResponse struct {
		Error string `json:"error"`
	}
	RegisterRequest struct {
		Bundle []byte `json:"bundle"`
		Name   string `json:"name"`
		// CSR is the machine's certificate request. It carries the
		// enrolment token, when one is needed, as a PKCS#9
		// challengePassword, so that one signature covers the key and the
		// authorisation together.
		CSR []byte `json:"csr,omitempty"`
	}
	RegisterResponse struct {
		FP string `json:"fp"`
		// Cert, CA and NotAfter are present when the relay issued a client
		// certificate. A relay with client certificates off returns none of
		// them and the machine keeps no key.
		Cert     []byte     `json:"cert,omitempty"`
		CA       []byte     `json:"ca,omitempty"`
		NotAfter *time.Time `json:"not_after,omitempty"`
	}
	// KeysResponse is what the relay knows about an identity: its bundle,
	// the name it registered under, and when. It is a convenience, not a
	// trust anchor; a client checks the bundle's own fingerprint against
	// what it asked for.
	KeysResponse struct {
		Bundle []byte `json:"bundle"`
		Name   string `json:"name"`
		// Created is when the mailbox was registered. Always sent; a
		// client refuses an answer without it by name.
		Created time.Time `json:"created"`
	}
	// AllowRequest carries an owner's allow list: the signed document
	// bytes exactly as the owner signed them and the signature over them
	// under the allow list's own domain, which a relay verifies against
	// the mailbox's registered bundle and stores verbatim. A request with
	// no document is refused with MsgNeedSignedAllowlist and nothing is
	// stored.
	AllowRequest struct {
		Document  []byte `json:"document,omitempty"`
		Signature []byte `json:"signature,omitempty"`
	}
	// AllowResponse is a mailbox's allow list as pushed, for its owner
	// alone: the document and signature verbatim, to verify with the
	// owner's own key, and State, one of the Allow* words, which is the
	// relay's own reading and is not to be trusted over the pair.
	AllowResponse struct {
		Document  []byte `json:"document"`
		Signature []byte `json:"signature"`
		State     string `json:"state"`
	}
	// CardRequest carries an owner's card: the signed document bytes
	// exactly as the owner signed them and the signature over them under
	// the card's own domain, which a relay verifies against the mailbox's
	// registered bundle and stores verbatim. A request with no document
	// is one whose signature does not verify, and is refused as such.
	CardRequest struct {
		Document  []byte `json:"document,omitempty"`
		Signature []byte `json:"signature,omitempty"`
	}
	// CardResponse is a mailbox's card as pushed, for its owner alone: the
	// document and signature verbatim, to verify with the owner's own key,
	// and State, one of the Card* words, which is the relay's own reading
	// and is not to be trusted over the pair. Always sent; a client
	// refuses an answer without it by name.
	CardResponse struct {
		Document  []byte `json:"document"`
		Signature []byte `json:"signature"`
		State     string `json:"state"`
	}
	// ListedEntry is one card the relay lists, with the bundle it was
	// verified against at the push: the bytes as stored, which the reader
	// verifies for itself — the bundle's fingerprint is the document's
	// owner, the signature verifies under the bundle's key, and the
	// document says listed — since the reader is the party that must not
	// trust the relay. An entry that fails is dropped and counted; a row
	// edited in the relay's database removes a name and never adds one.
	ListedEntry struct {
		Bundle    []byte `json:"bundle"`
		Document  []byte `json:"document"`
		Signature []byte `json:"signature"`
	}
	// ListedResponse is a page of the cards whose owners chose to be
	// listed, in fingerprint order from the after parameter exclusive, at
	// most limit entries, and how many such cards the relay holds in all,
	// so a client knows when it has the whole list. Listed is a count
	// whose zero the relay sends, as a listing's queued is, so absent and
	// zero are one number; entries is always sent, empty for the page
	// past the end, and a page with more entries than the limit asked
	// for is a relay that ignored the parameter, refused by name.
	ListedResponse struct {
		Entries []ListedEntry `json:"entries"`
		Listed  int64         `json:"listed"`
	}
	// ChannelsRequest carries an owner's channel directory: the document
	// bytes exactly as the owner signed them, and the signature over them
	// under the directory's own domain. The relay verifies the pair against
	// the mailbox's registered bundle, stores both verbatim and serves them
	// back the same way, so a sender verifies what the owner signed and
	// never what the relay says.
	ChannelsRequest struct {
		Document  []byte `json:"document"`
		Signature []byte `json:"signature"`
	}
	// ChannelsResponse is the directory as pushed. Queued, how many
	// messages wait under each channel name, is filled only for the owner
	// asking about their own mailbox: how busy a channel is tells a sender
	// something about the owner, so a sender's view is the signed document
	// and nothing else.
	ChannelsResponse struct {
		Document  []byte           `json:"document"`
		Signature []byte           `json:"signature"`
		Queued    map[string]int64 `json:"queued,omitempty"`
	}
	PostResponse struct {
		ID int64 `json:"id"`
	}
	// ForwardRequest carries a sealed envelope to a relay that is not the
	// recipient's, for it to pass on.
	//
	// The envelope is the sender's, byte for byte, from the first hop to
	// the last: it is what every hop stores and forwards, and nothing on
	// any hop can read, forge or re-address it. What the hops need beside
	// it is where it still has to go and where it has been, and those are
	// fields of the request rather than of the envelope, so that the
	// envelope is one thing everywhere and a relay rewrites nothing.
	//
	// Path is what remains: its first name is a neighbour of the relay
	// receiving the request, and the rest is that neighbour's business.
	// Via is the hops so far, each name written by the relay that wrote
	// it, which is what makes the reversed list a return path when every
	// name is relative to the relay reading it. Both are always sent, so
	// a courier's empty Via is [] and not an absent field; a user sends a
	// Path of at least one name and no Via, since a user writing one
	// would be forging a return path.
	ForwardRequest struct {
		Envelope json.RawMessage `json:"envelope"`
		Path     []string        `json:"path"`
		Via      []string        `json:"via"`
	}
	// ForwardResponse is the id of the row the relay queued, which the
	// poster reads back in its own queue listing. A 409 from the poster of
	// the row that already holds this envelope carries it too, so that a
	// retry after a lost answer learns the id its first attempt was given.
	ForwardResponse struct {
		ID int64 `json:"id"`
	}
	// StoredMessage carries an envelope back verbatim. It stays opaque here so
	// the relay never has to understand a payload it cannot read.
	StoredMessage struct {
		ID       int64     `json:"id"`
		Received time.Time `json:"received"`
		// Kind is envelope, stream or knock, always present; a client
		// refuses a row without it, or with any other word, by name.
		Kind string `json:"kind"`
		Size int64  `json:"size,omitempty"`
		// Channel is the name the message was posted under, always
		// present, as queued is; a client holds it to the channel name
		// rule and refuses a row without it by name.
		Channel string `json:"channel"`
		// Envelope is inline for an envelope and omitted for a stream, which
		// is fetched from its own endpoint.
		Envelope json.RawMessage `json:"envelope,omitempty"`
	}
	ListResponse struct {
		Messages []StoredMessage `json:"messages"`
		// Queued is how many messages the mailbox holds in all, whatever
		// the page: the messages the page is drawn from, less any the
		// relay cannot serve, so an upload still open is not in it.
		// Always present, so a client can tell an empty page beside a
		// count above zero, which means its cursor has skipped mail, from
		// a mailbox that is empty; zero is the count of an empty mailbox,
		// and a client reads zero as nothing to say.
		Queued int64 `json:"queued"`
		// DirectoriesChanged names the watched peers whose directory the
		// relay holds a newer issue of than the listing's peers parameter
		// said. Absent when none has, or when nothing was watched, so a
		// listing that watches nothing is byte for byte what it was.
		DirectoriesChanged []string `json:"directories_changed,omitempty"`
		// Allow is the state of the mailbox's allow list as the relay
		// holds it, one of the Allow* words, so the owner is told when it
		// is unsigned, missing or no longer verifies. Always present; a
		// client refuses a listing without it, or with any other word, by
		// name.
		Allow string `json:"allow"`
		// Card is the state of the mailbox's card as the relay holds it,
		// one of the Card* words, for the same reason: a card that no
		// longer verifies unlists the owner and closes their mailbox to
		// knocks, and the owner would otherwise learn that from nothing.
		// Always present; a client refuses a listing without it, or with
		// any other word, by name.
		Card string `json:"card"`
		// Directory is the state of the owner's channel directory, one of
		// the Directory* words, always sent and refused by name when it is
		// absent. A directory that does not verify routes nothing: every
		// named channel is refused until the owner pushes again, and the
		// owner would otherwise learn that from their senders' silence.
		Directory string `json:"directory"`
	}
	HealthResponse struct {
		OK bool `json:"ok"`
		// MaxBytes is the relay's max_bytes: the largest envelope it takes
		// and the budget a listing page follows, so a client can size what
		// it will hold of a page to the relay it talks to rather than to
		// the ceiling. Always sent; a health answer without it is refused
		// by name.
		MaxBytes int64 `json:"max_bytes"`
		// Registration is the relay's registration mode, one of the
		// Registration* words: what admission to this relay means, and so
		// what a name listed on it rests on. A relay that lies here is
		// admitting anybody, which is the case the word warns of. Always
		// sent; a health answer without it is refused by name.
		Registration string `json:"registration"`
		// MLDSA is the parameter set — 44, 65 or 87 — the relay requires of
		// a client's certificate key, so a machine can generate the right
		// one before it enrols. Absent when the relay issues no
		// certificates. It is a hint: the relay refuses a request whose key
		// does not match whatever it says here, so nothing can be talked
		// into a weaker key by a wrong answer.
		MLDSA int `json:"mldsa,omitempty"`
	}
)

// Registration modes. They govern who may create a mailbox; an existing
// mailbox may always re-register, which is only a change of display name.
const (
	// RegistrationOpen lets anyone create a mailbox.
	RegistrationOpen = "open"
	// RegistrationToken requires a valid enrolment token.
	RegistrationToken = "token"
	// RegistrationClosed creates no more mailboxes.
	RegistrationClosed = "closed"
)

// MaxDurationSeconds bounds a seconds field in an answer: a hundred years,
// which no lifetime a relay reports approaches and which is well under the
// 292 a time.Duration holds, so a client that multiplies the field by
// time.Second after checking it against this cannot wrap. A number from the
// network is bounded before it is multiplied.
const MaxDurationSeconds int64 = 100 * 365 * 24 * 3600

// Administration wire types. Everything here crosses /v1/admin, which only an
// identity named in the relay host's authorized file can reach.
type (
	// AdminStatusResponse is what one relay is doing right now.
	AdminStatusResponse struct {
		Registration    string     `json:"registration"`
		PublicURL       string     `json:"public_url"`
		Uptime          string     `json:"uptime"`
		Started         time.Time  `json:"started"`
		Administrators  int        `json:"administrators"`
		Mailboxes       int64      `json:"mailboxes"`
		QueuedMessages  int64      `json:"queued_messages"`
		QueuedBytes     int64      `json:"queued_bytes"`
		LiveTokens      int64      `json:"live_tokens"`
		Blocks          int64      `json:"blocks"`
		Limits          LimitsView `json:"limits"`
		AccessLog       string     `json:"access_log"`
		MaxBytes        int64      `json:"max_bytes"`
		TokenMaxAgeSecs int64      `json:"token_max_age_seconds"`

		// ClientCerts is off or required.
		ClientCerts string `json:"client_certs"`
		// CAFingerprint identifies the client certificate authority, empty
		// when there is none.
		CAFingerprint string `json:"ca_fingerprint,omitempty"`
		// CANotAfter is when that authority expires. Rotating it means
		// re-enrolling every machine, so an operator wants warning.
		CANotAfter *time.Time `json:"ca_not_after,omitempty"`
		// CertLifetimeSecs is how long an issued certificate lives.
		CertLifetimeSecs int64 `json:"cert_lifetime_seconds,omitempty"`
		// MLDSA is the parameter set of the authority and of every client key.
		MLDSA int `json:"mldsa,omitempty"`
		// LiveCerts counts certificates neither revoked nor expired.
		LiveCerts int64 `json:"live_certs"`
	}

	// LimitsView reports the limits in force. Zero means unlimited.
	LimitsView struct {
		RequestsPerMinute        int64 `json:"requests_per_minute"`
		PostsPerMinute           int64 `json:"posts_per_minute"`
		PostBytesPerHour         int64 `json:"post_bytes_per_hour"`
		UnauthenticatedPerMinute int64 `json:"unauthenticated_per_minute"`
		RegistrationsPerHour     int64 `json:"registrations_per_hour"`
		MaxMailboxes             int64 `json:"max_mailboxes"`
		MailboxMaxMessages       int64 `json:"mailbox_max_messages"`
		MailboxMaxBytes          int64 `json:"mailbox_max_bytes"`
		RelayMaxBytes            int64 `json:"relay_max_bytes"`
		MaxOpenUploads           int64 `json:"max_open_uploads"`
		MaxInflight              int64 `json:"max_inflight"`
		MaxWaiting               int64 `json:"max_waiting"`
		KnockMaxBytes            int64 `json:"knock_max_bytes"`
		MaxKnocksWaiting         int64 `json:"max_knocks_waiting"`
		KnocksPerHour            int64 `json:"knocks_per_hour"`
	}

	// MailboxRecord is one mailbox as an administrator sees it. It never
	// carries a message, only the shape of what is queued.
	MailboxRecord struct {
		FP             string    `json:"fp"`
		Name           string    `json:"name"`
		Created        time.Time `json:"created"`
		QueuedMessages int64     `json:"queued_messages"`
		QueuedBytes    int64     `json:"queued_bytes"`
		AllowlistSize  int64     `json:"allowlist_size"`
		// Allow is the state of the allow list, one of the Allow* words,
		// or empty for a mailbox that has never pushed one, which is a
		// value and not an absence. "broken" is the word to look for
		// after an incident: a list that does not verify is a row the
		// relay cannot vouch for, and refuses on.
		Allow string `json:"allow,omitempty"`
		// Card is the state of the card, one of the Card* words, or empty
		// for a mailbox that has never pushed one, which is a value and not
		// an absence; CardListed and CardKnocks are the two words the relay
		// parsed from it at the push, for the administrator's line, and
		// decide nothing. As with the allow list, "broken" is the word to
		// look for after an incident.
		Card       string `json:"card,omitempty"`
		CardListed bool   `json:"card_listed"`
		CardKnocks bool   `json:"card_knocks"`
		// Directory is the state of the channel directory, one of the
		// Directory* words, or empty for a mailbox that has never pushed
		// one, which is a value and not an absence: that mailbox has the
		// one channel, default. As with the allow list and the card,
		// "broken" is the word to look for after an incident, and it is
		// the heaviest of the three: a directory that does not verify
		// closes the mailbox to every post, default included.
		Directory string `json:"directory,omitempty"`
		// Channels is how many channels the mailbox's directory lists, zero
		// for a mailbox with none, which has default by that fact rather
		// than by a row. A count and never the names: what an owner's
		// channels are called is theirs to publish to their senders. It is
		// the count of what the relay parsed at the push and decides
		// nothing; Directory beside it is the word that says whether any
		// of them routes.
		Channels int64 `json:"channels"`
		Blocked  bool  `json:"blocked"`
	}
	MailboxListResponse struct {
		Mailboxes []MailboxRecord `json:"mailboxes"`
		// Next is the value to pass as ?after= for the following page, or
		// empty when this is the last one.
		Next string `json:"next"`
	}

	// CertRecord is one issued client certificate. The certificate itself is
	// never returned: the machine that asked for it has it, and the relay
	// keeps only enough to recognise and revoke it.
	CertRecord struct {
		Serial string `json:"serial"`
		// FP is the identity the certificate names. It is empty on a
		// mailbox's own listing, where every row is the caller's.
		FP        string    `json:"fp,omitempty"`
		Label     string    `json:"label"`
		SPKI      string    `json:"spki"`
		NotBefore time.Time `json:"not_before"`
		NotAfter  time.Time `json:"not_after"`
		Revoked   bool      `json:"revoked"`
		Reason    string    `json:"reason,omitempty"`
		// Current marks the certificate the request arrived on.
		Current bool `json:"current,omitempty"`
	}
	CertsResponse struct {
		Certs []CertRecord `json:"certs"`
	}
	// TrustAnchorResponse is the root a machine pins at enrolment. It is
	// fetched over a connection nothing has verified yet, and checked
	// against the hash in an enrolment token before it is believed.
	TrustAnchorResponse struct {
		TrustAnchor []byte `json:"trust_anchor"`
		SPKI        string `json:"spki"`
	}
	// CertRequest asks for a certificate, at enrolment or at renewal. The
	// CSR carries the machine's key, its label, and at enrolment the
	// enrolment token, all under one signature.
	CertRequest struct {
		CSR []byte `json:"csr"`
	}
	// CertResponse is a freshly issued certificate and the authority that
	// signed it, both DER.
	CertResponse struct {
		Cert     []byte    `json:"cert"`
		CA       []byte    `json:"ca"`
		NotAfter time.Time `json:"not_after"`
	}
	RevokeCertRequest struct {
		Reason string `json:"reason"`
	}
	RevokeCertResponse struct {
		Revoked bool `json:"revoked"`
	}

	BlockRecord struct {
		FP      string    `json:"fp"`
		Reason  string    `json:"reason"`
		Created time.Time `json:"created"`
		ByFP    string    `json:"by_fp"`
	}
	BlockRequest struct {
		Reason string `json:"reason"`
	}
	BlocksResponse struct {
		Blocks []BlockRecord `json:"blocks"`
	}

	// RegisterTokenRequest hands a signed token to the relay that will honour
	// it. Only the administrator who signed it may register it.
	RegisterTokenRequest struct {
		Token string `json:"token"`
	}
	// TokenRecord is a registered token. The token string itself is never
	// returned: once issued it exists only where the administrator and the
	// holder put it.
	TokenRecord struct {
		ID           string    `json:"id"`
		Issuer       string    `json:"issuer"`
		Relay        string    `json:"relay"`
		Use          string    `json:"use"`
		Subject      string    `json:"subject"`
		Note         string    `json:"note"`
		NotBefore    time.Time `json:"not_before"`
		NotAfter     time.Time `json:"not_after"`
		Uses         int       `json:"uses"`
		UsesLeft     int       `json:"uses_left"`
		Revoked      bool      `json:"revoked"`
		Created      time.Time `json:"created"`
		LastRedeemed time.Time `json:"last_redeemed"`
		// State is live, spent, revoked or expired.
		State string `json:"state"`
	}
	TokenListResponse struct {
		Tokens []TokenRecord `json:"tokens"`
	}
)

// Token states, in the order they take precedence when more than one applies.
const (
	TokenRevoked = "revoked"
	TokenExpired = "expired"
	TokenSpent   = "spent"
	TokenLive    = "live"
)

// List limits.
const (
	DefaultListLimit = 50
	MaxListLimit     = 200
	// MaxListedLimit is the most entries one page of the card listing
	// carries, and the default: a page over it is refused rather than
	// served at the cap, since a client sizes what it holds of a page to
	// this number, and a relay asked for more than it would serve is a
	// client from somewhere else.
	MaxListedLimit = 100
)

// MaxCardBytes caps a card's document, the bytes the owner signed: a card
// at every maximum as this client marshals it — a name of 64 bytes and
// issued to the nanosecond — is 199 bytes, and the cap leaves room for a
// signer whose encoder indented it. It is the wire's rule and both ends
// run it, the relay at the push and every reader of the listing at the
// entry, before the signature is checked, since a length is checked
// before anything is decoded. Without it a registered identity could
// push a card padded to the route's 64 KiB and take every reader's page
// over its hold, which the second reader of the listing found.
const MaxCardBytes = 512

// MaxListedBytes is the most the client holds of one page of the card
// listing: MaxListedLimit entries as this client marshals them, each a
// bundle, a card and a signature in base64 inside the entry's JSON, with
// the page's framing. The worst page is every card at MaxCardBytes, and
// TestLimitAListingPageIsHeldToItsBytes measured it on 2026-09-22:
//
//	210,286 bytes with cards as this client writes them, 247,926 with
//	every card padded to MaxCardBytes
//
// each entry a bundle of the one suite (1,222 bytes, 1,632 in base64), a
// card (up to 684 in base64), an Ed25519 signature (64 bytes, 88) and
// the entry's framing, and the hold is the round number above the worst
// page. A page over the hold is refused by name; the test feeds one at
// the hold and one over.
const MaxListedBytes = 256 << 10

// The listing's hold. A listing asked for with wait=D is held open until a
// message arrives after the id it asked from, or a watched directory is
// replaced, or D elapses; a longer D is clamped to MaxWait rather than
// refused, and a relay already holding as many listings as it allows
// answers at once, the hold degrading and never refusing. MaxWatchPeers caps
// how many peers one listing may watch the directories of, a protocol
// constant as MaxAllowlist is: the watcher has already fetched each one.
const (
	MaxWait       = 60 * time.Second
	MaxWatchPeers = 100
)

// The states of a mailbox's allow list, as the owner's listing and the
// administrator's record report it. There is no state for a list that
// merely lacks a signature: authentication data is signed or it is broken.
const (
	// AllowSigned is a list the owner signed, which verifies.
	AllowSigned = "signed"
	// AllowNone is a mailbox that has never pushed a list; any registered
	// sender may post.
	AllowNone = "none"
	// AllowBroken is a list that does not verify against the mailbox's
	// key, a row with no signature included. The relay refuses every post
	// to the mailbox until the owner pushes again.
	AllowBroken = "broken"
)

// The states of a mailbox's channel directory, the same three words the
// allow list and the card use, as the owner's listing reports it. The
// relay verifies the directory at every post, so a broken one refuses
// every named channel until the owner pushes again.
const (
	DirectorySigned = "signed"
	DirectoryNone   = "none"
	DirectoryBroken = "broken"
)

// The states of a mailbox's card, the allow list's three words, as the
// owner's listing and the administrator's record report it. A card that
// merely lacks a signature is broken, as a list is.
const (
	// CardSigned is a card the owner signed, which verifies.
	CardSigned = "signed"
	// CardNone is a mailbox that has never pushed a card: not listed, and
	// taking no knocks.
	CardNone = "none"
	// CardBroken is a card that does not verify against the mailbox's key,
	// a row with no signature included. The relay refuses every knock to
	// the mailbox, and a client drops the entry from the listing, until
	// the owner pushes again.
	CardBroken = "broken"
)

// MsgNeedSignedAllowlist is the 400 for an allow request with no document:
// a plain sentence saying what was missing, and nothing is stored.
const MsgNeedSignedAllowlist = "this relay takes a signed allow list; the request carries no document"

// MaxAllowlist caps the entries in one allow list.
//
// The request body limit is not a bound on this by itself: 16 MiB of
// fingerprints is about a quarter of a million entries, each validated and
// inserted in a single transaction. It is a property of the protocol rather
// than of one relay, so it is a constant and not a setting.
const MaxAllowlist = 1000

// MaxCouriers caps the neighbouring relays one relay accepts forwarded mail
// from: the lines its couriers file may hold, refused above it at load.
//
// It is a protocol constant for MaxAllowlist's reason rather than a setting:
// the relay holds the file to it today, and the route that will list the
// couriers back to a user — so that somebody with a restricted allow list
// can admit one by name — will be read by a client that must know the same
// bound before it reads the answer. That route is not in the tree yet, and
// this is a bound on both ends of it when it is. A thousand neighbours is far past any network of relays whose
// operators know one another, which is the only kind this is for.
const MaxCouriers = 1000

// MaxHops caps the relays one address may name: the names in a path and the
// hops already taken, counted together.
//
// It is the ceiling on courier.max_hops rather than the setting, which an
// operator may set lower; a relay refuses a higher one at the start, naming
// this. Like MaxAllowlist it is a property of the protocol and not of one
// relay: a sender's client holds an address to it before anything is sealed,
// every hop holds the two lists to it, and a client reading a message holds
// the return path it came by to it, so all three must agree. Thirty-two is
// far past any chain of relays whose operators know one another, and the
// number matters because the two lists and the carried window are sized from
// it: the window an envelope can be alive in the network is max_hops times
// forward_ttl.
const MaxHops = 32

// The channel caps, protocol constants for the same reason as MaxAllowlist:
// the sender's client, the owner's and the relay all validate a directory,
// and they must agree on the bounds. Names and descriptions are measured in
// bytes of UTF-8, not characters; internal/channels holds the rules.
const (
	// MaxChannels caps the channels in one directory.
	MaxChannels = 64
	// MaxChannelNameBytes caps a channel's name.
	MaxChannelNameBytes = 64
	// MaxChannelDescriptionBytes caps a channel's description.
	MaxChannelDescriptionBytes = 1024
)

// FramingAllowance is the slack above a relay's max_bytes granted to JSON
// framing and base64 expansion when reading a request body. It is also the
// whole body cap on every route that carries a small JSON request — a
// registration, a certificate request, an admin token, a stream's open —
// none of which reaches a tenth of it.
const FramingAllowance = 1 << 16

// MaxDirectoryBytes caps a channel directory's document, the bytes the
// owner signed. A directory at every maximum — MaxChannels channels, each
// name MaxChannelNameBytes and each description MaxChannelDescriptionBytes,
// both bounds set on every channel, and issued and both bounds carried to
// the nanosecond — measured on a document that passed Validate and as this
// client marshals it:
//
//	compact, times on UTC:        425,289 bytes
//	compact, times at +10:00:     425,934   <- the larger: a signer need not be on UTC
//	the same, tab-indented:       427,613
//	the same, four spaces:        430,700
//
// The names in that document are 63 "&" and one byte to tell them apart,
// "&" being the only byte a channel name may hold that encoding/json
// writes as a six-byte escape — a name refuses "<" and ">", which the
// Windows file-name rule forbids, while a description admits them.
//
// The cap leaves about 91 KiB above the widest of those, which is the room
// for a signer whose encoder indents further than this one: the bytes are
// whatever that encoder produced and the signature covers them, so another
// client may indent, and one that indents past the cap is told to send it
// compact. It is the wire's rule and both ends run it — the relay at the
// push and at every reading of a stored directory, this client before it
// sends one — before the signature is checked, since a length is checked
// before anything is decoded. Without it a registered identity could push a
// directory padded with whitespace to MaxDocumentBytes and have the relay
// verify that padding whole on every post to the mailbox and on every
// administrator's page.
const MaxDirectoryBytes = 512 << 10

// MaxAllowlistBytes caps an allow list's document, the same rule for the
// smaller of the two. A list of MaxAllowlist fingerprints, measured the
// same way:
//
//	compact, times on UTC:         67,136 bytes
//	compact, times at +10:00:      67,141   <- the larger, for the same reason
//	the same, tab-indented:        70,156
//	the same, four spaces:         76,171
//
// with about 54 KiB above the widest of those for an encoder that indents
// further, and run in the same four places.
const MaxAllowlistBytes = 128 << 10

// MaxDocumentBytes caps the request body of the two owner-signed
// documents, the allow list and the channel directory, at
// PUT /v1/mailbox/{fp}/allow and PUT /v1/mailbox/{fp}/channels; the client
// holds a request to it before the PUT and the relay refuses one over it
// before a byte of the body is read. That is its whole role: the route's
// read cap, the envelope around the document rather than the document.
// What the documents themselves may be is MaxDirectoryBytes and
// MaxAllowlistBytes above, which carry the measurements; this cap sits
// above the larger of them with room for the base64 the request carries it
// in, 4/3 of the document plus the envelope — 568,030 bytes measured for a
// directory at every maximum and 89,642 for an allow list, and 699,170 and
// 174,882 for one padded to its own cap — so that a document at its own cap
// always fits in a request this cap admits.
const MaxDocumentBytes = 1 << 20

// MaxHeaderBytes caps a request's line and headers together on the relay
// and the proxy, and a response's headers at the client. The largest
// header this protocol carries is the auth header at MaxAuthHeader bytes,
// so the cap leaves two orders of magnitude for a later auth version and
// for whatever a proxy in front of a client adds; net/http answers 431
// before any handler for a request over it.
const MaxHeaderBytes = 32 << 10

// MsgBodyTooLarge begins the 413 for a body over its route's cap; the
// sentence names the cap in bytes.
const MsgBodyTooLarge = "request body larger than this route takes"

// MaxBytesCeiling is the largest max_bytes a relay will accept. Beyond it,
// max_bytes plus FramingAllowance overflows int64 and http.MaxBytesReader,
// handed a negative limit, refuses every body.
const MaxBytesCeiling int64 = 1 << 30

// Message kinds. An envelope travels inline in a list response; a stream is
// fetched from its own endpoint, because it may be larger than memory. A
// knock is an envelope posted to the knock route: a stranger's one
// message to a mailbox whose card says knocks, past no allow list, listed
// by its own word so a receiver can file it as a knock before opening it.
// A client refuses a fourth word by name.
const (
	KindEnvelope = "envelope"
	KindStream   = "stream"
	KindKnock    = "knock"
)

// MsgNoKnocks is the 403 a knock meets at a mailbox that takes none: no
// card, a card that says no, or a card that no longer verifies, in one
// sentence, since the state of somebody else's card is not a stranger's
// to learn. auu knock tells it apart to say what the other person can run.
const MsgNoKnocks = "the recipient does not take knocks"

// MsgKnocksWaiting is the 429 a knock meets when the mailbox already
// holds as many knocks as the relay lets one hold. It carries no
// Retry-After: the relay cannot say when the recipient will fetch or
// remove them, and a client treats a 429 without one as final.
const MsgKnocksWaiting = "the recipient has as many knocks waiting as this relay allows (max_knocks_waiting)"

// UploadOffsetHeader is the header an upload attempt carries, saying where
// in the stream its body begins, and the header a 409 carries back, saying
// where the relay's copy ends. The name follows the tus convention, which
// is what anybody implementing a second client will expect.
const UploadOffsetHeader = "Upload-Offset"

// A stream is one request per attempt. The sender opens an upload, which
// charges the quota and answers an id, and then PUTs the sealed bytes from
// an offset to the end in one request with Content-Length equal to what is
// left; when the last byte lands the relay places the message and answers
// its id. An attempt that stops short keeps its bytes only when the relay
// holds at least ResumeThreshold of the stream in all and the attempt was
// the first: then the partial lives ResumeWindow, for one resumed attempt
// from where it ends; a resumed attempt that stops short, or a first one
// that stops under the threshold, leaves nothing, and the sender opens
// again from zero. So the relay never keeps less than a threshold's worth
// for an upload that did not complete, a message is placed by at most two
// attempts on one id, and a sender that trickles bytes buys nothing.
const (
	// ResumeWindow is how long a kept partial lives, from the moment it is
	// kept, and how long an opened upload waits for its first byte; the
	// edge is inclusive, a resume at exactly the window is taken.
	ResumeWindow = 60 * time.Second
	// ResumeWindowSeconds is ResumeWindow as the open answer carries it.
	ResumeWindowSeconds int64 = 60
)

// The sentences of an attempt refused by its length, as the relay's error
// text begins; a client tells them apart by the status.
const (
	// MsgLengthRequired is the 411 for an attempt with no Content-Length:
	// an attempt runs to the end, and the relay must be told where that is.
	MsgLengthRequired = "an upload attempt must carry Content-Length; a chunked body cannot be judged before it is read"
	// MsgNotToTheEnd is the 400 for an attempt whose offset and length do
	// not reach the stream's size.
	MsgNotToTheEnd = "an upload attempt runs from its offset to the end of the stream"
)

// Stream wire types.
type (
	// OpenStreamRequest declares how many bytes are coming. The relay reserves
	// that much quota before a byte is uploaded, so a stream that cannot fit
	// is refused before the work rather than after it.
	OpenStreamRequest struct {
		Size int64 `json:"size"`
		// Channel is the recipient's channel the stream is for, checked at
		// open exactly as an envelope's is at post. Absent means default.
		Channel string `json:"channel,omitempty"`
	}
	OpenStreamResponse struct {
		Upload  string    `json:"upload"`
		Expires time.Time `json:"expires"`
		// ResumeThreshold is the least the relay must hold of the stream,
		// in bytes, for a first attempt that stops short to be kept for a
		// resume: the relay's max_bytes.
		ResumeThreshold int64 `json:"resume_threshold"`
		// ResumeWindow is how long a kept partial lives, in seconds, and
		// how long this upload waits for its first byte.
		ResumeWindow int64 `json:"resume_window"`
	}
	// PutStreamResponse is the 201 that ends an attempt which reached the
	// end: the message's id in the recipient's mailbox.
	PutStreamResponse struct {
		ID int64 `json:"id"`
	}
)

// The 507 messages. They are constants because the client tells them apart
// to decide who it should be advising: the recipient, the operator of the
// relay it posted to, or nobody, since a queue that is full empties itself.
const (
	MsgMailboxFull = "recipient's mailbox is full"
	MsgRelayFull   = "relay storage is full"
	// MsgQueueFull is the 507 for mail this relay would have to carry to a
	// neighbour and has no room to hold. It is not the recipient's mailbox
	// and not this relay's storage: it is the queue between them, which
	// drains by itself as the neighbour takes what is waiting, so the
	// advice is to send it again later and to tell nobody.
	MsgQueueFull = "this relay's forwarding queue is full"
	// MsgCarriedFull is the 507 for a relay holding as many envelope
	// hashes as its carried_max_rows allows. The table is what makes a
	// retry idempotent and a loop die, so a row is never evicted to make
	// room for another: the relay refuses to carry anything new until the
	// oldest hashes expire, and says which setting it is.
	MsgCarriedFull = "this relay is already carrying as many messages as carried_max_rows allows"
)

// MsgAlreadyCarried is the 409 for an envelope this relay has already taken.
//
// It is the answer to a retry after a lost answer and to a loop arriving
// back where it started, and a courier reads it as the envelope having been
// handed over, because in both cases it has. Nothing is stored and no
// mailbox is charged.
const MsgAlreadyCarried = "already carried"

// MsgNoNeighbour is the phrase in the 404 for a path whose first name is not
// a relay this one can dial: the sentence names the name. A sender reads it
// as the address being wrong at that hop rather than as the recipient being
// unknown, and it is the only discovery of a relay's neighbours there is.
const MsgNoNeighbour = "no neighbour named"

// MsgForwardsNothing is the 403 for a forward request to a relay with no
// courier configuration at all, which is every relay until its operator
// peers it with another.
const MsgForwardsNothing = "this relay forwards nothing"

// MsgViaIsACouriers is the 400 for a user sending via, which would be a
// sender writing their own return path.
const MsgViaIsACouriers = "via is a courier's to write"

// MsgPathNamesARelay is the 400 for a user sending an empty path: a
// recipient on this relay takes a post to their mailbox, and a path is for
// one who is not.
const MsgPathNamesARelay = "a path names at least one relay; a recipient on this relay takes a post to their mailbox"

// MsgAddressRepeats is the phrase in the 400 for an address naming one relay
// twice, across the path and the hops so far together: the sentence names
// the name. With relative names this is conservative — two different hosts
// may share a name at different hops — and that is the right trade, since
// the sender cannot tell the two cases apart either.
const MsgAddressRepeats = "every relay in an address is named once"

// MsgChannelClosed is the phrase in the 403 for a post to a channel outside
// its period: the sentence is `channel "cfp" is not open: opens
// 2026-10-01T00:00:00Z`, the name first, then this, then the period from
// channels.OpenAt. The client tells it by the phrase from the other 403s a
// post can meet, and prints the time in local form.
const MsgChannelClosed = "is not open"

// MsgNoDirectory is the 404 for a mailbox whose owner has pushed no channel
// directory, which has the one channel, default. The client tells it from
// the 404 for a mailbox that is not there.
const MsgNoDirectory = "no directory: the mailbox has the one channel, default"

// MsgStorageError is the 500 the relay answers when a file or the database
// failed it: nothing the client can do would help, and the cause is in the
// relay's log. The client tells it from the relay's other 500s to say whose
// problem it is.
const MsgStorageError = "storage error"

// MsgWaitingWillNotHelp appears in a 429 whose cause is the size of this one
// request rather than the rate of them: one message larger than a sender's
// whole budget for the period will be refused just as firmly in an hour. Both
// sides share the phrase so the client can tell that kind of refusal from an
// ordinary rate limit and stop, rather than sleeping its way through three
// attempts to find out what the relay already said.
const MsgWaitingWillNotHelp = "waiting will not help"

// Auth is a parsed X-CCX-Auth header.
type Auth struct {
	FP    string
	TS    int64
	Nonce string
	Sig   []byte
}

// SigningString builds the exact bytes covered by a request signature. Both the
// client and the relay derive it the same way; if they ever disagree, requests
// fail closed with a 401.
func SigningString(method, pathWithQuery string, ts int64, nonceB64 string, body []byte) []byte {
	sum := sha256.Sum256(body)
	var b strings.Builder
	b.WriteString(httpDomain)
	b.WriteByte('\n')
	b.WriteString(strings.ToUpper(method))
	b.WriteByte('\n')
	b.WriteString(pathWithQuery)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(ts, 10))
	b.WriteByte('\n')
	b.WriteString(nonceB64)
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(sum[:]))
	return []byte(b.String())
}

// SignRequest stamps req with an auth header covering body.
func SignRequest(id *identity.Identity, req *http.Request, body []byte) error {
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	ts := time.Now().Unix()
	sig, err := id.Sign(SigningString(req.Method, req.URL.RequestURI(), ts, nonceB64, body))
	if err != nil {
		return err
	}
	req.Header.Set(AuthHeader, strings.Join([]string{
		authVersion,
		id.Fingerprint(),
		strconv.FormatInt(ts, 10),
		nonceB64,
		base64.StdEncoding.EncodeToString(sig),
	}, " "))
	return nil
}

// ParseAuth reads an auth header without checking anything cryptographic.
func ParseAuth(header string) (*Auth, error) {
	if len(header) > MaxAuthHeader {
		// Longer than the five fields and four spaces can be: not a
		// header of this shape, refused before a field is cut from it.
		return nil, errors.New("auth header longer than its shape allows")
	}
	fields := strings.Fields(header)
	if len(fields) != 5 {
		return nil, errors.New("malformed auth header")
	}
	if fields[0] != authVersion {
		return nil, fmt.Errorf("unsupported auth version %q", fields[0])
	}
	if !identity.ValidFingerprint(fields[1]) {
		return nil, errors.New("bad fingerprint in auth header")
	}
	ts, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, errors.New("bad timestamp in auth header")
	}
	nonce, err := base64.StdEncoding.DecodeString(fields[3])
	if err != nil || len(nonce) != nonceBytes {
		return nil, errors.New("bad nonce in auth header")
	}
	sig, err := base64.StdEncoding.DecodeString(fields[4])
	if err != nil {
		return nil, errors.New("bad signature in auth header")
	}
	return &Auth{FP: fields[1], TS: ts, Nonce: fields[3], Sig: sig}, nil
}

// FreshAt reports whether the request timestamp is inside the allowed window.
//
// The comparison is against the two edges of the window rather than against
// the absolute value of a difference. There is no correct abs over the whole
// range of a two's-complement integer: -MinInt64 is MinInt64, so a timestamp
// chosen to make the subtraction wrap stays negative after negation and
// compares as fresh. Nothing here subtracts.
func (a *Auth) FreshAt(now time.Time) bool {
	skew := int64(MaxSkew / time.Second)
	n := now.Unix()
	// n is a real clock reading, so these cannot overflow.
	return a.TS >= n-skew && a.TS <= n+skew
}

// Verify checks the signature against a peer's key.
func (a *Auth) Verify(pub *identity.Public, method, pathWithQuery string, body []byte) bool {
	return pub.Verify(SigningString(method, pathWithQuery, a.TS, a.Nonce, body), a.Sig)
}

// RequestPath returns the path-with-query used in the signature for a server
// side request, matching what the client signed.
func RequestPath(req *http.Request) string { return req.URL.RequestURI() }
