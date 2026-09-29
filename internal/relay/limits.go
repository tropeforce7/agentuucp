package relay

import (
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/tropeforce7/agentuucp/internal/ratelimit"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// Limits is the relay's rate limit and quota policy.
//
// Zero means unlimited for every numeric field, so the zero value is a relay
// that behaves exactly as it did before any of this existed. DefaultLimits is
// what auu-relay starts from.
type Limits struct {
	// Per verified identity.
	RequestsPerMinute int64
	PostsPerMinute    int64
	PostBytesPerHour  int64

	// Per source address, for callers who have not proved who they are.
	UnauthenticatedPerMinute int64
	RegistrationsPerHour     int64

	// Storage.
	MaxMailboxes       int64
	MailboxMaxMessages int64
	MailboxMaxBytes    int64
	RelayMaxBytes      int64
	// MaxOpenUploads caps the uploads one sender may have open at once,
	// across every mailbox it sends to: an upload is open from its 201
	// until it is placed, aborted or purged, and each is a file and a
	// reservation the relay holds for the sender. Over it an open is
	// answered 429 with a Retry-After of the seconds to the sender's
	// soonest expiry.
	MaxOpenUploads int64

	// KnockMaxBytes caps one knock envelope on the knock route, a stranger's
	// one message; zero means MaxBytes, the post's cap, since zero is
	// unlimited everywhere and a knock is a post. auu-relay holds it to
	// MaxBytes at the config's read.
	KnockMaxBytes int64
	// MaxKnocksWaiting caps the knockers one mailbox holds a knock from,
	// rows the relay has whatever the owner has read: one knocker holds
	// one row however often they knock, since a second knock from a key
	// replaces the first, so this is a count of knockers and no single
	// identity can fill it. A knock from a knocker the mailbox does not
	// already hold one from is refused 429 at it, without a Retry-After,
	// since the relay cannot say when the owner will fetch or remove
	// them. Zero is unlimited; auu-relay holds it to 1000, for the
	// reason MaxOpenUploads has a ceiling.
	MaxKnocksWaiting int64
	// KnocksPerHour caps the knocks one sender may post in an hour across
	// every mailbox, keyed by the verified fingerprint like every other
	// per-identity limit. Zero is unlimited.
	KnocksPerHour int64

	// MaxInflight caps requests being handled at once.
	MaxInflight int64
	// MaxWaiting caps listings held open at once across the relay. Over
	// it a listing that asked to be held is answered at once instead, so
	// the cap degrades the hold and never refuses a request. A held
	// listing keeps its in-flight slot for as long as it is held, so this
	// must sit well under MaxInflight.
	MaxWaiting int64
}

// DefaultLimits is the policy a relay on the open internet should start with:
// generous enough that no honest agent notices, tight enough that one identity
// or one address cannot take the relay away from everybody else.
func DefaultLimits() Limits {
	return Limits{
		RequestsPerMinute:        120,
		PostsPerMinute:           30,
		PostBytesPerHour:         256 << 20,
		UnauthenticatedPerMinute: 30,
		RegistrationsPerHour:     5,
		MaxMailboxes:             0,
		MailboxMaxMessages:       1000,
		MailboxMaxBytes:          1 << 30,
		RelayMaxBytes:            0,
		MaxOpenUploads:           4,
		KnockMaxBytes:            8192,
		MaxKnocksWaiting:         10,
		KnocksPerHour:            10,
		MaxInflight:              256,
		MaxWaiting:               64,
	}
}

// CourierLimits is what a relay's forwarding is bounded by: how far an
// address may reach, how long the relay keeps trying, how much it will hold
// for whom, and what a courier may spend.
//
// Zero is unlimited for every field that has an honest zero, as everywhere
// else. MaxHops and ForwardTTL have none — an address of no relays and a
// queue that gives up at once are not policies anybody wants — and
// auu-relay refuses a zero for either.
type CourierLimits struct {
	// MaxHops caps the relays one address may name, the path and the hops
	// so far together, at most relayapi.MaxHops.
	MaxHops int64
	// ForwardTTL is how long a row waits before the relay gives up on it.
	ForwardTTL time.Duration
	// QueueMaxBytes caps the bytes waiting to leave across the relay.
	QueueMaxBytes int64
	// QueueMaxMessages caps the rows waiting for one poster, and
	// QueueMaxBytesPerPoster their bytes. Neither applies to a courier: a
	// courier carries many people's mail, so one poster's share would
	// refuse a neighbour's queue for being busy, and the relay-wide bound
	// and the couriers file are what answer that instead.
	QueueMaxMessages       int64
	QueueMaxBytesPerPoster int64
	// PostsPerMinute and PostBytesPerHour are a courier's budgets, in
	// place of a user's on the forward route, keyed by the verified
	// fingerprint as every per-identity limit is.
	PostsPerMinute   int64
	PostBytesPerHour int64
	// CarriedMaxRows caps the envelope hashes this relay holds. A hash is
	// never evicted to make room, since the table is what makes a retry
	// idempotent and a loop die, so at the ceiling the relay refuses to
	// carry anything new until the oldest expire.
	CarriedMaxRows int64
}

// DefaultCourierLimits is the policy a relay peered with another should
// start with. Every number here is a guess to be corrected by running two
// relays, and the container suite is where that happens.
func DefaultCourierLimits() CourierLimits {
	return CourierLimits{
		MaxHops:                8,
		ForwardTTL:             72 * time.Hour,
		QueueMaxBytes:          1 << 30,
		QueueMaxMessages:       100,
		QueueMaxBytesPerPoster: 256 << 20,
		PostsPerMinute:         600,
		// Unlimited by default: a courier carries many people's mail, and
		// the relay-wide queue cap and the couriers file are the bounds
		// that suit that. A relay whose neighbour floods it removes one
		// line.
		PostBytesPerHour: 0,
		CarriedMaxRows:   1_000_000,
	}
}

// Quotas extracts what the queue and the carried table are bounded by.
func (c CourierLimits) Quotas() CourierQuotas {
	return CourierQuotas{
		QueueMaxBytes:          c.QueueMaxBytes,
		QueueMaxMessages:       c.QueueMaxMessages,
		QueueMaxBytesPerPoster: c.QueueMaxBytesPerPoster,
		CarriedMaxRows:         c.CarriedMaxRows,
	}
}

// CourierQuotasFor is a courier's own quotas: the relay-wide bounds alone,
// for the reason on QueueMaxMessages.
func (c CourierLimits) CourierQuotasFor() CourierQuotas {
	return CourierQuotas{
		QueueMaxBytes:  c.QueueMaxBytes,
		CarriedMaxRows: c.CarriedMaxRows,
	}
}

// CarriedWindow is how long a hash is kept for an envelope with hops still
// ahead of it: the life it can have in the network from here, which is the
// hops it has left plus this one, each of which may keep it for ForwardTTL.
//
// Sizing it by the whole network's worst case instead — MaxHops times
// ForwardTTL — would keep every hash for weeks at the defaults and years at
// the ceilings, and hold the poster's fingerprint on a handed row for just
// as long. An envelope cannot outlive the hops that are left to carry it.
func (c CourierLimits) CarriedWindow(pathLeft int) time.Duration {
	// The ceiling is clamped both ways, as the route clamps it: a zero or a
	// nonsense MaxHops is the zero value of this struct, which an embedder
	// can hand over and auu-relay never does, and a window of zero would
	// mean every hash was purgeable the moment it was written — the loop
	// defence off, silently, because a setting was unset.
	hops := c.MaxHops
	if hops <= 0 || hops > relayapi.MaxHops {
		hops = relayapi.MaxHops
	}
	if left := int64(pathLeft) + 1; left < hops {
		hops = left
	}
	return time.Duration(hops) * c.ForwardTTL
}

// Quotas extracts the storage limits the store enforces.
func (l Limits) Quotas() Quotas {
	return Quotas{
		MailboxMaxMessages: l.MailboxMaxMessages,
		MailboxMaxBytes:    l.MailboxMaxBytes,
		RelayMaxBytes:      l.RelayMaxBytes,
		MaxOpenUploads:     l.MaxOpenUploads,
		MaxKnocksWaiting:   l.MaxKnocksWaiting,
	}
}

// Access log modes.
const (
	// AccessLogFull records the request path and the verified caller.
	AccessLogFull = "full"
	// AccessLogMinimal records the route instead of the path and omits the
	// caller. It is enough to operate the relay and to tell an attack from
	// traffic, and it keeps who-talks-to-whom out of the log file.
	AccessLogMinimal = "minimal"
)

// Names for the limits, used in both the error text and the access log so an
// operator reading a user's complaint knows which knob to turn.
const (
	limitRequests = "requests"
	limitPosts    = "posts"
	// limitCourierPosts is a courier's own pair on the forward route, so
	// that the limit= field on a refusal says which bound was reached and
	// an operator is not left reading a user's name for a neighbour's
	// rate.
	limitCourierPosts    = "courier_posts"
	limitPostBytes       = "post bytes"
	limitUnauthenticated = "unauthenticated"
	limitRegistrations   = "registrations"
	limitInflight        = "inflight"
	limitMailboxFull     = "mailbox"
	limitRelayFull       = "relay storage"
	limitOpenUploads     = "open uploads"
	// limitKnocks is the sender's knock budget, knocks_per_hour, refused
	// with a Retry-After; limitKnocksWaiting is the recipient's,
	// max_knocks_waiting, refused without one, since the relay cannot say
	// when the recipient will fetch.
	limitKnocks        = "knocks"
	limitKnocksWaiting = "knocks_waiting"
	// limitWaiting is logged on a listing that asked to be held and was
	// answered at once because a cap on holds was reached. The request
	// was not refused; the field says why a held request was not held.
	limitWaiting = "waiting"
)

// maxWaitingPerIdentity caps the listings one identity may have held at
// once: two machines of one identity may each hold one, and a third
// request from it is answered at once. It is a constant rather than a
// setting because it is about what one person could want, not about what
// one relay can bear.
const maxWaitingPerIdentity = 2

// limiters is the relay's set of token buckets.
//
// Each bucket's idle timeout is its own interval, which is exactly the point
// at which an untouched bucket has refilled to capacity. Evicting then is
// indistinguishable from keeping the entry, so bounding the memory costs no
// enforcement at all.
type limiters struct {
	requests        *ratelimit.Limiter // keyed by verified fingerprint
	posts           *ratelimit.Limiter // keyed by verified fingerprint
	postBytes       *ratelimit.Limiter // keyed by verified fingerprint
	knocks          *ratelimit.Limiter // keyed by verified fingerprint
	unauthenticated *ratelimit.Limiter // keyed by source address
	registrations   *ratelimit.Limiter // keyed by source address
	// A courier's budgets on the forward route, in place of a user's
	// posts and postBytes, keyed by the verified fingerprint as those
	// are. They are a different pair because a courier carries many
	// people's mail: held to one person's rate, a neighbour's whole queue
	// would be refused for being busy.
	courierPosts     *ratelimit.Limiter
	courierPostBytes *ratelimit.Limiter
}

func newLimiters(l Limits, c CourierLimits, now func() time.Time) limiters {
	return limiters{
		courierPosts:     ratelimit.New(c.PostsPerMinute, time.Minute, time.Minute, now),
		courierPostBytes: ratelimit.New(c.PostBytesPerHour, time.Hour, time.Hour, now),
		requests:         ratelimit.New(l.RequestsPerMinute, time.Minute, time.Minute, now),
		posts:            ratelimit.New(l.PostsPerMinute, time.Minute, time.Minute, now),
		postBytes:        ratelimit.New(l.PostBytesPerHour, time.Hour, time.Hour, now),
		knocks:           ratelimit.New(l.KnocksPerHour, time.Hour, time.Hour, now),
		unauthenticated:  ratelimit.New(l.UnauthenticatedPerMinute, time.Minute, time.Minute, now),
		registrations:    ratelimit.New(l.RegistrationsPerHour, time.Hour, time.Hour, now),
	}
}

// unknownAddress is the bucket key for a caller whose address cannot be
// parsed. Rate limiting must never fail a request over a bookkeeping problem,
// so such callers share one bucket rather than being refused.
const unknownAddress = "unknown"

// clientIP is the address a rate limit bucket is keyed by: the connection's
// own. The relay terminates TLS itself and nothing stands in front of it, so
// no X-Forwarded-For header is read; a client sending one changes nothing.
func (s *Server) clientIP(r *http.Request) string {
	remote := parseAddr(r.RemoteAddr)
	if !remote.IsValid() {
		return unknownAddress
	}
	return remote.String()
}

// parseAddr pulls an address out of a RemoteAddr, with or without a port.
func parseAddr(remoteAddr string) netip.Addr {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}
