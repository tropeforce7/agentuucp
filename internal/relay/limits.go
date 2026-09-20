package relay

import (
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/tropeforce7/agentuucp/internal/ratelimit"
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
		MaxInflight:              256,
		MaxWaiting:               64,
	}
}

// Quotas extracts the storage limits the store enforces.
func (l Limits) Quotas() Quotas {
	return Quotas{
		MailboxMaxMessages: l.MailboxMaxMessages,
		MailboxMaxBytes:    l.MailboxMaxBytes,
		RelayMaxBytes:      l.RelayMaxBytes,
		MaxOpenUploads:     l.MaxOpenUploads,
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
	limitRequests        = "requests"
	limitPosts           = "posts"
	limitPostBytes       = "post bytes"
	limitUnauthenticated = "unauthenticated"
	limitRegistrations   = "registrations"
	limitInflight        = "inflight"
	limitMailboxFull     = "mailbox"
	limitRelayFull       = "relay storage"
	limitOpenUploads     = "open uploads"
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
	unauthenticated *ratelimit.Limiter // keyed by source address
	registrations   *ratelimit.Limiter // keyed by source address
}

func newLimiters(l Limits, now func() time.Time) limiters {
	return limiters{
		requests:        ratelimit.New(l.RequestsPerMinute, time.Minute, time.Minute, now),
		posts:           ratelimit.New(l.PostsPerMinute, time.Minute, time.Minute, now),
		postBytes:       ratelimit.New(l.PostBytesPerHour, time.Hour, time.Hour, now),
		unauthenticated: ratelimit.New(l.UnauthenticatedPerMinute, time.Minute, time.Minute, now),
		registrations:   ratelimit.New(l.RegistrationsPerHour, time.Hour, time.Hour, now),
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
