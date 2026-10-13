package channels

// Review D: the relay's request check, FreshAt, compares whole seconds
// (a.TS = owner.Unix(), n = relay.Unix()), while CheckIssued compared the
// document's issued, stamped time.Now() with nanoseconds, against
// relay.now + MaxSkew. An owner 300.9 s ahead had every request accepted
// and its directory, issued at its own now, refused 400 "ahead of now".
// The two edges of "the skew a relay allows" disagreed by up to a second
// (G13). Both are now judged in whole seconds, by relayapi.Ahead at MaxSkew.

import (
	"errors"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/allowlist"
	"github.com/tropeforce7/agentuucp/internal/card"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

func TestTheRequestSkewAndTheIssuedSkewAgree(t *testing.T) {
	relayNow := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	ownerNow := relayNow.Add(relayapi.MaxSkew + 900*time.Millisecond)
	a := relayapi.Auth{TS: ownerNow.Unix()}
	fresh := a.FreshAt(relayNow)
	err := CheckIssued(&Directory{Issued: ownerNow, Channels: []Channel{{Name: Default}}}, relayNow)
	if fresh && err != nil {
		t.Errorf("the relay accepts the owner's request (FreshAt) and refuses the directory it carries: %v", err)
	}

	// Every owner document the relay holds to the skew, at the edge, 0.9 s
	// past it and one second past it. With now 50 ms into its second, 0.9 s
	// past the edge is 0.85 s past now+MaxSkew, which a nanosecond bound
	// refused, and still in the second FreshAt takes a request stamped in.
	checks := []struct {
		doc   string
		check func(issued, now time.Time) error
	}{
		{"allow list", func(issued, now time.Time) error {
			return allowlist.CheckIssued(&allowlist.Document{Issued: issued}, now)
		}},
		{"channel directory", func(issued, now time.Time) error {
			return CheckIssued(&Directory{Issued: issued, Channels: []Channel{{Name: Default}}}, now)
		}},
		{"card", func(issued, now time.Time) error {
			return card.CheckIssued(&card.Document{Issued: issued}, now)
		}},
	}
	for _, now := range []time.Time{
		time.Date(2026, 10, 11, 12, 0, 0, 50*int(time.Millisecond), time.UTC),
		time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC),
	} {
		// The edge is the last instant of the Unix second now+MaxSkew
		// falls in, as FreshAt reads a request stamped in that second.
		edge := time.Unix(now.Unix()+int64(relayapi.MaxSkew/time.Second), 0).UTC()
		for _, r := range []struct {
			name   string
			issued time.Time
			taken  bool
		}{
			{"exactly now+MaxSkew", now.Add(relayapi.MaxSkew), true},
			{"0.9 s past the edge, the same second", edge.Add(900 * time.Millisecond), true},
			{"one second past the edge", edge.Add(time.Second), false},
		} {
			// The request stamped at the same instant is the witness: the
			// document is taken exactly when that request is fresh.
			fresh := (&relayapi.Auth{TS: r.issued.Unix()}).FreshAt(now)
			if fresh != r.taken {
				t.Fatalf("%s, now %s: FreshAt %v, the row says %v", r.name, now.Format(time.RFC3339Nano), fresh, r.taken)
			}
			for _, c := range checks {
				err := c.check(r.issued, now)
				switch {
				case r.taken && err != nil:
					t.Errorf("%s %s, now %s: the request is fresh and the document refused: %v",
						c.doc, r.name, now.Format(time.RFC3339Nano), err)
				case !r.taken && err == nil:
					t.Errorf("%s %s, now %s: the request is stale and the document taken",
						c.doc, r.name, now.Format(time.RFC3339Nano))
				case !r.taken && !errors.Is(err, relayapi.ErrAheadOfNow):
					t.Errorf("%s %s: refused, but not as ahead of now: %v", c.doc, r.name, err)
				}
			}
		}
	}
}
