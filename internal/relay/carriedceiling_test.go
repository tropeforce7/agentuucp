package relay

// The carried ceiling counts the hashes still standing, and a refusal for
// it purges the expired ones and asks the store once more (G7).

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/ratelimit"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// carriedFreedLine is what the relay logs when a carried 507 purged
// expired hashes before asking again.
const carriedFreedLine = "expired carried hashes removed"

// carriedCounts is the carried table as it stands, and the rows whose
// window has not passed by the relay's clock.
func carriedCounts(t *testing.T, h *harness) (all, standing int64) {
	t.Helper()
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM carried`).Scan(&all); err != nil {
		t.Fatal(err)
	}
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM carried WHERE expires > ?`, h.clock.Now().Unix()).Scan(&standing); err != nil {
		t.Fatal(err)
	}
	return all, standing
}

// realisticCarriedLimits is what auu-relay resolves for carried_max_rows 64
// at the default max_hops 8 with neither share set: a sixteenth (4) and a
// quarter (16) raised to CarriedShareFloor(8), 30 each.
func realisticCarriedLimits() CourierLimits {
	l := DefaultCourierLimits()
	l.CarriedMaxRows = 64
	l.CarriedRowsPerPoster = CarriedShareFloor(l.MaxHops)
	l.CarriedRowsPerCourier = CarriedShareFloor(l.MaxHops)
	return l
}

// plantCarried writes n hashes expiring at expires straight into the
// carried table, as earlier traffic would have left them, without the
// requests that would bring the hundredth request's purge round.
func plantCarried(t *testing.T, h *harness, prefix string, n int, expires time.Time) {
	t.Helper()
	for i := range n {
		if _, err := h.store.db.Exec(`INSERT INTO carried (hash, expires) VALUES (?, ?)`,
			fmt.Sprintf("%s-%03d", prefix, i), expires.Unix()); err != nil {
			t.Fatal(err)
		}
	}
}

// hasCarried says whether the table still holds a hash.
func hasCarried(t *testing.T, h *harness, hash string) bool {
	t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM carried WHERE hash = ?`, hash).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// calledFrom says whether a function of this package whose name ends in
// name is on the caller's stack.
func calledFrom(name string) bool {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		if strings.HasSuffix(f.Function, "/internal/relay."+name) {
			return true
		}
		if !more {
			return false
		}
	}
}

// carriedRoute is one of the two routes that write a carried hash: a
// user's forward to a neighbour, which the store takes by Enqueue, and a
// neighbour's delivery to a mailbox here, which it takes by Put.
type carriedRoute struct {
	name string
	// send makes the i'th fresh request on the route.
	send func(h *harness, i int) (int, []byte)
	// share is the bucket the route's hash is charged to.
	share func(h *harness) int64
}

// carriedRouteHarness is a relay peered with bar that accepts alpha's
// courier, at a carried ceiling of max rows and shares large enough that
// nothing here meets them, with the two routes over it. It is peered's
// relay with the clock its own: purgeAhead, when not zero, is how far
// ahead of the harness clock the clock reads to the carried 507's purge,
// and only to it, which is the second turning between the store's count
// and the purge. The store's count and the request around it read the
// harness clock as it stands.
func carriedRouteHarness(t *testing.T, max int64, purgeAhead time.Duration) (*harness, []carriedRoute) {
	t.Helper()
	limits := DefaultCourierLimits()
	limits.CarriedMaxRows = max
	limits.CarriedRowsPerPoster = CarriedShareFloor(limits.MaxHops)
	limits.CarriedRowsPerCourier = CarriedShareFloor(limits.MaxHops)
	courier := neighbourID(t, "alpha")
	c, err := NewCourier(CourierConfig{
		Home:           courierHome(t, map[string]string{"bar": "http://127.0.0.1:1"}),
		AuthorizedFile: couriersFile(t, courier),
		PublicURL:      "https://mine.example",
	}, slogDiscard())
	if err != nil {
		t.Fatal(err)
	}
	clock := newTestClock()
	now := func() time.Time {
		if purgeAhead != 0 && calledFrom("(*Server).carriedFreed") {
			return clock.Now().Add(purgeAhead)
		}
		return clock.Now()
	}
	h := newHarness(t, Config{Courier: c, CourierLimits: limits, Limits: DefaultLimits(), Now: now})
	h.clock = clock
	quiet(t, h)
	h.enroll(courier)
	alice, bob := h.user(t, "alice"), h.user(t, "bob")
	far := h.fpOf(t, "far")
	shareOf := func(l func(h *harness) *ratelimit.Limiter, fp string) func(h *harness) int64 {
		return func(h *harness) int64 { return left(l(h), fp) }
	}
	return h, []carriedRoute{
		{
			name: "a user's forward (Enqueue)",
			send: func(h *harness, i int) (int, []byte) {
				status, _, body := h.forward(alice, request(sealedFor(far, fmt.Sprintf("fwd%d", i)), []string{"bar"}, nil))
				return status, body
			},
			share: shareOf(func(h *harness) *ratelimit.Limiter { return h.server.lim.carried }, alice.Fingerprint()),
		},
		{
			name: "a courier's delivery (Put)",
			send: func(h *harness, i int) (int, []byte) {
				status, _, body := h.forward(courier, request(sealedFor(bob.Fingerprint(), fmt.Sprintf("dlv%d", i)), nil, nil))
				return status, body
			},
			share: shareOf(func(h *harness) *ratelimit.Limiter { return h.server.lim.courierCarried }, courier.Fingerprint()),
		},
	}
}

// TestOnePosterAndOneCourierStayUnderARealisticCeiling re-runs F5's
// scenario at carried_max_rows 64 with the shares auu-relay derives: one
// user forwards on paths of one to three relays as fast as its share
// allows, every row handed at once, for three windows; then the neighbour's
// courier delivers as fast as its share allows. The purge is run at every
// step so that only the shares are under test. Neither reaches the ceiling
// alone, and each leaves the other room.
func TestOnePosterAndOneCourierStayUnderARealisticCeiling(t *testing.T) {
	limits := realisticCarriedLimits()
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	alice, bob, carol := h.user(t, "alice"), h.user(t, "bob"), h.user(t, "carol")
	far := h.fpOf(t, "far")
	paths := [][]string{{"bar"}, {"bar", "next"}, {"bar", "next", "last"}}

	n, peak := 0, int64(0)
	step := limits.ForwardTTL / 4
	for s := 0; s < 12; s++ {
		for {
			p := paths[n%len(paths)]
			status, answer, body := h.forward(alice, request(sealedFor(far, fmt.Sprintf("a%d", n)), p, nil))
			n++
			if status == http.StatusTooManyRequests {
				break
			}
			if status != http.StatusCreated {
				t.Fatalf("alice's forward %d: %d %s", n, status, body)
			}
			if err := h.store.Handed(answer.ID, int64(1000+n), h.clock.Now()); err != nil {
				t.Fatal(err)
			}
		}
		if err := h.store.PurgeCarried(h.clock.Now()); err != nil {
			t.Fatal(err)
		}
		_, standing := carriedCounts(t, h)
		peak = max(peak, standing)
		h.clock.advance(step)
	}
	t.Logf("alice: peak standing %d hashes, share %d, ceiling %d", peak, limits.CarriedRowsPerPoster, limits.CarriedMaxRows)
	if peak > limits.CarriedRowsPerPoster {
		t.Errorf("one poster stood at %d hashes, over its share of %d", peak, limits.CarriedRowsPerPoster)
	}
	if status, _, body := h.forward(courier, request(sealedFor(bob.Fingerprint(), "from-afar"), nil, nil)); status != http.StatusCreated {
		t.Fatalf("after alice spent all she could, a courier's delivery: %d %s", status, body)
	}
	delivered := 1
	for {
		status, _, body := h.forward(courier, request(sealedFor(bob.Fingerprint(), fmt.Sprintf("c%d", delivered)), nil, nil))
		if status == http.StatusTooManyRequests {
			break
		}
		if status != http.StatusCreated {
			t.Fatalf("courier delivery %d: %d %s", delivered, status, body)
		}
		delivered++
	}
	all, standing := carriedCounts(t, h)
	t.Logf("courier delivered %d before its share refused; table %d rows, %d standing", delivered, all, standing)
	if status, _, body := h.forward(carol, request(sealedFor(far, "carol"), []string{"bar"}, nil)); status != http.StatusCreated {
		t.Errorf("after one poster and one courier spent their shares, a third party's forward: %d %s", status, body)
	}
}

// TestExpiredCarriedHashesDoNotFillTheCeiling: the ceiling counted every
// row of the carried table, expired ones included, and the table is purged
// only on every hundredth request, while the share's bucket refills by the
// clock as each hash's window passes. So on a relay that sees fewer than a
// hundred requests, one poster who never had more than its bucket standing
// filled the relay-wide ceiling with hashes whose windows had passed, and a
// neighbour's delivery was refused 507 "carried_max_rows". Now the ceiling
// counts the hashes standing, and the delivery is taken.
func TestExpiredCarriedHashesDoNotFillTheCeiling(t *testing.T) {
	limits := realisticCarriedLimits()
	courier := neighbourID(t, "alpha")
	h := peered(t, []string{"bar"}, []*identity.Identity{courier}, &limits)
	h.enroll(courier)
	alice, bob := h.user(t, "alice"), h.user(t, "bob")
	far := h.fpOf(t, "far")
	burst := limits.carriedBurst(limits.CarriedRowsPerPoster)

	n := 0
	for window := int64(0); window*burst < limits.CarriedMaxRows; window++ {
		for range burst {
			status, answer, body := h.forward(alice, request(sealedFor(far, fmt.Sprintf("q%d", n)), []string{"bar"}, nil))
			n++
			if status != http.StatusCreated {
				t.Fatalf("window %d, forward %d: %d %s", window, n, status, body)
			}
			if err := h.store.Handed(answer.ID, int64(2000+n), h.clock.Now()); err != nil {
				t.Fatal(err)
			}
		}
		h.clock.advance(limits.CarriedWindow(0) + time.Second)
	}
	all, standing := carriedCounts(t, h)
	t.Logf("alice forwarded %d one-hop envelopes, %d at a time a window apart; table %d rows, %d standing; %d requests served",
		n, burst, all, standing, h.server.requests.Load())
	status, _, body := h.forward(courier, request(sealedFor(bob.Fingerprint(), "from-afar"), nil, nil))
	t.Logf("a courier's delivery to bob: %d %s", status, body)
	if status == http.StatusInsufficientStorage {
		t.Errorf("one poster with %d hashes standing (share %d) has the relay refuse a neighbour's delivery at carried_max_rows %d: "+
			"the ceiling counts %d hashes whose window has passed", standing, limits.CarriedRowsPerPoster, limits.CarriedMaxRows, all-standing)
	}
}

// TestAHashStandsUntilTheSecondOfItsExpiry: the ceiling counts a hash while
// now < expires and the purge removes it once expires <= now, so the two
// agree at the edge: a second before its expiry it counts, and at its
// expiry it neither counts nor stays. With carried_max_rows - 1 other
// hashes standing beside it, the route is refused 507 a second before and
// taken at the second itself, and taken by the count, not by the purge:
// nothing is said in the log and the hash is still in the table until a
// purge at that second removes it, and it alone.
func TestAHashStandsUntilTheSecondOfItsExpiry(t *testing.T) {
	const ceiling = 4
	for i, route := range []string{"a user's forward (Enqueue)", "a courier's delivery (Put)"} {
		t.Run(route, func(t *testing.T) {
			h, routes := carriedRouteHarness(t, ceiling, 0)
			r := routes[i]
			start := h.clock.Now()
			expiry := start.Add(time.Hour)
			plantCarried(t, h, "standing", ceiling-1, start.Add(30*24*time.Hour))
			plantCarried(t, h, "edge", 1, expiry)

			h.clock.advance(time.Hour - time.Second)
			if n, err := h.store.purgeCarried(h.clock.Now()); err != nil || n != 0 {
				t.Fatalf("a purge a second before the edge removed %d (%v); want none", n, err)
			}
			status, body := r.send(h, 0)
			if status != http.StatusInsufficientStorage || errorText(t, body) != relayapi.MsgCarriedFull {
				t.Fatalf("a second before its expiry, with %d others standing: %d %s; want 507 %q",
					ceiling-1, status, body, relayapi.MsgCarriedFull)
			}
			if !hasCarried(t, h, "edge-000") {
				t.Fatal("a second before its expiry the hash was purged")
			}

			h.clock.advance(time.Second)
			if !h.clock.Now().Equal(expiry) {
				t.Fatalf("the clock is at %v; want the expiry %v", h.clock.Now(), expiry)
			}
			mark := len(h.logs.String())
			if status, body := r.send(h, 1); status != http.StatusCreated {
				t.Fatalf("at its expiry, with %d others standing: %d %s; want 201", ceiling-1, status, body)
			}
			if since := h.logs.String()[mark:]; strings.Contains(since, carriedFreedLine) {
				t.Errorf("at its expiry the route was taken by the purge, not by the count:\n%s", since)
			}
			if !hasCarried(t, h, "edge-000") {
				t.Fatal("at its expiry the hash was purged by the request; the count should have passed it over")
			}
			if all, standing := carriedCounts(t, h); all != ceiling+1 || standing != ceiling {
				t.Fatalf("table %d rows, %d standing; want %d and %d", all, standing, ceiling+1, ceiling)
			}
			if n, err := h.store.purgeCarried(expiry); err != nil || n != 1 {
				t.Fatalf("a purge at the expiry removed %d (%v); want the one hash", n, err)
			}
			if hasCarried(t, h, "edge-000") {
				t.Error("a purge at its expiry kept the hash")
			}
		})
	}
}

// TestTheCarriedCeilingAtItsEdges: at carried_max_rows - 1 standing the
// route is taken, and at carried_max_rows standing, with nothing expired
// for the purge to let go, it is refused 507 in the setting's words.
func TestTheCarriedCeilingAtItsEdges(t *testing.T) {
	const ceiling = 4
	for i, route := range []string{"a user's forward (Enqueue)", "a courier's delivery (Put)"} {
		t.Run(route, func(t *testing.T) {
			h, routes := carriedRouteHarness(t, ceiling, 0)
			r := routes[i]
			plantCarried(t, h, "standing", ceiling-1, h.clock.Now().Add(time.Hour))
			if status, body := r.send(h, 0); status != http.StatusCreated {
				t.Fatalf("at carried_max_rows - 1 standing: %d %s; want 201", status, body)
			}
			if _, standing := carriedCounts(t, h); standing != ceiling {
				t.Fatalf("%d standing after the taken request; want %d", standing, ceiling)
			}
			status, body := r.send(h, 1)
			if status != http.StatusInsufficientStorage || errorText(t, body) != relayapi.MsgCarriedFull {
				t.Fatalf("at carried_max_rows standing: %d %s; want 507 %q", status, body, relayapi.MsgCarriedFull)
			}
		})
	}
}

// TestATableAtTheCeilingOfExpiredHashesTakesTheNext: with the table at
// the ceiling and every hash in it expired but not yet purged, each route
// is taken on the store's first answer, since the count passes the expired
// hashes over: no purge is said, the expired hashes wait for housekeeping,
// and the share is spent once.
func TestATableAtTheCeilingOfExpiredHashesTakesTheNext(t *testing.T) {
	const ceiling = 4
	for i, route := range []string{"a user's forward (Enqueue)", "a courier's delivery (Put)"} {
		t.Run(route, func(t *testing.T) {
			h, routes := carriedRouteHarness(t, ceiling, 0)
			r := routes[i]
			plantCarried(t, h, "expired", ceiling, h.clock.Now().Add(-time.Minute))
			before, mark := r.share(h), len(h.logs.String())
			if status, body := r.send(h, 0); status != http.StatusCreated {
				t.Fatalf("at the ceiling, all of it expired: %d %s; want 201", status, body)
			}
			if since := h.logs.String()[mark:]; strings.Contains(since, carriedFreedLine) {
				t.Errorf("the route was taken by the purge, not by the count:\n%s", since)
			}
			if all, standing := carriedCounts(t, h); all != ceiling+1 || standing != 1 {
				t.Errorf("table %d rows, %d standing; want %d and the new hash alone", all, standing, ceiling+1)
			}
			if spent := before - r.share(h); spent != 1 {
				t.Errorf("the taken request spent %d of the share; want 1", spent)
			}
		})
	}
}

// TestACarriedRefusalPurgesWhatExpiredAndAsksAgain: the store counts by
// the clock it was given and the purge after its refusal by the clock
// then, so a hash standing to the count may have expired by the purge.
// With the table at the ceiling of hashes that expire in the second
// between, each route is refused by the store, purges, says how many went,
// asks again and is taken, its share spent once.
func TestACarriedRefusalPurgesWhatExpiredAndAsksAgain(t *testing.T) {
	const ceiling = 4
	for i, route := range []string{"a user's forward (Enqueue)", "a courier's delivery (Put)"} {
		t.Run(route, func(t *testing.T) {
			h, routes := carriedRouteHarness(t, ceiling, time.Second)
			r := routes[i]
			// Standing at the store's count, gone at the purge's second.
			plantCarried(t, h, "turning", ceiling, h.clock.Now().Add(time.Second))
			if _, standing := carriedCounts(t, h); standing != ceiling {
				t.Fatalf("%d standing before the request; want the ceiling, %d", standing, ceiling)
			}
			before, mark := r.share(h), len(h.logs.String())
			if status, body := r.send(h, 0); status != http.StatusCreated {
				t.Fatalf("at the ceiling, all of it expiring before the purge: %d %s; want 201", status, body)
			}
			want := fmt.Sprintf("msg=%q count=%d", carriedFreedLine, ceiling)
			if since := h.logs.String()[mark:]; !strings.Contains(since, want) {
				t.Errorf("the log after the purge does not say %s:\n%s", want, since)
			}
			if all, standing := carriedCounts(t, h); all != 1 || standing != 1 {
				t.Errorf("table %d rows, %d standing; want the new hash alone", all, standing)
			}
			if spent := before - r.share(h); spent != 1 {
				t.Errorf("the taken request spent %d of the share; want 1", spent)
			}
		})
	}
}

// TestACarriedRefusalWithNothingExpiredGivesTheShareBack: with the table
// at the ceiling and nothing in it expired, the purge lets nothing go, the
// store is not asked again, and each route is refused 507 in the setting's
// words, with no purge line in the log, nothing stored and the carried
// share given back.
func TestACarriedRefusalWithNothingExpiredGivesTheShareBack(t *testing.T) {
	const ceiling = 4
	for i, route := range []string{"a user's forward (Enqueue)", "a courier's delivery (Put)"} {
		t.Run(route, func(t *testing.T) {
			h, routes := carriedRouteHarness(t, ceiling, 0)
			r := routes[i]
			plantCarried(t, h, "standing", ceiling, h.clock.Now().Add(time.Hour))
			before, rows, mark := r.share(h), h.tableCounts(t), len(h.logs.String())
			status, body := r.send(h, 0)
			if status != http.StatusInsufficientStorage || errorText(t, body) != relayapi.MsgCarriedFull {
				t.Fatalf("at the ceiling, nothing expired: %d %s; want 507 %q", status, body, relayapi.MsgCarriedFull)
			}
			if since := h.logs.String()[mark:]; strings.Contains(since, carriedFreedLine) {
				t.Errorf("a purge that let nothing go was logged:\n%s", since)
			}
			if after := r.share(h); after != before {
				t.Errorf("the refused request kept %d of the share", before-after)
			}
			if after := h.tableCounts(t); after != rows {
				t.Errorf("the refused request stored something: before %+v, after %+v", rows, after)
			}
		})
	}
}
