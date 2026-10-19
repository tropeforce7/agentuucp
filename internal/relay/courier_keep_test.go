package relay

import (
	"context"
	"fmt"
	"net"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// connCount wraps a worker's real post with a trace that counts the
// connections its forwards went on, new and reused, and can close the
// connection under one post once it has been written whole.
type connCount struct {
	mu            sync.Mutex
	fresh, reused int
	posts         int
	// cutAfter, when not zero, is the post whose connection is closed once
	// its request is written: the neighbour reads it, and its answer never
	// comes back.
	cutAfter int
}

func (cc *connCount) wrap(w *workers) {
	w.post = func(ctx context.Context, c *client.Client, req *relayapi.ForwardRequest) (int64, error) {
		cc.mu.Lock()
		cc.posts++
		cut := cc.cutAfter != 0 && cc.posts == cc.cutAfter
		cc.mu.Unlock()
		var conn net.Conn
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(i httptrace.GotConnInfo) {
				cc.mu.Lock()
				if i.Reused {
					cc.reused++
				} else {
					cc.fresh++
				}
				cc.mu.Unlock()
				conn = i.Conn
			},
			WroteRequest: func(httptrace.WroteRequestInfo) {
				if cut && conn != nil {
					conn.Close()
				}
			},
		})
		return w.postToNeighbour(ctx, c, req)
	}
}

// queueFive posts five envelopes to A for the neighbour bar and returns
// their rows' ids.
func queueFive(t *testing.T, a *peerage) []int64 {
	t.Helper()
	sender := a.h.user(t, "alice")
	to := a.h.fpOf(t, "bob")
	var ids []int64
	for i := range 5 {
		status, answer, body := a.h.forward(sender, request(sealedFor(to, fmt.Sprintf("ct%d", i)), []string{"bar", "onward"}, nil))
		if status != 201 {
			t.Fatalf("the post to A: status %d: %s", status, body)
		}
		ids = append(ids, answer.ID)
	}
	return ids
}

// A courier draining a backlog to one neighbour makes one connection, one
// post-quantum handshake with its certificate, and sends every row's
// forward on it: the forward is a request net/http cannot send again, so
// the courier keeps its connection for it, and the neighbour keeps the
// connection behind each answer. It made one a row.
func TestACourierBacklogTakesOneHandshake(t *testing.T) {
	b := peered(t, []string{"onward"}, nil, nil)
	a := peer(t, b, "bar", "alpha", DefaultCourierLimits())
	ids := queueFive(t, a)

	w := worker(t, a.h)
	var cc connCount
	cc.wrap(w)
	w.drainOnce(t, "bar")
	for _, id := range ids {
		if row := a.h.outbound(t, id); row.State != OutHanded {
			t.Fatalf("row %d is %q, want handed: %s", id, row.State, row.Said)
		}
	}
	if cc.fresh != 1 || cc.reused != 4 {
		t.Fatalf("five rows went on %d new connections and %d reused; want one new, four reused", cc.fresh, cc.reused)
	}
}

// A connection that fails under a forward, written whole and its answer
// never back, is that attempt's failure: the turn ends there, the
// connection with it, and the next turn starts on a new one. The row is
// posted again, signed afresh, and the neighbour, which may already hold
// it, answers with the row it holds; the neighbour holds each of the five
// once, and nothing was sent again by the transport.
func TestACourierAfterATransportErrorStartsAFreshConnection(t *testing.T) {
	b := peered(t, []string{"onward"}, nil, nil)
	a := peer(t, b, "bar", "alpha", DefaultCourierLimits())
	ids := queueFive(t, a)

	w := worker(t, a.h)
	cc := connCount{cutAfter: 2}
	cc.wrap(w)
	w.drainOnce(t, "bar")
	if row := a.h.outbound(t, ids[0]); row.State != OutHanded {
		t.Fatalf("the first row is %q, want handed", row.State)
	}
	if row := a.h.outbound(t, ids[1]); row.State == OutHanded {
		t.Fatal("the row whose connection was cut is handed; the cut did not happen, so the test proves nothing")
	}
	if cc.posts != 2 || cc.fresh != 1 {
		t.Fatalf("the first turn made %d posts on %d new connections; want two posts, one connection, the turn ending at the cut", cc.posts, cc.fresh)
	}

	// The next turn, once the row and the neighbour are due again.
	a.h.clock.advance(2 * time.Hour)
	w.mu.Lock()
	clear(w.notBefore)
	w.mu.Unlock()
	w.drainOnce(t, "bar")
	if cc.fresh != 2 {
		t.Fatalf("two turns made %d new connections; want two, the second turn's own", cc.fresh)
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		row := a.h.outbound(t, id)
		if row.State != OutHanded || row.TheirID == 0 {
			t.Fatalf("row %d is %q with their id %d, want handed", id, row.State, row.TheirID)
		}
		if seen[row.TheirID] {
			t.Fatalf("two rows were handed as the neighbour's row %d", row.TheirID)
		}
		seen[row.TheirID] = true
	}
	var held int
	if err := b.store.db.QueryRow(`SELECT COUNT(*) FROM outbound WHERE neighbour = 'onward'`).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if held != 5 {
		t.Fatalf("the neighbour holds %d rows for the next hop, want the five once each", held)
	}
}
