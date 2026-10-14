package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestADroppedLongPollIsNotResentWithItsSpentNonce: a watch's long
// poll is a signed GET on a kept-alive connection. When that connection
// dies under the poll (the machine sleeps, a NAT entry expires, the relay
// restarts), net/http's transport re-sends an idempotent request that got
// no response on a reused connection, and it re-sends it as it was: the
// same X-CCX-Auth, the same stamp, the same nonce. The relay has already
// consumed that nonce (or the stamp is stale by now), so the replay is
// 401, and auu watch ends on "relay returned 401: unauthorized" although
// nothing is wrong with the certificate, the registration or the clock.
// The client must sign each wire attempt afresh, or forbid the transport's
// silent retry.
func TestADroppedLongPollIsNotResentWithItsSpentNonce(t *testing.T) {
	var mu sync.Mutex
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"max_bytes":16777216,"knock_max_bytes":16777216,"registration":"open","wire_level":1}`))
			return
		}
		mu.Lock()
		auths = append(auths, r.Header.Get(relayapi.AuthHeader))
		k := len(auths)
		mu.Unlock()
		if k == 2 {
			// The connection dies under the held listing, no answer sent.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("no hijacker")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"messages":[],"queued":0,"first":0,"last":0,"allow":"none","card":"none","directory":"none"}`))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.ListWait(ctx, ListRequest{Wait: time.Second}); err != nil {
		t.Fatalf("first listing: %v", err)
	}
	_, err = c.ListWait(ctx, ListRequest{Wait: time.Second})
	mu.Lock()
	defer mu.Unlock()
	t.Logf("second listing returned %v; the stub saw %d listing requests", err, len(auths))
	for i := 2; i < len(auths); i++ {
		if auths[i] == auths[1] {
			t.Fatalf("the poll dropped under the client was sent again with the very same %s (request %d repeats request 2): a spent nonce and an old stamp, which the relay refuses 401; want each wire attempt signed afresh, or no silent retry", relayapi.AuthHeader, i+1)
		}
	}
}
