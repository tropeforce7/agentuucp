package relay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/ratelimit"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// Upload accounting: the cap on what one sender may have open, and the
// post-bytes budget charging what the relay holds.

// left is what a key has of a limiter's budget: the largest spend it
// would allow, found by asking and giving back, which restores it exactly
// while the test's clock stands still.
func left(l *ratelimit.Limiter, key string) int64 {
	lo, hi := int64(0), l.Burst()
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if ok, _ := l.AllowN(key, mid); ok {
			l.Return(key, mid)
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// openCount is how many uploads a sender has open.
func (h *harness) openCount(from string) int {
	h.t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads WHERE from_fp = ?`, from).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// openOrFail opens a stream and fails the test if the relay refused.
func (h *harness) openOrFail(from *identity.Identity, toFP string, size int64) string {
	h.t.Helper()
	status, opened, body := h.openStream(from, toFP, size)
	if status != http.StatusCreated {
		h.t.Fatalf("open: %d %s", status, body)
	}
	return opened.Upload
}

// waitOnDisk waits for an upload's file to reach n bytes, the sign that
// the relay is inside the copy with the upload's lock held.
func (h *harness) waitOnDisk(id string, n int64) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, file := h.uploadLeft(id); file == n {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%d bytes never reached the disk for %s", n, id)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestLimitOpenUploadsAtTheCapAndOneOver: one sender may have
// max_open_uploads open at once, across every mailbox it sends to; at the
// cap the next open is 429 naming the limit, with Retry-After the seconds
// to the sender's soonest expiry rounded up, and the sentence saying an
// unfinished upload goes within sixty seconds of its last byte. Two
// senders do not share a count. An abort, a placement and an expiry each
// free a slot, and the purge frees every expired one; uploads that have
// expired untouched are let go by the open that meets them at the cap, so
// the open after the wait succeeds at once; uploads in flight, their locks
// held past their expiry, are not, and the open at the cap is refused with
// a Retry-After of one.
func TestLimitOpenUploadsAtTheCapAndOneOver(t *testing.T) {
	h := newHarness(t, Config{Limits: Limits{MaxOpenUploads: 2}})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	for _, p := range people {
		h.register(p)
	}
	blob := fakeStream(200, 3000)
	size := int64(len(blob))
	to := bob.Fingerprint()
	capped := func(t *testing.T, from *identity.Identity, retryAfter string) {
		t.Helper()
		status, body, hdr := h.send(from, "POST", "/v1/mailbox/"+to+"/streams", relayapi.OpenStreamRequest{Size: size}, nil)
		if status != http.StatusTooManyRequests {
			t.Fatalf("an open past the cap: %d %s; want 429", status, body)
		}
		want := "rate limited: open uploads; you have 2 uploads open, the most this relay allows one sender at once; " +
			"an unfinished upload goes within 60 seconds of its last byte"
		if got := errorText(t, body); got != want {
			t.Fatalf("the refusal says %q\nwant %q", got, want)
		}
		if got := hdr.Get("Retry-After"); got != retryAfter {
			t.Fatalf("Retry-After %q, want %q", got, retryAfter)
		}
	}

	// At the cap: two taken, the third refused, and the log names the limit.
	first := h.openOrFail(alice, to, size)
	second := h.openOrFail(alice, to, size)
	capped(t, alice, "60")
	if !strings.Contains(h.logs.String(), `limit="open uploads"`) {
		t.Fatalf("the refusal did not name its limit in the log:\n%s", h.logs.String())
	}
	// The seconds to the soonest expiry, rounded up: half a second on,
	// 59.5 s to go is 60; a second on, 59.
	h.clock.advance(500 * time.Millisecond)
	capped(t, alice, "60")
	h.clock.advance(500 * time.Millisecond)
	capped(t, alice, "59")

	t.Run("two senders do not share a count", func(t *testing.T) {
		h.openOrFail(carol, to, size)
		h.openOrFail(carol, to, size)
		capped(t, carol, "60")
		if h.openCount(alice.Fingerprint()) != 2 || h.openCount(carol.Fingerprint()) != 2 {
			t.Fatalf("alice has %d open and carol %d; want 2 each", h.openCount(alice.Fingerprint()), h.openCount(carol.Fingerprint()))
		}
	})

	t.Run("an abort frees a slot", func(t *testing.T) {
		if status, body, _ := h.sendRaw(alice, "DELETE", "/v1/uploads/"+first, nil, nil); status != http.StatusNoContent {
			t.Fatalf("abort: %d %s", status, body)
		}
		first = h.openOrFail(alice, to, size)
		// The soonest expiry is the older upload's, 59 s on.
		capped(t, alice, "59")
	})

	t.Run("a placement frees a slot", func(t *testing.T) {
		if status, body, _ := h.putStream(alice, second, blob, 0); status != http.StatusCreated {
			t.Fatalf("put: %d %s", status, body)
		}
		second = h.openOrFail(alice, to, size)
		capped(t, alice, "60")
	})

	t.Run("expired untouched, the next open lets them go and succeeds at once", func(t *testing.T) {
		h.clock.advance(61 * time.Second)
		third := h.openOrFail(alice, to, size)
		for _, id := range []string{first, second} {
			if row, file := h.uploadLeft(id); row || file >= 0 {
				t.Fatalf("after the open at the cap, %s: row %v, file %d; want gone, expired", id, row, file)
			}
		}
		if n := h.openCount(alice.Fingerprint()); n != 1 {
			t.Fatalf("alice has %d open after the expired two went, want the one just opened", n)
		}
		if !strings.Contains(h.logs.String(), "abandoned uploads removed") {
			t.Fatalf("the open at the cap did not run the purge:\n%s", h.logs.String())
		}
		first, second = third, h.openOrFail(alice, to, size)
		capped(t, alice, "60")
	})

	t.Run("the purge frees slots", func(t *testing.T) {
		h.clock.advance(61 * time.Second)
		h.server.purgeUploads(h.clock.Now())
		if n := h.openCount(alice.Fingerprint()); n != 0 {
			t.Fatalf("alice has %d open after the purge, want none", n)
		}
		first = h.openOrFail(alice, to, size)
		second = h.openOrFail(alice, to, size)
		capped(t, alice, "60")
	})

	t.Run("in flight past their expiry, the open at the cap is refused with a Retry-After of one", func(t *testing.T) {
		// Two attempts parked inside the copy, their locks held, while
		// the clock passes their expiry: the purge the open runs skips
		// them, and the relay cannot say when a transfer ends.
		release := make(chan struct{})
		var wg sync.WaitGroup
		// Past the stream header, which the relay reads whole before it
		// writes a byte, and under the threshold, so nothing is kept
		// when they end.
		const parkedAt = 2000
		for _, id := range []string{first, second} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.putParked(alice, id, blob, parkedAt, func() { <-release })
			}()
		}
		h.waitOnDisk(first, parkedAt)
		h.waitOnDisk(second, parkedAt)
		h.clock.advance(61 * time.Second)
		capped(t, alice, "1")
		if n := h.openCount(alice.Fingerprint()); n != 2 {
			t.Fatalf("alice has %d open with two in flight, want 2", n)
		}
		close(release)
		wg.Wait()
		// Both stopped short under the threshold and left nothing, so
		// the slots are free.
		if n := h.openCount(alice.Fingerprint()); n != 0 {
			t.Fatalf("alice has %d open after both attempts ended, want none", n)
		}
		h.openOrFail(alice, to, size)
	})
	h.assertCountersAgree()
}

// TestThePostBytesBudgetChargesWhatTheRelayHolds: an open charges the
// declared size, so a sender cannot open past its budget; what the relay
// never held comes back when the row goes unplaced. A placement gives
// nothing back. An abort, an expiry met at the route, the purge, a first
// attempt that leaves nothing and a resumed attempt that stops short each
// give back the size less what the row had received when it went: the
// whole size for a row at zero, the size less the kept bytes for a kept
// partial, whose bytes stay charged while it is kept. A placement that
// failed keeps the row and gives nothing back. A return after the hour
// fills the budget and no more. Two abandoned opens no longer spend the
// hour: the N01 row's gigabyte, in miniature.
func TestThePostBytesBudgetChargesWhatTheRelayHolds(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	from, to := alice.Fingerprint(), bob.Fingerprint()
	blob := fakeStream(200, 3000)
	size := int64(len(blob))
	const kept = 2500 // past the threshold of 2048, so a first attempt stopping there is kept
	burst := 10 * size
	fresh := func(t *testing.T) *harness {
		t.Helper()
		h := newHarness(t, Config{MaxBytes: 2048, Limits: Limits{PostBytesPerHour: burst}})
		h.register(alice)
		h.register(bob)
		return h
	}
	budget := func(t *testing.T, h *harness, want int64, after string) {
		t.Helper()
		if got := left(h.server.lim.postBytes, from); got != want {
			t.Fatalf("after %s the budget holds %d, want %d", after, got, want)
		}
	}
	// gains asserts what act gives back, measured either side of it: where
	// the clock has moved the bucket has refilled by the interval's share,
	// and the difference is the return alone.
	gains := func(t *testing.T, h *harness, act func(), want int64, what string) {
		t.Helper()
		before := left(h.server.lim.postBytes, from)
		act()
		if got := left(h.server.lim.postBytes, from) - before; got != want {
			t.Fatalf("%s gave back %d, want %d", what, got, want)
		}
	}
	keep := func(t *testing.T, h *harness, id string) {
		t.Helper()
		status, body, _ := h.putPartial(alice, id, blob, 0, kept)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "kept for one resume") {
			t.Fatalf("the first attempt stopping at %d: %d %s; want 400 kept", kept, status, body)
		}
	}

	t.Run("an open charges the declared size and a placement gives nothing back", func(t *testing.T) {
		h := fresh(t)
		id := h.openOrFail(alice, to, size)
		budget(t, h, burst-size, "the open")
		if status, body, _ := h.putStream(alice, id, blob, 0); status != http.StatusCreated {
			t.Fatalf("put: %d %s", status, body)
		}
		budget(t, h, burst-size, "the placement")
	})
	t.Run("an abort gives back the whole size", func(t *testing.T) {
		h := fresh(t)
		id := h.openOrFail(alice, to, size)
		if status, body, _ := h.sendRaw(alice, "DELETE", "/v1/uploads/"+id, nil, nil); status != http.StatusNoContent {
			t.Fatalf("abort: %d %s", status, body)
		}
		budget(t, h, burst, "the abort")
	})
	t.Run("an expiry met at the route gives back what the row never held", func(t *testing.T) {
		h := fresh(t)
		untouched := h.openOrFail(alice, to, size)
		partial := h.openOrFail(alice, to, size)
		keep(t, h, partial)
		budget(t, h, burst-2*size, "the kept partial, its bytes charged while it is kept")
		h.clock.advance(61 * time.Second)
		expired := func(id string) func() {
			return func() {
				if status, body, _ := h.putStream(alice, id, blob, 0); status != http.StatusGone {
					t.Fatalf("an attempt on the expired %s: %d %s; want 410", id, status, body)
				}
			}
		}
		gains(t, h, expired(untouched), size, "the expiry of an untouched upload")
		gains(t, h, expired(partial), size-kept, "the expiry of a kept partial")
	})
	t.Run("the purge gives back what each row never held", func(t *testing.T) {
		h := fresh(t)
		h.openOrFail(alice, to, size)
		keep(t, h, h.openOrFail(alice, to, size))
		h.clock.advance(61 * time.Second)
		gains(t, h, func() {
			h.server.purgeUploads(h.clock.Now())
			if n := h.openCount(from); n != 0 {
				t.Fatalf("%d uploads left after the purge, want none", n)
			}
		}, size+size-kept, "the purge of an untouched upload and a kept partial")
	})
	t.Run("a first attempt that leaves nothing gives back the whole size", func(t *testing.T) {
		h := fresh(t)
		id := h.openOrFail(alice, to, size)
		status, body, _ := h.putPartial(alice, id, blob, 0, 1000)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "nothing is kept") {
			t.Fatalf("the short attempt: %d %s; want 400 nothing kept", status, body)
		}
		budget(t, h, burst, "the short attempt")
	})
	t.Run("a resumed attempt that stops short gives back the size less the kept bytes", func(t *testing.T) {
		h := fresh(t)
		id := h.openOrFail(alice, to, size)
		keep(t, h, id)
		status, body, _ := h.putPartial(alice, id, blob, kept, kept+200)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "nothing is kept") {
			t.Fatalf("the resumed attempt stopping short: %d %s; want 400 nothing kept", status, body)
		}
		if row, _ := h.uploadLeft(id); row {
			t.Fatal("the upload survived a resumed attempt that stopped short")
		}
		budget(t, h, burst-kept, "the resumed attempt that stopped short")
	})
	t.Run("a placement that failed with the file gone aborts the upload and gives back the size", func(t *testing.T) {
		h := fresh(t)
		id := h.openOrFail(alice, to, size)
		// The attempt reaches the end with the upload's file gone from
		// under its name: the copy lands on the open handle, the rename
		// into the mailbox fails, and there is no file to put back to
		// what the row says, so the upload goes whole and the sender
		// opens anew; what the relay never held comes back.
		status, body := h.putRemovingTheFile(alice, id, blob, 100)
		if status != http.StatusInternalServerError {
			t.Fatalf("the attempt whose placement failed: %d %s; want 500", status, body)
		}
		if row, file := h.uploadLeft(id); row || file >= 0 {
			t.Fatalf("after the failed placement with the file gone: row %v, file %d; want the upload gone", row, file)
		}
		budget(t, h, burst, "the failed placement with the file gone")
	})
	t.Run("a placement that failed with the file present keeps the row, the file at what the row says, and the charge", func(t *testing.T) {
		h := fresh(t)
		id := h.openOrFail(alice, to, size)
		// The mailbox's directory cannot be made: a file stands where
		// it would go, so the placement fails before the rename with
		// the upload's file at full size under its name.
		dir := h.store.mailboxDir(to)
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dir, []byte("in the way"), 0o600); err != nil {
			t.Fatal(err)
		}
		if status, body, _ := h.putStream(alice, id, blob, 0); status != http.StatusInternalServerError {
			t.Fatalf("the attempt whose placement failed: %d %s; want 500", status, body)
		}
		if row, file := h.uploadLeft(id); !row || file != 0 {
			t.Fatalf("after the failed placement: row %v, file %d bytes; want the row and the file put back to 0, what the row says", row, file)
		}
		budget(t, h, burst-size, "the failed placement with the file kept")
		// The way cleared, the sender's next attempt from zero places
		// the stream whole, and the blob is served, not 410.
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}
		status, body, _ := h.putStream(alice, id, blob, 0)
		if status != http.StatusCreated {
			t.Fatalf("the attempt after the way was cleared: %d %s; want 201", status, body)
		}
		var done relayapi.PutStreamResponse
		if err := json.Unmarshal(body, &done); err != nil {
			t.Fatal(err)
		}
		status, got, _ := h.sendRaw(bob, "GET", "/v1/mailbox/"+to+"/"+strconv.FormatInt(done.ID, 10)+"/blob", nil, nil)
		if status != http.StatusOK || !bytes.Equal(got, blob) {
			t.Fatalf("the blob after the second attempt: %d, %d bytes; want 200 and the stream whole, %d bytes", status, len(got), len(blob))
		}
		budget(t, h, burst-size, "the placement")
	})
	t.Run("a return after the hour fills the budget and no more", func(t *testing.T) {
		h := fresh(t)
		id := h.openOrFail(alice, to, size)
		// The hour refills the bucket; the expiry the abort meets gives
		// the size back to a bucket already full, which stays full.
		h.clock.advance(time.Hour)
		budget(t, h, burst, "the hour")
		if status, body, _ := h.sendRaw(alice, "DELETE", "/v1/uploads/"+id, nil, nil); status != http.StatusGone {
			t.Fatalf("abort after the hour: %d %s; want 410, the upload having expired", status, body)
		}
		if row, _ := h.uploadLeft(id); row {
			t.Fatal("the expired row survived the abort")
		}
		budget(t, h, burst, "an expiry after the hour")
	})
	t.Run("two abandoned opens no longer spend the hour", func(t *testing.T) {
		h := newHarness(t, Config{Limits: Limits{PostBytesPerHour: 2 * size}})
		h.register(alice)
		h.register(bob)
		for range 2 {
			id := h.openOrFail(alice, to, size)
			if status, body, _ := h.sendRaw(alice, "DELETE", "/v1/uploads/"+id, nil, nil); status != http.StatusNoContent {
				t.Fatalf("abort: %d %s", status, body)
			}
		}
		// The third open, which the budget refused before what an
		// abandoned upload never held came back.
		if id := h.uploadStream(alice, to, blob); id <= 0 {
			t.Fatalf("the third stream after two abandoned opens: %d", id)
		}
	})
}

// TestARefusedOpenCostsAPostAndNoBytes: an open the store refuses after
// the budgets are charged — the sender's count at the cap, the mailbox
// full, the relay full, a storage error — is an upload the relay never
// made a row for, and the declared size comes back whole; the post is
// spent, being the budget that bounds how often a sender may ask. The
// fifth refusal, no mailbox, is the same line: it needs the mailbox to
// go between the route's look and the store's, which no test can arrange
// in one request.
func TestARefusedOpenCostsAPostAndNoBytes(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	from, to := alice.Fingerprint(), bob.Fingerprint()
	blob := fakeStream(200, 3000)
	size := int64(len(blob))
	burst := 10 * size
	for _, tc := range []struct {
		name   string
		limits Limits
		plant  func(t *testing.T, h *harness)
		status int
	}{
		{"the cap", Limits{MaxOpenUploads: 1}, nil, http.StatusTooManyRequests},
		{"the mailbox full", Limits{MailboxMaxBytes: size + 1}, nil, http.StatusInsufficientStorage},
		{"the relay full", Limits{RelayMaxBytes: size + 1}, nil, http.StatusInsufficientStorage},
		{"a storage error", Limits{RelayMaxBytes: 100 * size}, func(t *testing.T, h *harness) {
			// The relay's total is read from relay_stats when a relay
			// quota is set; without the table the open is a storage error.
			if _, err := h.store.db.Exec(`DROP TABLE relay_stats`); err != nil {
				t.Fatal(err)
			}
		}, http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.limits.PostBytesPerHour = burst
			tc.limits.PostsPerMinute = 10
			h := newHarness(t, Config{Limits: tc.limits})
			h.register(alice)
			h.register(bob)
			h.openOrFail(alice, to, size)
			if tc.plant != nil {
				tc.plant(t, h)
			}
			status, _, body := h.openStream(alice, to, size)
			if status != tc.status {
				t.Fatalf("the second open: %d %s; want %d", status, body, tc.status)
			}
			if got := left(h.server.lim.postBytes, from); got != burst-size {
				t.Fatalf("after the refusal the budget holds %d, want %d: the first open's charge alone", got, burst-size)
			}
			if got := left(h.server.lim.posts, from); got != 8 {
				t.Fatalf("after the refusal the sender has %d posts left, want 8: two spent", got)
			}
		})
	}
}

// TestAnAttemptSaysWhetherTheUploadWent: Received.Gone is true on every
// path that deletes the upload whole — an attempt that stopped short and
// left nothing, a kept partial whose sync failed, a finished copy whose
// sync and truncate both failed — and false where the row survives: a
// placement that failed, an offset that did not match, an upload already
// gone. The server gives back the row's charge on Gone alone.
func TestAnAttemptSaysWhetherTheUploadWent(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	blob := fakeStream(200, 3000)
	open := func(t *testing.T) (*harness, string) {
		t.Helper()
		h := newHarness(t, Config{MaxBytes: 2048})
		h.register(alice)
		h.register(bob)
		return h, h.openOrFail(alice, bob.Fingerprint(), int64(len(blob)))
	}
	receive := func(h *harness, id string, offset int64, r func(f *os.File, want int64) (int64, error)) (Received, error) {
		return h.store.ReceiveUpload(id, offset, 2048, h.clock.Now, time.Minute, r)
	}

	t.Run("stopped short and left nothing", func(t *testing.T) {
		h, id := open(t)
		received, err := receive(h, id, 0, func(f *os.File, want int64) (int64, error) {
			n, werr := f.Write(blob[:1000])
			return int64(n), werr
		})
		if !errors.Is(err, ErrShortAttempt) || !received.Gone || received.Kept {
			t.Fatalf("received %+v, %v; want Gone and not Kept with ErrShortAttempt", received, err)
		}
		if row, _ := h.uploadLeft(id); row {
			t.Fatal("the row survived")
		}
	})
	t.Run("a kept partial whose sync failed", func(t *testing.T) {
		h, id := open(t)
		received, err := receive(h, id, 0, func(f *os.File, want int64) (int64, error) {
			n, werr := f.Write(blob[:2500])
			if werr != nil {
				return int64(n), werr
			}
			f.Close() // the sync fails on the closed handle, and so does the truncate
			return int64(n), errors.New("the sender went away")
		})
		if err == nil || !errors.Is(err, os.ErrClosed) || !received.Gone || received.Kept {
			t.Fatalf("received %+v, %v; want Gone and not Kept with the sync's error", received, err)
		}
		if row, _ := h.uploadLeft(id); row {
			t.Fatal("the row survived")
		}
	})
	t.Run("a finished copy whose sync and truncate failed", func(t *testing.T) {
		h, id := open(t)
		received, err := receive(h, id, 0, func(f *os.File, want int64) (int64, error) {
			n, werr := f.Write(blob)
			if werr != nil {
				return int64(n), werr
			}
			f.Close()
			return int64(n), nil
		})
		if err == nil || !errors.Is(err, os.ErrClosed) || !received.Gone {
			t.Fatalf("received %+v, %v; want Gone with the sync's error", received, err)
		}
	})
	t.Run("a placement that failed with the file gone", func(t *testing.T) {
		h, id := open(t)
		received, err := receive(h, id, 0, func(f *os.File, want int64) (int64, error) {
			n, werr := f.Write(blob)
			if werr != nil {
				return int64(n), werr
			}
			// The file goes from under its name; the rename into the
			// mailbox fails and the transaction rolls back, and there is
			// no file to put back to what the row says: the upload goes.
			return int64(n), os.Remove(h.store.uploadPath(id))
		})
		if err == nil || !received.Gone || received.Placed != 0 {
			t.Fatalf("received %+v, %v; want Gone with the placement's error", received, err)
		}
		if row, file := h.uploadLeft(id); row || file >= 0 {
			t.Fatalf("after the failed placement: row %v, file %d; want the upload gone", row, file)
		}
	})
	t.Run("a placement that failed with the file present is put back to what the row says", func(t *testing.T) {
		h, id := open(t)
		dir := h.store.mailboxDir(bob.Fingerprint())
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dir, []byte("in the way"), 0o600); err != nil {
			t.Fatal(err)
		}
		received, err := receive(h, id, 0, func(f *os.File, want int64) (int64, error) {
			n, werr := f.Write(blob)
			return int64(n), werr
		})
		if err == nil || received.Gone || received.Placed != 0 || received.Offset != 0 {
			t.Fatalf("received %+v, %v; want not Gone, at offset 0, with the placement's error", received, err)
		}
		if row, file := h.uploadLeft(id); !row || file != 0 {
			t.Fatalf("after the failed placement: row %v, file %d bytes; want the row and the file at 0", row, file)
		}
		// The lock's entry is kept for the upload that is still there.
		if !h.store.uploadLocked(id) {
			t.Fatal("the lock's entry went with a placement that failed, the upload still there")
		}
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}
		received, err = receive(h, id, 0, func(f *os.File, want int64) (int64, error) {
			n, werr := f.Write(blob)
			return int64(n), werr
		})
		if err != nil || received.Placed == 0 {
			t.Fatalf("the attempt after the way was cleared: %+v, %v; want the stream placed", received, err)
		}
		_, size, err := h.store.MessageKind(bob.Fingerprint(), received.Placed)
		info, serr := os.Stat(h.store.messagePath(bob.Fingerprint(), received.Placed))
		if err != nil || serr != nil || size != int64(len(blob)) || info.Size() != size {
			t.Fatalf("the placed message: row %d bytes (%v), file %v (%v); want both %d, one copy", size, err, info, serr, len(blob))
		}
	})
	t.Run("a placement that failed after the rename leaves no message file", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("the directory's sync cannot be made to fail here")
		}
		h, id := open(t)
		// The mailbox's directory takes the rename but cannot be opened
		// to sync: the placement fails after the rename, placeUpload
		// removes the message file it left, and with the upload's file
		// gone from under its name the upload goes whole.
		dir := h.store.mailboxDir(bob.Fingerprint())
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o300); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0o700) })
		received, err := receive(h, id, 0, func(f *os.File, want int64) (int64, error) {
			n, werr := f.Write(blob)
			return int64(n), werr
		})
		if err == nil || !received.Gone || received.Placed != 0 {
			t.Fatalf("received %+v, %v; want Gone with the placement's error", received, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("a message file was left after a placement that failed past the rename: %v", entries)
		}
		if row, file := h.uploadLeft(id); row || file >= 0 {
			t.Fatalf("after the failed placement: row %v, file %d; want the upload gone", row, file)
		}
		var rows int
		if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != 0 {
			t.Fatalf("%d message rows after a placement that failed; want none", rows)
		}
	})
	t.Run("an offset that did not match", func(t *testing.T) {
		h, id := open(t)
		received, err := receive(h, id, 7, nil)
		if !errors.Is(err, ErrUploadOffset) || received.Gone {
			t.Fatalf("received %+v, %v; want ErrUploadOffset and not Gone", received, err)
		}
		if row, _ := h.uploadLeft(id); !row {
			t.Fatal("the row went on a mismatched offset")
		}
	})
	t.Run("an upload already gone", func(t *testing.T) {
		h, id := open(t)
		if gone, err := h.store.AbortUpload(id); err != nil || gone == nil || gone.ID != id || gone.Size != int64(len(blob)) || gone.Received != 0 {
			t.Fatalf("abort handed back %+v, %v; want the row as it stood", gone, err)
		}
		if gone, err := h.store.AbortUpload(id); err != nil || gone != nil {
			t.Fatalf("a second abort handed back %+v, %v; want nothing, the row being gone", gone, err)
		}
		received, err := receive(h, id, 0, nil)
		if !errors.Is(err, ErrNoUpload) || received.Gone {
			t.Fatalf("received %+v, %v; want ErrNoUpload and not Gone", received, err)
		}
	})
}

// putRemovingTheFile is an attempt written by hand that sends the whole
// stream but its last tail bytes, removes the upload's file from under
// its name while the relay's handle stays open on it, then sends the
// tail: the copy reaches the end on the handle, and the placement's
// rename finds nothing under the name.
func (h *harness) putRemovingTheFile(from *identity.Identity, upload string, blob []byte, tail int) (int, []byte) {
	h.t.Helper()
	req, err := http.NewRequest("PUT", h.srv.URL+"/v1/uploads/"+upload, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.ContentLength = int64(len(blob))
	req.Header.Set(relayapi.UploadOffsetHeader, "0")
	if err := relayapi.SignRequest(from, req, nil); err != nil {
		h.t.Fatal(err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		h.t.Fatal(err)
	}
	defer conn.Close()
	var wire bytes.Buffer
	fmt.Fprintf(&wire, "PUT %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n", req.URL.RequestURI(), req.Host, req.ContentLength)
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&wire, "%s: %s\r\n", k, v)
		}
	}
	wire.WriteString("\r\n")
	head := len(blob) - tail
	wire.Write(blob[:head])
	if _, err := conn.Write(wire.Bytes()); err != nil {
		h.t.Fatal(err)
	}
	h.waitOnDisk(upload, int64(head))
	if err := os.Remove(h.store.uploadPath(upload)); err != nil {
		h.t.Fatal(err)
	}
	if _, err := conn.Write(blob[head:]); err != nil {
		h.t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		h.t.Fatalf("reading the answer: %v", err)
	}
	defer resp.Body.Close()
	out := make([]byte, 0, 512)
	buf := make([]byte, 512)
	for {
		n, err := resp.Body.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			break
		}
	}
	return resp.StatusCode, out
}
