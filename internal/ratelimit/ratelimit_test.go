package ratelimit

import (
	"math"
	"strconv"
	"sync"
	"testing"
	"time"
)

// clock is an injected time source the tests advance by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestBurstThenRefill(t *testing.T) {
	c := newClock()
	l := New(3, time.Minute, time.Hour, c.Now)

	for i := range 3 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("token %d of the burst refused", i+1)
		}
	}
	ok, retry := l.Allow("a")
	if ok {
		t.Fatal("fourth call inside the interval was allowed")
	}
	// One token accrues every 20 seconds at 3 a minute.
	if retry != 20*time.Second {
		t.Fatalf("retryAfter %v, want 20s", retry)
	}

	// Just short of a refill period is still refused.
	c.advance(19 * time.Second)
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("allowed before a whole token had accrued")
	}
	c.advance(time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("refused after a full refill period")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("two tokens appeared where one had accrued")
	}

	// A long idle period refills to the burst and no further.
	c.advance(10 * time.Minute)
	for i := range 3 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("token %d unavailable after a long idle period", i+1)
		}
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("bucket refilled past its capacity")
	}
}

func TestRefillIsProportional(t *testing.T) {
	c := newClock()
	l := New(10, time.Minute, time.Hour, c.Now)
	for range 10 {
		l.Allow("a")
	}
	// Half an interval buys half a burst, and not one more.
	c.advance(30 * time.Second)
	for i := range 5 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("token %d of the half refill refused", i+1)
		}
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("half an interval produced more than half a burst")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	c := newClock()
	l := New(1, time.Minute, time.Hour, c.Now)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("first key refused")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("first key allowed twice")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("a second key was charged for the first key's traffic")
	}
}

func TestAllowNLargerThanBurst(t *testing.T) {
	c := newClock()
	l := New(1000, time.Hour, time.Hour, c.Now)

	ok, retry := l.AllowN("a", 1001)
	if ok {
		t.Fatal("a request larger than the whole burst was allowed")
	}
	if retry != time.Hour {
		t.Fatalf("retryAfter %v, want the full refill time of 1h", retry)
	}
	// It took nothing, so the budget is intact.
	if ok, _ := l.AllowN("a", 1000); !ok {
		t.Fatal("the refused oversize request consumed the budget")
	}
}

func TestAllowNSpendsAndReports(t *testing.T) {
	c := newClock()
	l := New(100, time.Minute, time.Hour, c.Now)
	if ok, _ := l.AllowN("a", 60); !ok {
		t.Fatal("first spend refused")
	}
	ok, retry := l.AllowN("a", 60)
	if ok {
		t.Fatal("second spend exceeded the budget but was allowed")
	}
	// 20 tokens short at 100 a minute is 12 seconds.
	if retry != 12*time.Second {
		t.Fatalf("retryAfter %v, want 12s", retry)
	}
	c.advance(12 * time.Second)
	if ok, _ := l.AllowN("a", 60); !ok {
		t.Fatal("refused after waiting exactly as long as it asked")
	}
}

func TestRetryAfterIsAtLeastOneSecond(t *testing.T) {
	c := newClock()
	l := New(600, time.Minute, time.Hour, c.Now) // a token every 100ms
	for range 600 {
		l.Allow("a")
	}
	if _, retry := l.Allow("a"); retry != time.Second {
		t.Fatalf("retryAfter %v, want it clamped up to 1s", retry)
	}
}

func TestIdleEviction(t *testing.T) {
	c := newClock()
	l := New(5, time.Minute, 2*time.Minute, c.Now)
	l.Allow("stale")
	c.advance(time.Minute)
	l.Allow("fresh")
	if l.Keys() != 2 {
		t.Fatalf("tracking %d keys, want 2", l.Keys())
	}
	// Now "stale" is 2m30s idle and "fresh" is 1m30s idle.
	c.advance(90 * time.Second)
	l.Allow("fresh")
	if l.Keys() != 1 {
		t.Fatalf("tracking %d keys after the idle sweep, want 1", l.Keys())
	}
	if !l.Peek("stale") {
		t.Fatal("the evicted key did not come back full")
	}
}

func TestCapEvictsLeastRecentKey(t *testing.T) {
	c := newClock()
	l := New(1, time.Minute, 0, c.Now) // idle 0 disables the sweep

	// Fill the table, oldest first.
	for i := range MaxKeys {
		l.Allow(strconv.Itoa(i))
		c.advance(time.Millisecond)
	}
	if l.Keys() != MaxKeys {
		t.Fatalf("tracking %d keys, want the cap of %d", l.Keys(), MaxKeys)
	}
	// Key 0 is the least recently seen and has no tokens left. Touching key 1
	// makes it more recent than key 0, so key 0 is the one that must go.
	l.Allow("1")
	l.Allow("new")
	if l.Keys() != MaxKeys {
		t.Fatalf("the table grew past the cap to %d", l.Keys())
	}
	if !l.Peek("0") {
		t.Fatal("the least recently seen key was not the one evicted")
	}
	if l.Peek("1") {
		t.Fatal("a recently seen key was evicted instead")
	}
}

func TestZeroRateIsUnlimited(t *testing.T) {
	l := New(0, time.Minute, time.Hour, nil)
	if !l.Unlimited() {
		t.Fatal("a zero rate did not produce an unlimited limiter")
	}
	for range 10_000 {
		if ok, retry := l.Allow("a"); !ok || retry != 0 {
			t.Fatal("an unlimited limiter refused a request")
		}
	}
	if ok, _ := l.AllowN("a", 1<<40); !ok {
		t.Fatal("an unlimited limiter refused a large spend")
	}
	if !l.Peek("a") {
		t.Fatal("Peek refused on an unlimited limiter")
	}
	// It must not allocate a key table at all.
	if l.Keys() != 0 {
		t.Fatalf("an unlimited limiter is tracking %d keys", l.Keys())
	}
}

func TestPeekTakesNothing(t *testing.T) {
	c := newClock()
	l := New(1, time.Minute, time.Hour, c.Now)
	if !l.Peek("a") || !l.Peek("a") {
		t.Fatal("Peek consumed a token")
	}
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("the token Peek reported was not there")
	}
	if l.Peek("a") {
		t.Fatal("Peek did not see the exhausted bucket")
	}
}

// The relay calls this from many request goroutines at once.
func TestConcurrentUse(t *testing.T) {
	l := New(1_000_000, time.Minute, time.Minute, time.Now)
	var wg sync.WaitGroup
	for g := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				l.Allow("shared")
				l.Allow(strconv.Itoa(g*500 + i))
				l.AllowN("shared-bytes", 16)
				l.Peek("shared")
			}
		}()
	}
	wg.Wait()
}

// A limiter is configured from operator input, so the extremes of the type
// must behave rather than misbehave.
func TestExtremeConfiguration(t *testing.T) {
	c := newClock()

	t.Run("a negative rate is unlimited", func(t *testing.T) {
		l := New(-1, time.Minute, time.Hour, c.Now)
		if !l.Unlimited() {
			t.Fatal("a negative rate produced a limited limiter")
		}
		if ok, _ := l.Allow("a"); !ok {
			t.Fatal("a negative rate refused a request")
		}
	})
	t.Run("MinInt64 rate is unlimited", func(t *testing.T) {
		l := New(math.MinInt64, time.Minute, time.Hour, c.Now)
		if !l.Unlimited() {
			t.Fatal("MinInt64 produced a limited limiter")
		}
	})
	t.Run("a zero or negative interval is unlimited", func(t *testing.T) {
		for _, d := range []time.Duration{0, -time.Second, math.MinInt64} {
			l := New(10, d, time.Hour, c.Now)
			if !l.Unlimited() {
				t.Fatalf("an interval of %v produced a limited limiter", d)
			}
		}
	})
	t.Run("MaxInt64 rate allows everything without overflowing", func(t *testing.T) {
		l := New(math.MaxInt64, time.Minute, time.Minute, c.Now)
		if l.Unlimited() {
			t.Fatal("MaxInt64 was treated as unlimited; it is a real, very large rate")
		}
		for i := range 1000 {
			if ok, _ := l.Allow("a"); !ok {
				t.Fatalf("call %d was refused by a MaxInt64 limiter", i)
			}
		}
		if ok, _ := l.AllowN("a", math.MaxInt64); !ok {
			t.Fatal("a MaxInt64 spend was refused by a MaxInt64 limiter")
		}
	})
	t.Run("AllowN at the extremes", func(t *testing.T) {
		l := New(1000, time.Minute, time.Hour, c.Now)
		ok, retry := l.AllowN("a", math.MaxInt64)
		if ok {
			t.Fatal("a MaxInt64 spend was allowed from a burst of 1000")
		}
		if retry != time.Minute {
			t.Fatalf("retryAfter %v, want the full refill time", retry)
		}
		// Nothing was taken.
		if ok, _ := l.AllowN("a", 1000); !ok {
			t.Fatal("the refused MaxInt64 spend consumed the budget")
		}
	})
	t.Run("a non-positive spend takes nothing", func(t *testing.T) {
		l := New(10, time.Minute, time.Hour, c.Now)
		for _, n := range []int64{0, -1, math.MinInt64} {
			if ok, retry := l.AllowN("a", n); !ok || retry != 0 {
				t.Fatalf("AllowN(%d) = %v, %v; a non-positive spend must be free", n, ok, retry)
			}
		}
		for range 10 {
			if ok, _ := l.Allow("a"); !ok {
				t.Fatal("a non-positive spend consumed the budget")
			}
		}
	})
	t.Run("burst of one", func(t *testing.T) {
		l := New(1, time.Minute, time.Hour, c.Now)
		if ok, _ := l.AllowN("a", 1); !ok {
			t.Fatal("a spend of exactly the burst was refused")
		}
		if ok, _ := l.AllowN("a", 2); ok {
			t.Fatal("a spend of one over the burst was allowed")
		}
	})
}

// TestLimitReturnNeverFillsPastTheBurst: a return gives a bucket at most
// what fills it. n at what was taken restores the bucket whole; n past
// it, one over and the type's maximum, fills it and no more, since a
// bucket cannot be fuller than a new one; a return after a refill adds to
// the refilled bucket and is bounded the same way. An unlimited limiter,
// n of zero or less, and a key with no bucket — never seen, or swept
// since — are each nothing done: the first has nothing to fill, the
// second nothing to give, and the third starts full when next seen.
func TestLimitReturnNeverFillsPastTheBurst(t *testing.T) {
	// holds asserts a key has exactly n tokens, by taking them and being
	// refused one more; the clock does not move, so nothing refills.
	holds := func(t *testing.T, l *Limiter, key string, n int64) {
		t.Helper()
		if n > 0 {
			if ok, _ := l.AllowN(key, n); !ok {
				t.Fatalf("%s does not hold %d", key, n)
			}
		}
		if ok, _ := l.Allow(key); ok {
			t.Fatalf("%s holds more than %d", key, n)
		}
	}

	t.Run("at what was taken, the bucket is whole", func(t *testing.T) {
		c := newClock()
		l := New(1000, time.Hour, time.Hour, c.Now)
		if ok, _ := l.AllowN("a", 600); !ok {
			t.Fatal("the charge was refused")
		}
		l.Return("a", 600)
		holds(t, l, "a", 1000)
	})
	t.Run("past what was taken, the bucket fills and no more", func(t *testing.T) {
		for _, n := range []int64{601, 1000, 1001, math.MaxInt64} {
			c := newClock()
			l := New(1000, time.Hour, time.Hour, c.Now)
			if ok, _ := l.AllowN("a", 600); !ok {
				t.Fatal("the charge was refused")
			}
			l.Return("a", n)
			holds(t, l, "a", 1000)
		}
	})
	t.Run("a return adds to the refilled bucket, bounded the same way", func(t *testing.T) {
		c := newClock()
		l := New(1000, time.Hour, time.Hour, c.Now)
		if ok, _ := l.AllowN("a", 1000); !ok {
			t.Fatal("the charge was refused")
		}
		// Half an hour refills 500, and a return of 300 makes 800.
		c.advance(30 * time.Minute)
		l.Return("a", 300)
		holds(t, l, "a", 800)
		// Empty again; a return of more than the burst fills it and no more.
		l.Return("a", 1500)
		holds(t, l, "a", 1000)
	})
	t.Run("an unlimited limiter does nothing", func(t *testing.T) {
		l := New(0, time.Hour, time.Hour, nil)
		l.Return("a", 1)
		l.Return("a", math.MaxInt64)
		if l.Keys() != 0 {
			t.Fatal("a return made an unlimited limiter track a key")
		}
	})
	t.Run("zero or less gives nothing", func(t *testing.T) {
		c := newClock()
		l := New(1000, time.Hour, time.Hour, c.Now)
		if ok, _ := l.AllowN("a", 600); !ok {
			t.Fatal("the charge was refused")
		}
		for _, n := range []int64{0, -1, math.MinInt64} {
			l.Return("a", n)
		}
		holds(t, l, "a", 400)
	})
	t.Run("a key with no bucket gets none", func(t *testing.T) {
		c := newClock()
		l := New(1000, time.Hour, time.Minute, c.Now)
		l.Return("never", 500)
		if l.Keys() != 0 {
			t.Fatal("a return made a bucket for a key never seen")
		}
		// Seen, then swept idle: the bucket is gone, and a return makes
		// no new one; the key starts full when it is next seen.
		if ok, _ := l.AllowN("swept", 600); !ok {
			t.Fatal("the charge was refused")
		}
		c.advance(2 * time.Minute)
		l.AllowN("other", 1) // the sweep runs on a spend
		if l.Keys() != 1 {
			t.Fatalf("%d keys after the sweep, want other alone", l.Keys())
		}
		l.Return("swept", 600)
		if l.Keys() != 1 {
			t.Fatal("a return made a bucket for a swept key")
		}
		holds(t, l, "swept", 1000)
	})
}
