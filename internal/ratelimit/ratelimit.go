// Package ratelimit is a token bucket keyed by string, used by the relay to
// bound what one identity or one source address can cost everybody else.
//
// It is deliberately small. A token bucket is arithmetic, not a dependency,
// and the relay needs no more than this: refill at a fixed rate, a burst equal
// to one interval's worth, and a bounded amount of memory however many keys an
// attacker invents.
package ratelimit

import (
	"container/list"
	"sync"
	"time"
)

// MaxKeys bounds the key table. Beyond it the least recently seen key is
// evicted, so an attacker with a large address space cannot grow the process
// without limit. Evicting is safe: a fresh key starts with a full bucket,
// which is exactly the state a key reaches after one idle interval anyway.
const MaxKeys = 100_000

// Limiter is a set of token buckets keyed by string, safe for concurrent use.
//
// A limiter built with a rate of zero is unlimited: it allows everything,
// allocates nothing, and takes no locks.
type Limiter struct {
	rate     float64 // tokens per interval, and the bucket capacity
	interval time.Duration
	idle     time.Duration
	now      func() time.Time

	mu      sync.Mutex
	buckets map[string]*list.Element
	lru     *list.List // most recently seen at the front
}

// entry is one key's bucket. last is both the time tokens were last computed
// and the time the key was last seen, because every access refills.
type entry struct {
	key    string
	tokens float64
	last   time.Time
}

// New creates a limiter allowing rate events per interval, with a burst equal
// to rate, and evicting keys idle for longer than idle.
//
// A rate of zero, or a non-positive interval, means unlimited. now is injected
// so tests need not sleep; production passes time.Now.
func New(rate int64, interval, idle time.Duration, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if rate <= 0 || interval <= 0 {
		return &Limiter{now: now}
	}
	return &Limiter{
		rate:     float64(rate),
		interval: interval,
		idle:     idle,
		now:      now,
		buckets:  make(map[string]*list.Element),
		lru:      list.New(),
	}
}

// Unlimited reports whether this limiter allows everything.
func (l *Limiter) Unlimited() bool { return l.buckets == nil }

// Burst is the bucket capacity: the most that can be taken at once. It is zero
// for an unlimited limiter.
func (l *Limiter) Burst() int64 { return int64(l.rate) }

// Allow takes one token for key. It reports whether the token was available
// and, if not, how long until one will be.
func (l *Limiter) Allow(key string) (bool, time.Duration) { return l.AllowN(key, 1) }

// AllowN takes n tokens at once, for byte budgets. A request larger than the
// whole burst is refused with retryAfter reporting the full refill time,
// because no amount of waiting will make it fit.
//
// Nothing is taken when the answer is no, so a caller that only wants to
// reject cheaply can call this and spend nothing.
func (l *Limiter) AllowN(key string, n int64) (bool, time.Duration) {
	if l.Unlimited() || n <= 0 {
		return true, 0
	}
	if float64(n) > l.rate {
		return false, roundUp(l.interval)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)
	e := l.touch(key, now)
	if e.tokens >= float64(n) {
		e.tokens -= float64(n)
		return true, 0
	}
	deficit := float64(n) - e.tokens
	return false, roundUp(time.Duration(deficit / l.rate * float64(l.interval)))
}

// Return gives n tokens back to key's bucket, for a cost that was charged
// and then not incurred: the relay charges a stream's declared size when
// the upload is opened, and gives back what it never held when the upload
// goes unplaced. The bucket is refilled to now first and then given at
// most what fills it, burst minus what it holds, so a return never makes
// a bucket fuller than a new one: what the sender could not have had is
// not created here. Nothing is done for an unlimited limiter, for n of
// zero or less, or for a key with no bucket, since a key never seen, or
// evicted or swept since it was, starts full when it is next seen.
func (l *Limiter) Return(key string, n int64) {
	if l.Unlimited() || n <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.buckets[key]; !ok {
		return
	}
	now := l.now()
	e := l.touch(key, now)
	e.tokens = min(e.tokens+float64(n), l.rate)
}

// Peek reports whether Allow would succeed, without taking anything.
func (l *Limiter) Peek(key string) bool {
	if l.Unlimited() {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	el, ok := l.buckets[key]
	if !ok {
		return true // an unseen key starts full
	}
	return refill(el.Value.(*entry), l.now(), l.rate, l.interval) >= 1
}

// Keys reports how many buckets are being tracked. It exists for tests and for
// the eviction assertions; the relay does not use it.
func (l *Limiter) Keys() int {
	if l.Unlimited() {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// touch returns key's bucket, refilled to now, moved to the front of the LRU
// list, creating it if this is the first time the key has been seen.
func (l *Limiter) touch(key string, now time.Time) *entry {
	if el, ok := l.buckets[key]; ok {
		e := el.Value.(*entry)
		e.tokens = refill(e, now, l.rate, l.interval)
		e.last = now
		l.lru.MoveToFront(el)
		return e
	}
	if len(l.buckets) >= MaxKeys {
		l.evictOldest()
	}
	e := &entry{key: key, tokens: l.rate, last: now}
	l.buckets[key] = l.lru.PushFront(e)
	return e
}

// evictOldest drops the least recently seen key.
func (l *Limiter) evictOldest() {
	back := l.lru.Back()
	if back == nil {
		return
	}
	l.lru.Remove(back)
	delete(l.buckets, back.Value.(*entry).key)
}

// sweep drops keys nobody has used for longer than idle. Because the list is
// in last-seen order it stops at the first key still in use, so the cost is
// proportional to what it removes rather than to the size of the table.
func (l *Limiter) sweep(now time.Time) {
	if l.idle <= 0 {
		return
	}
	for {
		back := l.lru.Back()
		if back == nil {
			return
		}
		e := back.Value.(*entry)
		if now.Sub(e.last) <= l.idle {
			return
		}
		l.lru.Remove(back)
		delete(l.buckets, e.key)
	}
}

// refill computes a bucket's token count at now without storing it.
func refill(e *entry, now time.Time, rate float64, interval time.Duration) float64 {
	elapsed := now.Sub(e.last)
	if elapsed <= 0 {
		return e.tokens
	}
	tokens := e.tokens + rate*(float64(elapsed)/float64(interval))
	if tokens > rate {
		tokens = rate
	}
	return tokens
}

// roundUp turns a wait into the whole number of seconds a Retry-After header
// can carry. Rounding down would invite a client straight back into a refusal,
// and a zero would invite it back immediately.
func roundUp(d time.Duration) time.Duration {
	if d <= time.Second {
		return time.Second
	}
	return (d + time.Second - 1).Truncate(time.Second)
}
