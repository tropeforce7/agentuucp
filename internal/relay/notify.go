package relay

import "sync"

// notifier wakes whoever is waiting on a key when something happens under
// it. A key names one thing about one mailbox: mailKey(fp) is a row arriving
// in it, dirKey(fp) is its owner pushing a newer directory. A held listing
// subscribes under every key it cares about, then looks, then waits on the
// one channel it was given, so a row that lands between the look and the
// wait is not missed: the wake for it has already closed the channel.
//
// A wake is a closed channel and nothing more. It does not say which key
// fired or what happened; the request that wakes looks again and answers
// what it finds, which may be nothing when the row was for a key another
// subscriber under the same channel had.
type notifier struct {
	mu     sync.Mutex
	closed bool
	// subs holds, under each key, the subscriptions registered under it.
	// A subscription under several keys is in each of their sets, and is
	// taken out of all of them the moment it is woken or cancelled, so a
	// wake channel is closed once whichever key fired first.
	subs map[string]map[*subscription]struct{}
}

type subscription struct {
	wake chan struct{}
	keys []string
}

func mailKey(fp string) string { return "mail:" + fp }

func dirKey(fp string) string { return "dir:" + fp }

// closedWake is what a subscription after Close is given: a channel already
// closed, so a request that arrives while the relay is stopping looks once
// and answers at once, as one woken would.
var closedWake = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// Subscribe registers one wake channel under every key. cancel takes the
// registration back and is safe to call after a wake, or twice; a caller
// that stops waiting for any reason calls it, so a request that timed out or
// was cut off leaves nothing behind.
func (n *notifier) Subscribe(keys ...string) (wake <-chan struct{}, cancel func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return closedWake, func() {}
	}
	if n.subs == nil {
		n.subs = map[string]map[*subscription]struct{}{}
	}
	sub := &subscription{wake: make(chan struct{}), keys: keys}
	for _, key := range keys {
		set := n.subs[key]
		if set == nil {
			set = map[*subscription]struct{}{}
			n.subs[key] = set
		}
		set[sub] = struct{}{}
	}
	return sub.wake, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.forget(sub)
	}
}

// Wake closes the wake channel of every subscription under key and forgets
// each of them, under every key it was registered under.
func (n *notifier) Wake(key string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for sub := range n.subs[key] {
		close(sub.wake)
		n.forget(sub)
	}
}

// Close wakes every subscription and refuses any more: Subscribe from now on
// hands back a channel already closed. The relay calls it before the
// listener is shut down, so nothing held waits out its timer while the
// process is trying to stop.
func (n *notifier) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	for _, set := range n.subs {
		for sub := range set {
			close(sub.wake)
			n.forget(sub)
		}
	}
	n.subs = nil
}

// forget takes a subscription out of every set it is in, dropping a set that
// empties so the map does not grow with keys nobody waits on. The caller
// holds the lock. A subscription already forgotten is not in any set, so
// forgetting it again finds nothing to do, which is what makes cancel after
// a wake, or a wake under a second key, safe.
func (n *notifier) forget(sub *subscription) {
	for _, key := range sub.keys {
		set := n.subs[key]
		delete(set, sub)
		if len(set) == 0 {
			delete(n.subs, key)
		}
	}
}

// waiting is how many subscriptions are registered under key, for the tests.
func (n *notifier) waiting(key string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.subs[key])
}
