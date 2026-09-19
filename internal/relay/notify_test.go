package relay

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
)

// woken reports whether a wake channel has been closed, without waiting.
func woken(wake <-chan struct{}) bool {
	select {
	case <-wake:
		return true
	default:
		return false
	}
}

// wokenWithin waits up to the patience for a wake channel to close. The
// patience is generous because the claim is that the wake happens, not how
// fast this machine schedules it.
func wokenWithin(t *testing.T, wake <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-wake:
	case <-time.After(15 * time.Second):
		t.Fatalf("%s did not wake", what)
	}
}

func TestAWakeReachesEverySubscriberUnderTheKeyAndNoneUnderAnother(t *testing.T) {
	var n notifier
	a1, cancelA1 := n.Subscribe("mail:a")
	a2, cancelA2 := n.Subscribe("mail:a")
	b, cancelB := n.Subscribe("mail:b")
	defer cancelA1()
	defer cancelA2()
	defer cancelB()
	if woken(a1) || woken(a2) || woken(b) {
		t.Fatal("a fresh subscription is already woken")
	}
	n.Wake("mail:a")
	if !woken(a1) || !woken(a2) {
		t.Fatal("a wake did not reach every subscriber under its key")
	}
	if woken(b) {
		t.Fatal("a wake under one key reached a subscriber under another")
	}
	// Woken subscriptions are forgotten: the key is gone from the map,
	// and a second wake under it has nobody to reach, which is not a
	// second close of the same channel.
	if n.waiting("mail:a") != 0 || n.waiting("mail:b") != 1 {
		t.Fatalf("after the wake: %d under a, %d under b", n.waiting("mail:a"), n.waiting("mail:b"))
	}
	n.Wake("mail:a")
	n.Wake("nobody")
	if woken(b) {
		t.Fatal("b was woken by a key it did not subscribe under")
	}

	// A subscription under several keys is woken once, by whichever key
	// fires first, and is out from under the others from then on: the
	// second key's wake must not close the channel again.
	both, cancelBoth := n.Subscribe("mail:c", "dir:d")
	defer cancelBoth()
	if n.waiting("mail:c") != 1 || n.waiting("dir:d") != 1 {
		t.Fatal("a subscription under two keys is not under both")
	}
	n.Wake("dir:d")
	if !woken(both) {
		t.Fatal("the second key's wake did not reach the subscription")
	}
	if n.waiting("mail:c") != 0 {
		t.Fatal("a subscription woken under one key is still registered under the other")
	}
	n.Wake("mail:c") // would panic on a channel closed twice
}

func TestCancelBeforeWakeLeavesNothingBehind(t *testing.T) {
	var n notifier
	wake, cancel := n.Subscribe("mail:a", "dir:b")
	if len(n.subs) != 2 {
		t.Fatalf("%d keys after one subscription under two", len(n.subs))
	}
	cancel()
	if len(n.subs) != 0 {
		t.Fatalf("the map holds %d keys after the only subscription was cancelled", len(n.subs))
	}
	n.Wake("mail:a")
	n.Wake("dir:b")
	if woken(wake) {
		t.Fatal("a cancelled subscription was woken")
	}
	// Cancel after a wake, and twice, is nothing: the subscription is
	// already out of the map.
	wake, cancel = n.Subscribe("mail:a")
	n.Wake("mail:a")
	cancel()
	cancel()
	if !woken(wake) || len(n.subs) != 0 {
		t.Fatalf("after a wake and two cancels: woken %v, %d keys", woken(wake), len(n.subs))
	}
	// One of two under a key cancelled leaves the other to be woken.
	stay, cancelStay := n.Subscribe("mail:a")
	defer cancelStay()
	_, cancelGo := n.Subscribe("mail:a")
	cancelGo()
	if n.waiting("mail:a") != 1 {
		t.Fatalf("%d under the key after one of two cancelled", n.waiting("mail:a"))
	}
	n.Wake("mail:a")
	if !woken(stay) {
		t.Fatal("cancelling one subscription took the other with it")
	}
}

func TestCloseWakesAllAndALaterSubscribeIsAlreadyWoken(t *testing.T) {
	var n notifier
	a, cancelA := n.Subscribe("mail:a")
	b, cancelB := n.Subscribe("mail:b", "dir:c")
	defer cancelA()
	defer cancelB()
	n.Close()
	if !woken(a) || !woken(b) {
		t.Fatal("Close did not wake every subscription")
	}
	if len(n.subs) != 0 {
		t.Fatalf("the map holds %d keys after Close", len(n.subs))
	}
	late, cancelLate := n.Subscribe("mail:a")
	defer cancelLate()
	if !woken(late) {
		t.Fatal("a subscription after Close is not already woken")
	}
	if len(n.subs) != 0 {
		t.Fatal("a subscription after Close was registered")
	}
	// A wake after Close, and a second Close, find nothing to do.
	n.Wake("mail:a")
	n.Close()
}

// Subscribe, Wake, cancel and Close from many goroutines at once: the race
// detector's test, and the proof that no channel is closed twice however
// the calls interleave.
func TestTheNotifierUnderManyGoroutines(t *testing.T) {
	var n notifier
	keys := []string{"mail:a", "mail:b", "dir:c", "dir:d"}
	var wg sync.WaitGroup
	for g := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				k1, k2 := keys[(g+i)%len(keys)], keys[(g+i+1)%len(keys)]
				wake, cancel := n.Subscribe(k1, k2)
				switch i % 4 {
				case 0:
					n.Wake(k1)
					<-wake
				case 1:
					n.Wake(k2)
					<-wake
					cancel()
				case 2:
					cancel()
				case 3:
					n.Wake(keys[(g+i+2)%len(keys)])
					cancel()
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 200 {
			for _, k := range keys {
				n.Wake(k)
			}
		}
	}()
	wg.Wait()
	// Every subscription was woken or cancelled, so nothing is left.
	if len(n.subs) != 0 {
		t.Fatalf("%d keys still held after every goroutine finished", len(n.subs))
	}
	// And Close races with the rest.
	var wg2 sync.WaitGroup
	for g := range 16 {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			for i := range 100 {
				wake, cancel := n.Subscribe(keys[(g+i)%len(keys)])
				if i == 50 && g == 0 {
					n.Close()
				}
				if i%2 == 0 {
					n.Wake(keys[(g+i)%len(keys)])
					<-wake
				}
				cancel()
			}
		}()
	}
	wg2.Wait()
	if !n.closed || len(n.subs) != 0 {
		t.Fatalf("after Close raced with the rest: closed %v, %d keys", n.closed, len(n.subs))
	}
}

// The wiring: a post wakes the recipient's mail key once the store has the
// row, a completed stream does the same, and a post to somebody else wakes
// nothing of theirs.
func TestAPostAndACompletedStreamWakeTheRecipient(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	n := h.server.notify

	bobMail, cancel := n.Subscribe(mailKey(bob.Fingerprint()))
	defer cancel()
	aliceMail, cancelAlice := n.Subscribe(mailKey(alice.Fingerprint()))
	defer cancelAlice()

	// A refused post wakes nobody: the wake is after the store has the
	// row, and a stranger's post never reaches it.
	stranger := ids(t, "stranger")[0]
	h.register(stranger)
	if status, body := h.do(bob, "PUT", "/v1/mailbox/"+bob.Fingerprint()+"/allow",
		h.allowReq(bob, alice.Fingerprint()), nil); status != http.StatusNoContent {
		t.Fatalf("allow: %d %s", status, body)
	}
	if status, body := h.postTo(stranger, bob, ""); status != http.StatusForbidden {
		t.Fatalf("a stranger's post: %d %s", status, body)
	}
	if woken(bobMail) {
		t.Fatal("a refused post woke the recipient")
	}
	if status, body := h.postTo(alice, bob, ""); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	wokenWithin(t, bobMail, "the recipient of a post")
	if n.waiting(mailKey(bob.Fingerprint())) != 0 {
		t.Fatal("the woken subscription is still registered")
	}
	if woken(aliceMail) {
		t.Fatal("a post to bob woke alice")
	}
	// The row is there for the listing the wake sends the client back to.
	if got, _ := h.queued(bob.Fingerprint()); got != 1 {
		t.Fatalf("%d queued after the wake, want 1", got)
	}

	// A placed stream: the open wakes nobody, since there is no row yet,
	// and neither does an attempt that stopped short; the attempt that
	// reaches the end does, with the placement.
	bobMail, cancel = n.Subscribe(mailKey(bob.Fingerprint()))
	defer cancel()
	blob := fakeStream(200, 3000)
	status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
	if status != http.StatusCreated {
		t.Fatalf("open: %d %s", status, body)
	}
	if woken(bobMail) {
		t.Fatal("an upload opened woke the recipient")
	}
	if status, body, _ := h.putPartial(alice, opened.Upload, blob, 0, 1000); status != http.StatusBadRequest {
		t.Fatalf("a partial attempt: %d %s", status, body)
	}
	if woken(bobMail) {
		t.Fatal("an attempt that stopped short woke the recipient")
	}
	// Nothing was kept under the threshold, so the upload is opened anew.
	status, opened, body = h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
	if status != http.StatusCreated {
		t.Fatalf("open again: %d %s", status, body)
	}
	if status, body, _ := h.putStream(alice, opened.Upload, blob, 0); status != http.StatusCreated {
		t.Fatalf("put: %d %s", status, body)
	}
	wokenWithin(t, bobMail, "the recipient of a placed stream")
	if woken(aliceMail) {
		t.Fatal("a stream to bob woke alice")
	}
}

// A directory push wakes the mailbox's directory key when it replaced what
// was stored, and not when it was refused or was the stored directory
// pushed again.
func TestADirectoryPushWakesItsWatchersOnlyWhenItChanges(t *testing.T) {
	h := newHarness(t, Config{})
	bob := ids(t, "bob")[0]
	h.register(bob)
	n := h.server.notify
	at := h.clock.Now()

	dir, cancel := n.Subscribe(dirKey(bob.Fingerprint()))
	defer cancel()
	if status, body, _ := h.pushDirectory(bob, bob, at, dflt, bugs); status != http.StatusNoContent {
		t.Fatalf("push: %d %s", status, body)
	}
	wokenWithin(t, dir, "a watcher of a pushed directory")

	// The same directory again is a 204 that changed nothing.
	dir, cancel = n.Subscribe(dirKey(bob.Fingerprint()))
	defer cancel()
	if status, body, _ := h.pushDirectory(bob, bob, at, dflt, bugs); status != http.StatusNoContent {
		t.Fatalf("the same push again: %d %s", status, body)
	}
	if woken(dir) {
		t.Fatal("pushing the stored directory again woke its watchers")
	}
	// An older one is refused, and wakes nobody.
	if status, body, _ := h.pushDirectory(bob, bob, at.Add(-time.Second), dflt); status != http.StatusConflict {
		t.Fatalf("an older push: %d %s", status, body)
	}
	if woken(dir) {
		t.Fatal("a refused push woke the directory's watchers")
	}
	// A newer one wakes.
	if status, body, _ := h.pushDirectory(bob, bob, at.Add(time.Second), dflt,
		channels.Channel{Name: "cfp"}); status != http.StatusNoContent {
		t.Fatalf("a newer push: %d %s", status, body)
	}
	wokenWithin(t, dir, "a watcher of a replaced directory")
	// The mail key is not the directory key.
	if n.waiting(mailKey(bob.Fingerprint())) != 0 {
		t.Fatal("a directory push touched the mail key")
	}
}

// Close wakes what the server holds and refuses to hold more, and is safe
// to call more than once.
func TestServerCloseWakesEverySubscriber(t *testing.T) {
	h := newHarness(t, Config{})
	bob := ids(t, "bob")[0]
	h.register(bob)
	n := h.server.notify
	mail, cancelMail := n.Subscribe(mailKey(bob.Fingerprint()))
	defer cancelMail()
	dir, cancelDir := n.Subscribe(dirKey(bob.Fingerprint()))
	defer cancelDir()
	h.server.Close()
	if !woken(mail) || !woken(dir) {
		t.Fatal("Close left a subscriber waiting")
	}
	late, cancelLate := n.Subscribe(mailKey(bob.Fingerprint()))
	defer cancelLate()
	if !woken(late) {
		t.Fatal("a subscription after Close is not already woken")
	}
	h.server.Close()
	// The relay still answers: Close is about what it holds, not what it
	// serves, and the shutdown that follows is the listener's.
	h.healthy()
}
