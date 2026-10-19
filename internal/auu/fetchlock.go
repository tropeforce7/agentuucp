package auu

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/tropeforce7/agentuucp/internal/lockfile"
	"github.com/tropeforce7/agentuucp/internal/store"
)

// fetchLocks is the fetch lock of each relay a command that changes a
// fetched record has taken, held until the command ends. A fetch reads the
// records whose acknowledgement is owed, asks the relay, and saves each one
// back with the acknowledgement made; a record moved or removed while it
// asked was put back where it had been, so a trust left the message in
// both boxes and an rm left it where it was. Under the lock the command and
// the fetch take turns, as auu damaged reopen and a fetch already do.
type fetchLocks struct {
	s    *store.Store
	held map[string]*lockfile.Lock
}

func newFetchLocks(s *store.Store) *fetchLocks {
	return &fetchLocks{s: s, held: map[string]*lockfile.Lock{}}
}

// take takes the fetch lock of the home's relay that name is, by the rule
// the home's names are taken under (S62), once for each relay. A relay this
// home no longer has is fetched by nobody, and there is no lock to take.
// The caller reads its record again once take returns, since a fetch that
// ran while it waited may have changed it.
func (l *fetchLocks) take(name string) error {
	relays, err := l.s.Relays()
	if err != nil {
		return err
	}
	for _, r := range relays {
		if !store.SameRelayName(r.Name, name) {
			continue
		}
		if _, ok := l.held[r.Name]; ok {
			return nil
		}
		lock, _, err := lockfile.Take(ctx(), filepath.Join(l.s.RelayDir(r), fetchLockName), fetchLockWait, fetchLockSleep)
		if errors.Is(err, lockfile.ErrHeld) {
			return transportErr(fmt.Errorf("another %s is fetching from %s; try again in a moment: %w", prog, r.Name, err))
		}
		if err != nil {
			return fmt.Errorf("taking the fetch lock for %s: %w", r.Name, err)
		}
		l.held[r.Name] = lock
		return nil
	}
	return nil
}

// release lets go of every lock taken.
func (l *fetchLocks) release() {
	for name, lock := range l.held {
		lock.Release()
		delete(l.held, name)
	}
}
