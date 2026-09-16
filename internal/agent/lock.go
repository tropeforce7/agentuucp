package agent

import (
	"errors"
	"fmt"

	"github.com/tropeforce7/agentuucp/internal/lockfile"
)

// ErrAnotherAgent is a lock file another agent holds.
var ErrAnotherAgent = errors.New("another agent is already running for this home")

// fileLock is the one-agent-per-home lock, held for the agent's lifetime
// and released by the kernel when it exits however it exits, so a crash
// leaves nothing stale. It is internal/lockfile's, which the fetch lock
// shares.
type fileLock struct{ l *lockfile.Lock }

// takeLock takes the lock or reports that another agent holds it.
func takeLock(path string) (*fileLock, error) {
	l, err := lockfile.Try(path)
	if errors.Is(err, lockfile.ErrHeld) {
		return nil, ErrAnotherAgent
	}
	if err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	return &fileLock{l: l}, nil
}

func (l *fileLock) release() error {
	if l == nil {
		return nil
	}
	return l.l.Release()
}
