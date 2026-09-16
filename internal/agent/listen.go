package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// watchInterval is how often a running agent checks that its socket is
// still there. The runtime directory is cleared at logout on Linux, and an
// agent whose socket is gone is one nobody can reach and should not go on
// holding keys.
const watchInterval = 30 * time.Second

// Listener is a bound socket and the lock that makes it the only one.
type Listener struct {
	net.Listener
	paths *Paths
	lock  *fileLock

	closeOnce sync.Once
	closeErr  error
}

// Listen binds the agent's socket for a home: takes the one-agent lock,
// removes a stale socket nothing answers on, listens, and makes the socket
// the user's alone. It fails with ErrAnotherAgent when one is running.
func Listen(home string) (*Listener, error) {
	paths, err := PathsFor(home)
	if err != nil {
		return nil, err
	}
	lock, err := takeLock(paths.Lock)
	if err != nil {
		return nil, err
	}
	// Under the lock, so a socket file is either a stale one or ours, never
	// another agent's.
	if _, err := os.Stat(paths.Socket); err == nil {
		if err := os.Remove(paths.Socket); err != nil {
			lock.release()
			return nil, fmt.Errorf("agent: removing the stale socket %s: %w", paths.Socket, err)
		}
	}
	l, err := net.Listen("unix", paths.Socket)
	if err != nil {
		lock.release()
		return nil, err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(paths.Socket, 0o600); err != nil {
			l.Close()
			lock.release()
			return nil, fmt.Errorf("agent: securing the socket: %w", err)
		}
	}
	return &Listener{Listener: l, paths: paths, lock: lock}, nil
}

// Paths is where this listener's files are.
func (l *Listener) Paths() *Paths { return l.paths }

// Close closes the socket and releases the lock. Go removes the socket
// file, having created it. Serve closes the listener when the agent stops
// and the caller closes it again on the way out; the second is a no-op.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.closeErr = l.Listener.Close()
		if lerr := l.lock.release(); l.closeErr == nil {
			l.closeErr = lerr
		}
	})
	return l.closeErr
}

// Run is the whole of a foreground agent: harden, listen, serve until told
// to stop, until SIGTERM or SIGINT, or until the socket disappears. It
// returns nil when it stopped for one of those reasons and the error when
// it could not start.
func Run(ctx context.Context, home Home, opts Options) error {
	if err := Harden(); err != nil {
		return err
	}
	l, err := Listen(home.Root())
	if err != nil {
		return err
	}
	defer l.Close()
	logger := opts.Log
	if logger == nil {
		logger = log.New(os.Stderr, "auu agent: ", log.LstdFlags)
		opts.Log = logger
	}
	s := NewServer(home, opts)
	logger.Printf("started for %s on %s (pid %d)", home.Root(), l.paths.Socket, os.Getpid())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	go func() {
		ticker := time.NewTicker(watchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopped:
				return
			case <-ctx.Done():
				logger.Printf("stopping: %v", ctx.Err())
				s.Stop()
				return
			case sig := <-signals:
				logger.Printf("stopping on %s", sig)
				s.Stop()
				return
			case <-ticker.C:
				if _, err := os.Stat(l.paths.Socket); errors.Is(err, os.ErrNotExist) {
					logger.Printf("stopping: the socket %s is gone", l.paths.Socket)
					s.Stop()
					return
				}
			}
		}
	}()
	err = s.Serve(l)
	logger.Printf("stopped")
	return err
}
