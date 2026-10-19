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
// still there and still its own. The runtime directory is cleared at logout
// on Linux, and an agent whose socket is gone, or is another file now, is one
// nobody can reach and should not go on holding keys. Options.WatchInterval
// replaces it, for a test.
const watchInterval = 30 * time.Second

// Listener is a bound socket and the lock that makes it the only one.
type Listener struct {
	net.Listener
	paths *Paths
	lock  *fileLock
	// info is the socket file as it was bound, so that the watch can tell
	// this socket from another file put at the same path, and Close removes
	// the path only while it is still this socket.
	info os.FileInfo

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
	// Go removes a socket file it created when the listener closes, whatever
	// is at the path by then. An agent stopping because its socket was
	// replaced would remove the replacement, which may be another agent's
	// socket, so Close removes the path itself and only while it is ours.
	if ul, ok := l.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(paths.Socket, 0o600); err != nil {
			l.Close()
			os.Remove(paths.Socket)
			lock.release()
			return nil, fmt.Errorf("agent: securing the socket: %w", err)
		}
	}
	info, err := os.Lstat(paths.Socket)
	if err != nil {
		l.Close()
		os.Remove(paths.Socket)
		lock.release()
		return nil, fmt.Errorf("agent: reading the socket it bound: %w", err)
	}
	return &Listener{Listener: l, paths: paths, lock: lock, info: info}, nil
}

// Paths is where this listener's files are.
func (l *Listener) Paths() *Paths { return l.paths }

// Close removes the file at the socket's path if that is still this
// socket, closes the socket, and releases the lock. The file is checked
// and removed before the socket closes, as Go itself does, because the
// open socket holds its file's inode and no new file can take that number
// while it does. The check and the removal are two steps, so a file put at
// the path between them would go; under the lock, only a runtime directory
// removed and made again in that moment, with a new agent in it, could put
// one there, and that agent would stop at its next look. Serve closes the
// listener when the agent stops and the caller closes it again on the way
// out; the second is a no-op.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		if state, _ := l.stat(); state == socketOurs {
			if err := os.Remove(l.paths.Socket); err != nil && !errors.Is(err, os.ErrNotExist) {
				l.closeErr = err
			}
		}
		if err := l.Listener.Close(); l.closeErr == nil {
			l.closeErr = err
		}
		if lerr := l.lock.release(); l.closeErr == nil {
			l.closeErr = lerr
		}
	})
	return l.closeErr
}

// socketState is what is at the socket's path now.
type socketState int

const (
	socketOurs     socketState = iota // the file this listener bound
	socketGone                        // nothing, or a path through something that is no longer a directory
	socketReplaced                    // another file
	socketUnknown                     // the path could not be read
)

// stat says what is at the socket's path: the socket this listener bound,
// nothing, another file, or something that cannot be read, whose error is
// returned with it.
func (l *Listener) stat() (socketState, error) {
	cur, err := os.Lstat(l.paths.Socket)
	switch {
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return socketGone, nil
	case err != nil:
		return socketUnknown, err
	case !os.SameFile(cur, l.info):
		return socketReplaced, nil
	}
	return socketOurs, nil
}

// Run is the whole of a foreground agent: harden, listen, serve until told
// to stop, until SIGTERM or SIGINT, or until its socket is gone or another
// file is at its path. It
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
	interval := opts.WatchInterval
	if interval <= 0 {
		interval = watchInterval
	}
	go func() {
		// A fault in the watch stops the agent cleanly: going on without it
		// would leave an agent that no longer heard SIGTERM, since the
		// signals are still taken from the default, or watched its socket
		// (S59).
		defer s.recoverFault("the agent's watch of its socket", s.Stop)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// An error reading the path is logged once for the agent's life,
		// not at every tick. The watch goes on, since the socket may still
		// be there.
		said := false
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
				switch state, err := statSocket(l); state {
				case socketGone:
					logger.Printf("stopping: the socket %s is gone", l.paths.Socket)
					s.Stop()
					return
				case socketReplaced:
					logger.Printf("stopping: the socket %s was replaced by another file", l.paths.Socket)
					s.Stop()
					return
				case socketUnknown:
					if !said {
						logger.Printf("cannot check the socket, still serving: %v", err)
						said = true
					}
				}
			}
		}
	}()
	err = s.Serve(l)
	logger.Printf("stopped")
	return err
}

// statSocket is the watch's look at its socket, a variable so a test can
// plant a fault in the watch.
var statSocket = func(l *Listener) (socketState, error) { return l.stat() }
