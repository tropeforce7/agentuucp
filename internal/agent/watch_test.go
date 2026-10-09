package agent

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The watch in Run: an agent whose socket is gone, or is another file now,
// stops, and leaves whatever is at the path alone. These run Run itself in
// this process, as TestTheAgentDeniesAttachment runs Harden, with the watch
// made short through Options.WatchInterval.

// testWatch is the interval these tests give the watch.
const testWatch = 20 * time.Millisecond

// stopBound is how long a watched agent is allowed to notice. The claim is
// "it stops", not how fast this machine is; a passing run stops at the
// first tick.
const stopBound = 5 * time.Second

// logBuffer is a log the agent's goroutines write and the test reads.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// watched is an agent running under Run.
type watched struct {
	home   *fakeHome
	paths  *Paths
	client *Client
	log    *logBuffer
	done   chan error
	cancel context.CancelFunc
}

// runWatched starts Run for a fake home with the watch at interval, and
// returns once the agent answers.
func runWatched(t *testing.T, interval time.Duration) *watched {
	t.Helper()
	runtimeDirFor(t)
	home := newFakeHome(t)
	paths, err := PathsFor(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &watched{home: home, paths: paths, client: c, log: &logBuffer{}, done: make(chan error, 1), cancel: cancel}
	go func() {
		w.done <- Run(ctx, home, Options{WatchInterval: interval, Log: log.New(w.log, "", 0)})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-w.done:
		case <-time.After(stopBound):
			t.Errorf("Run did not return after its context was cancelled; log:\n%s", w.log.String())
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := c.Status(); err == nil {
			return w
		}
		select {
		case err := <-w.done:
			t.Fatalf("Run returned before the agent answered: %v; log:\n%s", err, w.log.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent did not answer within ten seconds; log:\n%s", w.log.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stopped waits for Run to return on its own, within stopBound.
func (w *watched) stopped(t *testing.T) {
	t.Helper()
	select {
	case err := <-w.done:
		w.done <- err // for the Cleanup
		if err != nil {
			t.Fatalf("Run returned %v; log:\n%s", err, w.log.String())
		}
	case <-time.After(stopBound):
		t.Fatalf("Run did not stop within %v; log:\n%s", stopBound, w.log.String())
	}
}

// running asserts Run has not returned for as long as d.
func (w *watched) running(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case err := <-w.done:
		w.done <- err
		t.Fatalf("Run returned (%v) when it should still be serving; log:\n%s", err, w.log.String())
	case <-time.After(d):
	}
}

// replaceWith puts a file at the socket's path in one step: written beside
// it and renamed over it, so the watch never sees the path empty and calls
// it gone, and the new file cannot be given the socket's inode number back.
func replaceWith(t *testing.T, path string, content []byte) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestAnAgentStopsWhenItsSocketIsGone(t *testing.T) {
	w := runWatched(t, testWatch)
	if err := os.Remove(w.paths.Socket); err != nil {
		t.Fatal(err)
	}
	w.stopped(t)
	if want := "stopping: the socket " + w.paths.Socket + " is gone"; !strings.Contains(w.log.String(), want) {
		t.Errorf("the log does not say %q:\n%s", want, w.log.String())
	}
	socks, err := filepath.Glob(filepath.Join(w.paths.Dir, "*.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 0 {
		t.Errorf("the runtime directory holds a socket after the agent stopped: %v", socks)
	}
	if _, err := w.client.Status(); !errors.Is(err, ErrNotRunning) {
		t.Errorf("status after the agent stopped gave %v, want ErrNotRunning", err)
	}
}

func TestAnAgentStopsWhenItsSocketIsReplaced(t *testing.T) {
	w := runWatched(t, testWatch)
	content := []byte("not the agent's socket\n")
	replaceWith(t, w.paths.Socket, content)
	w.stopped(t)
	if want := "stopping: the socket " + w.paths.Socket + " was replaced by another file"; !strings.Contains(w.log.String(), want) {
		t.Errorf("the log does not say %q:\n%s", want, w.log.String())
	}
	if strings.Contains(w.log.String(), "is gone") {
		t.Errorf("a replaced socket was called gone:\n%s", w.log.String())
	}
	// Close removes the path only while it is the agent's own socket; the
	// file put there is somebody else's and is left as it was.
	got, err := os.ReadFile(w.paths.Socket)
	if err != nil {
		t.Fatalf("the file that replaced the socket is gone after the agent stopped: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("the file that replaced the socket now holds %q", got)
	}
}

// TestTheWatchSeesTheRuntimeDirectoryGo: the auu runtime directory removed
// whole, as logout clears everything under $XDG_RUNTIME_DIR on Linux, is
// the socket gone;
// and so is the directory replaced by a file, which reads as ENOTDIR and
// not as a missing file.
func TestTheWatchSeesTheRuntimeDirectoryGo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows the agent's lock is a handle opened with no sharing, so the runtime directory holding it cannot be removed while the agent runs")
	}
	t.Run("removed", func(t *testing.T) {
		w := runWatched(t, testWatch)
		if err := os.RemoveAll(w.paths.Dir); err != nil {
			t.Fatal(err)
		}
		w.stopped(t)
		if want := "stopping: the socket " + w.paths.Socket + " is gone"; !strings.Contains(w.log.String(), want) {
			t.Errorf("the log does not say %q:\n%s", want, w.log.String())
		}
	})
	t.Run("a file in its place", func(t *testing.T) {
		w := runWatched(t, testWatch)
		if err := os.RemoveAll(w.paths.Dir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(w.paths.Dir, []byte("not a directory\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(w.paths.Dir) })
		w.stopped(t)
		if want := "stopping: the socket " + w.paths.Socket + " is gone"; !strings.Contains(w.log.String(), want) {
			t.Errorf("the log does not say %q:\n%s", want, w.log.String())
		}
		if strings.Contains(w.log.String(), "cannot check the socket") {
			t.Errorf("ENOTDIR was taken for an unreadable path, not a gone one:\n%s", w.log.String())
		}
	})
}

// TestAStoppedAgentLeavesAReplacementSocketAlone: another agent's socket at
// the path is a replacement like any other file, and the first agent's
// going must not take it with it. Go unlinks a socket it bound when the
// listener closes, whatever is at the path by then, which is what this
// would catch.
func TestAStoppedAgentLeavesAReplacementSocketAlone(t *testing.T) {
	w := runWatched(t, testWatch)
	// Bound beside the path and renamed onto it, for the reason
	// replaceWith gives; the listener is this test's, closed by it.
	tmp := w.paths.Socket + ".new"
	second, err := net.Listen("unix", tmp)
	if err != nil {
		t.Fatal(err)
	}
	second.(*net.UnixListener).SetUnlinkOnClose(false)
	t.Cleanup(func() {
		second.Close()
		os.Remove(w.paths.Socket)
		os.Remove(tmp)
	})
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := second.Accept()
			if err != nil {
				return
			}
			c.Close()
			accepted <- struct{}{}
		}
	}()
	if err := os.Rename(tmp, w.paths.Socket); err != nil {
		t.Fatal(err)
	}
	w.stopped(t)
	if want := "stopping: the socket " + w.paths.Socket + " was replaced by another file"; !strings.Contains(w.log.String(), want) {
		t.Errorf("the log does not say %q:\n%s", want, w.log.String())
	}
	if _, err := os.Lstat(w.paths.Socket); err != nil {
		t.Fatalf("the second socket is gone after the first agent stopped: %v", err)
	}
	conn, err := net.DialTimeout("unix", w.paths.Socket, 5*time.Second)
	if err != nil {
		t.Fatalf("the second socket does not accept a connection after the first agent stopped: %v", err)
	}
	conn.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection did not reach the second listener")
	}
}

// TestAZeroWatchIntervalIsTheDefault: Options.WatchInterval zero is the
// thirty-second default, not a zero-length ticker, which panics, and not a
// tight loop. What can be shown cheaply is the negative: with the socket
// gone, an agent at the default is still running well past many test
// intervals. The test does not wait thirty seconds to show the exact
// number.
func TestAZeroWatchIntervalIsTheDefault(t *testing.T) {
	w := runWatched(t, 0)
	if err := os.Remove(w.paths.Socket); err != nil {
		t.Fatal(err)
	}
	w.running(t, 15*testWatch)
	w.cancel()
	w.stopped(t)
	if want := "stopping: " + context.Canceled.Error(); !strings.Contains(w.log.String(), want) {
		t.Errorf("the agent stopped for something other than its context:\n%s", w.log.String())
	}
	if strings.Contains(w.log.String(), "is gone") {
		t.Errorf("an agent at the default interval saw the socket gone at once:\n%s", w.log.String())
	}
}

// TestAnUnreadableSocketPathIsSaidOnceAndServed: a path the agent cannot
// stat is not a path that is gone. It is logged once, however many ticks
// pass, and the agent goes on; once the path can be read again, it still
// answers on its socket.
func TestAnUnreadableSocketPathIsSaidOnceAndServed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a directory's mode on Windows is the read-only attribute and does not stop a stat")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads through a directory of mode 0000")
	}
	w := runWatched(t, testWatch)
	if err := os.Chmod(w.paths.Dir, 0); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if !restored {
			os.Chmod(w.paths.Dir, 0o700)
			restored = true
		}
	}
	t.Cleanup(restore)
	const said = "cannot check the socket" // the line's own words
	deadline := time.Now().Add(stopBound)
	for !strings.Contains(w.log.String(), said) {
		if time.Now().After(deadline) {
			t.Fatalf("the agent never said it cannot check its socket; log:\n%s", w.log.String())
		}
		w.running(t, testWatch)
	}
	// Many more ticks, and the agent neither stops nor says it again.
	w.running(t, 15*testWatch)
	restore()
	if _, err := w.client.Status(); err != nil {
		t.Fatalf("the agent does not answer once its socket can be read again: %v; log:\n%s", err, w.log.String())
	}
	logged := w.log.String()
	if n := strings.Count(logged, said); n != 1 {
		t.Errorf("the unreadable path was logged %d times, want once:\n%s", n, logged)
	}
	if !strings.Contains(logged, "still serving") {
		t.Errorf("the log does not say the agent goes on:\n%s", logged)
	}
	if strings.Contains(logged, "stopping") {
		t.Errorf("an unreadable path stopped the agent:\n%s", logged)
	}
}

// TestStatusSaysNoAgentForAFileThatIsNotASocket: a plain file at the
// socket's path is no agent. A socket replaced by a plain file leaves
// exactly that. macOS dials it as ENOTSOCK and Linux as ECONNREFUSED.
func TestStatusSaysNoAgentForAFileThatIsNotASocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the ENOTSOCK this proves is a Unix answer; Windows' refusedErrnos are not changed and claim nothing for a plain file")
	}
	runtimeDirFor(t)
	home := newFakeHome(t)
	paths, err := PathsFor(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Socket, []byte("not a socket\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Status(); !errors.Is(err, ErrNotRunning) {
		t.Errorf("status against a plain file gave %v, want ErrNotRunning", err)
	}
}
