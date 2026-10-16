//go:build !(darwin || linux)

package agent

import (
	"bytes"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Where the platform gives no peer credentials (Windows, in the CI's
// Windows job), the notice that the runtime directory is relied on is the
// agent's to say, once, in its own log. A client asks the same question
// before it sends, and a client is a command, whose standard error is its
// user's: TestALockedCommandExits4WithOneSentence in internal/auu found
// the notice there, ahead of the one sentence (R70).

// syncBuffer is a log destination the agent's goroutines may write to
// while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const noPeerCredNotice = "no peer credentials on this platform"

func TestPeerCredSaysNothingWhereThePlatformHasNone(t *testing.T) {
	var std syncBuffer
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&std)
	t.Cleanup(func() { log.SetOutput(oldOut); log.SetFlags(oldFlags) })

	l, err := net.Listen("unix", filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	conn, err := net.DialTimeout("unix", l.Addr().String(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if peer := <-accepted; peer != nil {
		defer peer.Close()
	}
	for range 2 {
		c, err := PeerCred(conn.(*net.UnixConn))
		if err != nil {
			t.Fatal(err)
		}
		if c.UID != os.Getuid() || c.PID != -1 {
			t.Fatalf("PeerCred gave %+v, want the user's uid %d and PID -1", c, os.Getuid())
		}
	}
	if got := std.String(); got != "" {
		t.Fatalf("PeerCred wrote %q to the standard logger, which in a command is its standard error", got)
	}
}

func TestTheAgentSaysOnceThatItReliesOnTheRuntimeDirectory(t *testing.T) {
	runtimeDirFor(t)
	home := newFakeHome(t)
	var agentLog syncBuffer
	s := NewServer(home, Options{Log: log.New(&agentLog, "", 0)})
	l, err := Listen(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	defer func() { s.Stop(); <-done; l.Close() }()
	c, err := NewClient(home.Root())
	if err != nil {
		t.Fatal(err)
	}
	// Two connections of the user's own.
	for range 2 {
		if _, err := c.Status(); err != nil {
			t.Fatalf("status from the user's own agent: %v", err)
		}
	}
	if n := strings.Count(agentLog.String(), noPeerCredNotice); n != 1 {
		t.Fatalf("the agent's log says %q %d times over two connections, want once:\n%s", noPeerCredNotice, n, agentLog.String())
	}
}
