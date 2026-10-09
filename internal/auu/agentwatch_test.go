package auu

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
)

// TestADetachedAgentStopsWhenItsSocketIsGone: the agent 'auu passphrase
// set' leaves running, in a session of its own, is one nobody can reach
// once its socket is removed, and it exits rather than go on holding the
// keys. The process is watched by its pid, which the agent's log names,
// and the helper's watch is helperWatchInterval, set in TestMain.
func TestADetachedAgentStopsWhenItsSocketIsGone(t *testing.T) {
	u := encryptedUser(t, "alice", startRelay(t))
	paths, err := agent.PathsFor(u.home)
	if err != nil {
		t.Fatal(err)
	}
	logged, err := os.ReadFile(paths.Log)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`\(pid (\d+)\)`).FindSubmatch(logged)
	if m == nil {
		t.Fatalf("the agent's log does not name its pid:\n%s", logged)
	}
	pid, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	// Found before the socket goes, so that the process is there to find:
	// on Windows nothing else holds it open once it exits. On Unix it is
	// this process's child, and Wait is also what reaps it.
	p, err := os.FindProcess(pid)
	if err != nil {
		t.Fatalf("the agent (pid %d) is not there to watch: %v", pid, err)
	}
	exited := make(chan error, 1)
	go func() {
		_, err := p.Wait()
		exited <- err
	}()
	if !u.agentStatus().Running {
		t.Fatal("the agent is not running before its socket is removed")
	}
	if err := os.Remove(paths.Socket); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("waiting for the agent (pid %d): %v", pid, err)
		}
	case <-time.After(10 * time.Second):
		p.Kill()
		t.Fatalf("the agent (pid %d) was still running ten seconds after its socket was removed", pid)
	}
	logged, err = os.ReadFile(paths.Log)
	if err != nil {
		t.Fatal(err)
	}
	if want := "stopping: the socket " + paths.Socket + " is gone"; !strings.Contains(string(logged), want) {
		t.Errorf("the agent's log does not say %q:\n%s", want, logged)
	}
	if st := u.agentStatus(); st.Running {
		t.Errorf("status says an agent is running after it exited: %+v", st)
	}
}
