package auu

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
)

// strayProbeEnv marks the run TestAStrayRunOfTheTestBinaryRunsNoTests
// makes, so that should the guard it tests be missing, the suite that run
// would then start skips this test and starts nothing again.
const strayProbeEnv = "AUU_TEST_STRAY_PROBE"

// A run of this test binary as auu, without the helper switch, runs no
// tests: it says so and exits 2 at once (G35, R50a). Run as "agent run"
// it was a whole suite, which started an agent the same way, which ran a
// whole suite: the chain a mistaken spawn set off on 14 Oct.
func TestAStrayRunOfTheTestBinaryRunsNoTests(t *testing.T) {
	if os.Getenv(strayProbeEnv) != "" {
		t.Skip("the probe's own run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "agent", "run")
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, helperEnv+"=") && !strings.HasPrefix(kv, parentEnv+"=") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env, strayProbeEnv+"=1", "AUU_HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("the stray run: %v\n%s; want exit 2", err, out)
	}
	if !strings.Contains(string(out), `started as "agent run" without `+helperEnv+"=1; a test binary run as auu runs no tests") {
		t.Fatalf("the stray run said:\n%s", out)
	}
	if strings.Contains(string(out), "=== RUN") || strings.Contains(string(out), "PASS") {
		t.Fatalf("the stray run ran tests:\n%s", out)
	}
}

// An agent never starts another (G35, R50a): startAgent in a process whose
// environment carries the mark an agent is started with refuses, and no
// agent is started for the home.
func TestAnAgentNeverStartsAnother(t *testing.T) {
	agentEnv(t)
	t.Setenv(agentChildEnv, "1")
	home := t.TempDir()
	if err := startAgent(home); !errors.Is(err, errAgentStartsAgent) {
		t.Fatalf("startAgent under the mark: %v; want %v", err, errAgentStartsAgent)
	}
	paths, err := agent.PathsFor(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(paths.Socket); !os.IsNotExist(err) {
		t.Fatalf("an agent was started under the mark: its socket Lstat = %v", err)
	}
}

// The agent is started with the mark that stops it starting another, the
// home it serves, and this process's own environment beside them: the
// environment both platforms' spawn hand the agent.
func TestAnAgentIsStartedWithTheMark(t *testing.T) {
	env := agentEnviron("/a/home")
	has := map[string]bool{}
	for _, kv := range env {
		has[kv] = true
	}
	if !has[agentChildEnv+"=1"] || !has["AUU_HOME=/a/home"] {
		t.Fatalf("the agent's environment lacks the mark or the home: %v", env)
	}
	if len(env) != len(os.Environ())+2 {
		t.Fatalf("the agent's environment is %d entries; want this process's %d and two", len(env), len(os.Environ()))
	}
}
