//go:build unix

package auu

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/agent"
	"github.com/tropeforce7/agentuucp/internal/regular"
)

// TestTheAgentLogIsNeverOpenedThroughALink: startAgent opens the log beside
// the socket before it starts anything, and a symbolic link planted at the
// log's path is refused as a link rather than followed: a file of this
// user's own it points at keeps its bytes, not truncated, and the agent is
// not started, so no socket is made.
func TestTheAgentLogIsNeverOpenedThroughALink(t *testing.T) {
	base, err := os.MkdirTemp("", "auu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	t.Setenv("XDG_RUNTIME_DIR", base)
	home := t.TempDir()
	paths, err := agent.PathsFor(home)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "precious")
	if err := os.WriteFile(target, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, paths.Log); err != nil {
		t.Fatal(err)
	}
	err = startAgent(home)
	var me *regular.ModeError
	if err == nil || !errors.As(err, &me) || !strings.Contains(err.Error(), "is a symbolic link, not a regular file") {
		t.Fatalf("startAgent with a link at %s = %v, want the link refused as one", paths.Log, err)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "keep me" {
		t.Fatalf("the link's target holds %q (%v), want %q untouched", b, err, "keep me")
	}
	if _, err := os.Lstat(paths.Socket); !os.IsNotExist(err) {
		t.Fatalf("an agent was started: its socket Lstat = %v", err)
	}
}
