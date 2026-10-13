//go:build unix

package agent

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestALooseRuntimeDirectoryIsRefusedAndAPlantedSocketIsNeverDialled is the
// second adversarial pass over F16 (530815d), from the review's
// adv2_runtimedir_test.go: the fix of that commit took a runtime directory
// of this user's own whose mode was loose and made it 0700 through the
// handle, and what another user put in it while it was loose stayed, since
// chmod does not take away a socket already bound. Here the listener is
// planted by this test, as the other user would have planted it while the
// directory was 0777. The directory is now refused with the sentence that
// names its mode and both remedies, it is left as it was rather than
// mended, and the planted socket is never dialled: the client is never
// made, so no connection reaches the listener and nothing is read there.
func TestALooseRuntimeDirectoryIsRefusedAndAPlantedSocketIsNeverDialled(t *testing.T) {
	base := shortBase(t)
	dir := filepath.Join(base, runtimeSubdir)
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	id, err := homeID(home)
	if err != nil {
		t.Fatal(err)
	}
	// The other user's socket, bound while the directory was 0777.
	ln, err := net.Listen("unix", filepath.Join(dir, id+".sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1<<16)
		n, _ := c.Read(buf)
		c.Close()
		accepted <- n
	}()

	c, err := NewClient(home)
	if err == nil {
		// Had it been taken, this is what the planted socket would hear.
		c.Unlock([]byte("correct horse battery staple"), time.Minute, ScopeReceive)
		t.Fatalf("a runtime directory of mode 0777 holding a planted socket was taken; it is now mode %04o", permOf(t, dir))
	}
	want := "agent: " + dir + " is mode 0777: the agent's directory is yours alone, and one " +
		"other users can reach may hold what they put there; look at what is in it and make " +
		"it 0700 (chmod 0700 " + dir + "), or set XDG_RUNTIME_DIR to a directory of your own"
	if err.Error() != want {
		t.Fatalf("NewClient over a 0777 runtime directory = %q,\nwant %q", err, want)
	}
	if got := permOf(t, dir); got != 0o777 {
		t.Fatalf("the refused runtime directory is mode %04o, want 0777 left as it was", got)
	}
	// The agent's own start goes through the same door.
	if l, err := Listen(t.TempDir()); err == nil {
		l.Close()
		t.Fatal("Listen served under a runtime directory of mode 0777")
	} else if !strings.Contains(err.Error(), dir+" is mode 0777") {
		t.Fatalf("Listen's refusal = %q, want the mode named", err)
	}
	if got := permOf(t, dir); got != 0o777 {
		t.Fatalf("the refused runtime directory is mode %04o after Listen, want 0777 left as it was", got)
	}
	select {
	case n := <-accepted:
		t.Fatalf("the planted socket accepted a connection and read %d bytes", n)
	case <-time.After(300 * time.Millisecond):
	}
	if names := entriesOf(t, dir); len(names) != 1 || names[0] != id+".sock" {
		t.Fatalf("the refused runtime directory holds %v, want the planted socket alone", names)
	}
}
