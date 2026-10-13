//go:build unix

package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// peerHelperEnv makes this test's binary, run again under another uid, the
// other user's listener: it binds the socket named in the variable, says
// "ready", accepts one connection, and says how many bytes it read.
const peerHelperEnv = "AUU_TEST_PEER_LISTENER"

// TestTheClientSendsNothingToASocketAnsweredByAnotherUser: the client asks
// the kernel who answers on the socket before it sends a byte. A socket
// another user is listening on, at the path in a runtime directory that is
// this user's own and 0700 (the rename that put it there is the other
// user's having bound it while the directory was open to them), is refused
// with the sentence naming both uids, and the listener reads nothing: not
// the request, not the passphrase. Binding as another uid needs root, so
// that row runs as root alone, the listener being this test's binary run
// again under the nobody account, and is skipped otherwise. The control
// runs as anyone: a listener this test runs itself, the same uid, is sent
// the request whole, passphrase and all, so the check refuses nobody's own.
func TestTheClientSendsNothingToASocketAnsweredByAnotherUser(t *testing.T) {
	if path := os.Getenv(peerHelperEnv); path != "" {
		peerHelper(path)
		return
	}
	pass := []byte("correct horse battery staple")

	t.Run("another uid", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("binding a socket as another uid needs root; run as root (the container suite's machines are) to take this row")
		}
		nobody, err := user.Lookup("nobody")
		if err != nil {
			t.Skipf("no nobody account to listen as: %v", err)
		}
		uid, _ := strconv.Atoi(nobody.Uid)
		gid, _ := strconv.Atoi(nobody.Gid)
		home := t.TempDir()
		base := shortBase(t)
		if err := os.Chmod(base, 0o755); err != nil {
			t.Fatal(err)
		}
		c, err := NewClient(home) // makes base/auu, 0700, root's
		if err != nil {
			t.Fatal(err)
		}
		// Where nobody may bind, and where nobody may run this binary from.
		stage := filepath.Join(base, "stage")
		if err := os.Mkdir(stage, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stage, 0o777); err != nil {
			t.Fatal(err)
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(stage, "agent.test")
		copyFile(t, exe, bin, 0o755)
		staged := filepath.Join(stage, "s.sock")
		cmd := exec.Command(bin, "-test.run=^TestTheClientSendsNothingToASocketAnsweredByAnotherUser$", "-test.count=1")
		cmd.Env = append(os.Environ(), peerHelperEnv+"="+staged)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true}}
		cmd.Stderr = os.Stderr
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatalf("running the listener as uid %d: %v", uid, err)
		}
		defer cmd.Wait()
		lines := helperLines(out)
		if l := <-lines; l != "ready" {
			t.Fatalf("the listener as uid %d said %q, want ready", uid, l)
		}
		if err := os.Rename(staged, c.Socket()); err != nil {
			t.Fatal(err)
		}
		err = c.Unlock(pass, time.Minute, ScopeReceive)
		want := fmt.Sprintf("agent: %s is answered by uid %d, not by you (uid %d); nothing was sent. "+
			"Remove it, or set XDG_RUNTIME_DIR to a directory of your own", c.Socket(), uid, os.Getuid())
		if err == nil || err.Error() != want {
			t.Fatalf("Unlock to a socket uid %d answers = %v,\nwant %q", uid, err, want)
		}
		select {
		case l := <-lines:
			if l != "read 0" {
				t.Fatalf("the listener as uid %d: %q, want read 0: something was sent", uid, l)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the listener said nothing about what it read")
		}
	})

	t.Run("this uid", func(t *testing.T) {
		home := t.TempDir()
		shortBase(t)
		c, err := NewClient(home)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("unix", c.Socket())
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		got := make(chan request, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			frame, err := readFrame(conn)
			if err != nil {
				return
			}
			var req request
			if json.Unmarshal(frame, &req) != nil {
				return
			}
			writeFrame(conn, []byte(`{"ok":true}`))
			got <- req
		}()
		if err := c.Unlock(pass, time.Minute, ScopeReceive); err != nil {
			t.Fatalf("Unlock to a socket this uid answers: %v", err)
		}
		select {
		case req := <-got:
			if req.Op != OpUnlock || string(req.Passphrase) != string(pass) {
				t.Fatalf("the listener this uid runs was sent op %q passphrase %q, want the unlock whole", req.Op, req.Passphrase)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the listener this uid runs was sent nothing")
		}
	})
}

// peerHelper is the other user's side: bind, say ready, take one
// connection, say how much it read, and return.
func peerHelper(path string) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		fmt.Printf("listen: %v\n", err)
		return
	}
	defer ln.Close()
	fmt.Println("ready")
	ln.(*net.UnixListener).SetDeadline(time.Now().Add(10 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		fmt.Printf("accept: %v\n", err)
		return
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	n, _ := io.Copy(io.Discard, conn)
	conn.Close()
	fmt.Printf("read %d\n", n)
}

// helperLines is the helper's own lines, the test framework's left out.
func helperLines(r io.Reader) <-chan string {
	ch := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			l := sc.Text()
			if l == "ready" || strings.HasPrefix(l, "read ") || strings.HasPrefix(l, "listen: ") || strings.HasPrefix(l, "accept: ") {
				ch <- l
			}
		}
		close(ch)
	}()
	return ch
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(to, mode); err != nil {
		t.Fatal(err)
	}
}
