package auu

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
)

// The split proxy: its file, its control socket, and serve asking it.

// shortDir is a directory for a Unix socket: under the system temporary
// directory with a short name, since a socket path is at most 104 bytes on
// macOS and t.TempDir's are long.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "auup")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// splitProxy is a proxy with a control socket, started in this process
// with the given allow rule, in front of the fake upstream.
func splitProxy(t *testing.T, up *upstream, rule allowRule) (*keyProxy, *controlListener, *logBuffer, string) {
	t.Helper()
	p, logs := proxyFor(t, up)
	path := filepath.Join(shortDir(t), "control.sock")
	cl, err := startControl(p, path, rule)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	return p, cl, logs, path
}

// ownRule admits this process's uid.
func ownRule() allowRule {
	return allowRule{uids: map[int]bool{os.Getuid(): true}, gid: -1}
}

// dialControl opens a connection and returns it with a reader.
func dialControl(t *testing.T, path string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, bufio.NewReader(conn)
}

func say(t *testing.T, conn net.Conn, r *bufio.Reader, line string) string {
	t.Helper()
	fmt.Fprintln(conn, line)
	reply, err := readControlLine(r)
	if err != nil {
		return "closed: " + err.Error()
	}
	return reply
}

// The protocol from the same uid: PING answers, MINT hands out a live URL
// and holds the token for the connection, REVOKE ends it, a second MINT on
// one connection is refused and closes it, and closing the connection
// without a word revokes the token.
func TestControlSocketMintsForTheAllowedUidAndRevokesOnClose(t *testing.T) {
	up := newUpstream(t)
	p, _, logs, path := splitProxy(t, up, ownRule())

	conn, r := dialControl(t, path)
	if reply := say(t, conn, r, "PING"); reply != "OK" {
		t.Fatalf("PING: %q", reply)
	}
	// One request per connection: the socket has closed it.
	if _, err := readControlLine(r); err == nil {
		t.Fatal("the connection stayed open after PING")
	}

	conn, r = dialControl(t, path)
	reply := say(t, conn, r, "MINT")
	if !strings.HasPrefix(reply, "OK http://127.0.0.1:") {
		t.Fatalf("MINT: %q", reply)
	}
	base := strings.TrimPrefix(reply, "OK ")
	token := base[strings.LastIndex(base, "/")+1:]
	if p.state(token) != "live" || len(token) != 43 {
		t.Fatalf("the minted token is %q, %s", token, p.state(token))
	}
	if status, body := call(t, "POST", base+"/v1/messages", `{}`, map[string]string{"x-api-key": token}); status != 200 || body != `{"seen":true}` {
		t.Fatalf("through the split proxy: %d %s", status, body)
	}
	logged := waitForLog(t, logs, fmt.Sprintf("proxy: token %s minted for uid %d pid ", token[:8], os.Getuid()))
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if !strings.Contains(logged, fmt.Sprintf(" pid %d", os.Getpid())) {
			t.Fatalf("the mint is not logged with this pid:\n%s", logged)
		}
	}
	if reply := say(t, conn, r, "MINT"); reply != "ERR one mint per connection; close it to revoke" {
		t.Fatalf("a second MINT: %q", reply)
	}
	// The connection was closed with the refusal, and the token with it.
	if _, err := readControlLine(r); err == nil {
		t.Fatal("the connection stayed open after a second MINT")
	}
	waitState(t, p, token, "revoked token")

	// An explicit REVOKE on the minting connection.
	conn, r = dialControl(t, path)
	base = strings.TrimPrefix(say(t, conn, r, "MINT"), "OK ")
	token = base[strings.LastIndex(base, "/")+1:]
	if reply := say(t, conn, r, "REVOKE "+token); reply != "OK" {
		t.Fatalf("REVOKE: %q", reply)
	}
	waitState(t, p, token, "revoked token")
	if status, _ := call(t, "POST", base+"/v1/messages", `{}`, nil); status != 404 {
		t.Fatalf("a revoked token: %d", status)
	}

	// A close with no word at all revokes too: a serve that died.
	conn, r = dialControl(t, path)
	base = strings.TrimPrefix(say(t, conn, r, "MINT"), "OK ")
	token = base[strings.LastIndex(base, "/")+1:]
	conn.Close()
	waitState(t, p, token, "revoked token")

	// Nonsense, and a line too long.
	conn, r = dialControl(t, path)
	if reply := say(t, conn, r, "HELLO"); reply != `ERR unknown request "HELLO"; PING, MINT or REVOKE TOKEN` {
		t.Fatalf("HELLO: %q", reply)
	}
	conn, r = dialControl(t, path)
	if reply := say(t, conn, r, strings.Repeat("x", 2000)); !strings.HasPrefix(reply, "ERR a line longer than 1024 bytes") {
		t.Fatalf("a long line: %q", reply)
	}
}

// waitState waits for a token's state to settle, since a close is seen by
// the socket's goroutine a moment after the client made it.
func waitState(t *testing.T, p *keyProxy, token, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for p.state(token) != want {
		if time.Now().After(deadline) {
			t.Fatalf("token %s is %s, want %s", token[:8], p.state(token), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A connection from a uid the rule does not admit is closed before a byte
// is read, and logged with the uid. The rule admits uid+1 alone, so this
// process is the stranger; on Windows the socket carries no credentials
// and the directory is the check, as the agent says.
func TestControlSocketRefusesAnotherUidBeforeReading(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("an AF_UNIX socket on Windows carries no peer credentials")
	}
	up := newUpstream(t)
	p, _, logs, path := splitProxy(t, up, allowRule{uids: map[int]bool{os.Getuid() + 1: true}, gid: -1})
	conn, r := dialControl(t, path)
	fmt.Fprintln(conn, "MINT")
	if _, err := readControlLine(r); err == nil {
		t.Fatal("a stranger's MINT was answered")
	}
	logged := waitForLog(t, logs, fmt.Sprintf("proxy: refused a connection on the control socket from uid %d pid ", os.Getuid()))
	if strings.Contains(logged, "minted") {
		t.Fatal("a token was minted for a stranger")
	}
	// The group rule admits by primary group, which this process is in.
	rule := allowRule{uids: map[int]bool{}, gid: os.Getgid(), group: "own"}
	if !rule.allows(agentCred(os.Getuid(), os.Getgid())) {
		t.Fatal("the group rule refuses a peer whose primary group is the one")
	}
	if rule.allows(agentCred(os.Getuid()+1, os.Getgid()+1)) {
		t.Fatal("the group rule admits a peer in neither the uids nor the group")
	}
	// And serve's client says why it got nothing.
	src := &controlSource{path: path}
	if _, _, _, err := src.mint(); err == nil || !strings.Contains(err.Error(), "closed without answering; the proxy refuses this uid, or is not the proxy") {
		t.Fatalf("serve's mint against a socket that refuses it: %v", err)
	}
	if err := src.ping(); err == nil || !strings.Contains(err.Error(), "closed without answering") {
		t.Fatalf("serve's ping against a socket that refuses it: %v", err)
	}
	_ = p
}

// The proxy's own file: v, both key_file and control required, the
// address rules, unknown keys refused, and a bad uid.
func TestTheProxysOwnFileIsChecked(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	os.WriteFile(keyFile, []byte(realKey+"\n"), 0o600)
	write := func(t *testing.T, v any) string {
		t.Helper()
		path := filepath.Join(dir, "proxy.json")
		data, _ := json.Marshal(v)
		os.WriteFile(path, data, 0o600)
		return path
	}
	for _, c := range []struct {
		label string
		file  map[string]any
		want  string
	}{
		{"no v", map[string]any{"key_file": keyFile, "control": "/tmp/x"}, "v is 0; this auu understands version 1"},
		{"no key_file", map[string]any{"v": 1, "control": "/tmp/x"}, "key_file is required; it is the file the proxy holds the key from"},
		{"no control", map[string]any{"v": 1, "key_file": keyFile}, "control is required; it is the socket auu serve asks for tokens on"},
		{"a listen off the host", map[string]any{"v": 1, "key_file": keyFile, "control": "/tmp/x", "listen": "0.0.0.0:1"}, "is not a loopback address"},
		{"an http upstream off the host", map[string]any{"v": 1, "key_file": keyFile, "control": "/tmp/x", "upstream": "http://api.example.com"}, "plain http and not on this host"},
		{"an unknown key", map[string]any{"v": 1, "key_file": keyFile, "control": "/tmp/x", "port": 1}, `unknown field "port"`},
		{"a negative uid", map[string]any{"v": 1, "key_file": keyFile, "control": "/tmp/x", "allow_uids": []int{-1}}, "allow_uids has -1, which is not a uid"},
	} {
		t.Run(c.label, func(t *testing.T) {
			_, err := loadProxyFile(write(t, c.file))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
	f, err := loadProxyFile(write(t, map[string]any{"v": 1, "key_file": keyFile, "control": "/tmp/x", "allow_uids": []int{1000, 1001}}))
	if err != nil || f.Listen != defaultProxyListen || f.Upstream != defaultProxyUpstream || len(f.AllowUIDs) != 2 {
		t.Fatalf("a good file: %+v, %v", f, err)
	}
	if _, err := loadProxyFile(filepath.Join(dir, "nothing.json")); err == nil || !strings.Contains(err.Error(), "the split proxy is one file, and there is none here") {
		t.Fatalf("a missing file: %v", err)
	}
	// The rule from the file: the uids as given and no group; with
	// neither, the process's own primary group.
	rule, err := allowRuleFor(&f.proxyConfig)
	if err != nil || !rule.uids[1000] || !rule.uids[1001] || rule.gid != -1 {
		t.Fatalf("the rule from allow_uids: %+v, %v", rule, err)
	}
	rule, err = allowRuleFor(&proxyConfig{})
	if err != nil || rule.gid != os.Getgid() || len(rule.uids) != 0 {
		t.Fatalf("the default rule: %+v, %v", rule, err)
	}
	if _, err := allowRuleFor(&proxyConfig{AllowGroup: "no-such-group-here"}); err == nil {
		t.Fatal("a group that does not exist was accepted")
	}
	// The socket's directory must be there.
	if _, err := startControl(nil, filepath.Join(dir, "missing", "control.sock"), rule); err == nil || !strings.Contains(err.Error(), "is not there") {
		t.Fatalf("a control path in a missing directory: %v", err)
	}
	// The socket is given to the allowed group, which the proxy must be a
	// member of: gid 0 is one this process is not in, unless it is root.
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		p, _ := proxyFor(t, newUpstream(t))
		_, err := startControl(p, filepath.Join(shortDir(t), "control.sock"), allowRule{uids: map[int]bool{}, gid: 0, group: "root"})
		if err == nil || !strings.Contains(err.Error(), "giving it to group root: ") || !strings.Contains(err.Error(), "SupplementaryGroups=root in its unit") {
			t.Fatalf("a group the proxy is not in: %v", err)
		}
	}
}

// serve against a split proxy, end to end: the handler's environment
// carries the token from the proxy process and never the key, its request
// goes through, the twin's token is dead, and the proxy's log names
// serve's uid; then a control socket nobody listens on is the message's
// failure in the ledger, not a crash, and check says both sentences.
func TestServeAsksTheSplitProxyForATokenPerInvocation(t *testing.T) {
	up := newUpstream(t)
	alice, bob := newExpert(t, modeReadOnly)
	_, _, logs, path := splitProxy(t, up, ownRule())
	bob.config.Proxy = &proxyConfig{Control: path}
	bob.write(t)
	t.Setenv(envAPIKey, realKey)

	out := bob.run("serve", "check")
	if !strings.Contains(out, "proxy: control "+path+" (answering)\n") {
		t.Fatalf("serve check against a running proxy:\n%s", out)
	}
	envFile := filepath.Join(bob.home, "handler-environ")
	urlFile := filepath.Join(bob.home, "base-url")
	t.Setenv(handlerScript, "environ:"+envFile+";askold:"+urlFile+";save:"+urlFile+";ask")
	first := alice.ask(t, "jostle", "first", "through the split proxy")
	second := alice.ask(t, "jostle", "second", "and again")
	var stderr string
	var report roundJSON
	stderr = captureStderr(t, func() { report = bob.round(t) })
	if len(report.Answered) != 2 || len(report.Failed) != 0 {
		t.Fatalf("the round: %+v\n%s", report, stderr)
	}
	environ, _ := os.ReadFile(envFile)
	if strings.Contains(string(environ), realKey) {
		t.Fatalf("the real key is in the handler's environment:\n%s", environ)
	}
	vars := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(environ)), "\n") {
		name, value, _ := strings.Cut(line, "=")
		vars[name] = value
	}
	base, token := vars[envBaseURL], vars[envAPIKey]
	if !strings.HasPrefix(base, "http://127.0.0.1:") || len(token) != 43 || !strings.HasSuffix(base, "/"+token) {
		t.Fatalf("the handler was given %s=%q %s=%q", envBaseURL, base, envAPIKey, token)
	}
	if text := alice.replyOn(t, first.Thread).Text; text != "no saved url\nstatus 200 {\"seen\":true}" {
		t.Fatalf("the first: %q", text)
	}
	if text := alice.replyOn(t, second.Thread).Text; text != "old status 404\nstatus 200 {\"seen\":true}" {
		t.Fatalf("the second, asking the first's URL: %q", text)
	}
	seen := up.requests()
	if len(seen) != 2 || seen[0].key != realKey || seen[1].key != realKey {
		t.Fatalf("upstream saw %+v", seen)
	}
	if !strings.Contains(stderr, "proxy: asking "+path+" for a token per invocation") || strings.Contains(stderr, "minted") {
		t.Fatalf("serve's own output should say where it asks and nothing of the mint:\n%s", stderr)
	}
	// The revocation is written by the socket's goroutine after serve
	// closed the connection, so the count is waited for; a third of
	// either would be a bug, and is looked for once the two are there.
	waitForLogCount(t, logs, fmt.Sprintf("minted for uid %d", os.Getuid()), 2)
	logged := waitForLogCount(t, logs, " revoked\n", 2)
	if c := strings.Count(logged, fmt.Sprintf("minted for uid %d", os.Getuid())); c != 2 {
		t.Fatalf("the proxy logged %d mints for serve's uid, want 2:\n%s", c, logged)
	}
	if c := strings.Count(logged, " revoked\n"); c != 2 {
		t.Fatalf("the proxy logged %d revocations, want 2:\n%s", c, logged)
	}

	// Nobody listening: the message fails and is retried, serve goes on.
	gone := filepath.Join(shortDir(t), "nobody.sock")
	bob.config.Proxy = &proxyConfig{Control: gone}
	bob.write(t)
	out = bob.run("serve", "check")
	if !strings.Contains(out, "proxy: control "+gone+" (nobody is listening; auu serve will fail each message until it is: ") {
		t.Fatalf("serve check against nobody:\n%s", out)
	}
	third := alice.ask(t, "jostle", "third", "nobody home")
	var failed string
	failed = captureStderr(t, func() {
		out, err := bob.tryRun("serve", "--once", "--json")
		if err == nil {
			t.Fatalf("a round with the proxy gone succeeded:\n%s", out)
		}
		json.Unmarshal([]byte(out), &report)
	})
	if len(report.Failed) != 1 || report.Failed[0].ID != third.ID {
		t.Fatalf("the round with the proxy gone: %+v", report)
	}
	if !strings.Contains(failed, "was not answered: the proxy's control socket "+gone+": dial unix") {
		t.Fatalf("the failure sentence:\n%s", failed)
	}
	entry := bob.ledgerOf(t).Messages[third.ID]
	if entry == nil || entry.Failures != 1 || !entry.Handled.IsZero() || entry.GaveUp {
		t.Fatalf("the ledger entry: %+v", entry)
	}
}

// agentCred is a Cred for the rule tests.
func agentCred(uid, gid int) agent.Cred { return agent.Cred{UID: uid, GID: gid, PID: -1} }

// A fault answering one connection to the control socket closes that
// connection, and the socket answers the next (S59): the connection's
// goroutine is outside every HTTP handler, so a panic there ended serve and
// every handler's token with it. The fault is said once with its stack.
func TestAFaultInAControlConnectionEndsThatConnection(t *testing.T) {
	up := newUpstream(t)
	// Set before the listener starts, which copies it, and put back once
	// it has: nothing the listener runs reads the variable again.
	old := controlLine
	var faulted atomic.Bool
	controlLine = func(r *bufio.Reader) (string, error) {
		if faulted.CompareAndSwap(false, true) {
			panic("a fault planted in a control connection")
		}
		return readControlLine(r)
	}
	_, _, logs, path := splitProxy(t, up, ownRule())
	controlLine = old

	conn, r := dialControl(t, path)
	if reply := say(t, conn, r, "PING"); !strings.HasPrefix(reply, "closed: ") {
		t.Fatalf("the faulted connection answered %q", reply)
	}
	conn, r = dialControl(t, path)
	if reply := say(t, conn, r, "PING"); reply != "OK" {
		t.Fatalf("the connection after a fault: %q; logs:\n%s", reply, logs.String())
	}
	said := logs.String()
	if n := strings.Count(said, "a connection to the control socket ended with a fault"); n != 1 ||
		!strings.Contains(said, "a fault planted in a control connection") || !strings.Contains(said, "goroutine ") {
		t.Fatalf("the fault was said %d times, want once with its stack:\n%s", n, said)
	}
}
