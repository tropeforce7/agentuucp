package auu

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tropeforce7/agentuucp/internal/agent"
)

// The split proxy: the same proxy as its own process, run as a second
// account, so that the key is out of the handler's reach altogether. It
// reads a file of its own, holds the key, listens on loopback as the
// in-process proxy does, and opens a control socket — a Unix socket on
// which a caller the kernel says is one of the allowed uids, or in the
// allowed group, asks for a token and holds it for as long as the
// connection lives. auu serve, with control set in its own file, asks that
// socket for a token per invocation instead of running a proxy itself.
//
// The protocol is one line each way, readable with nc:
//
//	PING            OK
//	MINT            OK http://127.0.0.1:PORT/TOKEN
//	REVOKE TOKEN    OK, and the connection is closed
//
// A connection is one mint, and its close is the revoke: a serve that dies
// mid-invocation takes its token with it. Anything else is ERR and a close.

// defaultProxyFile is where 'auu serve proxy' reads its file when --config
// names none: the proxy runs as an account of its own, with no auu home.
const defaultProxyFile = "/etc/auu-proxy/proxy.json"

// controlLineMax bounds a line on the control socket.
const controlLineMax = 1024

// proxyFile is the split proxy's own file: v, and the section's keys at
// the top level. key_file and control are both required here — the proxy
// holds the key and listens for callers — where the expert's serve.json
// carries control alone and never names where the key is.
type proxyFile struct {
	V int `json:"v"`
	proxyConfig
	path string
}

// loadProxyFile reads and checks the proxy's file.
func loadProxyFile(path string) (*proxyFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, usageErrf("no %s; the split proxy is one file, and there is none here", path)
	}
	if err != nil {
		return nil, err
	}
	f := &proxyFile{path: path}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(f); err != nil {
		return nil, usageErrf("%s: %v", path, err)
	}
	if f.V != 1 {
		return nil, usageErrf("%s: v is %d; this %s understands version 1", path, f.V, prog)
	}
	f.fill()
	perr := func(format string, a ...any) error {
		return usageErrf("%s: %s", path, fmt.Sprintf(format, a...))
	}
	if strings.TrimSpace(f.KeyFile) == "" {
		return nil, perr("key_file is required; it is the file the proxy holds the key from")
	}
	if strings.TrimSpace(f.Control) == "" {
		return nil, perr("control is required; it is the socket auu serve asks for tokens on")
	}
	if err := f.checkAddresses(perr); err != nil {
		return nil, err
	}
	for _, uid := range f.AllowUIDs {
		if uid < 0 {
			return nil, perr("allow_uids has %d, which is not a uid", uid)
		}
	}
	return f, nil
}

// allowRule is who may use the control socket, from the file.
type allowRule struct {
	uids  map[int]bool
	gid   int
	group string
}

// allowRuleFor resolves the file's allow keys: the uids as given, and the
// group by name to its gid, or the proxy's own primary group when the file
// names neither.
func allowRuleFor(f *proxyConfig) (allowRule, error) {
	rule := allowRule{uids: map[int]bool{}, gid: -1}
	for _, uid := range f.AllowUIDs {
		rule.uids[uid] = true
	}
	switch {
	case f.AllowGroup != "":
		g, err := osuser.LookupGroup(f.AllowGroup)
		if err != nil {
			return rule, fmt.Errorf("proxy: allow_group %q: %v", f.AllowGroup, err)
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			return rule, fmt.Errorf("proxy: allow_group %q has gid %q", f.AllowGroup, g.Gid)
		}
		rule.gid, rule.group = gid, f.AllowGroup
	case len(f.AllowUIDs) == 0:
		rule.gid = os.Getgid()
		if g, err := osuser.LookupGroupId(strconv.Itoa(rule.gid)); err == nil {
			rule.group = g.Name
		} else {
			rule.group = strconv.Itoa(rule.gid)
		}
	}
	return rule, nil
}

// allows says whether a peer may use the socket: its uid is listed, or its
// primary group is the one, or the group is among the groups the platform
// handed over with the credentials, or, failing those, among the ones the
// account database lists for it.
func (r allowRule) allows(c agent.Cred) bool {
	if r.uids[c.UID] {
		return true
	}
	if r.gid < 0 {
		return false
	}
	if c.GID == r.gid {
		return true
	}
	for _, g := range c.Groups {
		if g == r.gid {
			return true
		}
	}
	if c.Groups == nil && c.UID >= 0 {
		if u, err := osuser.LookupId(strconv.Itoa(c.UID)); err == nil {
			if ids, err := u.GroupIds(); err == nil {
				for _, id := range ids {
					if id == strconv.Itoa(r.gid) {
						return true
					}
				}
			}
		}
	}
	return false
}

// describe is the rule as the startup line says it.
func (r allowRule) describe() string {
	var parts []string
	if len(r.uids) > 0 {
		uids := make([]string, 0, len(r.uids))
		for uid := range r.uids {
			uids = append(uids, strconv.Itoa(uid))
		}
		parts = append(parts, "uid "+plainList(uids))
	}
	if r.gid >= 0 {
		parts = append(parts, "group "+r.group)
	}
	return strings.Join(parts, " or ")
}

// controlListener is the control socket, serving.
type controlListener struct {
	ln   net.Listener
	path string
	done chan struct{}
}

// startControl opens the control socket for a proxy: refuses a directory
// that is not there, replaces a socket file nobody answers on and refuses
// one somebody does, makes the socket 0660 and gives it, and the
// directory when the directory is the proxy's, to the allowed group, so
// that group's members may knock and nobody else can, and serves. The
// peer's credentials decide after that.
//
// The group is the callers' own, never the proxy's: a caller put in the
// proxy's group to reach the socket would be in the group that may read
// the key file, which is the whole of what the split proxy exists to
// prevent. Giving a file to another group needs the proxy to be a member
// of it, which is the unit's SupplementaryGroups= line.
func startControl(p *keyProxy, path string, rule allowRule) (*controlListener, error) {
	dir := filepath.Dir(path)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("proxy: control %s: the directory %s is not there; the unit's RuntimeDirectory makes it, or make it 0750 for the proxy's user", path, dir)
	}
	if _, err := os.Stat(path); err == nil {
		// Something is at the path. Another proxy answering there keeps
		// it; a stale file from a proxy that is gone is removed.
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("proxy: control %s: another proxy is already listening there", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("proxy: control %s: removing the stale socket: %v", path, err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("proxy: control %s: %v", path, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o660); err != nil {
			ln.Close()
			return nil, fmt.Errorf("proxy: control %s: making it 0660: %v", path, err)
		}
		if rule.gid >= 0 && rule.gid != os.Getgid() {
			if err := os.Chown(path, -1, rule.gid); err != nil {
				ln.Close()
				return nil, fmt.Errorf("proxy: control %s: giving it to group %s: %v; the proxy must be a member of that group, which is SupplementaryGroups=%s in its unit",
					path, rule.group, err, rule.group)
			}
			// The directory too, when it is the proxy's to give: made by
			// RuntimeDirectory= for the proxy's account, it is 0750 and
			// the proxy's group, which the callers are not in.
			if err := os.Chown(dir, -1, rule.gid); err != nil {
				p.logf("proxy: control %s: the directory %s could not be given to group %s (%v); its members reach the socket only if the directory lets them",
					path, dir, rule.group, err)
			}
		}
	}
	cl := &controlListener{ln: ln, path: path, done: make(chan struct{})}
	go cl.serve(p, rule)
	return cl, nil
}

// Close stops the socket; Go removes the file it created.
func (cl *controlListener) Close() error {
	err := cl.ln.Close()
	<-cl.done
	return err
}

func (cl *controlListener) serve(p *keyProxy, rule allowRule) {
	defer close(cl.done)
	for {
		conn, err := cl.ln.Accept()
		if err != nil {
			return
		}
		go cl.handle(p, rule, conn)
	}
}

// handle is one connection: the peer's credentials, then one request,
// then, for a mint, the rest of the connection's life.
func (cl *controlListener) handle(p *keyProxy, rule allowRule, conn net.Conn) {
	defer conn.Close()
	cred := agent.Cred{UID: os.Getuid(), GID: os.Getgid(), PID: -1}
	if uc, ok := conn.(*net.UnixConn); ok {
		c, err := agent.PeerCred(uc)
		if err != nil || !rule.allows(c) {
			// Closed without a byte: a process that may not ask gets no
			// conversation at all, not even a refusal.
			p.logf("proxy: refused a connection on the control socket from uid %d pid %d", c.UID, c.PID)
			return
		}
		cred = c
	}
	r := bufio.NewReaderSize(conn, controlLineMax)
	line, err := readControlLine(r)
	if err != nil {
		fmt.Fprintf(conn, "ERR %v\n", err)
		return
	}
	verb, arg, _ := strings.Cut(line, " ")
	switch verb {
	case "PING":
		fmt.Fprintln(conn, "OK")
	case "REVOKE":
		// A revoke on a connection of its own, for a caller that did not
		// keep the minting one.
		p.revoke(arg)
		fmt.Fprintln(conn, "OK")
	case "MINT":
		token, baseURL, err := p.mint(fmt.Sprintf(" for uid %d pid %d", cred.UID, cred.PID))
		if err != nil {
			fmt.Fprintf(conn, "ERR %v\n", err)
			return
		}
		defer p.revoke(token)
		fmt.Fprintf(conn, "OK %s\n", baseURL)
		// The token lives while this connection does. A REVOKE ends it
		// early; anything else on the line ends the connection, and with
		// it the token.
		for {
			line, err := readControlLine(r)
			if err != nil {
				return
			}
			verb, arg, _ := strings.Cut(line, " ")
			if verb == "REVOKE" && arg == token {
				fmt.Fprintln(conn, "OK")
				return
			}
			fmt.Fprintln(conn, "ERR one mint per connection; close it to revoke")
			return
		}
	default:
		fmt.Fprintf(conn, "ERR unknown request %q; PING, MINT or REVOKE TOKEN\n", verb)
	}
}

// readControlLine is one line, bounded by the reader's buffer, without
// its newline. A line that does not fit is refused rather than read on.
func readControlLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", fmt.Errorf("a line longer than %d bytes", controlLineMax)
	}
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// controlSource is serve's side of the socket: a token per invocation,
// held on its own connection.
type controlSource struct {
	path string
}

// mint asks the proxy for a token and keeps the connection until release
// is called, which revokes it. A socket nobody answers on is the error a
// message fails with.
func (c *controlSource) mint() (token, baseURL string, release func(), err error) {
	conn, err := net.DialTimeout("unix", c.path, 5*time.Second)
	if err != nil {
		return "", "", nil, fmt.Errorf("the proxy's control socket %s: %v", c.path, err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	// A refused caller is closed before a byte is read, and on Linux that
	// close can land before this write, which then fails with a broken
	// pipe rather than the read meeting EOF. Either way the peer closed
	// without answering, and that is what is said; a pipe error is not a
	// sentence for a person.
	if _, err := fmt.Fprintln(conn, "MINT"); err != nil {
		conn.Close()
		return "", "", nil, fmt.Errorf("%s", closedWithoutAnswering(c.path))
	}
	r := bufio.NewReaderSize(conn, controlLineMax)
	line, err := readControlLine(r)
	if err != nil {
		conn.Close()
		return "", "", nil, fmt.Errorf("%s", closedWithoutAnswering(c.path))
	}
	verb, rest, _ := strings.Cut(line, " ")
	if verb != "OK" || rest == "" {
		conn.Close()
		return "", "", nil, fmt.Errorf("the proxy's control socket %s: %s", c.path, line)
	}
	conn.SetDeadline(time.Time{})
	token = rest[strings.LastIndex(rest, "/")+1:]
	release = func() {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "REVOKE %s\n", token)
		readControlLine(r)
		conn.Close()
	}
	return token, rest, release, nil
}

// ping says whether a proxy answers on the socket.
func (c *controlSource) ping() error {
	conn, err := net.DialTimeout("unix", c.path, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(conn, "PING"); err != nil {
		return errors.New(closedWithoutAnswering(""))
	}
	line, err := readControlLine(bufio.NewReaderSize(conn, controlLineMax))
	if err != nil {
		return errors.New(closedWithoutAnswering(""))
	}
	if line != "OK" {
		return errors.New(line)
	}
	return nil
}

// closedWithoutAnswering is the sentence for a control socket that took
// the connection and closed it with no reply: the proxy refusing this
// uid, or something else listening there. With a path it names the
// socket; ping's caller names it.
func closedWithoutAnswering(path string) string {
	if path == "" {
		return "closed without answering; the proxy refuses this uid, or is not the proxy"
	}
	return fmt.Sprintf("the proxy's control socket %s closed without answering; the proxy refuses this uid, or is not the proxy", path)
}

// tokenSource is what serve asks for a token per invocation: the proxy in
// this process, or the split proxy over its control socket.
type tokenSource interface {
	mint() (token, baseURL string, release func(), err error)
}

// mint is keyProxy as a tokenSource: the release is the revoke.
func (p *keyProxy) mintFor() (token, baseURL string, release func(), err error) {
	token, baseURL, err = p.mint("")
	if err != nil {
		return "", "", nil, err
	}
	return token, baseURL, func() { p.revoke(token) }, nil
}

// inProcess wraps keyProxy so that serve holds one interface either way.
type inProcess struct{ *keyProxy }

func (p inProcess) mint() (string, string, func(), error) { return p.mintFor() }

// serveProxy is 'auu serve proxy': the proxy as its own process, until it
// is told to stop.
func serveProxy(config string) error {
	path := config
	if strings.TrimSpace(path) == "" {
		path = defaultProxyFile
	}
	f, err := loadProxyFile(path)
	if err != nil {
		return err
	}
	key, err := readKeyFile(f.KeyFile)
	if err != nil {
		return err
	}
	rule, err := allowRuleFor(&f.proxyConfig)
	if err != nil {
		return usageErrf("%s: %v", path, err)
	}
	logf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, prog+": "+format+"\n", a...) }
	p, err := startKeyProxy(&f.proxyConfig, key, logf)
	if err != nil {
		return err
	}
	defer p.Close()
	cl, err := startControl(p, f.Control, rule)
	if err != nil {
		return err
	}
	defer cl.Close()
	logf("proxy: holding the key from %s, listening on %s, upstream %s; tokens on %s for %s (pid %d)",
		f.KeyFile, p.ln.Addr(), f.Upstream, f.Control, rule.describe(), os.Getpid())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	logf("proxy: stopping")
	return nil
}
