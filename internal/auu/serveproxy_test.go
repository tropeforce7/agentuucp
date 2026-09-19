package auu

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The key-holding proxy: the handler is given a token and never the key.

const realKey = "sk-ant-api03-THE-REAL-KEY-000000000000000000000000000000000000000000000000000000000000000000000000000000-AA"

// seenRequest is one request as the fake upstream received it.
type seenRequest struct {
	method, path, key, auth, version string
	body                             string
}

// upstream is a fake api.anthropic.com on loopback: it records what it
// received — the key in full, since this is the test that asserts it, and
// the test alone sees it — and answers with a fixed body.
type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen []seenRequest
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.seen = append(u.seen, seenRequest{method: r.Method, path: r.URL.Path, key: r.Header.Get("x-api-key"),
			auth: r.Header.Get("authorization"), version: r.Header.Get("anthropic-version"), body: string(body)})
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"seen":true}`)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) requests() []seenRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seenRequest(nil), u.seen...)
}

// logBuffer collects the proxy's lines.
type logBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *logBuffer) logf(format string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, format+"\n", a...)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// waitForLog waits for a line to appear in the proxy's log and returns
// the log as it then stands. The proxy writes its request line after the
// response has been copied to the client, since the line reports the
// status, the bytes and the time taken, and its refusal line after the
// refusal has been written; a client can therefore finish reading, and a
// test can read the buffer, before the line is there. Reading it is a
// race, and this is the wait that settles it: a deadline of seconds, never
// less, as the guide says, with the whole log in the failure.
func waitForLog(t *testing.T, logs *logBuffer, want string) string {
	t.Helper()
	return waitForLogCount(t, logs, want, 1)
}

// waitForLogCount waits until a line has appeared at least n times.
func waitForLogCount(t *testing.T, logs *logBuffer, want string, n int) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := logs.String(); strings.Count(got, want) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("the log did not come to say %q %d time(s) within 5s; it says:\n%s", want, n, logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// proxyFor is a running proxy in front of the fake upstream, with its log.
func proxyFor(t *testing.T, up *upstream) (*keyProxy, *logBuffer) {
	t.Helper()
	// check does not read the key file, so any path names one here.
	cfg := &proxyConfig{KeyFile: "key", Listen: "127.0.0.1:0", Upstream: up.URL}
	if err := cfg.check(&serveConfig{path: "serve.json"}); err != nil {
		t.Fatal(err)
	}
	logs := &logBuffer{}
	p, err := startKeyProxy(cfg, realKey, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p, logs
}

// call sends one request through the proxy.
func call(t *testing.T, method, rawURL, body string, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(out))
}

// A request under a live token reaches upstream with the real key and the
// path the token was stripped from, the placebo and any bearer gone, the
// method, the body and every other header intact; a request with no
// token, an unknown one or a revoked one is 404, upstream sees nothing,
// and the log names which.
func TestProxyForwardsUnderALiveTokenAndRefusesTheRest(t *testing.T) {
	up := newUpstream(t)
	p, logs := proxyFor(t, up)
	token, base, err := p.mint("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(base, "http://127.0.0.1:") || !strings.HasSuffix(base, "/"+token) || len(token) != 43 {
		t.Fatalf("the base URL is %q, the token %q", base, token)
	}

	status, body := call(t, "POST", base+"/v1/messages?beta=1", `{"model":"x"}`, map[string]string{
		"x-api-key": token, "authorization": "Bearer something", "anthropic-version": "2023-06-01"})
	if status != http.StatusOK || body != `{"seen":true}` {
		t.Fatalf("through the proxy: %d %s", status, body)
	}
	seen := up.requests()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(seen))
	}
	got := seen[0]
	if got.method != "POST" || got.path != "/v1/messages" || got.key != realKey || got.auth != "" ||
		got.version != "2023-06-01" || got.body != `{"model":"x"}` {
		t.Fatalf("upstream saw %+v", got)
	}
	logged := waitForLog(t, logs, "proxy: "+token[:8]+" POST /v1/messages 200 in 13 out 13 ")
	if strings.Contains(logged, realKey) || strings.Contains(logged, token[8:]) {
		t.Fatal("the log carries the key, or the whole token")
	}

	// HEAD under the token, as Claude Code's probe arrives.
	if status, _ := call(t, "HEAD", base+"/api/hello", "", nil); status != http.StatusOK {
		t.Fatalf("the probe: %d", status)
	}

	before := len(up.requests())
	for _, c := range []struct{ label, url, reason string }{
		{"no token", p.base + "/v1/messages", "no token"},
		{"the root", p.base + "/", "no token"},
		{"an unknown token", p.base + "/" + strings.Repeat("x", 43) + "/v1/messages", "unknown token"},
	} {
		status, body := call(t, "POST", c.url, `{}`, map[string]string{"x-api-key": "anything"})
		if status != http.StatusNotFound || !strings.Contains(body, "no live invocation token") {
			t.Fatalf("%s: %d %s", c.label, status, body)
		}
		waitForLog(t, logs, "refused: "+c.reason)
	}
	p.revoke(token)
	status, _ = call(t, "POST", base+"/v1/messages", `{}`, map[string]string{"x-api-key": token})
	if status != http.StatusNotFound {
		t.Fatalf("a revoked token: %d", status)
	}
	waitForLog(t, logs, "refused: revoked token")
	if len(up.requests()) != before {
		t.Fatal("a refused request reached upstream")
	}
}

// A streaming answer reaches the client chunk by chunk: the upstream
// writes three lines with a pause between, and each arrives before the
// next is written.
func TestProxyStreamsChunkByChunk(t *testing.T) {
	const pause = 300 * time.Millisecond
	up := &upstream{}
	up.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		for i := range 3 {
			fmt.Fprintf(w, "data: chunk %d\n\n", i)
			f.Flush()
			time.Sleep(pause)
		}
	}))
	defer up.Close()
	p, _ := proxyFor(t, up)
	_, base, err := p.mint("")
	if err != nil {
		t.Fatal(err)
	}
	// The clock starts before the request: a proxy that buffered would
	// hand over the headers, and everything after them, only at the end.
	start := time.Now()
	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	scan := bufio.NewScanner(resp.Body)
	var arrivals []time.Duration
	for scan.Scan() {
		if strings.HasPrefix(scan.Text(), "data:") {
			arrivals = append(arrivals, time.Since(start))
		}
	}
	if len(arrivals) != 3 {
		t.Fatalf("%d chunks arrived, want 3", len(arrivals))
	}
	// The first chunk arrives well before the upstream has finished
	// writing, which takes three pauses; a proxy that buffered would hand
	// everything over at the end.
	if arrivals[0] > pause {
		t.Fatalf("the first chunk arrived after %s; the answer was buffered", arrivals[0])
	}
	if arrivals[2]-arrivals[0] < pause {
		t.Fatalf("the chunks arrived together: %v", arrivals)
	}
}

// Every mint is a fresh token, the seventeenth live one is refused, and a
// revoked one is dead.
func TestProxyTokensAreDistinctAndCapped(t *testing.T) {
	p, _ := proxyFor(t, newUpstream(t))
	seen := map[string]bool{}
	var tokens []string
	for i := range maxLiveTokens {
		token, _, err := p.mint("")
		if err != nil {
			t.Fatalf("mint %d: %v", i+1, err)
		}
		if seen[token] {
			t.Fatalf("token %d repeats an earlier one", i+1)
		}
		seen[token] = true
		tokens = append(tokens, token)
	}
	if _, _, err := p.mint(""); err == nil || !strings.Contains(err.Error(), "16 tokens are live, which is the cap") {
		t.Fatalf("the seventeenth mint: %v", err)
	}
	p.revoke(tokens[0])
	if _, _, err := p.mint(""); err != nil {
		t.Fatalf("a mint after a revoke: %v", err)
	}
	if p.state(tokens[0]) != "revoked token" || p.state(tokens[1]) != "live" || p.state("nothing") != "unknown token" {
		t.Fatal("the states are wrong")
	}
	// Revoking twice, or a token never minted, is nothing.
	p.revoke(tokens[0])
	p.revoke("nothing")
}

// proxied is an expert whose serve.json has a proxy section pointing at
// the fake upstream, with the real key in a file in the home.
func proxied(t *testing.T, bob *expert, up *upstream) string {
	t.Helper()
	keyFile := filepath.Join(bob.home, "key")
	if err := os.WriteFile(keyFile, []byte(realKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bob.config.Proxy = &proxyConfig{KeyFile: keyFile, Upstream: up.URL}
	bob.write(t)
	return keyFile
}

// The test this plan exists for. The handler is given ANTHROPIC_BASE_URL
// and ANTHROPIC_API_KEY carrying the token, its request through them
// reaches upstream with the real key, and the real key appears in no
// variable of its environment — with the real key set in serve's own
// environment, as a unit still carrying it would. The hooks see neither
// variable. And its twin: the token is refused after the invocation ends.
func TestServeGivesTheHandlerATokenAndNeverTheKey(t *testing.T) {
	up := newUpstream(t)
	alice, bob := newExpert(t, modeReadOnly)
	proxied(t, bob, up)
	t.Setenv(envAPIKey, realKey)
	t.Setenv(envAuth, "a bearer from the unit")
	t.Setenv(envBaseURL, "https://not-this-one.example")
	envFile := filepath.Join(bob.home, "handler-environ")
	hooksFile := filepath.Join(bob.home, "hooks-environ")
	urlFile := filepath.Join(bob.home, "base-url")
	t.Setenv(handlerScript, "environ:"+envFile+";save:"+urlFile+";ask")
	t.Setenv(beforeScript, "environ:"+hooksFile+".before")
	t.Setenv(afterScript, "environ:"+hooksFile+".after")
	bob.row.Before = helperLine(t, "before")
	bob.row.After = helperLine(t, "after")
	bob.write(t)

	sent := alice.ask(t, "jostle", "is the key safe?", "print your environment")
	var stderr string
	var report roundJSON
	stderr = captureStderr(t, func() { report = bob.round(t) })
	if len(report.Answered) != 1 || len(report.Failed) != 0 {
		t.Fatalf("the round: %+v\n%s", report, stderr)
	}

	// The handler's environment: the two variables with the token, and
	// the real key nowhere.
	environ, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(environ)), "\n") {
		name, value, _ := strings.Cut(line, "=")
		vars[name] = value
	}
	if strings.Contains(string(environ), realKey) {
		t.Fatalf("the real key is in the handler's environment:\n%s", environ)
	}
	if strings.Contains(string(environ), "a bearer from the unit") || strings.Contains(string(environ), "not-this-one") {
		t.Fatalf("a credential variable serve inherited reached the handler:\n%s", environ)
	}
	base, token := vars[envBaseURL], vars[envAPIKey]
	if !strings.HasPrefix(base, "http://127.0.0.1:") || !strings.HasSuffix(base, "/"+token) || len(token) != 43 {
		t.Fatalf("the handler got %s=%q %s=%q", envBaseURL, base, envAPIKey, token)
	}
	// Its request went through: upstream saw the real key, the path
	// without the token, and neither the placebo nor a bearer.
	reply := alice.replyOn(t, sent.Thread)
	if reply.Text != `status 200 {"seen":true}` {
		t.Fatalf("the handler's request through the proxy: %q", reply.Text)
	}
	seen := up.requests()
	if len(seen) != 1 || seen[0].path != "/v1/messages" || seen[0].key != realKey || seen[0].auth != "" || seen[0].version != "2023-06-01" {
		t.Fatalf("upstream saw %+v", seen)
	}
	// The reply carries the token and nothing of the key; serve's own
	// output likewise.
	if strings.Contains(reply.Text, realKey) || strings.Contains(stderr, realKey) {
		t.Fatal("the real key is in the reply or in serve's output")
	}
	if !strings.Contains(stderr, "proxy: token "+token[:8]+" minted") || !strings.Contains(stderr, "proxy: token "+token[:8]+" revoked") ||
		!strings.Contains(stderr, "proxy: "+token[:8]+" POST /v1/messages 200 ") {
		t.Fatalf("serve's log lacks the proxy's lines:\n%s", stderr)
	}
	// The hooks see neither variable, and no inherited credential.
	for _, hook := range []string{".before", ".after"} {
		he, err := os.ReadFile(hooksFile + hook)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{envBaseURL, envAPIKey, envAuth} {
			if strings.Contains(string(he), name+"=") {
				t.Fatalf("the %s hook has %s in its environment", hook[1:], name)
			}
		}
		if strings.Contains(string(he), realKey) {
			t.Fatalf("the %s hook has the real key", hook[1:])
		}
	}

	// The twin: the token is refused once the invocation has ended, while
	// the same proxy is still running. Two asks in one round: the second
	// invocation asks the URL the first saved, and gets 404, while its own
	// is answered.
	saved, err := os.ReadFile(urlFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(saved)) != base {
		t.Fatalf("the saved URL is %q, the environment said %q", saved, base)
	}
	// The file from the round above names a proxy that stopped with it;
	// the first of the two finds no file, saves its own, and the second
	// asks that one.
	os.Remove(urlFile)
	t.Setenv(handlerScript, "askold:"+urlFile+";save:"+urlFile+";ask")
	bob.row.Before, bob.row.After = "", ""
	bob.write(t)
	first := alice.ask(t, "jostle", "first", "the first of two")
	second := alice.ask(t, "jostle", "second", "the second of two")
	if report := bob.round(t); len(report.Answered) != 2 || len(report.Failed) != 0 {
		t.Fatalf("the round of two: %+v", report)
	}
	if text := alice.replyOn(t, first.Thread).Text; text != "no saved url\nstatus 200 {\"seen\":true}" {
		t.Fatalf("the first of two: %q", text)
	}
	if text := alice.replyOn(t, second.Thread).Text; text != "old status 404\nstatus 200 {\"seen\":true}" {
		t.Fatalf("the second of two, asking the first's URL: %q", text)
	}
	// Three answered requests reached upstream in all, each under the real
	// key, and the refused one did not.
	seen = up.requests()
	if len(seen) != 3 {
		t.Fatalf("upstream saw %d requests, want 3: %+v", len(seen), seen)
	}
	for _, r := range seen {
		if r.key != realKey || r.auth != "" {
			t.Fatalf("upstream saw %+v", r)
		}
	}
}

// serve check says the proxy line without the key, warns when serve's own
// environment carries a credential, and refuses each bad section with
// its sentence.
func TestServeCheckSaysTheProxyLineAndRefusesBadSections(t *testing.T) {
	up := newUpstream(t)
	_, bob := newExpert(t, modeReadOnly)
	keyFile := proxied(t, bob, up)

	out := bob.run("serve", "check")
	want := fmt.Sprintf("proxy: key from %s (%d bytes), listen 127.0.0.1:0, upstream %s\n", keyFile, len(realKey), up.URL)
	if !strings.Contains(out, want) {
		t.Fatalf("serve check:\n%s\nwant %q", out, want)
	}
	if strings.Contains(out, realKey) {
		t.Fatal("serve check printed the key")
	}
	t.Setenv(envAPIKey, realKey)
	warning := captureStderr(t, func() { bob.run("serve", "check") })
	if !strings.Contains(warning, "auu: ANTHROPIC_API_KEY is set in serve's environment and is not passed to the handler or the hooks; the proxy holds the key, and the line that sets it can go\n") {
		t.Fatalf("the warning:\n%s", warning)
	}
	os.Unsetenv(envAPIKey)

	empty := filepath.Join(bob.home, "empty")
	os.WriteFile(empty, []byte("\n\n"), 0o600)
	for _, c := range []struct {
		label string
		proxy proxyConfig
		want  string
	}{
		{"a missing key file", proxyConfig{KeyFile: filepath.Join(bob.home, "nothing")},
			"proxy: key_file " + filepath.Join(bob.home, "nothing") + " does not exist; it holds the API key on its first line"},
		{"an empty key file", proxyConfig{KeyFile: empty},
			"proxy: key_file " + empty + " is empty; it holds the API key on its first line"},
		{"a listen off the host", proxyConfig{KeyFile: keyFile, Listen: "0.0.0.0:8080"},
			`proxy: listen "0.0.0.0:8080" is not a loopback address; a proxy reachable off the host is the key on the network. Use 127.0.0.1:0`},
		{"a listen with no port", proxyConfig{KeyFile: keyFile, Listen: "127.0.0.1"},
			`proxy: listen "127.0.0.1" is not host:port`},
		{"a plain http upstream off the host", proxyConfig{KeyFile: keyFile, Upstream: "http://api.example.com"},
			`proxy: upstream "http://api.example.com" is plain http and not on this host; the key would cross the network in the clear. Use https://`},
		{"an upstream that is not a URL", proxyConfig{KeyFile: keyFile, Upstream: "api.anthropic.com"},
			`proxy: upstream "api.anthropic.com" is not an http or https URL`},
		{"both key_file and control", proxyConfig{KeyFile: keyFile, Control: "/run/auu-proxy/control.sock"},
			"proxy: key_file and control are both set; key_file is the proxy in this process and control is one running apart, and it is one or the other"},
		{"neither", proxyConfig{},
			"proxy: one of key_file and control is required; a proxy section with neither holds no key and asks nobody for one"},
		{"allow_group with key_file", proxyConfig{KeyFile: keyFile, AllowGroup: "auu-expert"},
			"proxy: allow_uids and allow_group belong to the split proxy's own file, /etc/auu-proxy/proxy.json; they mean nothing here"},
		{"allow_uids with control", proxyConfig{Control: "/run/auu-proxy/control.sock", AllowUIDs: []int{1000}},
			"proxy: allow_uids and allow_group belong to the split proxy's own file, /etc/auu-proxy/proxy.json; they mean nothing here"},
		{"listen with control", proxyConfig{Control: "/run/auu-proxy/control.sock", Listen: "127.0.0.1:9000"},
			"proxy: listen and upstream belong to the split proxy's own file, /etc/auu-proxy/proxy.json, when control is set"},
	} {
		t.Run(c.label, func(t *testing.T) {
			cfg := c.proxy
			bob.config.Proxy = &cfg
			bob.write(t)
			_, err := bob.tryRun("serve", "check")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			// And serve itself refuses the same way, before its lock.
			if _, err := bob.tryRun("serve", "--once"); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("serve --once: got %v, want %q", err, c.want)
			}
		})
	}
	// An unknown key in the section is refused as everywhere in the file.
	raw := map[string]any{"v": 1, "channels": map[string]any{"jostle": map[string]any{"dir": bob.dir, "exec": bob.row.Exec}},
		"proxy": map[string]any{"key_file": keyFile, "port": 8080}}
	data, _ := json.Marshal(raw)
	os.WriteFile(bob.path, data, 0o600)
	if _, err := bob.tryRun("serve", "check"); err == nil || !strings.Contains(err.Error(), `unknown field "port"`) {
		t.Fatalf("an unknown proxy key: %v", err)
	}
	// A file with no proxy section: the handler is told nothing, and the
	// check says nothing about a proxy.
	bob.config.Proxy = nil
	bob.write(t)
	if out := bob.run("serve", "check"); strings.Contains(out, "proxy") {
		t.Fatalf("serve check mentions a proxy that is not configured:\n%s", out)
	}
}

// rawProxyRequest is one request to the proxy written by hand: the request
// line, Host, Connection: close, the headers given, a Content-Length of
// declared when it is not negative, and sent bytes of the body — none for
// a body declared and never sent. The answer is read under a deadline.
func rawProxyRequest(t *testing.T, addr, method, path string, headers map[string]string, declared int64, sent []byte) (int, string, bool) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var wire strings.Builder
	fmt.Fprintf(&wire, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", method, path, addr)
	if declared >= 0 {
		fmt.Fprintf(&wire, "Content-Length: %d\r\n", declared)
	}
	for k, v := range headers {
		fmt.Fprintf(&wire, "%s: %s\r\n", k, v)
	}
	wire.WriteString("\r\n")
	wire.Write(sent)
	if _, err := io.WriteString(conn, wire.String()); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading the answer to a hand-written %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, strings.TrimSpace(string(out)), resp.Close
}

// TestLimitTheProxyCapsHeadersAndBodies: the proxy's listener carries the
// relay's header cap and a request body cap of its own, the upstream's
// documented request size limit. A header block over
// relayapi.MaxHeaderBytes plus net/http's 4096 bytes of read-ahead is 431
// from net/http before the proxy sees it; a body declared one byte over
// proxyMaxRequestBytes and never sent is 413 before a byte, naming the
// bytes, the connection closed behind the answer and nothing reaching
// upstream; one without a length that runs past the cap is cut at the cap
// on its way upstream and answered 413 too, upstream seeing at most the
// cap's worth of it; a body at the cap is passed on whole. The log names
// each refusal.
func TestLimitTheProxyCapsHeadersAndBodies(t *testing.T) {
	up := newUpstream(t)
	p, logs := proxyFor(t, up)
	token, base, err := p.mint("")
	if err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimPrefix(p.base, "http://")
	path := "/" + token + "/v1/messages"

	const slop = 4096
	frame := len("POST  HTTP/1.1\r\nHost: \r\nConnection: close\r\nContent-Length: 0\r\nX-Junk: \r\n\r\n") + len(path) + len(addr)
	for _, tc := range []struct {
		name  string
		total int
		want  int
	}{
		{"a block at the cap plus net/http's slop", relayapi.MaxHeaderBytes + slop, http.StatusOK},
		{"one byte over", relayapi.MaxHeaderBytes + slop + 1, http.StatusRequestHeaderFieldsTooLarge},
	} {
		status, body, _ := rawProxyRequest(t, addr, "POST", path,
			map[string]string{"X-Junk": strings.Repeat("j", tc.total-frame)}, 0, nil)
		if status != tc.want {
			t.Fatalf("%s, a header block of %d bytes: %d %.120s; want %d", tc.name, tc.total, status, body, tc.want)
		}
	}
	before := len(up.requests())

	status, body, closed := rawProxyRequest(t, addr, "POST", path, nil, proxyMaxRequestBytes+1, nil)
	if status != http.StatusRequestEntityTooLarge || !strings.Contains(body, fmt.Sprintf("at most %d bytes", proxyMaxRequestBytes)) || !closed {
		t.Fatalf("a body one byte over the cap, unsent: %d %q closed=%v; want 413 naming the bytes with the connection closed", status, body, closed)
	}
	waitForLog(t, logs, fmt.Sprintf("body of %d bytes over the cap of %d", proxyMaxRequestBytes+1, proxyMaxRequestBytes))
	if len(up.requests()) != before {
		t.Fatal("the refused body reached upstream")
	}

	// Without a length, past the cap: cut on the way upstream.
	over := proxyMaxRequestBytes + 1
	chunked := fmt.Sprintf("%x\r\n", over) + strings.Repeat("x", int(over)) + "\r\n0\r\n\r\n"
	status, body, _ = rawProxyRequest(t, addr, "POST", path, map[string]string{"Transfer-Encoding": "chunked"}, -1, []byte(chunked))
	if status != http.StatusRequestEntityTooLarge || !strings.Contains(body, fmt.Sprintf("at most %d bytes", proxyMaxRequestBytes)) {
		t.Fatalf("a chunked body over the cap: %d %q; want 413 naming the bytes", status, body)
	}
	waitForLog(t, logs, fmt.Sprintf("body over %d bytes, refused", proxyMaxRequestBytes))
	// A body without a length is forwarded as it arrives, so upstream may
	// have seen the request begin; what it saw ends at the cap, never past
	// it — the cut is on the way through.
	for _, r := range up.requests()[before:] {
		if len(r.body) > int(proxyMaxRequestBytes) {
			t.Fatalf("upstream saw %d bytes of a chunked body, over the cap of %d", len(r.body), proxyMaxRequestBytes)
		}
	}

	// At the cap: passed on whole, every byte of it.
	atCap := strings.Repeat("y", int(proxyMaxRequestBytes))
	status, body = call(t, "POST", base+"/v1/messages", atCap, map[string]string{"x-api-key": token})
	if status != http.StatusOK || body != `{"seen":true}` {
		t.Fatalf("a body at the cap: %d %.80s; want it passed on", status, body)
	}
	whole := false
	for _, r := range up.requests() {
		if r.body == atCap {
			whole = true
		}
	}
	if !whole {
		t.Fatalf("upstream did not see the body at the cap whole")
	}
}
