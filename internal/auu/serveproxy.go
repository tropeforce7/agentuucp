package auu

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// The key-holding proxy.
//
// A handler that answers with Claude Code needs an Anthropic API key, and
// what it reads is untrusted mail: a crafted ask can have the key printed
// into a reply and carried back over the relay, and in side-copy mode the
// model has a shell besides. So the handler never holds the key. serve
// holds it, in memory, read once from a file at start, and runs a reverse
// proxy on loopback; each invocation of the handler is given a base URL
// with a random token in its path, live for that invocation alone, which
// the proxy exchanges for the real key on the way to Anthropic. Off the
// host the URL is worthless, since the proxy is loopback; after the
// invocation it is worthless too, since the token is dead.
//
// What one account cannot protect is said in docs/serve.md: with the proxy
// in-process, serve and the handler are the same user, so a file serve can
// read the handler can read too. The proxy keeps the key out of the
// handler's environment and out of every reply; it does not stop a shell
// that is told where the file is. The split proxy, another user under its
// own unit, is the answer to that, and 'auu serve proxy' is it.

// The two variables a handler is given, and the three that are dropped
// from the environment serve inherited whenever a proxy is configured, so
// that a unit still carrying the real key cannot hand it on.
const (
	envBaseURL = "ANTHROPIC_BASE_URL"
	envAPIKey  = "ANTHROPIC_API_KEY"
	envAuth    = "ANTHROPIC_AUTH_TOKEN"
)

var credentialVars = []string{envAPIKey, envAuth, envBaseURL}

const (
	// maxLiveTokens caps how many invocation tokens are live at once. Serve
	// is serial, so one is the ordinary case; the cap is the guarantee.
	maxLiveTokens = 16
	// tokenBytes is the size of a token: 32 bytes of the kernel's
	// randomness, base64url without padding.
	tokenBytes = 32
	// revokedRemembered is how many dead tokens are kept so that a request
	// under one is refused as "revoked" rather than "unknown": a word for
	// the operator, never a fact for the caller, who gets the same 404.
	revokedRemembered = 64
	// tokenShown is how much of a token a log line shows.
	tokenShown = 8

	defaultProxyListen   = "127.0.0.1:0"
	defaultProxyUpstream = "https://api.anthropic.com"

	// proxyMaxRequestBytes caps a request body through the proxy. The body
	// is the handler's whole conversation as JSON, which can legitimately
	// be large, so the cap is the size the upstream itself takes: the
	// Claude API's request size limit for the Messages and Token Counting
	// endpoints is 32 MB (platform.claude.com/docs/en/api/overview, under
	// "Request size limits"), answered 413 request_too_large past it. The
	// cap is 32 MiB, above the API's figure by the difference between the
	// two units, so a body the upstream would take is never refused here on
	// the margin; one over it is refused before a byte, with a sentence
	// naming the bytes, and a body that arrives without a length is cut at
	// the same cap. A loopback body from this host's own handler is still a
	// body from outside the process, and a bound is written down.
	proxyMaxRequestBytes int64 = 32 << 20
)

// ProxyTimeouts bounds how long one connection may occupy the proxy. Three
// of the four are the relay's: the request line and headers within ten
// seconds, the request body within five minutes (the conversation as JSON,
// megabytes at most, read in seconds across loopback), an idle connection
// kept two minutes. There is no write timeout, deliberately: net/http's
// runs from the request header to the end of the response, and the
// response is the model's answer, silent until it is ready on a call that
// does not stream and minutes long either way — a five-minute bound would
// cut a long answer and a per-write stall deadline would cut a silent one.
// The bound on the response is Claude Code's own client timeout across
// the loopback. The request line and headers are capped at
// relayapi.MaxHeaderBytes as the relay's are.
type ProxyTimeouts struct {
	ReadHeader, Read, Write, Idle time.Duration
}

// DefaultProxyTimeouts is what the proxy runs with; cmd/auu-relay's test
// holds the shared three to the relay's defaults.
func DefaultProxyTimeouts() ProxyTimeouts {
	return ProxyTimeouts{ReadHeader: 10 * time.Second, Read: 5 * time.Minute, Write: 0, Idle: 2 * time.Minute}
}

// proxyConfig is the proxy section of serve.json.
type proxyConfig struct {
	// KeyFile names the file the real key is the first line of. Read once
	// at start, never logged, never put in any environment.
	KeyFile string `json:"key_file,omitempty"`
	// Listen is the proxy's address, loopback only; a port of 0 lets the
	// kernel choose.
	Listen string `json:"listen,omitempty"`
	// Upstream is where requests go, over TLS with the system roots.
	Upstream string `json:"upstream,omitempty"`
	// Control, AllowUIDs and AllowGroup are the split proxy's, which runs
	// as another user: the Unix socket serve asks for tokens on, and who
	// may ask. Known here so that a file written for it is refused by
	// name rather than as an unknown key.
	Control    string `json:"control,omitempty"`
	AllowUIDs  []int  `json:"allow_uids,omitempty"`
	AllowGroup string `json:"allow_group,omitempty"`

	upstream *url.URL
}

// fill puts in the defaults the file left out.
func (p *proxyConfig) fill() {
	if strings.TrimSpace(p.Listen) == "" {
		p.Listen = defaultProxyListen
	}
	if strings.TrimSpace(p.Upstream) == "" {
		p.Upstream = defaultProxyUpstream
	}
}

// check is every rule the expert's section must satisfy, without
// listening or reading the key: one of key_file and control and not
// both, since key_file is the proxy in this process and control is one
// running apart as another account, whose own file holds the rest; a
// loopback listen; an https upstream unless it is loopback too. In split
// mode the expert's file names neither the key nor who may ask for
// tokens: the handler can read this file, and learns nothing from it.
func (p *proxyConfig) check(cfg *serveConfig) error {
	perr := func(format string, a ...any) error {
		return usageErrf("%s: proxy: %s", cfg.path, fmt.Sprintf(format, a...))
	}
	hasKey, hasControl := strings.TrimSpace(p.KeyFile) != "", strings.TrimSpace(p.Control) != ""
	switch {
	case hasKey && hasControl:
		return perr("key_file and control are both set; key_file is the proxy in this process and control is one running apart, and it is one or the other")
	case !hasKey && !hasControl:
		return perr("one of key_file and control is required; a proxy section with neither holds no key and asks nobody for one")
	}
	if len(p.AllowUIDs) > 0 || p.AllowGroup != "" {
		return perr("allow_uids and allow_group belong to the split proxy's own file, %s; they mean nothing here", defaultProxyFile)
	}
	if hasControl {
		// The addresses are the proxy process's business; this file says
		// only where to ask.
		if p.Listen != defaultProxyListen || p.Upstream != defaultProxyUpstream {
			return perr("listen and upstream belong to the split proxy's own file, %s, when control is set", defaultProxyFile)
		}
		return nil
	}
	return p.checkAddresses(perr)
}

// checkAddresses is the rule for listen and upstream, in whichever file
// they are: a loopback listen, and an https upstream unless it is on this
// host too.
func (p *proxyConfig) checkAddresses(perr func(string, ...any) error) error {
	host, _, err := net.SplitHostPort(p.Listen)
	if err != nil {
		return perr("listen %q is not host:port (%v)", p.Listen, err)
	}
	if !loopbackHost(host) {
		return perr("listen %q is not a loopback address; a proxy reachable off the host is the key on the network. Use 127.0.0.1:0", p.Listen)
	}
	u, err := url.Parse(p.Upstream)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return perr("upstream %q is not an http or https URL", p.Upstream)
	}
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return perr("upstream %q is plain http and not on this host; the key would cross the network in the clear. Use https://", p.Upstream)
	}
	p.upstream = u
	return nil
}

// loopbackHost says whether a host names this machine and nothing else.
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// readKeyFile is the real key: the first line of the file, with the
// surrounding white space gone. A file that is missing or has nothing on
// its first line is refused by path, since a proxy holding no key would
// forward every request to be refused upstream, one at a time.
func readKeyFile(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", usageErrf("proxy: key_file %s does not exist; it holds the API key on its first line", path)
	}
	if err != nil {
		return "", usageErrf("proxy: key_file %s: %v", path, err)
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 0, 4096), 64*1024)
	if scan.Scan() {
		if key := strings.TrimSpace(scan.Text()); key != "" {
			return key, nil
		}
	}
	return "", usageErrf("proxy: key_file %s is empty; it holds the API key on its first line", path)
}

// keyProxy is the proxy: the key, the listener, the live tokens.
type keyProxy struct {
	key      string
	upstream *url.URL
	ln       net.Listener
	srv      *http.Server
	rp       *httputil.ReverseProxy
	// base is http://127.0.0.1:PORT, to which a token is appended.
	base string
	logf func(format string, a ...any)

	mu      sync.Mutex
	live    map[string]bool
	revoked []string
}

// startKeyProxy listens and serves. logf is where the lines go: serve's
// standard error, so the journal.
func startKeyProxy(cfg *proxyConfig, key string, logf func(string, ...any)) (*keyProxy, error) {
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("proxy: listening on %s: %v", cfg.Listen, err)
	}
	p := &keyProxy{
		key: key, upstream: cfg.upstream, ln: ln, logf: logf,
		base: "http://" + ln.Addr().String(),
		live: map[string]bool{},
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(p.upstream)
			// Every credential the handler sent goes, whatever it was:
			// the placebo, or anything it was talked into adding.
			pr.Out.Header.Del("X-Api-Key")
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("X-Api-Key", p.key)
		},
		// Server-sent events pass chunk by chunk: an answer streams as it
		// is written, not when it is complete.
		FlushInterval: -1,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          8,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: time.Second,
			// No response header timeout: a model's answer can take
			// minutes, and Claude Code has timeouts of its own.
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// A body without a length that ran past the cap fails the
			// upstream write with MaxBytesReader's error: the caller's
			// fault, said as such, not the upstream's.
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, proxyTooLarge(), http.StatusRequestEntityTooLarge)
				p.logf("proxy: %s body over %d bytes, refused", r.Method, proxyMaxRequestBytes)
				return
			}
			http.Error(w, "the proxy could not reach its upstream; the operator's log says why", http.StatusBadGateway)
			p.logf("proxy: upstream %s: %v", p.upstream.Host, err)
		},
		ErrorLog: nil,
	}
	t := DefaultProxyTimeouts()
	p.srv = &http.Server{
		Handler:           p,
		MaxHeaderBytes:    relayapi.MaxHeaderBytes,
		ReadHeaderTimeout: t.ReadHeader,
		ReadTimeout:       t.Read,
		WriteTimeout:      t.Write,
		IdleTimeout:       t.Idle,
	}
	go p.srv.Serve(ln)
	return p, nil
}

// Close stops the proxy; every live token dies with it.
func (p *keyProxy) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := p.srv.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		err = p.srv.Close()
	}
	return err
}

// mint issues a token for one invocation and returns it with the base URL
// the handler is given. by is what the log line says after "minted": who
// asked, on the control socket, and nothing in-process. The seventeenth
// live token is refused: serve is serial, and sixteen live at once is a
// bug somewhere, not a load.
func (p *keyProxy) mint(by string) (token, baseURL string, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("proxy: drawing a token: %v", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.live) >= maxLiveTokens {
		return "", "", fmt.Errorf("proxy: %d tokens are live, which is the cap; nothing was issued", len(p.live))
	}
	p.live[token] = true
	p.logf("proxy: token %s minted%s", tokenTag(token), by)
	return token, p.base + "/" + token, nil
}

// revoke ends a token. A request under it from now on is refused, and
// said to be revoked rather than unknown in the log.
func (p *keyProxy) revoke(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.live[token] {
		return
	}
	delete(p.live, token)
	p.revoked = append(p.revoked, token)
	if len(p.revoked) > revokedRemembered {
		p.revoked = p.revoked[len(p.revoked)-revokedRemembered:]
	}
	p.logf("proxy: token %s revoked", tokenTag(token))
}

// state says what a token is to the proxy: live, revoked, or nothing.
func (p *keyProxy) state(token string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.live[token] {
		return "live"
	}
	for _, t := range p.revoked {
		if t == token {
			return "revoked token"
		}
	}
	return "unknown token"
}

// ServeHTTP is one request: the first path element is the token, and it
// decides. A refusal is 404 with one sentence, whatever the reason, so a
// caller learns nothing from the difference; the log says which.
func (p *keyProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	token, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	// The path is the caller's, decoded by net/http before it is seen, so
	// what the log carries of it is escaped, and the tag is cut by
	// characters rather than bytes.
	refuse := func(reason string) {
		http.Error(w, "no live invocation token in the path; this proxy answers the handler serve is running and nobody else", http.StatusNotFound)
		p.logf("proxy: %s %s %s refused: %s", tokenTag(token), r.Method, identity.PrintableText("/"+rest), reason)
	}
	if !looksLikeToken(token) {
		// Claude Code's own paths begin /v1 and /api; a request that
		// arrived with no token in front of them is one, and is said so.
		refuse("no token")
		return
	}
	if st := p.state(token); st != "live" {
		refuse(st)
		return
	}
	// The body under its cap: one that declares itself over it is refused
	// before a byte is read, and one without a length is cut at the cap
	// on its way upstream.
	if r.ContentLength > proxyMaxRequestBytes {
		w.Header().Set("Connection", "close")
		http.Error(w, proxyTooLarge(), http.StatusRequestEntityTooLarge)
		p.logf("proxy: %s %s %s refused: body of %d bytes over the cap of %d", tokenTag(token), r.Method, identity.PrintableText("/"+rest), r.ContentLength, proxyMaxRequestBytes)
		return
	}
	out := r.Clone(r.Context())
	out.URL.Path = "/" + rest
	out.URL.RawPath = ""
	out.Body = http.MaxBytesReader(w, r.Body, proxyMaxRequestBytes)
	cw := &countingWriter{ResponseWriter: w}
	p.rp.ServeHTTP(cw, out)
	p.logf("proxy: %s %s %s %d in %d out %d %s", tokenTag(token), r.Method, identity.PrintableText("/"+rest), cw.status,
		max(r.ContentLength, 0), cw.written, time.Since(start).Round(time.Millisecond))
}

// proxyTooLarge is the 413's sentence: the cap in bytes.
func proxyTooLarge() string {
	return fmt.Sprintf("request body larger than the proxy passes on: at most %d bytes, the upstream's own request size limit", proxyMaxRequestBytes)
}

// looksLikeToken says whether a path element has a token's shape: the 43
// characters 32 bytes make in base64url. Anything else is a path with no
// token in front of it.
func looksLikeToken(s string) bool {
	if len(s) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// tokenTag is the part of a token a log line carries.
func tokenTag(token string) string {
	tag := token
	if utf8.RuneCountInString(tag) > tokenShown {
		kept := 0
		for i := range tag {
			if kept == tokenShown {
				tag = tag[:i]
				break
			}
			kept++
		}
	}
	return identity.PrintableText(tag)
}

// countingWriter is the response as the log describes it: the status and
// the bytes. Unwrap is what lets the reverse proxy's flushes through.
type countingWriter struct {
	http.ResponseWriter
	status  int
	written int64
}

func (c *countingWriter) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
	c.ResponseWriter.WriteHeader(status)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(b)
	c.written += int64(n)
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// withoutCredentials is an environment with the three variables gone.
func withoutCredentials(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if name == envAPIKey || name == envAuth || name == envBaseURL {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// credentialsInEnvironment names the variables serve's own environment
// carries, for the warning that they are not passed on.
func credentialsInEnvironment() []string {
	var found []string
	for _, name := range credentialVars {
		if _, ok := os.LookupEnv(name); ok {
			found = append(found, name)
		}
	}
	return found
}
