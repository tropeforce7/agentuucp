package client

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/clientca"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/pki"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
)

// answerBodies is every answer body a relay sends, each of which carries
// sections (D28, R3). A row inside a list is not here: it carries none.
var answerBodies = []any{
	&relayapi.ErrorResponse{}, &relayapi.RegisterResponse{}, &relayapi.KeysResponse{},
	&relayapi.AllowResponse{}, &relayapi.CardResponse{}, &relayapi.ListedResponse{},
	&relayapi.CouriersResponse{}, &relayapi.ChannelsResponse{}, &relayapi.PostResponse{},
	&relayapi.ForwardResponse{}, &relayapi.QueueResponse{}, &relayapi.ListResponse{},
	&relayapi.HealthResponse{}, &relayapi.AdminStatusResponse{}, &relayapi.MailboxListResponse{},
	&relayapi.CertsResponse{}, &relayapi.TrustAnchorResponse{}, &relayapi.CertResponse{},
	&relayapi.RevokeCertResponse{}, &relayapi.BlocksResponse{}, &relayapi.TokenListResponse{},
	&relayapi.OpenStreamResponse{}, &relayapi.PutStreamResponse{},
	&relayapi.MailboxAnswer{}, &relayapi.TokenAnswer{},
}

// withKey is an answer body as raw JSON with one key set at its top.
func withKey(t *testing.T, body any, key string, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m[key] = value
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// answering is a relay that answers every request with the bytes given.
func answering(t *testing.T, status int, body []byte) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(srv.URL, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func section(name string, critical bool) map[string]any {
	return map[string]any{"name": name, "critical": critical, "data": map[string]any{"n": 1}}
}

// Every answer body, through the one path every answer takes: taken whole;
// a field it does not have refused (P1); a section this build does not
// know ignored; one marked critical refusing the answer by its name.
func TestEveryAnswerTakesNothingNewButSections(t *testing.T) {
	for _, body := range answerBodies {
		name := reflect.TypeOf(body).Elem().Name()
		t.Run(name, func(t *testing.T) {
			read := func(raw []byte) error {
				out := reflect.New(reflect.TypeOf(body).Elem()).Interface()
				return answering(t, http.StatusOK, raw).do(context.Background(), "GET", "/v1/x", nil, out, nil)
			}
			whole, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if err := read(whole); err != nil {
				t.Fatalf("the answer whole: %v; want it taken", err)
			}
			if err := read(withKey(t, body, "colour", "blue")); !errors.Is(err, ErrMalformedAnswer) ||
				!strings.Contains(err.Error(), `unknown field "colour"`) {
				t.Errorf("a field it does not have: %v; want it refused by name", err)
			}
			if err := read(withKey(t, body, "sections", []any{section("later", false)})); err != nil {
				t.Errorf("a section this build does not know, not critical: %v; want it ignored", err)
			}
			err = read(withKey(t, body, "sections", []any{section("must-know", true)}))
			if !errors.Is(err, ErrMalformedAnswer) ||
				!strings.Contains(err.Error(), `answered GET /v1/x with a section it must not be read without (section "must-know"); update auu`) {
				t.Errorf("a critical section: %v; want the answer refused naming it", err)
			}
		})
	}
}

// R4: an answer's sections together, as this build encodes them compactly,
// are held to wire.MaxAPISectionBytes; the body's own hold has already
// bounded what arrived.
func TestLimitAnAnswersSectionsAreHeldTo16KiB(t *testing.T) {
	list := func(n int) []wire.Section {
		empty, _ := json.Marshal([]wire.Section{{Name: "later", Data: json.RawMessage(`""`)}})
		pad := n - len(empty)
		return []wire.Section{{Name: "later", Data: json.RawMessage(`"` + strings.Repeat("a", pad) + `"`)}}
	}
	for _, tc := range []struct {
		n    int
		want string
	}{
		{wire.MaxAPISectionBytes, ""},
		{wire.MaxAPISectionBytes + 1, fmt.Sprintf("with sections of %d bytes, over the %d an answer may carry", wire.MaxAPISectionBytes+1, wire.MaxAPISectionBytes)},
	} {
		sections := list(tc.n)
		if encoded, _ := json.Marshal(sections); len(encoded) != tc.n {
			t.Fatalf("the list measures %d, want %d", len(encoded), tc.n)
		}
		raw := withKey(t, &relayapi.PostResponse{ID: 1}, "sections", sections)
		err := answering(t, http.StatusOK, raw).do(context.Background(), "GET", "/v1/x", nil, &relayapi.PostResponse{}, nil)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%d bytes: %v; want them taken", tc.n, err)
		case tc.want != "" && (!errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%d bytes: %v; want %q", tc.n, err, tc.want)
		}
	}
}

// R2: a refusal is read strictly too. One whose words this build cannot
// read keeps its status and says, with the relay and the route, that it
// could not read them, so a newer relay's refusal is never an empty
// sentence; one with a section it must not be read without says so.
func TestARefusalThisBuildCannotReadKeepsItsStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
		want string
	}{
		{"a refusal whole", []byte(`{"error":"no such mailbox"}`), "no such mailbox"},
		{"a field it does not have", []byte(`{"error":"no such mailbox","colour":"blue"}`), "refused GET /v1/x (404) in words this build cannot read"},
		{"not JSON at all", []byte(`404 page not found`), "refused GET /v1/x (404) in words this build cannot read"},
		{"a section not critical", []byte(`{"error":"no such mailbox","sections":[{"name":"later","critical":false,"data":1}]}`), "no such mailbox"},
		{"a critical section", []byte(`{"error":"no such mailbox","sections":[{"name":"must-know","critical":true,"data":1}]}`),
			`refused GET /v1/x (404) with a section it must not be read without (section "must-know"); update auu`},
	} {
		c := answering(t, http.StatusNotFound, tc.body)
		err := c.do(context.Background(), "GET", "/v1/x", nil, nil, nil)
		var he *HTTPError
		if !errors.As(err, &he) || he.Status != http.StatusNotFound || !strings.Contains(he.Message, tc.want) {
			t.Errorf("%s: %v; want status 404 and %q", tc.name, err, tc.want)
		}
		if strings.Contains(tc.want, "cannot read") && !strings.Contains(he.Message, "the relay at "+c.base) {
			t.Errorf("%s: %q does not name the relay", tc.name, he.Message)
		}
	}
}

// The two answers read outside the common path hold their sections the same
// way: the placed stream's id from a PUT, and the trust anchor.
func TestThePlacedStreamAndTheAnchorHoldTheirSections(t *testing.T) {
	var answer atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(answer.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	upload := strings.Repeat("b", 32)
	put := func(body string) (int64, error) {
		answer.Store(body)
		return c.PutStream(context.Background(), upload, 0, bytes.NewReader([]byte("sealed")), 6)
	}
	if id, err := put(`{"id":7,"sections":[{"name":"later","critical":false,"data":1}]}`); err != nil || id != 7 {
		t.Errorf("a placed stream with a section not critical: %d, %v; want 7", id, err)
	}
	if _, err := put(`{"id":7,"sections":[{"name":"must-know","critical":true,"data":1}]}`); !errors.Is(err, ErrMalformedAnswer) ||
		!strings.Contains(err.Error(), `(section "must-know"); update auu`) {
		t.Errorf("a placed stream with a critical section: %v", err)
	}
	if _, err := put(`{"id":7,"colour":"blue"}`); !errors.Is(err, ErrMalformedAnswer) {
		t.Errorf("a placed stream with a field it does not have: %v", err)
	}

	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	var anchor atomic.Value
	asrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"trust_anchor":"` + b64(bundle.Anchor.Raw) + `","spki":"` + strings.Repeat("f", 64) + `"` + anchor.Load().(string) + `}`))
	}))
	server, err := clientca.NewServer(bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	asrv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS13}
	asrv.StartTLS()
	defer asrv.Close()
	for _, tc := range []struct{ extra, want string }{
		{``, ""},
		{`,"sections":[{"name":"later","critical":false,"data":1}]`, ""},
		{`,"sections":[{"name":"must-know","critical":true,"data":1}]`, `(section "must-know"); update auu`},
		{`,"colour":"blue"`, `unknown field "colour"`},
	} {
		anchor.Store(tc.extra)
		_, _, err := FetchTrustAnchor(t.Context(), asrv.URL)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("the anchor with %q: %v; want it taken", tc.extra, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("the anchor with %q: %v; want %q", tc.extra, err, tc.want)
		}
	}
}

// A sentence the client builds about a relay's answer names what the relay
// chose escaped: a map key encoding/json names in a type error, and the
// trust anchor's reason phrase. Neither may reach a terminal as itself.
func TestWhatARelayChoseInAnAnswersSentenceIsEscaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"queued":{"\u001b[31mred\nline":"not a number"}}`))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = c.do(context.Background(), "GET", "/v1/channels", nil, &relayapi.ChannelsResponse{}, nil)
	if !errors.Is(err, ErrMalformedAnswer) {
		t.Fatalf("a map key over a type error: %v; want ErrMalformedAnswer", err)
	}
	if msg := err.Error(); strings.ContainsAny(msg, "\x1b\n") {
		t.Errorf("a map key in a type error: %q carries a control byte as itself", msg)
	}

	// No relay-chosen URL reaches a refusal's route now that no redirect is
	// followed (ruling 65), so the sentence is fed one directly: relayOf and
	// routeOf escape whatever the request they are handed says, so a path
	// that later builds one from a relay's words cannot drive a terminal.
	req, err := http.NewRequest("GET", "http://relay.example/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.Host = "relay\x1b[2J.example"
	req.URL.Path = "/\x1b]0;title\x07\nforged"
	he := httpError(&http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Request: req}, []byte("x"))
	if !strings.Contains(he.Message, "in words this build cannot read") {
		t.Fatalf("a refusal with a chosen route: %q; want the unreadable sentence", he.Message)
	}
	if strings.ContainsAny(he.Message, "\x1b\x07\n") {
		t.Errorf("a refusal with a chosen route: %q carries a control byte as itself", he.Message)
	}

	// The reason phrase is written by hand, since net/http writes its own.
	asrv := anchorRelay(t, func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 500 \x1b]0;title\x07\x1b[2Jforged\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		_ = buf.Flush()
	})
	_, _, err = FetchTrustAnchor(t.Context(), asrv.URL)
	if err == nil || !strings.Contains(err.Error(), "fetching the relay's trust anchor: 500") {
		t.Fatalf("an anchor refused with a reason phrase: %v", err)
	}
	if msg := err.Error(); strings.ContainsAny(msg, "\x1b\x07") {
		t.Errorf("the anchor's reason phrase: %q carries a control byte as itself", msg)
	}
}

// anchorRelay is a TLS relay with the handshake the client pins, answering
// with h. The anchor fetch verifies nothing at the handshake but the
// transport, so any certificate of the hierarchy does.
func anchorRelay(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	bundle := pki.TestHierarchy(t, []string{"127.0.0.1"}, mldsa.MLDSA65())
	srv := httptest.NewUnstartedServer(h)
	server, err := clientca.NewServer(bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := server.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// Ruling 65: the client follows no redirect, on any path. A 3xx is an
// answer, refused as malformed naming its status, and the Location is
// never fetched: a relay API has no reason to redirect, and the signed
// header would go to whoever the Location named.
func TestARelayThatRedirectsIsRefusedAndNotFollowed(t *testing.T) {
	var followed atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testIdentity(t, "alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	refused := func(what, route string, err error) {
		t.Helper()
		want := "answered " + route + " with a redirect (302), which this build does not follow"
		if !errors.Is(err, ErrMalformedAnswer) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v; want %q", what, err, want)
		}
		if strings.Contains(err.Error(), "elsewhere") {
			t.Errorf("%s: %q repeats the Location", what, err)
		}
	}
	refused("an answer", "GET /v1/health", c.do(context.Background(), "GET", "/v1/health", nil, &relayapi.HealthResponse{}, nil))
	refused("a post", "POST /v1/x", c.do(context.Background(), "POST", "/v1/x", []byte(`{}`), &relayapi.PostResponse{}, nil))
	_, err = c.PutStream(context.Background(), strings.Repeat("b", 32), 0, bytes.NewReader([]byte("sealed")), 6)
	refused("a placed stream", "PUT /v1/uploads/"+strings.Repeat("b", 32), err)
	fp := strings.Repeat("a", 64)
	_, _, err = c.Blob(context.Background(), fp, 7, 0, -1)
	refused("a blob", "GET /v1/mailbox/"+fp+"/7/blob", err)

	asrv := anchorRelay(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed.Add(1)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	if _, _, err := FetchTrustAnchor(t.Context(), asrv.URL); err == nil ||
		!strings.Contains(err.Error(), "its trust anchor with a redirect (302), which this build does not follow") {
		t.Errorf("the anchor: %v; want the redirect refused", err)
	}
	if n := followed.Load(); n != 0 {
		t.Errorf("the Location was fetched %d times; want never", n)
	}
}

// relayHTTP is a rule only where every path reaches it: no file of this
// package names http.Client other than behind a pointer, outside relayHTTP,
// so none builds one by a literal, new or a declared value; none names
// http.DefaultClient or the package functions that use it (Get, Post, Head,
// PostForm), so none reaches Go's default redirect policy by omission; and
// none assigns CheckRedirect, so none undoes the policy on a client it was
// handed.
func TestEveryClientThisPackageBuildsComesFromRelayHTTP(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	isHTTPClient := func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Client" {
			return false
		}
		x, ok := sel.X.(*ast.Ident)
		return ok && x.Name == "http"
	}
	defaultPolicy := map[string]bool{"DefaultClient": true, "Get": true, "Post": true, "Head": true, "PostForm": true}
	built := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, imp := range file.Imports {
				if imp.Path.Value == `"net/http"` && imp.Name != nil {
					t.Errorf("%s: net/http imported as %s, which this walk would not see", fset.Position(imp.Pos()), imp.Name.Name)
				}
			}
			for _, decl := range file.Decls {
				fn, _ := decl.(*ast.FuncDecl)
				inHelper := fn != nil && fn.Name.Name == "relayHTTP"
				var stack []ast.Node
				ast.Inspect(decl, func(n ast.Node) bool {
					if n == nil {
						stack = stack[:len(stack)-1]
						return false
					}
					parent := ast.Node(nil)
					if len(stack) > 0 {
						parent = stack[len(stack)-1]
					}
					stack = append(stack, n)
					if isHTTPClient(n) {
						if _, behindPointer := parent.(*ast.StarExpr); !behindPointer {
							built++
							if !inHelper {
								t.Errorf("%s: an http.Client made outside relayHTTP", fset.Position(n.Pos()))
							}
						}
					}
					if sel, ok := n.(*ast.SelectorExpr); ok && defaultPolicy[sel.Sel.Name] {
						if x, ok := sel.X.(*ast.Ident); ok && x.Name == "http" {
							t.Errorf("%s: http.%s follows redirects under Go's default policy", fset.Position(n.Pos()), sel.Sel.Name)
						}
					}
					if as, ok := n.(*ast.AssignStmt); ok && !inHelper {
						for _, lhs := range as.Lhs {
							if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "CheckRedirect" {
								t.Errorf("%s: CheckRedirect assigned outside relayHTTP", fset.Position(lhs.Pos()))
							}
						}
					}
					return true
				})
			}
		}
	}
	if built != 1 {
		t.Errorf("found %d http.Client values made; want the one in relayHTTP", built)
	}
}

// The wire level is written by every health answer checked, under the
// listing's lock and outside it, and read without one: under -race this
// fails unless the field is atomic.
func TestTheWireLevelIsReadAndWrittenWithoutARace(t *testing.T) {
	health, err := json.Marshal(relayapi.HealthResponse{
		OK: true, MaxBytes: 1 << 20, KnockMaxBytes: 1 << 10, Registration: relayapi.RegistrationOpen, WireLevel: relayapi.WireLevel,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := answering(t, http.StatusOK, health)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			_ = c.WireLevel()
		}
	}()
	for range 20 {
		if _, err := c.HealthInfo(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	if got := c.WireLevel(); got != relayapi.WireLevel {
		t.Errorf("WireLevel() = %d, want %d", got, relayapi.WireLevel)
	}
}
