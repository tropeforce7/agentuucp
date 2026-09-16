package relayapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
)

func signed(t *testing.T, id *identity.Identity, method, url string, body []byte) (*http.Request, *Auth) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(id, req, body); err != nil {
		t.Fatal(err)
	}
	auth, err := ParseAuth(req.Header.Get(AuthHeader))
	if err != nil {
		t.Fatal(err)
	}
	return req, auth
}

func TestSignThenVerify(t *testing.T) {
	id, _ := identity.Generate("a")
	body := []byte(`{"hello":"world"}`)
	req, auth := signed(t, id, "POST", "https://relay.example/v1/mailbox/abc?after=3", body)

	if auth.FP != id.Fingerprint() {
		t.Fatal("wrong fingerprint in header")
	}
	if !auth.FreshAt(time.Now()) {
		t.Fatal("fresh request considered stale")
	}
	if !auth.Verify(id.Public(), req.Method, req.URL.RequestURI(), body) {
		t.Fatal("valid signature rejected")
	}
}

// What the server reconstructs from an incoming request must match what the
// client signed.
func TestServerSideReconstruction(t *testing.T) {
	id, _ := identity.Generate("a")
	body := []byte("payload")
	req, _ := signed(t, id, "GET", "https://relay.example/v1/mailbox/abc?after=3&limit=10", body)

	srv := httptest.NewRequest(req.Method, req.URL.RequestURI(), bytes.NewReader(body))
	srv.Header = req.Header
	auth, err := ParseAuth(srv.Header.Get(AuthHeader))
	if err != nil {
		t.Fatal(err)
	}
	if !auth.Verify(id.Public(), srv.Method, RequestPath(srv), body) {
		t.Fatal("server side verification failed")
	}
}

func TestVerifyFailsOnChanges(t *testing.T) {
	id, _ := identity.Generate("a")
	other, _ := identity.Generate("b")
	body := []byte("payload")
	req, auth := signed(t, id, "POST", "https://relay.example/v1/mailbox/abc", body)
	path := req.URL.RequestURI()

	cases := []struct {
		name         string
		method, path string
		body         []byte
		pub          *identity.Public
	}{
		{"changed method", "DELETE", path, body, id.Public()},
		{"changed path", req.Method, "/v1/mailbox/def", body, id.Public()},
		{"changed query", req.Method, path + "?after=1", body, id.Public()},
		{"changed body", req.Method, path, []byte("payload!"), id.Public()},
		{"empty body", req.Method, path, nil, id.Public()},
		{"wrong key", req.Method, path, body, other.Public()},
	}
	for _, c := range cases {
		if auth.Verify(c.pub, c.method, c.path, c.body) {
			t.Fatalf("%s: signature still verified", c.name)
		}
	}
}

func TestStaleTimestamp(t *testing.T) {
	id, _ := identity.Generate("a")
	_, auth := signed(t, id, "GET", "https://relay.example/v1/health", nil)
	if auth.FreshAt(time.Now().Add(MaxSkew + time.Minute)) {
		t.Fatal("stale request accepted")
	}
	if auth.FreshAt(time.Now().Add(-(MaxSkew + time.Minute))) {
		t.Fatal("far future request accepted")
	}
}

func TestParseAuthRejects(t *testing.T) {
	id, _ := identity.Generate("a")
	req, _ := signed(t, id, "GET", "https://relay.example/v1/health", nil)
	valid := req.Header.Get(AuthHeader)

	bad := []string{
		"",
		"v1 a b c",
		"v2 " + valid[3:],
		"v1 nothex 1 AAAA AAAA",
		valid + " extra",
	}
	for _, h := range bad {
		if _, err := ParseAuth(h); err == nil {
			t.Fatalf("accepted bad header %q", h)
		}
	}
}
