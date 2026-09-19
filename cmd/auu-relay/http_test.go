package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/auu"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestTheRelaySpeaksHTTP11Alone: the relay's listener has HTTP/2 off. The
// tree's client cloned http.DefaultTransport, whose ForceAttemptHTTP2 is
// true, and the server set no TLSNextProto, so every deployed exchange was
// HTTP/2 while every test in the tree, through httptest, was HTTP/1.1 —
// the drain of an unread body, Connection: close on a refusal and the
// stall deadline on the connection were proven on the protocol nobody
// deployed. Now newHTTPServer's empty TLSNextProto keeps ServeTLS from
// installing h2 and buildTLS offers http/1.1 alone by ALPN: a handshake
// offering h2 then http/1.1 negotiates http/1.1, and a client transport
// that would force h2 is answered over HTTP/1.1 with the request served.
func TestTheRelaySpeaksHTTP11Alone(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, pool := selfSigned(t, dir)
	cfg := Defaults()
	cfg.TLS.Mode = ModeFiles
	cfg.TLS.CertFile = certPath
	cfg.TLS.KeyFile = keyPath
	tlsCfg, err := buildTLS(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCfg.NextProtos) != 1 || tlsCfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("NextProtos %v, want http/1.1 alone", tlsCfg.NextProtos)
	}
	srv := newHTTPServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.WriteHeader(http.StatusOK)
	}), tlsCfg, DefaultTimeouts())
	if srv.TLSNextProto == nil || len(srv.TLSNextProto) != 0 {
		t.Fatalf("TLSNextProto %v, want an empty map, which is what turns h2 off", srv.TLSNextProto)
	}
	if srv.MaxHeaderBytes != relayapi.MaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes %d, want relayapi.MaxHeaderBytes %d", srv.MaxHeaderBytes, relayapi.MaxHeaderBytes)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()

	// A handshake offering h2 first.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	negotiated := conn.ConnectionState().NegotiatedProtocol
	conn.Close()
	if negotiated != "http/1.1" {
		t.Fatalf("a handshake offering h2 negotiated %q, want http/1.1", negotiated)
	}

	// A transport that would force h2, as the tree's client did: served
	// over HTTP/1.1.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("the test's transport does not force h2; it should, to show the relay declining it")
	}
	resp, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Get("https://" + ln.Addr().String() + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Proto != "HTTP/1.1" || resp.Header.Get("X-Proto") != "HTTP/1.1" || resp.TLS.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("a forcing client got %s (server saw %s, ALPN %q); want HTTP/1.1 at both ends",
			resp.Proto, resp.Header.Get("X-Proto"), resp.TLS.NegotiatedProtocol)
	}
}

// TestTheProxyKeepsTheRelaysTimeouts: serve's key-holding proxy runs under
// the relay's body and idle timeouts, its own header timeout (ten seconds
// since PLAN-PROXY, under the relay's fifteen), the relay's header cap,
// and no write timeout — net/http's runs from the request header to the
// end of the response, and the proxy's response is the model's answer,
// silent until ready on a call that does not stream and minutes long
// either way; the bound is Claude Code's own client timeout across the
// loopback. The two the proxy shares are held to the relay's here so that
// one moving without the other is a failing test.
func TestTheProxyKeepsTheRelaysTimeouts(t *testing.T) {
	relay := DefaultTimeouts()
	proxy := auu.DefaultProxyTimeouts()
	if proxy.Read != relay.Read {
		t.Errorf("the proxy's read timeout is %s, the relay's %s; want them equal", proxy.Read, relay.Read)
	}
	if proxy.Idle != relay.Idle {
		t.Errorf("the proxy's idle timeout is %s, the relay's %s; want them equal", proxy.Idle, relay.Idle)
	}
	if proxy.ReadHeader <= 0 || proxy.ReadHeader > relay.ReadHeader {
		t.Errorf("the proxy's header timeout is %s; want one set, no longer than the relay's %s", proxy.ReadHeader, relay.ReadHeader)
	}
	if proxy.Write != 0 {
		t.Errorf("the proxy's write timeout is %s; want none, the model's answer being the response", proxy.Write)
	}
}
