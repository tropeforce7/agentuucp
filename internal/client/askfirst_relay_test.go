package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/client"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// countingListener counts the bytes the server read off every connection.
type countingListener struct {
	net.Listener
	read *atomic.Int64
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return countingConn{Conn: c, read: l.read}, nil
}

type countingConn struct {
	net.Conn
	read *atomic.Int64
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

// A post or forward over the relay's cap is answered with the relay's
// refusal, not a dropped link (57d): the relay refuses a declared length
// over the route's cap before it reads a byte and closes the connection,
// and Go's server drains none of a body that large, so a body already on
// the wire met a reset and the 413 was lost. A body over askFirstOver asks
// first, as an upload does (R42a), so the refusal comes before the body is
// sent: the relay reads a small part of what a whole body would be, and
// the client has its 413 with the relay's sentence. A small post does not
// ask, and costs no round trip.
func TestAPostOverTheRelaysCapIsAnsweredNotReset(t *testing.T) {
	dir := t.TempDir()
	st, err := relay.OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	handler := relay.NewServer(st, relay.Config{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Limits: relay.DefaultLimits(), MaxBytes: 64 << 10,
	})
	t.Cleanup(handler.Close)
	var asked atomic.Value
	asked.Store("")
	front := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Store(r.Header.Get("Expect"))
		handler.ServeHTTP(w, r)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var read atomic.Int64
	srv := &http.Server{Handler: front}
	go srv.Serve(countingListener{Listener: ln, read: &read})
	t.Cleanup(func() { srv.Close() })
	url := "http://" + ln.Addr().String()

	alice, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Generate("bob")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []*identity.Identity{alice, bob} {
		if err := st.Register(id.Fingerprint(), id.Public().Bundle(), id.Name, relay.RegisterOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	c, err := client.New(url, alice, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		send func(env *envelope.Envelope) error
	}{
		{"a post", func(env *envelope.Envelope) error { _, err := c.Post(context.Background(), env, ""); return err }},
		{"a forward", func(env *envelope.Envelope) error {
			raw, err := json.Marshal(env)
			if err != nil {
				return err
			}
			_, err = c.Forward(context.Background(), &relayapi.ForwardRequest{Envelope: raw, Path: []string{"elsewhere"}})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const size = 8 << 20
			read.Store(0)
			env := &envelope.Envelope{V: envelope.Version, To: bob.Fingerprint(), CT: make([]byte, size)}
			err := tc.send(env)
			var he *client.HTTPError
			if !errors.As(err, &he) || he.Status != http.StatusRequestEntityTooLarge || !strings.Contains(he.Error(), "bytes") {
				t.Fatalf("%s over the relay's cap: %v; want the relay's 413 with its sentence, not a transport failure", tc.name, err)
			}
			if got := asked.Load(); got != "100-continue" {
				t.Fatalf("%s over the relay's cap asked %q before its body; want 100-continue", tc.name, got)
			}
			if n := read.Load(); n >= size/2 {
				t.Fatalf("the relay read %d bytes of a refused %d-byte %s; want its headers and not its body", n, size, tc.name)
			}
		})
	}

	// A small post does not ask: the relay answers it with nothing waited.
	small := &envelope.Envelope{V: envelope.Version, To: bob.Fingerprint(), CT: []byte("small")}
	if _, err := c.Post(context.Background(), small, ""); err != nil {
		t.Fatalf("a small post: %v", err)
	}
	if got := asked.Load(); got != "" {
		t.Fatalf("a small post asked %q before its body; want no Expect", got)
	}
}
