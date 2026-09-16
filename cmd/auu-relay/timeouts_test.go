package main

import (
	"net"
	"net/http"
	"testing"
	"time"
)

// A caller that declares a body and never sends it holds a handler goroutine.
// ReadTimeout is what ends that, and it is a security property rather than a
// detail, so it is tested rather than assumed.
func TestReadTimeoutEndsAStalledBody(t *testing.T) {
	srv := newHTTPServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body the way the relay does.
		buf := make([]byte, 1<<20)
		for {
			if _, err := r.Body.Read(buf); err != nil {
				return
			}
		}
	}), nil, Timeouts{ReadHeader: time.Second, Read: 500 * time.Millisecond,
		Write: 2 * time.Second, Idle: time.Second})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "POST /v1/mailbox/x HTTP/1.1\r\nHost: x\r\nContent-Length: 1073741824\r\n\r\n0123456789"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	// The connection must be closed by the server well before the declared
	// gigabyte could arrive.
	// The margin is generous on purpose: the claim is that the server does not
	// wait for a gigabyte that will never arrive, not that it reacts in any
	// particular millisecond. A contended runner must not fail this.
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	buf := make([]byte, 128)
	if _, err := conn.Read(buf); err == nil {
		// A response is fine too; what matters is that it did not hang.
		t.Logf("server responded after %v", time.Since(start))
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("the server waited %v for a body that never came", elapsed)
	}
}

// A caller that opens a connection and sends nothing must not hold it.
func TestReadHeaderTimeoutEndsASilentConnection(t *testing.T) {
	srv := newHTTPServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		nil, Timeouts{ReadHeader: 300 * time.Millisecond, Read: time.Second,
			Write: time.Second, Idle: time.Second})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Half a request line, then silence.
	if _, err := conn.Write([]byte("GET /v1/health HTT")); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	buf := make([]byte, 128)
	conn.Read(buf) // returns on close or on the 408
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("the server waited %v for a header that never came", elapsed)
	}
}

// The shipped timeouts must all be positive; a zero means no timeout at all.
func TestDefaultTimeoutsAreAllSet(t *testing.T) {
	d := DefaultTimeouts()
	for name, v := range map[string]time.Duration{
		"ReadHeader": d.ReadHeader, "Read": d.Read, "Write": d.Write, "Idle": d.Idle,
	} {
		if v <= 0 {
			t.Errorf("%s is %v; a non-positive timeout means none at all", name, v)
		}
	}
	srv := newHTTPServer(":8080", nil, nil, d)
	if srv.ReadHeaderTimeout != d.ReadHeader || srv.ReadTimeout != d.Read ||
		srv.WriteTimeout != d.Write || srv.IdleTimeout != d.Idle {
		t.Fatalf("newHTTPServer did not apply the timeouts: read-header %v, read %v, write %v, idle %v",
			srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}
