package relay

// The second review's tests of F8 (reviews/mythos-review-2/
// _adversarial-tests-2/A/adv2_f8_test.go), kept as regression tests under
// their names without the review's prefix. Since G12 the declared length is
// judged before the claimed fingerprint is looked up, so a body declared
// over the cap is 413 for a registered fingerprint and an unregistered one
// alike: the 413 below no longer says a mailbox exists, and the budget the
// first test holds the answers to is the same either way.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// TestAnExistenceProbeCostsWhatAKeyLookupCosts quantifies F8's
// residual at the default unauthenticated_per_minute: every answer, hit or
// miss, spends one token of the address's budget, the same budget GET
// /v1/keys spends, so one address learns at most UnauthenticatedPerMinute
// fingerprints' existence a minute by either route together. Since G12 the
// probe's 413 is answered alike for a stranger, so only the key lookup's
// 200 still says a mailbox exists.
func TestAnExistenceProbeCostsWhatAKeyLookupCosts(t *testing.T) {
	lim := DefaultLimits()
	h := newHarness(t, Config{Limits: lim})
	alice := h.user(t, "alice")
	nobody := h.fpOf(t, "nobody")
	probe := func(claimed string) int {
		t.Helper()
		conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		nonce := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
		sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
		auth := fmt.Sprintf("v1 %s %d %s %s", claimed, time.Now().Unix(), nonce, sig)
		fmt.Fprintf(conn, "POST /v1/mailbox/%s HTTP/1.1\r\nHost: relay\r\n%s: %s\r\nContent-Length: %d\r\n\r\n",
			claimed, relayapi.AuthHeader, auth, relayapi.DefaultMaxBytes+relayapi.FramingAllowance+1)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	answered := 0
	bits := 0
	for i := range 2 * lim.UnauthenticatedPerMinute {
		var st int
		switch i % 3 {
		case 0:
			st = probe(alice.Fingerprint())
		case 1:
			st = probe(nobody)
		default:
			st, _, _ = h.send(nil, "GET", "/v1/keys/"+alice.Fingerprint(), nil, nil)
		}
		if st != http.StatusTooManyRequests {
			answered++
		}
		if st == http.StatusOK {
			bits++
		}
	}
	t.Logf("of %d probes and lookups inside one minute, %d were answered (%d key lookups said a mailbox exists); budget %d/min",
		2*lim.UnauthenticatedPerMinute, answered, bits, lim.UnauthenticatedPerMinute)
	if int64(answered) > lim.UnauthenticatedPerMinute {
		t.Errorf("%d answers in a minute from one address, over unauthenticated_per_minute %d", answered, lim.UnauthenticatedPerMinute)
	}
}

// TestMemoryBeforeTheSignatureIsInflightTimesTheCap measures §5's
// "memory before signature" suspicion on HEAD: requests naming a registered
// fingerprint, unsigned, each declaring a body just under the post cap and
// sending all of it but the last byte, are all buffered at once, and the
// unauthenticated budget (here 1 a minute) is charged only when a refusal
// is written, after the read. Peak memory is max_inflight × postCap from
// one address: 256 × (16 MiB + 64 KiB) ≈ 4 GiB at the defaults. A
// measurement, not a finding: no guide promises otherwise.
func TestMemoryBeforeTheSignatureIsInflightTimesTheCap(t *testing.T) {
	const maxBytes = int64(1 << 20)
	const inflight = 8
	h := newHarness(t, Config{MaxBytes: maxBytes, Limits: Limits{UnauthenticatedPerMinute: 1, MaxInflight: inflight + 2}})
	alice := h.user(t, "alice")
	declared := h.server.postCap() - 1
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var conns []net.Conn
	for range inflight {
		conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		nonce := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
		sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
		auth := fmt.Sprintf("v1 %s %d %s %s", alice.Fingerprint(), time.Now().Unix(), nonce, sig)
		fmt.Fprintf(conn, "POST /v1/mailbox/%s HTTP/1.1\r\nHost: relay\r\n%s: %s\r\nContent-Length: %d\r\n\r\n",
			alice.Fingerprint(), relayapi.AuthHeader, auth, declared)
		conn.Write(bytes.Repeat([]byte("x"), int(declared-1)))
	}
	time.Sleep(500 * time.Millisecond)
	var during runtime.MemStats
	runtime.ReadMemStats(&during)
	grew := int64(during.HeapInuse) - int64(before.HeapInuse)
	t.Logf("%d unsigned bodies of %d bytes naming a registered fingerprint, from one address with a budget of 1/min: heap in use grew %d bytes (%.1f× the bodies); nothing charged yet",
		inflight, declared, grew, float64(grew)/float64(inflight*declared))
	for _, c := range conns {
		c.Close()
	}
}
