package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rawRequest sends one request over the socket as bytes, past the
// client's own checks, and returns the reply.
func rawRequest(t *testing.T, a *running, req *request) response {
	t.Helper()
	conn, err := net.Dial("unix", a.client.Socket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(raw)))
	conn.Write(prefix[:])
	conn.Write(raw)
	frame, err := readFrame(conn)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	var resp response
	if err := json.Unmarshal(frame, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestLimitUnlockTTL: the ttl of an unlock request, in seconds, is within
// [0, MaxTTL]: a negative and the type's minimum are refused, zero is
// until lock, the bound is a year, and one over and the type's maximum
// are refused naming the bound; nothing is multiplied first.
func TestLimitUnlockTTL(t *testing.T) {
	a := startAgent(t)
	max := int64(MaxTTL / time.Second)
	for _, ttl := range []int64{-1, math.MinInt64} {
		resp := rawRequest(t, a, &request{Op: OpUnlock, Passphrase: []byte(passphrase), TTL: ttl})
		if resp.OK || !strings.Contains(resp.Error, "negative") {
			t.Errorf("ttl %d: %+v; want the refusal naming a negative", ttl, resp)
		}
		if st, _ := a.client.Status(); !st.Locked {
			t.Errorf("ttl %d unlocked the agent", ttl)
		}
	}
	for _, ttl := range []int64{max + 1, math.MaxInt64} {
		resp := rawRequest(t, a, &request{Op: OpUnlock, Passphrase: []byte(passphrase), TTL: ttl})
		if resp.OK || !strings.Contains(resp.Error, "at most "+strconv.FormatInt(max, 10)) {
			t.Errorf("ttl %d: %+v; want the refusal naming the bound", ttl, resp)
		}
		if st, _ := a.client.Status(); !st.Locked {
			t.Errorf("ttl %d unlocked the agent", ttl)
		}
	}
	for _, ttl := range []int64{0, 1, max} {
		resp := rawRequest(t, a, &request{Op: OpUnlock, Passphrase: []byte(passphrase), TTL: ttl})
		if !resp.OK {
			t.Errorf("ttl %d: %+v", ttl, resp)
		}
		st, err := a.client.Status()
		if err != nil || st.Locked {
			t.Errorf("ttl %d left the agent locked: %+v %v", ttl, st, err)
		}
		if ttl == 0 && !st.Until.IsZero() {
			t.Errorf("ttl 0 set an expiry: %+v", st)
		}
		if ttl != 0 {
			if want := a.clock.Now().Add(time.Duration(ttl) * time.Second).Truncate(time.Second); st.Until.Sub(want).Abs() > time.Second {
				t.Errorf("ttl %d: until %s, want %s", ttl, st.Until, want)
			}
		}
		a.client.Lock()
	}
}

// TestLimitGenerateParams: the parameter set of a generate request is one
// of 44, 65 and 87; each neighbour, zero, a negative and the type's
// extremes are refused naming the three.
func TestLimitGenerateParams(t *testing.T) {
	a := startAgent(t)
	a.unlockSend(t, DefaultSendTTL)
	for _, n := range []int{0, -1, 43, 45, 64, 66, 86, 88, math.MinInt, math.MaxInt} {
		resp := rawRequest(t, a, &request{Op: OpGenerate, Key: CertPrefix + "work", Params: n})
		if resp.OK || !strings.Contains(resp.Error, "must be 44, 65 or 87, got "+strconv.Itoa(n)) {
			t.Errorf("params %d: %+v; want the refusal naming the three", n, resp)
		}
	}
	for _, n := range []int{44, 65, 87} {
		resp := rawRequest(t, a, &request{Op: OpGenerate, Key: CertPrefix + "work", Params: n})
		if !resp.OK || len(resp.PublicKey) == 0 {
			t.Errorf("params %d: %+v", n, resp)
		}
	}
}

// TestLimitFrameLength: a frame's length prefix is within [1, MaxFrame]:
// zero is an empty frame, one over the bound and the type's maximum are
// refused before anything is allocated, and one and the bound are read.
func TestLimitFrameLength(t *testing.T) {
	frame := func(n uint32, payload []byte) []byte {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], n)
		return append(prefix[:], payload...)
	}
	for _, n := range []uint32{0, MaxFrame + 1, math.MaxUint32} {
		_, err := readFrame(bytes.NewReader(frame(n, nil)))
		if !errors.Is(err, ErrFrame) {
			t.Errorf("length %d: %v; want ErrFrame", n, err)
		}
	}
	for _, n := range []uint32{1, MaxFrame} {
		payload := bytes.Repeat([]byte{'x'}, int(n))
		got, err := readFrame(bytes.NewReader(frame(n, payload)))
		if err != nil || len(got) != int(n) {
			t.Errorf("length %d: read %d bytes, %v", n, len(got), err)
		}
	}
	// The bound, declared and not delivered: the read fails, and it fails
	// on the bytes, not on the number.
	_, err := readFrame(bytes.NewReader(frame(MaxFrame, []byte("short"))))
	if !errors.Is(err, ErrFrame) || !strings.Contains(err.Error(), "EOF") {
		t.Errorf("a frame declared at the bound and cut short: %v", err)
	}
}
