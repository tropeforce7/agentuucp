package relay

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// TestLimitOpenStreamSize: the size a sender declares for a stream is
// within [the smallest stream, MaxStreamSize], and under max_stream_bytes
// when the relay sets one: zero, a negative, the type's minimum, one under
// the smallest, one over the cap and the type's maximum are each refused
// with a sentence naming the bound, before anything is reserved.
func TestLimitOpenStreamSize(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	smallest := int64(stream.HeaderSize + stream.MinChunk0 + stream.TagSize)

	t.Run("no max_stream_bytes", func(t *testing.T) {
		h := newHarness(t, Config{})
		h.register(alice)
		h.register(bob)
		for _, tc := range []struct {
			size int64
			says string
		}{
			{0, "size must be positive"},
			{-1, "size must be positive"},
			{math.MinInt64, "size must be positive"},
			{smallest - 1, "the smallest possible one is " + strconv.FormatInt(smallest, 10)},
			{MaxStreamSize + 1, "no relay accepts more than"},
			{math.MaxInt64, "no relay accepts more than"},
		} {
			status, _, body := h.openStream(alice, bob.Fingerprint(), tc.size)
			if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), tc.says) {
				t.Errorf("size %d: %d %s; want 400 saying %q", tc.size, status, body, tc.says)
			}
			if n := h.reserved(bob.Fingerprint()); n != 0 {
				t.Errorf("size %d left %d uploads open", tc.size, n)
			}
		}
		for _, size := range []int64{smallest, MaxStreamSize} {
			status, _, body := h.openStream(alice, bob.Fingerprint(), size)
			if status != http.StatusCreated {
				t.Errorf("size %d: %d %s; want 201", size, status, body)
			}
		}
	})

	t.Run("max_stream_bytes", func(t *testing.T) {
		const cap = 10 << 20
		h := newHarness(t, Config{MaxStreamBytes: cap})
		h.register(alice)
		h.register(bob)
		for _, size := range []int64{cap + 1, MaxStreamSize} {
			status, _, body := h.openStream(alice, bob.Fingerprint(), size)
			if status != http.StatusForbidden || !strings.Contains(errorText(t, body), "max_stream_bytes is "+strconv.Itoa(cap)) {
				t.Errorf("size %d: %d %s; want 403 naming max_stream_bytes", size, status, body)
			}
		}
		if status, _, body := h.openStream(alice, bob.Fingerprint(), cap); status != http.StatusCreated {
			t.Errorf("size at the cap: %d %s; want 201", status, body)
		}
	})
}

// TestLimitListingParameters: after is a message id or zero and limit is
// positive, each read from the query as text: a negative, the type's
// minimum, the text one past the type's maximum, a sign inside the
// digits, a leading space and a digit outside ASCII are each 400 naming
// the parameter; zero after, a plus sign (as %2B, since a bare plus is a
// space in a query), and the type's maximum are taken. A limit over MaxListLimit is answered with MaxListLimit rows,
// which the client's listing documents.
func TestLimitListingParameters(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	for range 3 {
		if status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(), sealed(t, alice, bob.Public(), "x"), nil); status != http.StatusOK {
			t.Fatalf("post: %d %s", status, body)
		}
	}
	list := func(t *testing.T, query string) (int, relayapi.ListResponse, []byte) {
		t.Helper()
		status, body := h.do(bob, "GET", "/v1/mailbox/"+bob.Fingerprint()+query, nil, nil)
		var out relayapi.ListResponse
		if status == http.StatusOK {
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatal(err)
			}
		}
		return status, out, body
	}
	for _, tc := range []struct{ param, value string }{
		{"after", "-1"}, {"after", strconv.FormatInt(math.MinInt64, 10)}, {"after", "9223372036854775808"},
		{"after", "1-2"}, {"after", "%201"}, {"after", "\u0661"}, {"after", "0x1"},
		{"limit", "0"}, {"limit", "-1"}, {"limit", "-0"}, {"limit", strconv.FormatInt(math.MinInt64, 10)},
		{"limit", "9223372036854775808"}, {"limit", "%201"}, {"limit", "\u0661"},
	} {
		status, _, body := list(t, "?"+tc.param+"="+tc.value)
		if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), "bad "+tc.param+" parameter") {
			t.Errorf("%s=%s: %d %s; want 400 naming the parameter", tc.param, tc.value, status, body)
		}
	}
	for _, tc := range []struct {
		query string
		rows  int
	}{
		{"?after=0", 3}, {"?after=-0", 3}, {"?after=%2B0", 3}, {"?after=9223372036854775807", 0},
		{"?limit=1", 1}, {"?limit=%2B1", 1}, {"?limit=9223372036854775807", 3},
		{"?limit=" + strconv.Itoa(relayapi.MaxListLimit), 3}, {"?limit=" + strconv.Itoa(relayapi.MaxListLimit+1), 3},
	} {
		status, out, body := list(t, tc.query)
		if status != http.StatusOK || len(out.Messages) != tc.rows {
			t.Errorf("%s: %d, %d rows %s; want 200 and %d rows", tc.query, status, len(out.Messages), body, tc.rows)
		}
	}
}

// TestLimitMessageIDInPath: the id in a delete or a blob path is
// positive: zero, a negative, the type's minimum, the text one past the
// type's maximum, a sign inside the digits and a digit outside ASCII are
// each 400 "bad message id" before the store is asked; a plus sign and
// the type's maximum reach the store, which has no such message.
func TestLimitMessageIDInPath(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	for _, route := range []struct{ method, tail string }{{"DELETE", ""}, {"GET", "/blob"}} {
		for _, id := range []string{"0", "-1", "-0", strconv.FormatInt(math.MinInt64, 10), "9223372036854775808", "1-2", "\u0661", "0x1", "%201"} {
			status, body := h.do(bob, route.method, "/v1/mailbox/"+bob.Fingerprint()+"/"+id+route.tail, nil, nil)
			if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), "bad message id") {
				t.Errorf("%s %s: %d %s; want 400 bad message id", route.method, id, status, body)
			}
		}
		for _, id := range []string{"+1", "9223372036854775807"} {
			status, body := h.do(bob, route.method, "/v1/mailbox/"+bob.Fingerprint()+"/"+id+route.tail, nil, nil)
			if status != http.StatusNotFound {
				t.Errorf("%s %s: %d %s; want 404", route.method, id, status, body)
			}
		}
	}
}

// TestLimitUploadOffset: the offset an attempt declares is the upload's
// own, never negative: a negative, the type's minimum, the text one past
// the type's maximum, a sign inside the digits, an empty value and a
// digit outside ASCII are each 400 naming the header (a leading space
// cannot arrive: net/http trims a header's value); an offset that is a
// number but not the upload's is 409 saying where the upload is; a plus
// sign before zero at the start is taken, and the attempt from it that
// runs to the end places the stream, the header saying so.
func TestLimitUploadOffset(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	blob := fakeStream(200, 3000)
	status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
	if status != http.StatusCreated {
		t.Fatalf("open: %d %s", status, body)
	}
	for _, offset := range []string{"-1", strconv.FormatInt(math.MinInt64, 10), "9223372036854775808", "1-2", "\u0660", ""} {
		status, body, _ := h.sendRaw(alice, "PUT", "/v1/uploads/"+opened.Upload, blob,
			map[string]string{relayapi.UploadOffsetHeader: offset})
		if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), relayapi.UploadOffsetHeader) {
			t.Errorf("offset %q: %d %s; want 400 naming the header", offset, status, body)
		}
	}
	for _, offset := range []string{"1", "9223372036854775807"} {
		status, body, hdr := h.sendRaw(alice, "PUT", "/v1/uploads/"+opened.Upload, blob,
			map[string]string{relayapi.UploadOffsetHeader: offset})
		if status != http.StatusConflict || hdr.Get(relayapi.UploadOffsetHeader) != "0" {
			t.Errorf("offset %s before anything was sent: %d %s; want 409 with the header at 0", offset, status, body)
		}
	}
	status, body, hdr := h.sendRaw(alice, "PUT", "/v1/uploads/"+opened.Upload, blob,
		map[string]string{relayapi.UploadOffsetHeader: "+0"})
	if status != http.StatusCreated || hdr.Get(relayapi.UploadOffsetHeader) != strconv.Itoa(len(blob)) {
		t.Errorf("offset +0: %d %s; want 201 and the header at %d", status, body, len(blob))
	}
}

// TestLimitManifestChunkLength: the length the first chunk's header
// declares for the manifest is within [MinChunk0, MaxChunk0] and leaves
// room for a final chunk: one under, one over, zero and the type's
// maximum are refused as the attempt's first bytes pass, naming the
// bounds, and the refusal leaves no upload behind.
func TestLimitManifestChunkLength(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	upload := func(t *testing.T, length uint32, payload int) (int, []byte) {
		t.Helper()
		blob := fakeStream(0, payload)
		binary.BigEndian.PutUint32(blob[stream.EncSize:], length)
		status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		status, body, _ = h.putStream(alice, opened.Upload, blob, 0)
		var left int
		if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads WHERE id = ?`, opened.Upload).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if status == http.StatusBadRequest && left != 0 {
			t.Errorf("a refused shape left its upload behind")
		}
		return status, body
	}
	for _, length := range []uint32{stream.MinChunk0 - 1, stream.MaxChunk0 + 1, math.MaxUint32, 0} {
		status, body := upload(t, length, 3000)
		if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), "outside ["+strconv.Itoa(stream.MinChunk0)+", "+strconv.Itoa(stream.MaxChunk0)+"]") {
			t.Errorf("length %d: %d %s; want 400 naming the bounds", length, status, body)
		}
	}
	// In range, but one byte longer than the upload leaves room for.
	if status, body := upload(t, stream.MinChunk0+1, stream.MinChunk0+stream.TagSize); status != http.StatusBadRequest || !strings.Contains(errorText(t, body), "does not leave room") {
		t.Errorf("a manifest chunk that fills the upload: %d %s; want 400", status, body)
	}
}

// TestLimitWatchIssued: the issued stamp beside each watched peer is
// nanoseconds since the epoch and open: the type's minimum, a negative,
// zero, a plus sign (as %2B) and the type's maximum each parse and are
// each a time the relay compares with the directory's, never subtracts
// from, so each is 200; the text one past the type's maximum, a sign
// inside the digits, an empty stamp and a digit outside ASCII are each
// 400 "bad peers parameter".
func TestLimitWatchIssued(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	for _, issued := range []string{"9223372036854775808", "\u0661", "1-2", ""} {
		status, body := h.do(bob, "GET", "/v1/mailbox/"+bob.Fingerprint()+"?peers="+alice.Fingerprint()+":"+issued, nil, nil)
		if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), "bad peers parameter") {
			t.Errorf("issued %q: %d %s; want 400", issued, status, body)
		}
	}
	for _, issued := range []string{strconv.FormatInt(math.MinInt64, 10), "-1", "0", "%2B1", "9223372036854775807"} {
		status, body := h.do(bob, "GET", "/v1/mailbox/"+bob.Fingerprint()+"?peers="+alice.Fingerprint()+":"+issued, nil, nil)
		if status != http.StatusOK {
			t.Errorf("issued %s: %d %s; want 200", issued, status, body)
		}
	}
}

// TestLimitSweepFileNames: a body file is named by its id's digits; the
// startup sweep removes as an orphan a file whose name is not an id, or
// is one written another way — a sign, a leading zero, a negative, the
// text one past the type's maximum — and keeps the one the row names.
func TestLimitSweepFileNames(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []*identity.Identity{alice, bob} {
		if err := s.Register(id.Fingerprint(), id.Public().Bundle(), id.Name, RegisterOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.Put(bob.Fingerprint(), "default", relayapi.KindEnvelope, "", sealed(t, alice, bob.Public(), "x"), Quotas{})
	if err != nil {
		t.Fatal(err)
	}
	real := s.messagePath(bob.Fingerprint(), id)
	s.Close()
	strays := []string{"+" + strconv.FormatInt(id, 10), "0" + strconv.FormatInt(id, 10), "-" + strconv.FormatInt(id, 10), "-2", "0", "9223372036854775808", "9223372036854775807", strconv.FormatInt(math.MinInt64, 10)}
	for _, name := range strays {
		if err := os.WriteFile(filepath.Join(filepath.Dir(real), name), []byte("stray"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err = OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.Swept().Orphans; got != len(strays) {
		t.Errorf("swept %d orphans, want %d", got, len(strays))
	}
	for _, name := range strays {
		if _, err := os.Stat(filepath.Join(filepath.Dir(real), name)); !os.IsNotExist(err) {
			t.Errorf("%q survived the sweep", name)
		}
	}
	if _, err := os.Stat(real); err != nil {
		t.Errorf("the message's own file did not survive: %v", err)
	}
}

// TestLimitWaitParameter: the wait a listing asks for, read from the query
// as text: a negative, the text one past the type's maximum, a bare
// number, "inf", a unit alone, a digit outside ASCII and a fraction with
// no unit are each 400 "bad wait parameter"; zero, a plus sign and an
// empty value (absent) are taken. Above the ceiling it is served at the
// ceiling, which TestLimitWaitAboveTheCeilingIsServedAtIt shows.
func TestLimitWaitParameter(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)
	box := "/v1/mailbox/" + alice.Fingerprint()
	for _, wait := range []string{"-1s", "-9223372036854775808ns", "9223372036854775808ns", "1", "inf", "s", "\u0661s", "1.5", "x"} {
		status, body := h.do(alice, "GET", box+"?wait="+wait, nil, nil)
		if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), "bad wait parameter") {
			t.Errorf("wait=%q: %d %s; want 400", wait, status, body)
		}
	}
	for _, wait := range []string{"0s", "%2B1ms", "", "1ms"} {
		status, body := h.do(alice, "GET", box+"?wait="+wait, nil, nil)
		if status != http.StatusOK {
			t.Errorf("wait=%q: %d %s; want 200", wait, status, body)
		}
	}
}

// TestLimitFingerprintsOneShortOnTheWire: the fingerprint in a mailbox
// path is held at authedWithCert and the caller's in the auth header at
// ParseAuth, before the relay makes a directory of the first two
// characters or logs the first sixteen; one character short is 400 for
// the path and 401 for the header, and no mailbox directory is made.
func TestLimitFingerprintsOneShortOnTheWire(t *testing.T) {
	h := newHarness(t, Config{})
	alice := ids(t, "alice")[0]
	h.register(alice)
	short := strings.Repeat("a", 63)
	status, body := h.do(alice, "POST", "/v1/mailbox/"+short, sealed(t, alice, alice.Public(), "x"), nil)
	if status != http.StatusBadRequest || !strings.Contains(errorText(t, body), "bad mailbox fingerprint") {
		t.Errorf("a path fingerprint one short: %d %s; want 400", status, body)
	}
	if _, err := os.Stat(filepath.Join(h.messagesDir(), short[:2])); err == nil {
		t.Errorf("a directory was made for a fingerprint one short")
	}
	// The auth header, with a fingerprint one short in place of alice's.
	req, err := http.NewRequest("GET", h.srv.URL+"/v1/mailbox/"+alice.Fingerprint(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayapi.SignRequest(alice, req, nil); err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get(relayapi.AuthHeader)
	req.Header.Set(relayapi.AuthHeader, strings.Replace(auth, alice.Fingerprint(), short, 1))
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an auth fingerprint one short: %d; want 401", resp.StatusCode)
	}
}

// TestLimitMessageDirectoryEntries: the sweep and the mailbox count read
// the relay's own message directory by its entries, each one segment
// joined under the directory it was listed from. A stray at any level —
// a file beside the shards, a directory named by a Windows device or a
// dot-dot form, a file in a shard, a directory with a file in it inside a
// mailbox — is skipped, not removed and not a reason to fail the start;
// a file in a mailbox whose name is not an id is the orphan the sweep
// removes; the message's own file survives; and nothing outside the
// message directory is touched.
func TestLimitMessageDirectoryEntries(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	scratch := t.TempDir()
	dir := filepath.Join(scratch, "messages")
	witness := filepath.Join(scratch, "witness")
	if err := os.WriteFile(witness, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(filepath.Join(scratch, "relay.db"), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []*identity.Identity{alice, bob} {
		if err := s.Register(id.Fingerprint(), id.Public().Bundle(), id.Name, RegisterOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.Put(bob.Fingerprint(), "default", relayapi.KindEnvelope, "", sealed(t, alice, bob.Public(), "x"), Quotas{})
	if err != nil {
		t.Fatal(err)
	}
	real := s.messagePath(bob.Fingerprint(), id)
	box := filepath.Dir(real)
	s.Close()
	dirs := []string{filepath.Join(dir, "CON"), filepath.Join(dir, "..x"), filepath.Join(dir, "a b", "c"), filepath.Join(box, "junk"), filepath.Join(s.tmpDir(), "held")}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := []string{filepath.Join(dir, "stray"), filepath.Join(filepath.Dir(box), "stray"), filepath.Join(box, "junk", "inside"), filepath.Join(s.tmpDir(), "held", "inside")}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	orphan := filepath.Join(box, "notanid")
	if err := os.WriteFile(orphan, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(filepath.Join(scratch, "relay.db"), dir)
	if err != nil {
		t.Fatalf("the start failed on a stray entry: %v", err)
	}
	defer s.Close()
	if got := s.Swept(); got.Orphans != 1 || got.Temp != 0 || got.Missing != 0 {
		t.Errorf("swept %+v; want one orphan and nothing else", got)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("the orphan survived the sweep")
	}
	if _, err := os.Stat(real); err != nil {
		t.Errorf("the message's own file did not survive: %v", err)
	}
	for _, p := range append(dirs, files...) {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("the sweep touched %q, which is not the relay's: %v", p, err)
		}
	}
	if held, err := s.mailboxesHoldingFiles(); err != nil || held != 1 {
		t.Errorf("mailboxes holding files: %d, %v; want one, the stray directories counted as none", held, err)
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "messages", "witness", "relay.db", "relay.db-wal", "relay.db-shm", "relay.db-journal":
		default:
			t.Errorf("%q appeared beside the message directory", e.Name())
		}
	}
	if _, err := os.Stat(witness); err != nil {
		t.Errorf("the witness beside the message directory is gone: %v", err)
	}
}
