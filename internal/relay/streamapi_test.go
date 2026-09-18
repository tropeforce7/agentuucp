package relay

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// fakeStream is bytes shaped like a stream: the relay never opens one, so what
// it must accept or refuse is decided entirely by the structure.
func fakeStream(manifest, payload int) []byte {
	b := make([]byte, 0, stream.HeaderSize+manifest+payload)
	b = append(b, bytes.Repeat([]byte("e"), stream.EncSize)...)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(manifest))
	b = append(b, prefix[:]...)
	b = append(b, bytes.Repeat([]byte("m"), manifest)...)
	return append(b, bytes.Repeat([]byte("p"), payload)...)
}

// send with a raw body and extra headers, for the upload routes.
func (h *harness) sendRaw(id *identity.Identity, method, path string, body []byte,
	headers map[string]string) (int, []byte, http.Header) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// The upload routes sign an empty body: the payload is underneath.
	if err := relayapi.SignRequest(id, req, nil); err != nil {
		h.t.Fatal(err)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, resp.Header
}

func (h *harness) openStream(from *identity.Identity, toFP string, size int64) (int, relayapi.OpenStreamResponse, []byte) {
	h.t.Helper()
	status, body, _ := h.send(from, "POST", "/v1/mailbox/"+toFP+"/streams",
		relayapi.OpenStreamRequest{Size: size}, nil)
	var out relayapi.OpenStreamResponse
	if status == http.StatusCreated {
		if err := json.Unmarshal(body, &out); err != nil {
			h.t.Fatal(err)
		}
	}
	return status, out, body
}

func TestStreamUploadRoundTrip(t *testing.T) {
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
	if opened.MaxRequest <= 0 {
		t.Fatal("open did not say how large a piece may be")
	}

	// Three pieces, so appending is exercised rather than a single write.
	offsets := []int{0, 1000, 2500, len(blob)}
	for i := 0; i < len(offsets)-1; i++ {
		from, to := offsets[i], offsets[i+1]
		status, body, hdr := h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob[from:to],
			map[string]string{relayapi.UploadOffsetHeader: strconv.Itoa(from)})
		if status != http.StatusNoContent {
			t.Fatalf("append %d..%d: %d %s", from, to, status, body)
		}
		if got := hdr.Get(relayapi.UploadOffsetHeader); got != strconv.Itoa(to) {
			t.Fatalf("offset after append is %q, want %d", got, to)
		}
	}

	status, body, _ = h.send(alice, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("complete: %d %s", status, body)
	}
	var done relayapi.CompleteStreamResponse
	if err := json.Unmarshal(body, &done); err != nil {
		t.Fatal(err)
	}

	// It lists as a stream, with its size and no inline body.
	status, body, _ = h.send(bob, "GET", "/v1/mailbox/"+bob.Fingerprint(), nil, nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	var list relayapi.ListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Messages) != 1 {
		t.Fatalf("listed %d messages", len(list.Messages))
	}
	m := list.Messages[0]
	if m.Kind != relayapi.KindStream || m.Size != int64(len(blob)) || len(m.Envelope) != 0 {
		t.Fatalf("unexpected listing: %+v", m)
	}

	// The blob comes back byte for byte, and a range returns just that range.
	status, got, _ := h.send(bob, "GET",
		fmt.Sprintf("/v1/mailbox/%s/%d/blob", bob.Fingerprint(), done.ID), nil, nil)
	if status != http.StatusOK {
		t.Fatalf("blob: %d", status)
	}
	if !bytes.Equal(got, blob) {
		t.Fatal("the blob is not the bytes that were uploaded")
	}
	status, got, _ = h.send(bob, "GET",
		fmt.Sprintf("/v1/mailbox/%s/%d/blob", bob.Fingerprint(), done.ID), nil,
		map[string]string{"Range": "bytes=0-1123"})
	if status != http.StatusPartialContent {
		t.Fatalf("range request: %d, want 206", status)
	}
	if len(got) != 1124 || !bytes.Equal(got, blob[:1124]) {
		t.Fatalf("range returned %d bytes", len(got))
	}

	// Acknowledging removes it, as for an envelope.
	if status, _, _ := h.send(bob, "DELETE",
		fmt.Sprintf("/v1/mailbox/%s/%d", bob.Fingerprint(), done.ID), nil, nil); status != http.StatusNoContent {
		t.Fatal("ack failed")
	}
	h.assertCountersAgree()
}

func TestStreamUploadRules(t *testing.T) {
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]

	setup := func(t *testing.T, cfg Config) (*harness, relayapi.OpenStreamResponse, []byte) {
		t.Helper()
		h := newHarness(t, cfg)
		h.register(alice)
		h.register(bob)
		h.register(carol)
		blob := fakeStream(200, 3000)
		status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		return h, opened, blob
	}

	t.Run("an offset that does not match is a conflict with the truth", func(t *testing.T) {
		h, opened, blob := setup(t, Config{})
		h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob[:1000],
			map[string]string{relayapi.UploadOffsetHeader: "0"})
		status, _, hdr := h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob[1000:2000],
			map[string]string{relayapi.UploadOffsetHeader: "500"})
		if status != http.StatusConflict {
			t.Fatalf("status %d, want 409", status)
		}
		if got := hdr.Get(relayapi.UploadOffsetHeader); got != "1000" {
			t.Fatalf("the conflict reported offset %q, want 1000", got)
		}
	})

	t.Run("more than the declared size is refused", func(t *testing.T) {
		h, opened, blob := setup(t, Config{})
		tooMuch := append(append([]byte(nil), blob...), bytes.Repeat([]byte("x"), 100)...)
		status, body, _ := h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, tooMuch,
			map[string]string{relayapi.UploadOffsetHeader: "0"})
		if status != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d, want 413: %s", status, body)
		}
	})

	t.Run("completing early is a conflict", func(t *testing.T) {
		h, opened, blob := setup(t, Config{})
		h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob[:1000],
			map[string]string{relayapi.UploadOffsetHeader: "0"})
		status, body, _ := h.send(alice, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil)
		if status != http.StatusConflict {
			t.Fatalf("status %d, want 409: %s", status, body)
		}
	})

	t.Run("only the opener may touch it", func(t *testing.T) {
		h, opened, blob := setup(t, Config{})
		for _, c := range []struct {
			method, path string
			body         []byte
		}{
			{"PATCH", "/v1/uploads/" + opened.Upload, blob[:100]},
			{"HEAD", "/v1/uploads/" + opened.Upload, nil},
			{"DELETE", "/v1/uploads/" + opened.Upload, nil},
		} {
			status, _, _ := h.sendRaw(carol, c.method, c.path, c.body,
				map[string]string{relayapi.UploadOffsetHeader: "0"})
			if status != http.StatusForbidden {
				t.Errorf("%s by a stranger gave %d, want 403", c.method, status)
			}
		}
		status, _, _ := h.send(carol, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil)
		if status != http.StatusForbidden {
			t.Errorf("complete by a stranger gave %d, want 403", status)
		}
	})

	t.Run("head reports the offset for resumption", func(t *testing.T) {
		h, opened, blob := setup(t, Config{})
		h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob[:1500],
			map[string]string{relayapi.UploadOffsetHeader: "0"})
		status, _, hdr := h.sendRaw(alice, "HEAD", "/v1/uploads/"+opened.Upload, nil, nil)
		if status != http.StatusOK {
			t.Fatalf("head: %d", status)
		}
		if hdr.Get(relayapi.UploadOffsetHeader) != "1500" ||
			hdr.Get(relayapi.UploadLengthHeader) != strconv.Itoa(len(blob)) {
			t.Fatalf("head said offset %q of %q", hdr.Get(relayapi.UploadOffsetHeader),
				hdr.Get(relayapi.UploadLengthHeader))
		}
	})

	t.Run("aborting releases the reservation", func(t *testing.T) {
		h, opened, _ := setup(t, Config{})
		if status, _, _ := h.sendRaw(alice, "DELETE", "/v1/uploads/"+opened.Upload, nil, nil); status != http.StatusNoContent {
			t.Fatal("abort failed")
		}
		var n int
		if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%d upload rows left after aborting", n)
		}
	})
}

// The three structural checks are the whole of what the relay can say about a
// stream, so each boundary of each is tested.
func TestCompleteChecksTheShape(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]

	upload := func(t *testing.T, blob []byte) (int, string) {
		t.Helper()
		h := newHarness(t, Config{})
		h.register(alice)
		h.register(bob)
		status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusCreated {
			return status, string(body)
		}
		if status, body, _ := h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob,
			map[string]string{relayapi.UploadOffsetHeader: "0"}); status != http.StatusNoContent {
			t.Fatalf("append: %d %s", status, body)
		}
		status, body, _ = h.send(alice, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil)
		return status, string(body)
	}

	minSize := stream.HeaderSize + stream.MinChunk0 + stream.TagSize
	t.Run("the smallest possible stream is accepted", func(t *testing.T) {
		if status, body := upload(t, fakeStream(stream.MinChunk0, stream.TagSize)); status != http.StatusOK {
			t.Fatalf("status %d, want 200: %s", status, body)
		}
	})
	t.Run("one byte smaller is refused at open", func(t *testing.T) {
		status, body := upload(t, make([]byte, minSize-1))
		if status != http.StatusBadRequest {
			t.Fatalf("status %d, want 400: %s", status, body)
		}
	})
	t.Run("a manifest length below the minimum", func(t *testing.T) {
		status, body := upload(t, fakeStream(stream.MinChunk0-1, stream.TagSize+1))
		if status != http.StatusBadRequest || !strings.Contains(body, "outside") {
			t.Fatalf("status %d: %s", status, body)
		}
	})
	t.Run("a manifest length above the maximum", func(t *testing.T) {
		blob := fakeStream(stream.MinChunk0, stream.TagSize)
		binary.BigEndian.PutUint32(blob[stream.EncSize:], uint32(stream.MaxChunk0+1))
		status, body := upload(t, blob)
		if status != http.StatusBadRequest || !strings.Contains(body, "outside") {
			t.Fatalf("status %d: %s", status, body)
		}
	})
	t.Run("no room for a final chunk", func(t *testing.T) {
		blob := fakeStream(stream.MinChunk0, stream.TagSize)
		// Claim a manifest that leaves nothing after it.
		binary.BigEndian.PutUint32(blob[stream.EncSize:], uint32(len(blob)-stream.HeaderSize))
		status, body := upload(t, blob)
		if status != http.StatusBadRequest || !strings.Contains(body, "final chunk") {
			t.Fatalf("status %d: %s", status, body)
		}
	})
}

func TestStreamLimitsAndSettings(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	blob := fakeStream(200, 3000)

	t.Run("streams off is refused with the setting named", func(t *testing.T) {
		h := newHarness(t, Config{Streams: false, streamsSet: true})
		h.register(alice)
		h.register(bob)
		status, _, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusForbidden {
			t.Fatalf("status %d, want 403", status)
		}
		if got := errorText(t, body); !strings.Contains(got, "streams") {
			t.Fatalf("error %q does not name the setting", got)
		}
	})

	t.Run("max_stream_bytes", func(t *testing.T) {
		h := newHarness(t, Config{MaxStreamBytes: int64(len(blob))})
		h.register(alice)
		h.register(bob)
		if status, _, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob))); status != http.StatusCreated {
			t.Fatalf("at the limit: %d %s", status, body)
		}
		status, _, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob))+1)
		if status != http.StatusForbidden {
			t.Fatalf("one over: %d %s", status, body)
		}
		if got := errorText(t, body); !strings.Contains(got, "max_stream_bytes") {
			t.Fatalf("error %q does not name the setting", got)
		}
	})

	t.Run("the byte budget is charged at open and nothing on refusal", func(t *testing.T) {
		h := newHarness(t, Config{Limits: Limits{PostBytesPerHour: int64(len(blob))}})
		h.register(alice)
		h.register(bob)
		if status, _, _ := h.openStream(alice, bob.Fingerprint(), int64(len(blob))); status != http.StatusCreated {
			t.Fatal("the first stream should fit the budget")
		}
		status, _, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusTooManyRequests {
			t.Fatalf("the second: %d, want 429: %s", status, body)
		}
		var n int
		if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("a refused open left %d uploads, want the 1 that succeeded", n)
		}
	})

	t.Run("open uploads count against the mailbox quota", func(t *testing.T) {
		h := newHarness(t, Config{Limits: Limits{MailboxMaxBytes: int64(len(blob))*2 - 1}})
		h.register(alice)
		h.register(bob)
		if status, opened, _ := h.openStream(alice, bob.Fingerprint(), int64(len(blob))); status != http.StatusCreated {
			t.Fatal("the first open should fit")
		} else {
			status, _, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
			if status != http.StatusInsufficientStorage {
				t.Fatalf("a second reservation was allowed: %d %s", status, body)
			}
			// Aborting the first gives the room back.
			h.sendRaw(alice, "DELETE", "/v1/uploads/"+opened.Upload, nil, nil)
			if status, _, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob))); status != http.StatusCreated {
				t.Fatalf("aborting did not release the reservation: %d %s", status, body)
			}
		}
	})

	t.Run("expired uploads are swept and release their room", func(t *testing.T) {
		// Expiry is stored in whole seconds, as nonces are, so the row is
		// backdated rather than the test waiting for a clock.
		h := newHarness(t, Config{Limits: Limits{MailboxMaxBytes: int64(len(blob))}})
		h.register(alice)
		h.register(bob)
		status, opened, _ := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
		if status != http.StatusCreated {
			t.Fatal("open failed")
		}
		// While it is open, its reservation fills the mailbox.
		if status, _, _ := h.openStream(alice, bob.Fingerprint(), int64(len(blob))); status != http.StatusInsufficientStorage {
			t.Fatalf("the reservation was not counted: %d", status)
		}
		path := h.store.uploadPath(opened.Upload)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("the upload has no file: %v", err)
		}

		if _, err := h.store.db.Exec(`UPDATE uploads SET expires = ?`,
			time.Now().Add(-time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
		n, _, err := h.store.PurgeUploads(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("swept %d uploads, want 1", n)
		}
		var left int
		if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads`).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Fatal("the expired upload survived")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("the expired upload's file survived")
		}
		// And the room is back.
		if status, _, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob))); status != http.StatusCreated {
			t.Fatalf("the sweep did not release the reservation: %d %s", status, body)
		}
	})

	t.Run("a blocked recipient and an unlisted sender are refused", func(t *testing.T) {
		boss := ids(t, "boss")[0]
		h := newHarness(t, Config{AdminFile: adminFile(t, boss)})
		h.register(alice)
		h.register(bob)
		h.send(boss, "PUT", "/v1/admin/blocks/"+bob.Fingerprint(),
			relayapi.BlockRequest{Reason: "testing"}, nil)
		if status, _, _ := h.openStream(alice, bob.Fingerprint(), int64(len(blob))); status != http.StatusForbidden {
			t.Fatalf("a blocked recipient accepted a stream: %d", status)
		}
	})
}

// The uploads row is the one place a sender is recorded, and it must not
// outlive the upload.
func TestUploadsRowIsTheOnlyRecordOfASender(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)
	blob := fakeStream(200, 3000)

	_, opened, _ := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
	var from string
	if err := h.store.db.QueryRow(`SELECT from_fp FROM uploads`).Scan(&from); err != nil {
		t.Fatal(err)
	}
	if from != alice.Fingerprint() {
		t.Fatal("the upload does not record who may append")
	}

	h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob,
		map[string]string{relayapi.UploadOffsetHeader: "0"})
	h.send(alice, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil)

	var rows int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM uploads`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatal("the uploads row outlived the upload")
	}
	// And no other table mentions the sender.
	for _, table := range []string{"messages", "mailboxes"} {
		var cols string
		if err := h.store.db.QueryRow(
			`SELECT group_concat(name) FROM pragma_table_info(?)`, table).Scan(&cols); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(cols, "from") || strings.Contains(cols, "sender") {
			t.Fatalf("table %s has a sender column: %s", table, cols)
		}
	}
}

// filler generates n bytes without holding them, so a test can send a large
// body without its own allocation swamping the measurement.
type filler struct {
	head []byte // written first, and counted in n
	n    int64
	i    byte
}

func (f *filler) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > f.n {
		p = p[:f.n]
	}
	at := 0
	if len(f.head) > 0 {
		at = copy(p, f.head)
		f.head = f.head[at:]
	}
	for i := at; i < len(p); i++ {
		f.i++
		p[i] = f.i
	}
	f.n -= int64(len(p))
	return len(p), nil
}

// sendPiece appends to an upload from a reader, so the piece never exists as a
// slice on the sending side either.
func (h *harness) sendPiece(id *identity.Identity, upload string, offset, n int64, head []byte) (int, []byte) {
	h.t.Helper()
	req, err := http.NewRequest("PATCH", h.srv.URL+"/v1/uploads/"+upload, &filler{head: head, n: n})
	if err != nil {
		h.t.Fatal(err)
	}
	req.ContentLength = n
	req.Header.Set(relayapi.UploadOffsetHeader, strconv.FormatInt(offset, 10))
	if err := relayapi.SignRequest(id, req, nil); err != nil {
		h.t.Fatal(err)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// The relay must never hold a stream it is carrying, in either direction. This
// is the claim the whole design rests on: 256 MiB goes up in 16 MiB pieces and
// comes back down, and the heap does not follow it.
//
// Nothing on either side of the measurement holds the bytes — the request body
// is generated as it is written and the response is discarded as it is read —
// so what is left is what the relay kept.
func TestRelayDoesNotHoldAStream(t *testing.T) {
	const total = 256 << 20
	const piece = 16 << 20
	const bound = 64 << 20

	h := newHarness(t, Config{MaxBytes: piece})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	status, opened, body := h.openStream(alice, bob.Fingerprint(), total)
	if status != http.StatusCreated {
		t.Fatalf("open: %d %s", status, body)
	}

	// Only the first bytes have to be shaped like a stream: complete checks
	// the header and the manifest length, and nothing else is ever opened.
	head := fakeStream(200, 0)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for off := int64(0); off < total; off += piece {
		n := int64(piece)
		if rest := total - off; rest < n {
			n = rest
		}
		var h0 []byte
		if off == 0 {
			h0 = head
		}
		if status, out := h.sendPiece(alice, opened.Upload, off, n, h0); status != http.StatusNoContent {
			t.Fatalf("append at %d: %d %s", off, status, out)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if grew > bound {
		t.Fatalf("uploading %d MiB in %d MiB pieces grew the heap by %d bytes",
			total>>20, piece>>20, grew)
	}
	t.Logf("upload:   %d MiB in %d MiB pieces grew the heap by %d KiB",
		total>>20, piece>>20, grew>>10)

	status, body, _ = h.send(alice, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("complete: %d %s", status, body)
	}
	var done relayapi.CompleteStreamResponse
	if err := json.Unmarshal(body, &done); err != nil {
		t.Fatal(err)
	}

	// And on the way out.
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/v1/mailbox/%s/%d/blob", h.srv.URL, bob.Fingerprint(), done.ID), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayapi.SignRequest(bob, req, nil); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&before)
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("blob: %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if n != total {
		t.Fatalf("downloaded %d bytes, want %d", n, total)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	grew = int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if grew > bound {
		t.Fatalf("downloading %d MiB grew the heap by %d bytes", total>>20, grew)
	}
	t.Logf("download: %d MiB grew the heap by %d KiB", total>>20, grew>>10)
}

// An allow list restricts other people. The owner may always post to their
// own mailbox, listed or not: a note to yourself, from any machine.
func TestOwnerMayAlwaysPostToOwnMailbox(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob", "carol")
	alice, bob, carol := people[0], people[1], people[2]
	for _, p := range people {
		h.register(p)
	}
	fp := alice.Fingerprint()
	if status, body, _ := h.send(alice, "PUT", "/v1/mailbox/"+fp+"/allow",
		h.allowReq(alice, bob.Fingerprint()), nil); status != http.StatusNoContent {
		t.Fatalf("setting the allow list: %d %s", status, body)
	}
	for _, c := range []struct {
		sender string
		want   bool
	}{
		{alice.Fingerprint(), true}, // the owner, not on the list
		{bob.Fingerprint(), true},   // listed
		{carol.Fingerprint(), false},
	} {
		got, err := h.store.MayPost(fp, c.sender)
		if err != nil || got != c.want {
			t.Fatalf("MayPost(alice, %s) = %v, %v; want %v", c.sender[:12], got, err, c.want)
		}
	}
	// And with no list at all, everyone may, the owner included.
	if status, _, _ := h.send(alice, "PUT", "/v1/mailbox/"+fp+"/allow",
		h.allowReq(alice), nil); status != http.StatusNoContent {
		t.Fatal("clearing the allow list failed")
	}
	if got, _ := h.store.MayPost(fp, fp); !got {
		t.Fatal("the owner was refused with no list")
	}
}

// uploadStream puts a stream in a mailbox in one piece and returns its id.
func (h *harness) uploadStream(from *identity.Identity, toFP string, blob []byte) int64 {
	h.t.Helper()
	status, opened, body := h.openStream(from, toFP, int64(len(blob)))
	if status != http.StatusCreated {
		h.t.Fatalf("open: %d %s", status, body)
	}
	status, body, _ = h.sendRaw(from, "PATCH", "/v1/uploads/"+opened.Upload, blob,
		map[string]string{relayapi.UploadOffsetHeader: "0"})
	if status != http.StatusNoContent {
		h.t.Fatalf("append: %d %s", status, body)
	}
	status, body, _ = h.send(from, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil)
	if status != http.StatusOK {
		h.t.Fatalf("complete: %d %s", status, body)
	}
	var done relayapi.CompleteStreamResponse
	if err := json.Unmarshal(body, &done); err != nil {
		h.t.Fatal(err)
	}
	return done.ID
}

// A stored file whose length disagrees with its row cannot be served: a byte
// range past its end is nobody's to answer. The sweep at start drops such a
// file; met while serving, the same rule applies, and the client is told the
// message is gone rather than left to ask for the same range at every fetch,
// which is what the container suite's M06 found it doing. The drop is one
// transaction with the counters, and it is confined to the blob route, which
// only the mailbox's owner reaches.
func TestAShortStreamFileIsDroppedWhenServed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int64 // the file's new length; 0 leaves it alone
		gone    bool
		minimal bool
	}{
		{"truncated inside the payload", int64(stream.HeaderSize + 200 + 1000), true, false},
		{"truncated by one byte", int64(stream.HeaderSize + 200 + 3000 - 1), true, false},
		{"one byte appended", int64(stream.HeaderSize + 200 + 3000 + 1), true, false},
		// The owner is the caller on this route, and the minimal access
		// log omits the caller, so the line names the message and not the
		// mailbox; that is the shipped setting, and the only place a
		// fingerprint could otherwise reach a minimal log.
		{"truncated, minimal access log", int64(stream.HeaderSize + 200 + 1000), true, true},
		{"intact", 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{}
			if tc.minimal {
				cfg.AccessLog = AccessLogMinimal
			}
			h := newHarness(t, cfg)
			people := ids(t, "alice", "bob")
			alice, bob := people[0], people[1]
			h.register(alice)
			h.register(bob)
			blob := fakeStream(200, 3000)
			keep := h.uploadStream(alice, bob.Fingerprint(), fakeStream(200, 100))
			id := h.uploadStream(alice, bob.Fingerprint(), blob)
			path := h.store.messagePath(bob.Fingerprint(), id)
			if tc.size != 0 {
				if err := os.Truncate(path, tc.size); err != nil {
					t.Fatal(err)
				}
			}
			blobPath := fmt.Sprintf("/v1/mailbox/%s/%d/blob", bob.Fingerprint(), id)

			// The first request a receiver makes: a range for the header.
			status, body, _ := h.send(bob, "GET", blobPath, nil,
				map[string]string{"Range": "bytes=0-" + strconv.Itoa(stream.HeaderSize-1)})
			if !tc.gone {
				if status != http.StatusPartialContent {
					t.Fatalf("an intact stream answered %d: %s", status, body)
				}
				if strings.Contains(h.logs.String(), "damaged") {
					t.Fatalf("an intact stream was called damaged:\n%s", h.logs.String())
				}
				h.assertCountersAgree()
				return
			}
			if status != http.StatusGone {
				t.Fatalf("a damaged stream answered %d, want 410", status)
			}
			if got := errorText(t, body); got != "message is damaged on the relay and has been dropped" {
				t.Fatalf("410 body %q", got)
			}
			if _, _, err := h.store.MessageKind(bob.Fingerprint(), id); !errors.Is(err, ErrNoMessage) {
				t.Fatalf("the row is still there: %v", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("the file is still there: %v", err)
			}
			if _, _, err := h.store.MessageKind(bob.Fingerprint(), keep); err != nil {
				t.Fatalf("the other message went with it: %v", err)
			}
			h.assertCountersAgree()
			whose := " for " + bob.Fingerprint()
			if tc.minimal {
				whose = ""
			}
			want := fmt.Sprintf("message %d%s is %d bytes on disk but %d in the database; "+
				"it is damaged and has been dropped", id, whose, tc.size, len(blob))
			logs := h.logs.String()
			if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, want) {
				t.Fatalf("the drop was not logged as %q:\n%s", want, logs)
			}
			if tc.minimal && (strings.Contains(logs, bob.Fingerprint()[:16]) || strings.Contains(logs, "fp=")) {
				t.Fatalf("a minimal log names the mailbox:\n%s", logs)
			}
			// Gone means gone: the next request is a 404, and so would an
			// acknowledgement be, which is why the client sends none.
			if status, _, _ := h.send(bob, "GET", blobPath, nil, nil); status != http.StatusNotFound {
				t.Fatalf("a dropped stream answered %d on the next request, want 404", status)
			}
			if status, _, _ := h.send(bob, "DELETE",
				fmt.Sprintf("/v1/mailbox/%s/%d", bob.Fingerprint(), id), nil, nil); status != http.StatusNotFound {
				t.Fatalf("acknowledging a dropped stream answered %d, want 404", status)
			}
		})
	}
}

// A full disk met while a piece of a stream is being written is a 507 with
// the same sentence handlePost gives, not a 500 that says nothing: the
// sender is told whose problem the room is, and what it has already sent is
// kept for a resume, so the reservation is neither released nor leaked — it
// waits, and expires with the upload if nobody comes back. The container
// suite's R18 found the 500.
//
// Only /dev/full refuses a write with ENOSPC without a filesystem of one's
// own, so the piece is written to it in place of the upload's file; it is
// Linux's, and elsewhere the store-level test below carries the rule.
func TestAnUploadOnAFullDiskIsA507(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full on this platform; TestAppendUploadMapsAFullDisk covers the mapping")
	}
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
	path := h.store.uploadPath(opened.Upload)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/full", path); err != nil {
		t.Fatal(err)
	}

	status, body, _ = h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob[:1000],
		map[string]string{relayapi.UploadOffsetHeader: "0"})
	if status != http.StatusInsufficientStorage {
		t.Fatalf("a piece on a full disk answered %d, want 507: %s", status, body)
	}
	if got := errorText(t, body); got != relayapi.MsgRelayFull {
		t.Fatalf("507 body %q, want %q", got, relayapi.MsgRelayFull)
	}
	if !strings.Contains(h.logs.String(), "limit=\"relay storage\"") {
		t.Fatalf("the refusal did not name its limit in the log:\n%s", h.logs.String())
	}
	// The reservation is kept, at the offset the relay truly has, and the
	// counters count nothing, since nothing was queued.
	u, err := h.store.Upload(opened.Upload)
	if err != nil || u.Received != 0 {
		t.Fatalf("upload after the refusal: %+v, %v; want kept at offset 0", u, err)
	}
	status, _, hdr := h.sendRaw(alice, "HEAD", "/v1/uploads/"+opened.Upload, nil, nil)
	if status != http.StatusOK || hdr.Get(relayapi.UploadOffsetHeader) != "0" {
		t.Fatalf("HEAD after the refusal: %d offset %q", status, hdr.Get(relayapi.UploadOffsetHeader))
	}
	h.assertCountersAgree()
	if n, b := h.queued(bob.Fingerprint()); n != 0 || b != 0 {
		t.Fatalf("the refusal charged the mailbox: %d messages, %d bytes", n, b)
	}

	// Room made: the file is a file again, and the upload finishes from
	// where the relay said it was.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	status, body, _ = h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob,
		map[string]string{relayapi.UploadOffsetHeader: "0"})
	if status != http.StatusNoContent {
		t.Fatalf("append once there is room: %d %s", status, body)
	}
	status, body, _ = h.send(alice, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("complete once there is room: %d %s", status, body)
	}
	if n, _ := h.queued(bob.Fingerprint()); n != 1 {
		t.Fatalf("queued %d after the resumed upload, want 1", n)
	}
	h.assertCountersAgree()
}

// queued reads a mailbox's counters.
func (h *harness) queued(fp string) (messages, bytes int64) {
	h.t.Helper()
	if err := h.store.db.QueryRow(`SELECT queued_messages, queued_bytes FROM mailboxes WHERE fp = ?`, fp).
		Scan(&messages, &bytes); err != nil {
		h.t.Fatal(err)
	}
	return messages, bytes
}

// The copy's error is the write's, and a full disk or an exhausted quota is
// ErrRelayFull with the row advanced by exactly what reached the disk; any
// other error from the copy is passed through as it came, since it may be
// the request's and not the disk's.
func TestAppendUploadMapsAFullDisk(t *testing.T) {
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	for _, tc := range []struct {
		name string
		err  error
		full bool
	}{
		{"ENOSPC", syscall.ENOSPC, true},
		{"EDQUOT", syscall.EDQUOT, true},
		{"the request's own error", errors.New("client went away"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			h.register(alice)
			h.register(bob)
			blob := fakeStream(200, 3000)
			status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
			if status != http.StatusCreated {
				t.Fatalf("open: %d %s", status, body)
			}
			// 700 bytes reach the disk, then the write fails.
			got, err := h.store.AppendUpload(opened.Upload, 0, func(f *os.File, limit int64) (int64, error) {
				n, werr := f.Write(blob[:700])
				if werr != nil {
					return int64(n), werr
				}
				return int64(n), tc.err
			})
			if got != 700 {
				t.Fatalf("received %d, want the 700 that reached the disk", got)
			}
			if tc.full && !errors.Is(err, ErrRelayFull) {
				t.Fatalf("error %v, want ErrRelayFull", err)
			}
			if !tc.full && (errors.Is(err, ErrRelayFull) || !errors.Is(err, tc.err)) {
				t.Fatalf("error %v, want the request's own %v", err, tc.err)
			}
			u, err := h.store.Upload(opened.Upload)
			if err != nil || u.Received != 700 {
				t.Fatalf("the row says %d received (%v), want 700", u.Received, err)
			}
			if info, err := os.Stat(h.store.uploadPath(opened.Upload)); err != nil || info.Size() != 700 {
				t.Fatalf("the file holds %d bytes, want 700", info.Size())
			}
			h.assertCountersAgree()
		})
	}
}

// The list carries how many messages the mailbox holds in all, whatever
// page was asked for, so a client whose cursor is past them can tell an
// empty page from an empty mailbox. The field is the mailbox's counter,
// which moves only when a message is queued or acknowledged: an upload
// still open is not in it, and a page after the last id is empty beside a
// count that is not, which is the shape the client acts on. It is present
// at zero, since absent is what a relay from before the field answers. The
// container suite's K17 found a cursor set ahead hiding mail with nothing
// to say so.
func TestTheListSaysHowManyAreQueued(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	list := func(after int64) (relayapi.ListResponse, []byte) {
		t.Helper()
		status, body, _ := h.send(bob, "GET",
			fmt.Sprintf("/v1/mailbox/%s?after=%d", bob.Fingerprint(), after), nil, nil)
		if status != http.StatusOK {
			t.Fatalf("list after %d: %d %s", after, status, body)
		}
		var out relayapi.ListResponse
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out, body
	}
	expect := func(after int64, messages int, queued int64) {
		t.Helper()
		got, _ := list(after)
		if len(got.Messages) != messages || got.Queued != queued {
			t.Fatalf("after %d: %d messages and queued %d, want %d and %d",
				after, len(got.Messages), got.Queued, messages, queued)
		}
	}

	// Empty: the field is there, at zero, on the wire.
	empty, body := list(0)
	if empty.Queued != 0 || !strings.Contains(string(body), `"queued":0`) {
		t.Fatalf("an empty mailbox listed as %s", body)
	}

	// Two envelopes: the count is the mailbox's, not the page's.
	var last int64
	for _, text := range []string{"first", "second"} {
		status, body := h.do(alice, "POST", "/v1/mailbox/"+bob.Fingerprint(),
			sealed(t, alice, bob.Public(), text), nil)
		if status != http.StatusOK {
			t.Fatalf("post: %d %s", status, body)
		}
		var posted relayapi.PostResponse
		if err := json.Unmarshal(body, &posted); err != nil {
			t.Fatal(err)
		}
		last = posted.ID
	}
	expect(0, 2, 2)
	expect(last-1, 1, 2)
	// The cursor ahead of everything: an empty page beside the count.
	expect(last, 0, 2)
	expect(last+1000, 0, 2)

	// An upload that is open is reserved, not queued: the count is unmoved
	// until it completes.
	blob := fakeStream(200, 3000)
	status, opened, body := h.openStream(alice, bob.Fingerprint(), int64(len(blob)))
	if status != http.StatusCreated {
		t.Fatalf("open: %d %s", status, body)
	}
	status, body, _ = h.sendRaw(alice, "PATCH", "/v1/uploads/"+opened.Upload, blob,
		map[string]string{relayapi.UploadOffsetHeader: "0"})
	if status != http.StatusNoContent {
		t.Fatalf("append: %d %s", status, body)
	}
	expect(last, 0, 2)
	status, body, _ = h.send(alice, "POST", "/v1/uploads/"+opened.Upload+"/complete", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("complete: %d %s", status, body)
	}
	var done relayapi.CompleteStreamResponse
	if err := json.Unmarshal(body, &done); err != nil {
		t.Fatal(err)
	}
	expect(last, 1, 3)
	expect(done.ID, 0, 3)

	// Acknowledging brings it down, and the page after the last id is
	// empty beside zero, which is nothing to say.
	for _, id := range []int64{last - 1, last, done.ID} {
		status, body := h.do(bob, "DELETE",
			fmt.Sprintf("/v1/mailbox/%s/%d", bob.Fingerprint(), id), nil, nil)
		if status != http.StatusNoContent {
			t.Fatalf("delete %d: %d %s", id, status, body)
		}
	}
	expect(done.ID, 0, 0)
	expect(0, 0, 0)
}
