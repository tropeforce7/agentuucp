package relay

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
)

// This test encodes immediate revocation semantics proposed by Mythos.
// Failure demonstrates the behavior at the named baseline; the release
// plan may deliberately choose admission at open instead.
func TestARevokedSenderCannotFinishPreviouslyOpenedUpload(t *testing.T) {
	for _, resume := range []bool{false, true} {
		name := "first_attempt"
		if resume {
			name = "kept_partial_resume"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, Config{MaxBytes: 2048})
			people := ids(t, "sender", "owner", "other")
			sender, owner, other := people[0], people[1], people[2]
			for _, id := range people {
				h.register(id)
			}
			issued := time.Now().Add(-time.Second)
			if status, body, _ := h.pushAllow(owner, owner, issued, sender.Fingerprint()); status != http.StatusNoContent {
				t.Fatalf("admit sender: %d %s", status, body)
			}
			blob := fakeStream(200, 3000)
			status, opened, body := h.openStream(sender, owner.Fingerprint(), int64(len(blob)))
			if status != http.StatusCreated {
				t.Fatalf("allowed open: %d %s", status, body)
			}
			offset := 0
			if resume {
				offset = 2500
				status, body, _ = h.putPartial(sender, opened.Upload, blob, 0, offset)
				if status != http.StatusBadRequest {
					t.Fatalf("interrupted first attempt: %d %s", status, body)
				}
				u, err := h.store.Upload(opened.Upload)
				if err != nil || u.Received != int64(offset) {
					t.Fatalf("partial was not kept at offset %d: %+v %v", offset, u, err)
				}
			}
			// An empty list reopens this protocol's mailbox. Keep another
			// identity on the list to revoke sender rather than clearing it.
			if status, body, _ := h.pushAllow(owner, owner, issued.Add(time.Second), other.Fingerprint()); status != http.StatusNoContent {
				t.Fatalf("revoke sender: %d %s", status, body)
			}
			allowed, err := h.store.MayPost(owner.Fingerprint(), sender.Fingerprint())
			if err != nil || allowed {
				t.Fatalf("revocation not effective: allowed=%v err=%v", allowed, err)
			}
			if status, _, body := h.openStream(sender, owner.Fingerprint(), int64(len(blob))); status != http.StatusForbidden || errorText(t, body) != refusedSender {
				t.Fatalf("control: a fresh open after revocation was not refused: %d %s", status, body)
			}
			status, body, _ = h.putStream(sender, opened.Upload, blob, offset)
			if status != http.StatusForbidden || errorText(t, body) != refusedSender {
				t.Errorf("previously opened upload after revocation: %d %s; want 403 %q", status, body, refusedSender)
			}
			listStatus, listBody, _ := h.send(owner, "GET", "/v1/mailbox/"+owner.Fingerprint(), nil, nil)
			if listStatus != http.StatusOK {
				t.Fatalf("owner listing: %d %s", listStatus, listBody)
			}
			var list relayapi.ListResponse
			if err := json.Unmarshal(listBody, &list); err != nil {
				t.Fatal(err)
			}
			if len(list.Messages) != 0 {
				t.Errorf("revoked sender placed %d message(s); want none", len(list.Messages))
			}
			row, file := h.uploadLeft(opened.Upload)
			if row || file != -1 {
				t.Errorf("upload reservation/file remains: row=%v file=%d", row, file)
			}
			h.assertCountersAgree()
		})
	}
}
