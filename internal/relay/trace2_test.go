package relay

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

// The second adversarial trace, at v0.9.0 (reviews/trace/): the quota
// arithmetic, the upload lock and the purge. Its tests are here as the
// regression tests, each renamed for what it proves.

// TestAnEnvelopeIsChargedAgainstStreamReservations: OpenUpload counted what
// other open uploads had reserved as though it were already queued, and
// Put, the envelope path, read queued_bytes alone. An admitted sender who
// opened a stream for everything free and then posted envelopes filled the
// mailbox to its quota with the reservation uncounted, and when the stream
// completed the mailbox and the relay held more than their quotas by up to
// one stream. Now one helper answers both, so an envelope into the
// reservation is refused, and a stream after an envelope is refused the
// same way: the reservation counts in both directions.
func TestAnEnvelopeIsChargedAgainstStreamReservations(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	const quota = 8192 + 4096
	q := Quotas{MailboxMaxBytes: quota, RelayMaxBytes: quota}
	id, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	const streamSize = 8192
	if err := h.store.OpenUpload(id, bob.Fingerprint(), alice.Fingerprint(), "default",
		streamSize, now, now.Add(time.Hour), q, 0); err != nil {
		t.Fatal(err)
	}
	// 8192 reserved of 12288, so at most 4096 is left for anything else.
	envelope := bytes.Repeat([]byte("e"), 4097)
	if _, err := h.store.Put(bob.Fingerprint(), "default", envelope, q); !errors.Is(err, ErrMailboxFull) {
		t.Errorf("an envelope of %d bytes was queued for a mailbox with %d of its %d byte quota reserved by an open upload (err=%v); "+
			"expected ErrMailboxFull, since only %d bytes are unreserved", len(envelope), streamSize, quota, err, quota-streamSize)
	}
	// What is unreserved is taken.
	if _, err := h.store.Put(bob.Fingerprint(), "default", envelope[:4096], q); err != nil {
		t.Fatalf("an envelope that fits beside the reservation was refused: %v", err)
	}
	// And the stream, completed on top of it, leaves the mailbox and the
	// relay at their quotas, not past them.
	if _, err := h.store.AppendUpload(id, 0, func(f *os.File, limit int64) (int64, error) {
		return io.Copy(f, io.LimitReader(bytes.NewReader(bytes.Repeat([]byte("s"), streamSize)), limit))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CompleteUpload(id); err != nil {
		t.Fatal(err)
	}
	var queued, relayQueued int64
	if err := h.store.db.QueryRow(`SELECT queued_bytes FROM mailboxes WHERE fp = ?`, bob.Fingerprint()).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if err := h.store.db.QueryRow(`SELECT queued_bytes FROM relay_stats WHERE id = 1`).Scan(&relayQueued); err != nil {
		t.Fatal(err)
	}
	if queued > quota {
		t.Errorf("the mailbox holds %d bytes against a mailbox_max_bytes of %d; expected the quota to hold", queued, quota)
	}
	if relayQueued > quota {
		t.Errorf("the relay holds %d bytes against a relay_max_bytes of %d; expected the quota to hold", relayQueued, quota)
	}

	// The other direction, which held before and holds through the same
	// helper now: with the mailbox at its quota, a stream of one byte is
	// refused; and after an acknowledgement makes room for exactly one
	// more, a stream that would take two is refused while one is taken.
	other, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.OpenUpload(other, bob.Fingerprint(), alice.Fingerprint(), "default",
		1, now, now.Add(time.Hour), q, 0); !errors.Is(err, ErrMailboxFull) {
		t.Errorf("a stream was opened for a mailbox at its quota: %v", err)
	}
	// The relay-wide quota by the same arithmetic: a second mailbox with
	// room of its own is still refused by the relay's total.
	if err := h.store.OpenUpload(other, alice.Fingerprint(), bob.Fingerprint(), "default",
		1, now, now.Add(time.Hour), q, 0); !errors.Is(err, ErrRelayFull) {
		t.Errorf("a stream was opened for another mailbox while the relay is at its quota: %v", err)
	}
	if _, err := h.store.Put(alice.Fingerprint(), "default", []byte("e"), q); !errors.Is(err, ErrRelayFull) {
		t.Errorf("an envelope was queued for another mailbox while the relay is at its quota: %v", err)
	}
}

// TestAnEnvelopeIsCountedBesideStreamReservations: the mirror for the
// message count. With mailbox_max_messages 2, one open upload and one
// envelope queued are the two, and a second envelope is refused, as a
// second stream would be.
func TestAnEnvelopeIsCountedBesideStreamReservations(t *testing.T) {
	h := newHarness(t, Config{})
	people := ids(t, "alice", "bob")
	alice, bob := people[0], people[1]
	h.register(alice)
	h.register(bob)

	q := Quotas{MailboxMaxMessages: 2}
	id, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := h.store.OpenUpload(id, bob.Fingerprint(), alice.Fingerprint(), "default",
		16, now, now.Add(time.Hour), q, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Put(bob.Fingerprint(), "default", []byte("first"), q); err != nil {
		t.Fatalf("the envelope beside one reservation was refused: %v", err)
	}
	if _, err := h.store.Put(bob.Fingerprint(), "default", []byte("second"), q); !errors.Is(err, ErrMailboxFull) {
		t.Errorf("a second envelope was queued beside one reservation under mailbox_max_messages 2 (err=%v); expected ErrMailboxFull", err)
	}
	other, err := NewUploadID()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.OpenUpload(other, bob.Fingerprint(), alice.Fingerprint(), "default",
		16, now, now.Add(time.Hour), q, 0); !errors.Is(err, ErrMailboxFull) {
		t.Errorf("a second stream was opened beside one envelope and one reservation under mailbox_max_messages 2: %v", err)
	}
}
