package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tropeforce7/agentuucp/internal/channels"
	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/wire"
	"github.com/tropeforce7/agentuucp/internal/withdraw"
)

// withdrawPath is the withdrawal route for one row of one mailbox.
func withdrawPath(fp string, id int64) string {
	return "/v1/mailbox/" + fp + "/withdraw/" + strconv.FormatInt(id, 10)
}

// keyOf is the withdrawal key a sender holds for an envelope it sealed.
func keyOf(t *testing.T, raw []byte) string {
	t.Helper()
	var env relayapi.Carried
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	return withdraw.EnvelopeKey(env.To, env.CT)
}

// postToWithdraw posts a fresh message from one identity to another on a
// channel, empty for none, and answers its row and the key its sender
// would hold for it.
func (h *harness) postToWithdraw(from, to *identity.Identity, ch string) (int64, string) {
	h.t.Helper()
	body := sealedTo(h.t, from, to.Public(), "to be withdrawn", ch)
	status, id := h.postOnce(from, to, body)
	if status != http.StatusOK || id == 0 {
		h.t.Fatalf("the post to withdraw: %d, id %d", status, id)
	}
	return id, keyOf(h.t, body)
}

// withdrawAs asks the withdrawal route, as from, to put note in the place of
// row id of mailbox fp by key.
func (h *harness) withdrawAs(from *identity.Identity, fp string, id int64, key string, note []byte) (int, []byte) {
	h.t.Helper()
	// Written by hand rather than marshalled: encoding/json compacts a
	// RawMessage, and a note padded to a size must arrive at that size.
	k, err := json.Marshal(key)
	if err != nil {
		h.t.Fatal(err)
	}
	body := append(append(append([]byte(`{"key":`), k...), `,"note":`...), note...)
	return h.do(from, "POST", withdrawPath(fp, id), append(body, '}'), nil)
}

// padded is an envelope with spaces before its closing brace, so that it is
// exactly n bytes and still the same envelope to every reader.
func padded(t *testing.T, raw []byte, n int) []byte {
	t.Helper()
	if n < len(raw) {
		t.Fatalf("cannot pad %d bytes to %d", len(raw), n)
	}
	out := append([]byte{}, raw[:len(raw)-1]...)
	out = append(out, bytes.Repeat([]byte(" "), n-len(raw))...)
	return append(out, '}')
}

// withdrawState is everything a refused withdrawal must leave as it was,
// and the one thing it spends.
type withdrawState struct {
	rows, bytes int64
	carried     int
	nonces      int
}

func (h *harness) withdrawState(fp string) withdrawState {
	h.t.Helper()
	rows, bytes := h.held(fp)
	return withdrawState{rows: rows, bytes: bytes, carried: h.carriedRows(h.t), nonces: h.nonceCount()}
}

// unchanged requires that a refused withdrawal left the mailbox, its
// counters and the carried table as they were and spent the one nonce its
// signature did, as a refused post does.
func (h *harness) unchanged(label, fp string, before withdrawState) {
	h.t.Helper()
	after := h.withdrawState(fp)
	if after.rows != before.rows || after.bytes != before.bytes || after.carried != before.carried {
		h.t.Errorf("%s: rows %d, bytes %d, carried %d after the refusal; want %d, %d and %d",
			label, after.rows, after.bytes, after.carried, before.rows, before.bytes, before.carried)
	}
	if after.nonces != before.nonces+1 {
		h.t.Errorf("%s: nonces %d after the refusal, want %d", label, after.nonces, before.nonces+1)
	}
	h.assertCountersAgree()
}

// A withdrawal through a real relay: the relay says it is at wire level 3;
// the note takes the message's place, under a row id above it, on its
// channel, with a key of its own, and the message's file is gone; the
// mailbox's other mail stays; the counters agree with a fresh count; a
// listing held past the message is woken by the note; and no log line
// carries the key or its stored form.
func TestAWithdrawalPutsItsNoteInTheMessagesPlace(t *testing.T) {
	h := newHarness(t, Config{})
	if got := h.health(t).WireLevel; got != 3 {
		t.Fatalf("the health answer says wire level %d, want 3", got)
	}
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	fp := bob.Fingerprint()
	kept, _ := h.postToWithdraw(alice, bob, "")
	id, key := h.postToWithdraw(alice, bob, "")

	l := h.list(bob, fmt.Sprintf("after=%d&%s", id, longHold))
	h.holding(1)
	note := sealedTo(t, alice, bob.Public(), "withdrawn", "")
	status, body := h.withdrawAs(alice, fp, id, key, note)
	if status != http.StatusOK {
		t.Fatalf("the withdrawal: %d %s", status, body)
	}
	var answer relayapi.PostResponse
	if err := json.Unmarshal(body, &answer); err != nil {
		t.Fatal(err)
	}
	if answer.ID <= id {
		t.Fatalf("the note is row %d, want one above the message's %d", answer.ID, id)
	}
	if _, err := os.Stat(h.store.messagePath(fp, id)); !os.IsNotExist(err) {
		t.Errorf("the message's file is still there: %v", err)
	}
	rows, err := h.store.List(fp, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].ID != kept || rows[1].ID != answer.ID {
		t.Fatalf("bob's mailbox lists %+v; want the kept message and the note", rows)
	}
	if !bytes.Equal(rows[1].Envelope, note) || rows[1].Channel != channels.Default || rows[1].Kind != relayapi.KindEnvelope {
		t.Errorf("the note is listed as %+v; want the note's bytes, an envelope on default", rows[1])
	}
	if got := h.withdrawColumn(fp, answer.ID); got != withdraw.Stored(keyOf(t, note)) {
		t.Errorf("the note's column is %q, want its own key's stored form", got)
	}
	h.assertCountersAgree()

	status, listed, _ := l.answer(t)
	if status != http.StatusOK || len(listed.Messages) != 1 || listed.Messages[0].ID != answer.ID {
		t.Fatalf("the held listing was answered %d %+v; want the note", status, listed)
	}
	for _, secret := range []string{key, withdraw.Stored(key)} {
		if strings.Contains(h.logs.String(), secret) {
			t.Fatalf("a log line carries %s", secret)
		}
	}
}

// placeStream uploads a fake stream of payload bytes from one identity to
// another through the upload route and answers its row and its bytes. The
// first byte of its encapsulation is seal, since a real seal's
// encapsulation is another value for every stream and fakeStream's is
// always the same: two fake streams would otherwise share their first
// bytes, and so their key.
func (h *harness) placeStream(from, to *identity.Identity, payload int, seal byte) (int64, []byte) {
	h.t.Helper()
	blob := fakeStream(200, payload)
	blob[0] = seal
	status, opened, body := h.openStream(from, to.Fingerprint(), int64(len(blob)))
	if status != http.StatusCreated {
		h.t.Fatalf("open: %d %s", status, body)
	}
	status, body, _ = h.putStream(from, opened.Upload, blob, 0)
	if status != http.StatusCreated {
		h.t.Fatalf("put: %d %s", status, body)
	}
	var done relayapi.PutStreamResponse
	if err := json.Unmarshal(body, &done); err != nil {
		h.t.Fatal(err)
	}
	return done.ID, blob
}

// A stream is withdrawn as an envelope is, by withdraw.StreamKey of its
// bytes, and it is the largest thing the route frees: the stream's row and
// file go, the note is listed in its place on the stream's channel, the
// mailbox's count is unchanged and its bytes are down by the stream's size
// less the note's, against a fresh count. The wrong form of key, the
// envelope key over the same bytes, and another stream's key are each the
// one 404 with nothing changed.
func TestAPlacedStreamIsWithdrawnByItsStreamKey(t *testing.T) {
	h := newHarness(t, Config{})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	fp := bob.Fingerprint()
	// Past the prefix, so that the envelope key over the whole and the
	// stream key over the prefix are two values.
	id, blob := h.placeStream(alice, bob, 3000+withdraw.StreamPrefix, 1)
	_, other := h.placeStream(alice, bob, 3000, 2)
	key, err := withdraw.StreamKey(fp, bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := withdraw.StreamKey(fp, bytes.NewReader(other), int64(len(other)))
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]string{
		"the envelope key over its bytes": withdraw.EnvelopeKey(fp, blob),
		"another stream's key":            otherKey,
	} {
		before := h.withdrawState(fp)
		status, body := h.withdrawAs(alice, fp, id, k, sealedTo(t, alice, bob.Public(), "withdrawn", ""))
		wantRefusal(t, name, status, body, http.StatusNotFound, relayapi.CodeNotWithdrawable, relayapi.MsgNotWithdrawable)
		h.unchanged(name, fp, before)
	}

	rowsBefore, bytesBefore := h.held(fp)
	note := sealedTo(t, alice, bob.Public(), "withdrawn", "")
	status, body := h.withdrawAs(alice, fp, id, key, note)
	if status != http.StatusOK {
		t.Fatalf("the stream's withdrawal: %d %s", status, body)
	}
	var answer relayapi.PostResponse
	if err := json.Unmarshal(body, &answer); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.store.messagePath(fp, id)); !os.IsNotExist(err) {
		t.Errorf("the stream's file is still there: %v", err)
	}
	var left int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE id = ?`, id).Scan(&left); err != nil || left != 0 {
		t.Errorf("the stream's row: %d left, %v", left, err)
	}
	rows, err := h.store.List(fp, id, 10)
	if err != nil {
		t.Fatal(err)
	}
	var found *Row
	for i := range rows {
		if rows[i].ID == answer.ID {
			found = &rows[i]
		}
	}
	if found == nil || found.Kind != relayapi.KindEnvelope || found.Channel != channels.Default || !bytes.Equal(found.Envelope, note) {
		t.Fatalf("the note is not listed in the stream's place: %+v", rows)
	}
	rowsAfter, bytesAfter := h.held(fp)
	if rowsAfter != rowsBefore || bytesAfter != bytesBefore-int64(len(blob))+int64(len(note)) {
		t.Errorf("the mailbox holds %d rows of %d bytes; want %d rows of %d", rowsAfter, bytesAfter,
			rowsBefore, bytesBefore-int64(len(blob))+int64(len(note)))
	}
	h.assertCountersAgree()
}

// Every row the key does not open is answered alike, 404 under
// not-withdrawable with its one sentence, word for word the same, and
// leaves the mailbox, its counters and the carried table as they were:
// a row that does not exist, another mailbox's row with that mailbox's
// own key, a knock's row, with its own key or one written into its column
// by hand, a row from before the column, another message's
// key, the key with one bit flipped, a row already replaced whose key is
// shown again, and a row its owner removed.
func TestEveryRowTheKeyDoesNotOpenIsRefusedAlike(t *testing.T) {
	h := newHarness(t, Config{})
	alice, bob, carol := neighbourID(t, "alice"), neighbourID(t, "bob"), neighbourID(t, "carol")
	h.enroll(alice, bob, carol)
	fp := bob.Fingerprint()

	id, key := h.postToWithdraw(alice, bob, "")
	_, otherKey := h.postToWithdraw(alice, bob, "")
	carolsID, carolsKey := h.postToWithdraw(alice, carol, "")
	if status, body, _ := h.pushCard(bob, bob, time.Now(), false, true); status != http.StatusNoContent {
		t.Fatalf("card push: %d %s", status, body)
	}
	if status, body, _ := h.knock(carol, bob, "hello"); status != http.StatusOK {
		t.Fatalf("knock: %d %s", status, body)
	}
	_, knockID, _ := h.knockerOf(fp)
	// A knock keeps no key, and one given a key by hand opens to none:
	// the kind is asked as well as the column.
	knockKey := strings.Repeat("d", 64)
	if _, err := h.store.db.Exec(`UPDATE messages SET withdraw = ? WHERE id = ?`, withdraw.Stored(knockKey), knockID); err != nil {
		t.Fatal(err)
	}
	oldID, oldKey := h.postToWithdraw(alice, bob, "")
	if _, err := h.store.db.Exec(`UPDATE messages SET withdraw = '' WHERE id = ?`, oldID); err != nil {
		t.Fatal(err)
	}
	doneID, doneKey := h.postToWithdraw(alice, bob, "")
	if status, body := h.withdrawAs(alice, fp, doneID, doneKey, sealedTo(t, alice, bob.Public(), "withdrawn", "")); status != http.StatusOK {
		t.Fatalf("the first withdrawal: %d %s", status, body)
	}
	goneID, goneKey := h.postToWithdraw(alice, bob, "")
	if removed, err := h.store.Delete(fp, goneID); err != nil || !removed {
		t.Fatalf("bob's removal: %v %v", removed, err)
	}
	raw, _ := hex.DecodeString(key)
	raw[len(raw)-1] ^= 1
	flipped := hex.EncodeToString(raw)

	var first []byte
	for _, c := range []struct {
		name string
		id   int64
		key  string
	}{
		{"no such row", id + 1000, key},
		{"another mailbox's row", carolsID, carolsKey},
		{"a knock's row", knockID, key},
		{"a knock's row given a key by hand", knockID, knockKey},
		{"a row from before the column", oldID, oldKey},
		{"another message's key", id, otherKey},
		{"one bit flipped", id, flipped},
		{"a row already replaced", doneID, doneKey},
		{"a row its owner removed", goneID, goneKey},
	} {
		before := h.withdrawState(fp)
		status, body := h.withdrawAs(alice, fp, c.id, c.key, sealedTo(t, alice, bob.Public(), "withdrawn", ""))
		wantRefusal(t, c.name, status, body, http.StatusNotFound, relayapi.CodeNotWithdrawable, relayapi.MsgNotWithdrawable)
		if first == nil {
			first = body
		} else if !bytes.Equal(body, first) {
			t.Errorf("%s is answered %s and the first %s: the two are told apart", c.name, body, first)
		}
		h.unchanged(c.name, fp, before)
	}
	if got := h.withdrawColumn(fp, id); got != withdraw.Stored(key) {
		t.Errorf("the message after the refusals keeps %q", got)
	}
	if n, _ := h.queued(carol.Fingerprint()); n != 1 {
		t.Errorf("carol holds %d messages after a withdrawal named her row on bob's path, want 1", n)
	}
}

// What the route refuses before the store, each by its own sentence and
// with nothing changed: an id that is not a positive integer, a key in each
// shape that is not a key's, a note that is not an envelope, one addressed
// to another mailbox, and one over MaxWithdrawBytes. A note of exactly
// MaxWithdrawBytes is taken.
func TestAWithdrawalsRequestIsHeldToItsShape(t *testing.T) {
	h := newHarness(t, Config{})
	alice, bob, carol := neighbourID(t, "alice"), neighbourID(t, "bob"), neighbourID(t, "carol")
	h.enroll(alice, bob, carol)
	fp := bob.Fingerprint()
	id, key := h.postToWithdraw(alice, bob, "")
	note := sealedTo(t, alice, bob.Public(), "withdrawn", "")

	for _, bad := range []string{"0", "-1", "x", "1.5"} {
		before := h.withdrawState(fp)
		status, body := h.do(alice, "POST", "/v1/mailbox/"+fp+"/withdraw/"+bad, relayapi.WithdrawRequest{Key: key, Note: note}, nil)
		wantRefusal(t, "id "+bad, status, body, http.StatusBadRequest, "", "bad message id")
		h.unchanged("id "+bad, fp, before)
	}
	for name, k := range map[string]string{
		"empty": "", "63": key[:63], "65": key + "0", "uppercase": strings.ToUpper(key), "not hex": "g" + key[1:],
	} {
		before := h.withdrawState(fp)
		status, body := h.withdrawAs(alice, fp, id, k, note)
		wantRefusal(t, "a key "+name, status, body, http.StatusBadRequest, "", "withdrawal key is not 64 lowercase hex characters")
		if strings.Contains(string(body), k) && k != "" {
			t.Errorf("a key %s is echoed: %s", name, body)
		}
		h.unchanged("a key "+name, fp, before)
	}
	for _, c := range []struct {
		name, want string
		note       []byte
	}{
		{"a note that is not an envelope", "note: malformed envelope: json: cannot unmarshal array into Go value of type relayapi.Carried", []byte(`[1]`)},
		{"a note to carol", "envelope is not addressed to this mailbox", sealedTo(t, alice, carol.Public(), "withdrawn", "")},
	} {
		before := h.withdrawState(fp)
		status, body := h.withdrawAs(alice, fp, id, key, c.note)
		wantRefusal(t, c.name, status, body, http.StatusBadRequest, "", c.want)
		h.unchanged(c.name, fp, before)
	}
	before := h.withdrawState(fp)
	status, body := h.withdrawAs(alice, fp, id, key, padded(t, note, relayapi.MaxWithdrawBytes+1))
	wantRefusal(t, "a note one byte over", status, body, http.StatusRequestEntityTooLarge, "", "withdrawal note too large")
	h.unchanged("a note one byte over", fp, before)

	if status, body := h.withdrawAs(alice, fp, id, key, padded(t, note, relayapi.MaxWithdrawBytes)); status != http.StatusOK {
		t.Fatalf("a note of exactly MaxWithdrawBytes: %d %s", status, body)
	}
}

// A relay whose max_bytes is under MaxWithdrawBytes holds a note to it, as
// it holds a post: one byte over is refused with nothing changed, and a
// note of exactly max_bytes is taken.
func TestAWithdrawalsNoteIsHeldToMaxBytes(t *testing.T) {
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	body := sealedTo(t, alice, bob.Public(), "to be withdrawn", "")
	limit := int64(len(body) + 100)
	h := newHarness(t, Config{MaxBytes: limit})
	h.enroll(alice, bob)
	fp := bob.Fingerprint()
	status, id := h.postOnce(alice, bob, body)
	if status != http.StatusOK {
		t.Fatalf("the post: %d", status)
	}
	note := sealedTo(t, alice, bob.Public(), "withdrawn", "")
	before := h.withdrawState(fp)
	status, got := h.withdrawAs(alice, fp, id, keyOf(t, body), padded(t, note, int(limit)+1))
	wantRefusal(t, "a note one byte over max_bytes", status, got, http.StatusRequestEntityTooLarge, "", "withdrawal note too large")
	h.unchanged("a note one byte over max_bytes", fp, before)
	if status, got := h.withdrawAs(alice, fp, id, keyOf(t, body), padded(t, note, int(limit))); status != http.StatusOK {
		t.Fatalf("a note of exactly max_bytes: %d %s", status, got)
	}
}

// Replace refuses a key that is not a key's shape, and a note's own key
// that is not one, as ErrNotWithdrawable with nothing written, whoever
// calls it: the route holds the key's shape first, and the store does not
// rely on that.
func TestReplaceRefusesAKeyOfAnotherShape(t *testing.T) {
	h := newHarness(t, Config{})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	fp := bob.Fingerprint()
	id, key := h.postToWithdraw(alice, bob, "")
	note := sealedTo(t, alice, bob.Public(), "withdrawn", "")
	for name, c := range map[string]struct{ key, own string }{
		"an empty key":           {"", ""},
		"an uppercase key":       {strings.ToUpper(withdraw.Stored(key)), ""},
		"a note's key misshapen": {withdraw.Stored(key), "x"},
	} {
		if _, err := h.store.Replace(fp, id, c.key, c.own, channels.Default, true, note, Quotas{}, Forwarded{}); !errors.Is(err, ErrNotWithdrawable) {
			t.Errorf("%s: %v; want ErrNotWithdrawable", name, err)
		}
	}
	if rows, _ := h.held(fp); rows != 1 {
		t.Fatalf("bob holds %d rows after the refusals, want the one message", rows)
	}
	if got := h.withdrawColumn(fp, id); got != withdraw.Stored(key) {
		t.Fatalf("the message keeps %q", got)
	}
}

// The post's own refusals, on this route, each before the key is looked
// at, so a wrong key meets them as a right one would: a sender the owner
// does not admit, a blocked mailbox, a courier's mailbox, a mailbox that is
// gone, a channel that does not exist, and a note over its channel's
// max_bytes. Nothing changes for any of them.
func TestAWithdrawalMeetsThePostsRefusalsBeforeItsKey(t *testing.T) {
	t.Run("admission, blocks and channels", func(t *testing.T) {
		h := newHarness(t, Config{})
		alice, bob, carol := neighbourID(t, "alice"), neighbourID(t, "bob"), neighbourID(t, "carol")
		h.enroll(alice, bob, carol)
		fp := bob.Fingerprint()
		id, key := h.postToWithdraw(alice, bob, "")
		for _, k := range []string{key, strings.Repeat("a", 64)} {
			kind := "the right key"
			if k != key {
				kind = "a wrong key"
			}

			before := h.withdrawState(fp)
			status, body := h.withdrawAs(alice, fp, id, k, sealedTo(t, alice, bob.Public(), "withdrawn", "nope"))
			wantRefusal(t, "no such channel, "+kind, status, body, http.StatusNotFound, relayapi.CodeNoSuchChannel, `no such channel "nope"`)
			h.unchanged("no such channel", fp, before)

			if status, body, _ := h.pushAllow(bob, bob, time.Now().Add(time.Duration(len(kind))*time.Second), carol.Fingerprint()); status != http.StatusNoContent {
				t.Fatalf("allow push: %d %s", status, body)
			}
			before = h.withdrawState(fp)
			status, body = h.withdrawAs(alice, fp, id, k, sealedTo(t, alice, bob.Public(), "withdrawn", ""))
			wantRefusal(t, "not admitted, "+kind, status, body, http.StatusForbidden, "", msgNotAllowed)
			h.unchanged("not admitted", fp, before)
			if _, err := h.store.db.Exec(`DELETE FROM allowlists WHERE fp = ?`, fp); err != nil {
				t.Fatal(err)
			}
		}
		if err := h.store.SetBlock(fp, "flooding", alice.Fingerprint(), time.Now()); err != nil {
			t.Fatal(err)
		}
		before := h.withdrawState(fp)
		status, body := h.withdrawAs(alice, fp, id, key, sealedTo(t, alice, bob.Public(), "withdrawn", ""))
		wantRefusal(t, "blocked", status, body, http.StatusForbidden, "", "recipient is blocked on this relay")
		h.unchanged("blocked", fp, before)
	})

	t.Run("a note over its channel's size", func(t *testing.T) {
		h := newHarness(t, Config{})
		alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
		h.enroll(alice, bob)
		fp := bob.Fingerprint()
		body := sealedTo(t, alice, bob.Public(), "to be withdrawn", "bugs")
		limit := int64(len(body) + 100)
		h.pushRules(bob, time.Now(), channels.Channel{Name: "bugs", MaxBytes: limit})
		status, id := h.postOnce(alice, bob, body)
		if status != http.StatusOK {
			t.Fatalf("the post: %d", status)
		}
		note := padded(t, sealedTo(t, alice, bob.Public(), "withdrawn", "bugs"), int(limit)+1)
		for _, k := range []string{keyOf(t, body), strings.Repeat("a", 64)} {
			before := h.withdrawState(fp)
			status, got := h.withdrawAs(alice, fp, id, k, note)
			e := refusal(t, got)
			if status != http.StatusRequestEntityTooLarge || e.Code != relayapi.CodeChannelSize {
				t.Fatalf("a note over the channel's max_bytes: %d %s", status, got)
			}
			h.unchanged("over the channel's size", fp, before)
		}
	})

	t.Run("a courier's mailbox", func(t *testing.T) {
		courier := neighbourID(t, "alpha")
		h := peered(t, []string{"bar"}, []*identity.Identity{courier}, nil)
		h.enroll(courier)
		alice := h.user(t, "alice")
		to := courier.Fingerprint()
		raw := sealed(t, alice, courier.Public(), "x")
		id, err := h.store.Put(to, channels.Default, relayapi.KindEnvelope, "", withdraw.Stored(keyOf(t, raw)), raw, Quotas{}, Forwarded{})
		if err != nil {
			t.Fatal(err)
		}
		before := h.withdrawState(to)
		status, body := h.withdrawAs(alice, to, id, keyOf(t, raw), sealed(t, alice, courier.Public(), "withdrawn"))
		wantRefusal(t, "a courier's mailbox", status, body, http.StatusForbidden, "", msgNotAllowed)
		h.unchanged("a courier's mailbox", to, before)
	})

	t.Run("a mailbox that is gone", func(t *testing.T) {
		h := newHarness(t, Config{})
		alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
		h.enroll(alice, bob)
		fp := bob.Fingerprint()
		id, key := h.postToWithdraw(alice, bob, "")
		if gone, err := h.store.Deregister(fp); err != nil || !gone {
			t.Fatalf("deregistering bob: %v %v", gone, err)
		}
		status, body := h.withdrawAs(alice, fp, id, key, sealedTo(t, alice, bob.Public(), "withdrawn", ""))
		wantRefusal(t, "a mailbox that is gone", status, body, http.StatusNotFound, "", "no such mailbox")
	})
}

// The channel: a message on a channel that has since closed is withdrawn
// all the same, the note on that channel, since the period is not asked of
// a note that takes a row's place (D195); a note on any channel but its
// message's own is refused once the key has matched, even where that
// channel is open, and a wrong key on another channel is the one 404, so
// the channel check says nothing to a caller without the key (R146 P7).
func TestAWithdrawalIsOnItsMessagesOwnChannel(t *testing.T) {
	h := newHarness(t, Config{})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	fp := bob.Fingerprint()
	h.pushRules(bob, h.clock.Now(), channels.Channel{Name: "bugs"}, channels.Channel{Name: "cfp"})
	id, key := h.postToWithdraw(alice, bob, "bugs")
	otherID, otherKey := h.postToWithdraw(alice, bob, "bugs")

	const sentence = "the note is not on the channel of the message it takes the place of"
	for _, ch := range []string{"", "cfp"} {
		before := h.withdrawState(fp)
		status, body := h.withdrawAs(alice, fp, id, key, sealedTo(t, alice, bob.Public(), "withdrawn", ch))
		wantRefusal(t, "a note on "+strconv.Quote(ch), status, body, http.StatusBadRequest, "", sentence)
		h.unchanged("a note on another channel", fp, before)
		status, body = h.withdrawAs(alice, fp, id, otherKey, sealedTo(t, alice, bob.Public(), "withdrawn", ch))
		wantRefusal(t, "a wrong key on "+strconv.Quote(ch), status, body, http.StatusNotFound, relayapi.CodeNotWithdrawable, relayapi.MsgNotWithdrawable)
	}

	// bugs closes. The message on it is withdrawn; a post to it is not taken.
	closed := h.clock.Now().Add(-time.Minute)
	h.pushRules(bob, h.clock.Now().Add(time.Second), channels.Channel{Name: "bugs", NotAfter: &closed}, channels.Channel{Name: "cfp"})
	if status, body := h.postTo(alice, bob, "bugs"); status != http.StatusForbidden {
		t.Fatalf("a post to bugs once closed: %d %s; want it refused", status, body)
	}
	status, body := h.withdrawAs(alice, fp, otherID, otherKey, sealedTo(t, alice, bob.Public(), "withdrawn", "bugs"))
	if status != http.StatusOK {
		t.Fatalf("a withdrawal on bugs once closed: %d %s", status, body)
	}
	var answer relayapi.PostResponse
	if err := json.Unmarshal(body, &answer); err != nil {
		t.Fatal(err)
	}
	rows, err := h.store.List(fp, otherID, 10)
	if err != nil || len(rows) != 1 || rows[0].ID != answer.ID || rows[0].Channel != "bugs" {
		t.Fatalf("after the withdrawal: %+v %v; want the note on bugs", rows, err)
	}
	// The note on the closed channel keeps no key, so it cannot be
	// withdrawn in turn: the period is spared once per message, and a
	// message is no slot for new mail while its channel is closed.
	if got := h.withdrawColumn(fp, answer.ID); got != "" {
		t.Fatalf("a note stored on a closed channel keeps %q; want no key", got)
	}
	before := h.withdrawState(fp)
	status, body = h.withdrawAs(alice, fp, answer.ID, keyOf(t, rows[0].Envelope), sealedTo(t, alice, bob.Public(), "and again", "bugs"))
	wantRefusal(t, "the note withdrawn in turn", status, body, http.StatusNotFound, relayapi.CodeNotWithdrawable, relayapi.MsgNotWithdrawable)
	h.unchanged("the note withdrawn in turn", fp, before)
}

// On a channel outside its period a note is held to the larger of the
// message it takes the place of and WithdrawFloorBytes (D198), since the
// relay cannot tell a note from any other envelope: over a message smaller
// than the floor, a note one byte over the floor is refused 400 with
// note-too-large and nothing changed, and one at the floor is taken; over
// a message larger than the floor, a note one byte over the message is
// refused and one its size is taken; on the channel while it is open the
// same over-size note is taken; and a stream, a large row, takes the
// largest note there is. The rule is asked after the key and the channel.
func TestANoteOnAClosedChannelIsNoLargerThanItsMessage(t *testing.T) {
	type world struct {
		h          *harness
		alice, bob *identity.Identity
		fp         string
	}
	open := func(t *testing.T) world {
		h := newHarness(t, Config{})
		alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
		h.enroll(alice, bob)
		h.pushRules(bob, h.clock.Now(), channels.Channel{Name: "bugs"})
		return world{h, alice, bob, bob.Fingerprint()}
	}
	closeBugs := func(w world) {
		closed := w.h.clock.Now().Add(-time.Minute)
		w.h.pushRules(w.bob, w.h.clock.Now().Add(time.Second), channels.Channel{Name: "bugs", NotAfter: &closed})
	}
	post := func(w world, text string) (int64, string, int) {
		body := sealedTo(w.h.t, w.alice, w.bob.Public(), text, "bugs")
		status, id := w.h.postOnce(w.alice, w.bob, body)
		if status != http.StatusOK {
			w.h.t.Fatalf("the post: %d", status)
		}
		return id, keyOf(w.h.t, body), len(body)
	}
	note := func(w world, n int) []byte {
		return padded(w.h.t, sealedTo(w.h.t, w.alice, w.bob.Public(), "withdrawn", "bugs"), n)
	}
	floor := relayapi.WithdrawFloorBytes
	big := strings.Repeat("x", 3*floor)

	t.Run("over a message smaller than the floor", func(t *testing.T) {
		w := open(t)
		id, key, size := post(w, "small")
		if size >= floor {
			t.Fatalf("the small message is %d bytes, not under the floor of %d", size, floor)
		}
		closeBugs(w)
		before := w.h.withdrawState(w.fp)
		status, body := w.h.withdrawAs(w.alice, w.fp, id, key, note(w, floor+1))
		wantRefusal(t, "one byte over the floor", status, body, http.StatusBadRequest, relayapi.CodeNoteTooLarge, relayapi.MsgNoteTooLarge)
		w.h.unchanged("one byte over the floor", w.fp, before)
		if status, body := w.h.withdrawAs(w.alice, w.fp, id, key, note(w, floor)); status != http.StatusOK {
			t.Fatalf("a note at the floor: %d %s", status, body)
		}
	})
	t.Run("over a message larger than the floor", func(t *testing.T) {
		w := open(t)
		id, key, size := post(w, big)
		if size <= floor {
			t.Fatalf("the large message is %d bytes, not over the floor of %d", size, floor)
		}
		closeBugs(w)
		before := w.h.withdrawState(w.fp)
		status, body := w.h.withdrawAs(w.alice, w.fp, id, key, note(w, size+1))
		wantRefusal(t, "one byte over the message", status, body, http.StatusBadRequest, relayapi.CodeNoteTooLarge, relayapi.MsgNoteTooLarge)
		w.h.unchanged("one byte over the message", w.fp, before)
		if status, body := w.h.withdrawAs(w.alice, w.fp, id, key, note(w, size)); status != http.StatusOK {
			t.Fatalf("a note the message's size: %d %s", status, body)
		}
	})
	t.Run("on the channel while it is open", func(t *testing.T) {
		w := open(t)
		id, key, _ := post(w, "small")
		if status, body := w.h.withdrawAs(w.alice, w.fp, id, key, note(w, floor+1)); status != http.StatusOK {
			t.Fatalf("a note over the floor on an open channel: %d %s", status, body)
		}
	})
	// The rule is asked only after the key and the channel, so an
	// oversized note tells nobody without the key that a row is there or
	// how large it is: a wrong key and a row that keeps no key are the one
	// 404, and the right key with a note on another closed channel is the
	// other-channel 400, each with nothing changed.
	t.Run("after the key and the channel", func(t *testing.T) {
		w := open(t)
		w.h.pushRules(w.bob, w.h.clock.Now().Add(time.Second), channels.Channel{Name: "bugs"}, channels.Channel{Name: "cfp"})
		id, key, _ := post(w, "small")
		bare, _, _ := post(w, "small too")
		if _, err := w.h.store.db.Exec(`UPDATE messages SET withdraw = '' WHERE id = ?`, bare); err != nil {
			t.Fatal(err)
		}
		closed := w.h.clock.Now().Add(-time.Minute)
		w.h.pushRules(w.bob, w.h.clock.Now().Add(2*time.Second),
			channels.Channel{Name: "bugs", NotAfter: &closed}, channels.Channel{Name: "cfp", NotAfter: &closed})
		over := note(w, floor+1)
		for _, c := range []struct {
			name string
			id   int64
			key  string
		}{
			{"a wrong key", id, strings.Repeat("a", 64)},
			{"a row that keeps no key", bare, key},
			{"no such row", id + 1000, key},
		} {
			before := w.h.withdrawState(w.fp)
			status, body := w.h.withdrawAs(w.alice, w.fp, c.id, c.key, over)
			wantRefusal(t, c.name, status, body, http.StatusNotFound, relayapi.CodeNotWithdrawable, relayapi.MsgNotWithdrawable)
			w.h.unchanged(c.name, w.fp, before)
		}
		elsewhere := padded(t, sealedTo(t, w.alice, w.bob.Public(), "withdrawn", "cfp"), floor+1)
		before := w.h.withdrawState(w.fp)
		status, body := w.h.withdrawAs(w.alice, w.fp, id, key, elsewhere)
		wantRefusal(t, "the right key on another closed channel", status, body, http.StatusBadRequest, "",
			"the note is not on the channel of the message it takes the place of")
		w.h.unchanged("the right key on another closed channel", w.fp, before)
	})
	t.Run("over a stream", func(t *testing.T) {
		w := open(t)
		blob := fakeStream(200, relayapi.MaxWithdrawBytes)
		blob[0] = 1
		status, opened, body := w.h.openStreamTo(w.alice, w.fp, int64(len(blob)), "bugs")
		if status != http.StatusCreated {
			t.Fatalf("open: %d %s", status, body)
		}
		status, body, _ = w.h.putStream(w.alice, opened.Upload, blob, 0)
		if status != http.StatusCreated {
			t.Fatalf("put: %d %s", status, body)
		}
		var done relayapi.PutStreamResponse
		if err := json.Unmarshal(body, &done); err != nil {
			t.Fatal(err)
		}
		key, err := withdraw.StreamKey(w.fp, bytes.NewReader(blob), int64(len(blob)))
		if err != nil {
			t.Fatal(err)
		}
		closeBugs(w)
		if status, body := w.h.withdrawAs(w.alice, w.fp, done.ID, key, note(w, relayapi.MaxWithdrawBytes)); status != http.StatusOK {
			t.Fatalf("the largest note over a stream on a closed channel: %d %s", status, body)
		}
		w.h.assertCountersAgree()
	})
}

// The budgets: a refused withdrawal spends a post's token as a refused
// post does, which the next post then meets; and the note takes its
// message's place in the mailbox's quotas, so a mailbox at its message
// count takes it, while a note larger than its message into a mailbox
// with no room for the difference is 507 with nothing changed.
func TestAWithdrawalIsChargedAsAPost(t *testing.T) {
	t.Run("posts", func(t *testing.T) {
		h := newHarness(t, Config{Limits: Limits{PostsPerMinute: 2}})
		alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
		h.enroll(alice, bob)
		id, _ := h.postToWithdraw(alice, bob, "")
		status, body := h.withdrawAs(alice, bob.Fingerprint(), id, strings.Repeat("a", 64), sealedTo(t, alice, bob.Public(), "withdrawn", ""))
		if status != http.StatusNotFound {
			t.Fatalf("a wrong key: %d %s", status, body)
		}
		if status, body := h.postTo(alice, bob, ""); status != http.StatusTooManyRequests {
			t.Fatalf("the post after a post and a refused withdrawal: %d %s; want the budget spent", status, body)
		}
	})
	t.Run("room", func(t *testing.T) {
		alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
		body := sealedTo(t, alice, bob.Public(), "to be withdrawn", "")
		h := newHarness(t, Config{Limits: Limits{MailboxMaxMessages: 1, MailboxMaxBytes: int64(len(body) + 10)}})
		h.enroll(alice, bob)
		fp := bob.Fingerprint()
		status, id := h.postOnce(alice, bob, body)
		if status != http.StatusOK {
			t.Fatalf("the post: %d", status)
		}
		note := sealedTo(t, alice, bob.Public(), "withdrawn", "")
		before := h.withdrawState(fp)
		status, got := h.withdrawAs(alice, fp, id, keyOf(t, body), padded(t, note, len(body)+11))
		wantRefusal(t, "a note too large for the room", status, got, http.StatusInsufficientStorage,
			relayapi.RefusalMailboxFull.Code, relayapi.RefusalMailboxFull.Msg)
		h.unchanged("a note too large for the room", fp, before)
		if _, err := os.Stat(h.store.messagePath(fp, id)); err != nil {
			t.Fatalf("the message's file after the refusal: %v", err)
		}
		// At its one message, the mailbox takes a note no larger than the
		// room its message leaves.
		if status, got := h.withdrawAs(alice, fp, id, keyOf(t, body), padded(t, note, len(body)+10)); status != http.StatusOK {
			t.Fatalf("a note that fits the room the message leaves: %d %s", status, got)
		}
		h.assertCountersAgree()
	})
}

// The transaction: a store fault after the message's row is taken out and
// before the note's is written leaves the message, its file and the
// counters as they were; and a crash after the commit and before the
// message's file is removed leaves a file no row names, which the sweep at
// the next start takes.
func TestAWithdrawalIsOneTransaction(t *testing.T) {
	t.Run("a fault before the note's row", func(t *testing.T) {
		h := newHarness(t, Config{})
		alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
		h.enroll(alice, bob)
		fp := bob.Fingerprint()
		id, key := h.postToWithdraw(alice, bob, "")
		if _, err := h.store.db.Exec(`CREATE TRIGGER no_note BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'no'); END`); err != nil {
			t.Fatal(err)
		}
		before := h.withdrawState(fp)
		status, body := h.withdrawAs(alice, fp, id, key, sealedTo(t, alice, bob.Public(), "withdrawn", ""))
		wantRefusal(t, "a fault", status, body, http.StatusInternalServerError, relayapi.RefusalStorageError.Code, relayapi.RefusalStorageError.Msg)
		h.unchanged("a fault", fp, before)
		if got := h.withdrawColumn(fp, id); got != withdraw.Stored(key) {
			t.Fatalf("the message after the fault keeps %q", got)
		}
		if _, err := os.Stat(h.store.messagePath(fp, id)); err != nil {
			t.Fatalf("the message's file after the fault: %v", err)
		}
	})
	t.Run("a crash before the file goes", func(t *testing.T) {
		dir := t.TempDir()
		st, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
		if err != nil {
			t.Fatal(err)
		}
		h := serveStore(t, st, Config{})
		alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
		h.enroll(alice, bob)
		fp := bob.Fingerprint()
		id, key := h.postToWithdraw(alice, bob, "")
		path := st.messagePath(fp, id)
		kept, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if status, body := h.withdrawAs(alice, fp, id, key, sealedTo(t, alice, bob.Public(), "withdrawn", "")); status != http.StatusOK {
			t.Fatalf("the withdrawal: %d %s", status, body)
		}
		h.server.Close()
		st.Close()
		// What a crash between the commit and the unlink leaves.
		if err := os.WriteFile(path, kept, 0o600); err != nil {
			t.Fatal(err)
		}
		again, err := OpenStore(filepath.Join(dir, "relay.db"), filepath.Join(dir, "messages"))
		if err != nil {
			t.Fatal(err)
		}
		defer again.Close()
		if got := again.Swept(); got.Orphans != 1 {
			t.Fatalf("the sweep found %+v; want the message's file as the one orphan", got)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("the message's file after the sweep: %v", err)
		}
	})
}

// The repeat: a withdrawal whose answer was lost is asked again and
// answered with the note's row, nothing stored, by the post's storing
// sequence; the same note posted by the ordinary route after it is
// answered the same. One note, one answer.
func TestAWithdrawalAskedAgainIsAnsweredAsTheFirst(t *testing.T) {
	h := newHarness(t, Config{})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	fp := bob.Fingerprint()
	id, key := h.postToWithdraw(alice, bob, "")
	note := sealedTo(t, alice, bob.Public(), "withdrawn", "")
	var ids []int64
	for range 2 {
		status, body := h.withdrawAs(alice, fp, id, key, note)
		if status != http.StatusOK {
			t.Fatalf("the withdrawal: %d %s", status, body)
		}
		var answer relayapi.PostResponse
		if err := json.Unmarshal(body, &answer); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, answer.ID)
	}
	status, posted := h.postOnce(alice, bob, note)
	if status != http.StatusOK {
		t.Fatalf("the note by the ordinary route: %d", status)
	}
	if ids[0] != ids[1] || posted != ids[0] {
		t.Fatalf("answered %v and then %d; want one id", ids, posted)
	}
	if rows, _ := h.held(fp); rows != 1 {
		t.Fatalf("bob holds %d rows; want the one note", rows)
	}
}

// When the threat is the host: a column changed through the store's own
// handle refuses the sender's true key; a column set to the stored form of
// a key the editor chose lets the editor withdraw the message, which the
// security model already grants whoever writes the database. And two rows
// with one column, which a repeat stored without its hash leaves (D134),
// are withdrawn each by its own id, the other staying.
func TestTheColumnIsWhatTheRelayHolds(t *testing.T) {
	h := newHarness(t, Config{})
	alice, bob := neighbourID(t, "alice"), neighbourID(t, "bob")
	h.enroll(alice, bob)
	fp := bob.Fingerprint()
	id, key := h.postToWithdraw(alice, bob, "")
	chosen := strings.Repeat("b", 64)
	if _, err := h.store.db.Exec(`UPDATE messages SET withdraw = ? WHERE id = ?`, withdraw.Stored(strings.Repeat("c", 64)), id); err != nil {
		t.Fatal(err)
	}
	status, body := h.withdrawAs(alice, fp, id, key, sealedTo(t, alice, bob.Public(), "withdrawn", ""))
	wantRefusal(t, "the true key on an edited row", status, body, http.StatusNotFound, relayapi.CodeNotWithdrawable, relayapi.MsgNotWithdrawable)
	if _, err := h.store.db.Exec(`UPDATE messages SET withdraw = ? WHERE id = ?`, withdraw.Stored(chosen), id); err != nil {
		t.Fatal(err)
	}
	if status, body := h.withdrawAs(alice, fp, id, chosen, sealedTo(t, alice, bob.Public(), "withdrawn", "")); status != http.StatusOK {
		t.Fatalf("the editor's key: %d %s", status, body)
	}

	raw := sealed(t, alice, bob.Public(), "stored twice")
	stored := withdraw.Stored(keyOf(t, raw))
	first, err := h.store.Put(fp, channels.Default, relayapi.KindEnvelope, "", stored, raw, Quotas{}, Forwarded{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.store.Put(fp, channels.Default, relayapi.KindEnvelope, "", stored, raw, Quotas{}, Forwarded{})
	if err != nil {
		t.Fatal(err)
	}
	if status, body := h.withdrawAs(alice, fp, first, keyOf(t, raw), sealedTo(t, alice, bob.Public(), "withdrawn", "")); status != http.StatusOK {
		t.Fatalf("the first of two: %d %s", status, body)
	}
	if got := h.withdrawColumn(fp, second); got != stored {
		t.Fatalf("the second of two keeps %q after the first was withdrawn", got)
	}
	if status, body := h.withdrawAs(alice, fp, second, keyOf(t, raw), sealedTo(t, alice, bob.Public(), "withdrawn", "")); status != http.StatusOK {
		t.Fatalf("the second of two: %d %s", status, body)
	}
}

// MaxWithdrawBytes is the measured worst case: a note built by the
// withdrawal section's own NoteBody and Section and sealed, a 64-byte channel name inside the seal and on the
// outer field, and a reason at the subject's cap of 4,096 bytes, each a
// "<", in the text and in the withdrawal section, is exactly that many
// bytes. The reason is held to the subject's rule, at its cap and one
// past it; and the figure is under what a relay of this release stores
// inline and lists in a page.
func TestMaxWithdrawBytesIsTheLargestNote(t *testing.T) {
	reason := strings.Repeat("<", 4096)
	if err := message.ValidSubject(reason); err != nil {
		t.Fatalf("a reason at the subject's cap: %v", err)
	}
	if err := message.ValidSubject(reason + "<"); err == nil {
		t.Fatal("a reason one byte past the subject's cap is taken")
	}
	if got := len(largestNote(t, reason)); got != relayapi.MaxWithdrawBytes {
		t.Fatalf("the largest note is %d bytes; MaxWithdrawBytes says %d", got, relayapi.MaxWithdrawBytes)
	}
	if relayapi.MaxWithdrawBytes > relayapi.DefaultMaxBytes || relayapi.MaxWithdrawBytes > relayapi.MaxPageBytes {
		t.Fatal("a note at MaxWithdrawBytes is over what a relay stores inline")
	}
}

// WithdrawFloorBytes is the measured largest note with no reason: the
// same note at every other maximum, a 64-byte channel name inside the seal
// and on the outer field, and the reason empty. It is what a note may come
// to on a closed channel whatever the message it takes the place of
// (D198), so a withdrawal with no reason always fits there.
func TestWithdrawFloorBytesIsTheLargestNoteWithNoReason(t *testing.T) {
	if got := len(largestNote(t, "")); got != relayapi.WithdrawFloorBytes {
		t.Fatalf("the largest note with no reason is %d bytes; WithdrawFloorBytes says %d", got, relayapi.WithdrawFloorBytes)
	}
	if relayapi.WithdrawFloorBytes >= relayapi.MaxWithdrawBytes {
		t.Fatal("the floor is not under the largest note")
	}
}

// largestNote is a withdrawal note at every maximum but its reason, built
// by the section's own NoteBody and Section and sealed, a 64-byte channel
// name inside the seal and on the outer field, as the bytes a post carries.
func largestNote(t *testing.T, reason string) []byte {
	t.Helper()
	from, to := neighbourID(t, "alice"), neighbourID(t, "bob")
	id := strings.Repeat("a", 32)
	sec, err := withdraw.Section(id, reason)
	if err != nil {
		t.Fatal(err)
	}
	ch := strings.Repeat("c", relayapi.MaxChannelNameBytes)
	env, _, err := envelope.SealSections(from, to.Public(), ch, withdraw.NoteBody(id, id, reason), []wire.Section{sec})
	if err != nil {
		t.Fatal(err)
	}
	env.Ch = ch
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
