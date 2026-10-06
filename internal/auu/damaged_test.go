package auu

import (
	"bytes"
	"context"
	"crypto/hpke"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tropeforce7/agentuucp/internal/envelope"
	"github.com/tropeforce7/agentuucp/internal/identity"
	"github.com/tropeforce7/agentuucp/internal/message"
	"github.com/tropeforce7/agentuucp/internal/relay"
	"github.com/tropeforce7/agentuucp/internal/store"
	"github.com/tropeforce7/agentuucp/internal/stream"
)

// storedFile is where the relay keeps one queued message's bytes.
func storedFile(messages, fp string, id int64) string {
	return filepath.Join(messages, fp[:2], fp, strconv.FormatInt(id, 10))
}

// editFile replaces old with new in a file, length unchanged, the way a
// byte flipped on a disk leaves the relay none the wiser.
func editFile(t *testing.T, path, old, new string) {
	t.Helper()
	if len(old) != len(new) {
		t.Fatalf("editFile: %q and %q differ in length", old, new)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(old)) {
		t.Fatalf("editFile: %s does not contain %q", path, old)
	}
	if err := os.WriteFile(path, bytes.Replace(data, []byte(old), []byte(new), 1), 0o600); err != nil {
		t.Fatal(err)
	}
}

// damagedRecord reads the record kept beside one relay's message.
func damagedRecord(t *testing.T, s *store.Store, relay string, id int64) store.DamagedRecord {
	t.Helper()
	path := strings.TrimSuffix(damagedPathOf(t, s, relay, id), ".bin") + ".json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the record: %v", err)
	}
	var rec store.DamagedRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("the record %s: %v", path, err)
	}
	return rec
}

// A message this key cannot open is kept under damaged/<relay>/ as the
// bytes the relay served and a record with the cause in a word, said with
// the file's path and acknowledged; the inbox counts what was kept and says
// how many are there and where, every time, until a person removes them.
// One case per cause. The container suite's M01 found the message gone with
// one line naming a relay row number and hiding the cause.
func TestADamagedMessageIsKeptWithItsCause(t *testing.T) {
	srv, st, messages := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	bobFP := bob.exportFingerprint()
	relayName := bob.defaultRelayName()
	carol, _ := identity.Generate("carol")
	mallory, _ := identity.Generate("mallory")

	send := func(subject string) int64 {
		t.Helper()
		before, _ := st.List(bobFP, 0, 100)
		alice.run("send", "--to", "bob", "--subject", subject, "some words of some length, so there is a byte to flip")
		after, _ := st.List(bobFP, 0, 100)
		if len(after) != len(before)+1 {
			t.Fatalf("queued %d before and %d after", len(before), len(after))
		}
		return after[len(after)-1].ID
	}

	// did not decrypt: a byte of the ciphertext, flipped on the relay's
	// disk to another base64 character, so the envelope still parses.
	flipped := send("flipped")
	file := storedFile(messages, bobFP, flipped)
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(data, []byte(`"ct":"`)) + 6 + 100
	if data[at] == 'A' {
		data[at] = 'B'
	} else {
		data[at] = 'A'
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// not addressed to this key: the envelope names carol, though the
	// relay queues it for bob.
	misaddressed := send("misaddressed")
	editFile(t, storedFile(messages, bobFP, misaddressed), `"to":"`+bobFP+`"`, `"to":"`+carol.Fingerprint()+`"`)

	// sender signature failed: an envelope built by hand, claiming alice
	// and signed by mallory, posted from alice's own client so that the
	// relay's allow list lets it through. The wire constants are written
	// here as literals, from outside the package that defines them.
	inner, err := json.Marshal(&envelope.Inner{V: envelope.Version,
		From: alice.exportFingerprint(), FromBundle: mustBundle(t, alice), To: bobFP,
		ID:   "0123456789abcdef0123456789abcdef",
		Body: message.Body{Type: message.TypeNote, Thread: "0123456789abcdef0123456789abcdef", Subject: "forged", Text: "not alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := mallory.Sign(append([]byte("ccx-sig-v1"+bobFP), inner...))
	if err != nil {
		t.Fatal(err)
	}
	bobPub := mustParseBundle(t, mustBundle(t, bob))
	ct, err := hpke.Seal(bobPub.KEM, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("ccx-envelope-v1"+bobFP), append(sig, inner...))
	if err != nil {
		t.Fatal(err)
	}
	forged := postAs(t, alice, &envelope.Envelope{V: envelope.Version, To: bobFP, CT: ct})

	// malformed: a version this build does not know, edited into the
	// stored file.
	fromTheFuture := send("from the future")
	editFile(t, storedFile(messages, bobFP, fromTheFuture), `"v":1`, `"v":2`)

	good := send("the good one")
	queued, err := st.List(bobFP, 0, 100)
	if err != nil || len(queued) != 5 {
		t.Fatalf("queued %d (%v), want 5", len(queued), err)
	}
	// What the relay serves for each, to compare with what is kept.
	served := map[int64][]byte{}
	for _, q := range queued {
		served[q.ID] = q.Envelope
	}

	var inbox inboxJSON
	var out string
	warnings := captureStderr(t, func() { out = bob.run("inbox", "--json") })
	if err := json.Unmarshal([]byte(out), &inbox); err != nil {
		t.Fatalf("inbox --json: %v\n%s", err, out)
	}
	if inbox.Fetch.Delivered != 1 || inbox.Fetch.Unreadable != 4 || inbox.Fetch.Kept != 4 || inbox.Fetch.Quarantined != 0 {
		t.Fatalf("fetch: %+v, want one delivered, four unreadable, four kept", inbox.Fetch)
	}
	if len(inbox.Messages) != 1 || inbox.Messages[0].Subject != "the good one" {
		t.Fatalf("inbox: %+v", inbox.Messages)
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for _, tc := range []struct {
		id    int64
		cause string
	}{
		{flipped, "did not decrypt"},
		{misaddressed, "not addressed to this key"},
		{forged, "sender signature failed"},
		{fromTheFuture, "malformed"},
	} {
		fmt.Fprintf(&want, "warning: relay message %d could not be opened (%s) and was kept as %s; ask the sender to send it again\n",
			tc.id, tc.cause, damagedPathOf(t, s, relayName, tc.id))
		// The bytes as the relay served them, and the record beside them.
		kept, err := os.ReadFile(damagedPathOf(t, s, relayName, tc.id))
		if err != nil || !bytes.Equal(kept, served[tc.id]) {
			t.Errorf("message %d: kept bytes %v, equal to what the relay served: %v", tc.id, err, bytes.Equal(kept, served[tc.id]))
		}
		rec := damagedRecord(t, s, relayName, tc.id)
		var received = queued[0].Received
		for _, q := range queued {
			if q.ID == tc.id {
				received = q.Received
			}
		}
		if rec.RelayID != tc.id || rec.Relay != relayName || !rec.Received.Equal(received) || rec.Cause != tc.cause {
			t.Errorf("message %d: record %+v, want id %d on %s received %s cause %q", tc.id, rec, tc.id, relayName, received, tc.cause)
		}
	}
	if warnings != want.String() {
		t.Fatalf("stderr:\n%s\nwant:\n%s", warnings, want.String())
	}
	if _, err := os.Stat(damagedPathOf(t, s, relayName, good)); !os.IsNotExist(err) {
		t.Fatal("the good message was kept as damaged")
	}
	// Every damaged one acknowledged, whatever the channel's setting says:
	// nobody will read them, and leaving them queued would block the
	// mailbox. The good one is kept, since default keeps.
	left, err := st.List(bobFP, 0, 100)
	if err != nil || len(left) != 1 || left[0].ID != good {
		t.Fatalf("the relay holds %v (%v), want the good message alone", left, err)
	}

	// Said every time, in the human output, until a person removes them.
	warnings = captureStderr(t, func() { out = bob.run("inbox") })
	summary := fmt.Sprintf("4 damaged message(s) kept under %s; ask their senders to send them again\n", s.DamagedDir())
	if !strings.HasSuffix(out, summary) || warnings != "" {
		t.Fatalf("the next inbox:\n%s\nstderr %q\nwant it to end with %q and stderr empty", out, warnings, summary)
	}
	if err := os.RemoveAll(s.DamagedDir()); err != nil {
		t.Fatal(err)
	}
	if out = bob.run("inbox"); strings.Contains(out, "damaged") {
		t.Fatalf("inbox with damaged/ removed still says:\n%s", out)
	}
}

// mustBundle is a user's public bundle, from their home.
func mustBundle(t *testing.T, u *user) []byte {
	t.Helper()
	s, err := store.Open(u.home)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Public().Bundle()
}

func mustParseBundle(t *testing.T, bundle []byte) *identity.Public {
	t.Helper()
	pub, err := identity.ParseBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// postAs posts an envelope as it stands from a user's own client, and
// returns its relay id.
func postAs(t *testing.T, u *user, env *envelope.Envelope) int64 {
	t.Helper()
	s, err := store.Open(u.home)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.DefaultRelay()
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(s, id, r)
	if err != nil {
		t.Fatal(err)
	}
	relayID, err := c.Post(context.Background(), env, "")
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return relayID
}

// A stream that will not open keeps its manifest chunk only, never the
// payload, whether the manifest or the payload is what did not survive; and
// a stream the relay dropped as damaged is counted as unreadable but not as
// kept, since nothing of it is here. The container suite's M07 and M07b
// found the stream gone with one line each.
func TestADamagedStreamKeepsItsManifestOnly(t *testing.T) {
	srv, st, messages := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	bobFP := bob.exportFingerprint()
	relayName := bob.defaultRelayName()

	payload := make([]byte, 300<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	file := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"manifest flipped", "payload flipped", "truncated on the relay"} {
		alice.run("send", "--to", "bob", "--subject", subject, "--attach", file, "streamed")
	}
	queued, err := st.List(bobFP, 0, 10)
	if err != nil || len(queued) != 3 {
		t.Fatalf("queued %d (%v), want 3", len(queued), err)
	}
	manifestFlipped, payloadFlipped, truncated := queued[0].ID, queued[1].ID, queued[2].ID

	// The manifest chunk is what the header's prefix says it is.
	manifestOf := func(id int64) []byte {
		t.Helper()
		data, err := os.ReadFile(storedFile(messages, bobFP, id))
		if err != nil {
			t.Fatal(err)
		}
		n := int(binary.BigEndian.Uint32(data[stream.EncSize:stream.HeaderSize]))
		return append([]byte{}, data[:stream.HeaderSize+n]...)
	}
	flipAt := func(id int64, offset int) {
		t.Helper()
		path := storedFile(messages, bobFP, id)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[offset] ^= 1
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wantManifest := map[int64][]byte{manifestFlipped: manifestOf(manifestFlipped), payloadFlipped: manifestOf(payloadFlipped)}
	flipAt(manifestFlipped, stream.HeaderSize+10)
	// The flipped manifest chunk is what is kept: the bytes as served.
	wantManifest[manifestFlipped] = manifestOf(manifestFlipped)
	flipAt(payloadFlipped, len(wantManifest[payloadFlipped])+10)
	if err := os.Truncate(storedFile(messages, bobFP, truncated), queued[2].Size-4096); err != nil {
		t.Fatal(err)
	}

	var inbox inboxJSON
	var out string
	warnings := captureStderr(t, func() { out = bob.run("inbox", "--json") })
	if err := json.Unmarshal([]byte(out), &inbox); err != nil {
		t.Fatalf("inbox --json: %v\n%s", err, out)
	}
	if inbox.Fetch.Delivered != 0 || inbox.Fetch.Unreadable != 3 || inbox.Fetch.Kept != 2 {
		t.Fatalf("fetch: %+v, want three unreadable and two kept", inbox.Fetch)
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("warning: relay message %d could not be opened (did not decrypt) and was kept as %s; ask the sender to send it again\n",
		manifestFlipped, damagedPathOf(t, s, relayName, manifestFlipped)) +
		fmt.Sprintf("warning: relay message %d could not be opened (did not decrypt) and was kept as %s; ask the sender to send it again\n",
			payloadFlipped, damagedPathOf(t, s, relayName, payloadFlipped)) +
		fmt.Sprintf("warning: relay message %d was damaged on the relay and has been dropped there; ask the sender to send it again\n", truncated)
	if warnings != want {
		t.Fatalf("stderr:\n%s\nwant:\n%s", warnings, want)
	}
	for id, manifest := range wantManifest {
		kept, err := os.ReadFile(damagedPathOf(t, s, relayName, id))
		if err != nil {
			t.Fatalf("message %d: %v", id, err)
		}
		if !bytes.Equal(kept, manifest) {
			t.Errorf("message %d: kept %d bytes, want the %d of the manifest chunk", id, len(kept), len(manifest))
		}
		if len(kept) > 64<<10 {
			t.Errorf("message %d: kept %d bytes, which is payload", id, len(kept))
		}
		if rec := damagedRecord(t, s, relayName, id); rec.Cause != "did not decrypt" || rec.RelayID != id || rec.Relay != relayName {
			t.Errorf("message %d: record %+v", id, rec)
		}
	}
	if _, err := os.Stat(damagedPathOf(t, s, relayName, truncated)); !os.IsNotExist(err) {
		t.Fatal("a stream the relay dropped was kept")
	}
	// Nothing of any payload anywhere in the home.
	filepath.Walk(bob.home, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && info.Size() > 64<<10 {
			t.Errorf("payload on disk: %s (%d bytes)", path, info.Size())
		}
		return nil
	})
	if left, err := st.List(bobFP, 0, 10); err != nil || len(left) != 0 {
		t.Fatalf("the relay still holds %d (%v)", len(left), err)
	}
	// The summary counts what is here: two, not the three that were
	// unreadable.
	out = bob.run("inbox")
	if !strings.Contains(out, fmt.Sprintf("2 damaged message(s) kept under %s;", s.DamagedDir())) {
		t.Fatalf("inbox:\n%s", out)
	}
}

// The budget, met through a fetch: a message that alone exceeds it is not
// kept and the warning says so with both sizes; one that fits evicts the
// oldest kept to make room; and what the summary counts is what is there.
func TestDamagedMessagesBeyondTheBudgetAreSaidToBe(t *testing.T) {
	restore := store.DamagedBudget
	store.DamagedBudget = 10000
	t.Cleanup(func() { store.DamagedBudget = restore })

	srv, st, messages := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	bobFP := bob.exportFingerprint()
	relayName := bob.defaultRelayName()

	// Three envelopes, each too damaged to open: two of about seven
	// kilobytes, which fit a ten-kilobyte budget one at a time, and one of
	// about twelve, which never fits.
	send := func(subject string, textLen int) int64 {
		t.Helper()
		before, _ := st.List(bobFP, 0, 100)
		alice.run("send", "--to", "bob", "--subject", subject, strings.Repeat("x", textLen))
		after, _ := st.List(bobFP, 0, 100)
		id := after[len(after)-1].ID
		if len(after) != len(before)+1 {
			t.Fatal("nothing queued")
		}
		editFile(t, storedFile(messages, bobFP, id), `"v":1`, `"v":2`)
		return id
	}
	first := send("first", 2000)
	second := send("second", 2000)
	huge := send("huge", 6000)
	queued, _ := st.List(bobFP, 0, 100)
	size := map[int64]int64{}
	for _, q := range queued {
		size[q.ID] = int64(len(q.Envelope))
	}
	if size[first]+size[second] <= 10000 || size[first] > 10000 || size[huge] <= 10000 {
		t.Fatalf("sizes %v do not make the case: two that fit one at a time and one that never does", size)
	}

	var inbox inboxJSON
	var out string
	warnings := captureStderr(t, func() { out = bob.run("inbox", "--json") })
	if err := json.Unmarshal([]byte(out), &inbox); err != nil {
		t.Fatalf("inbox --json: %v\n%s", err, out)
	}
	if inbox.Fetch.Unreadable != 3 || inbox.Fetch.Kept != 2 {
		t.Fatalf("fetch: %+v, want three unreadable and two kept", inbox.Fetch)
	}
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("warning: relay message %d could not be opened (malformed) and was kept as %s; ask the sender to send it again\n", first, damagedPathOf(t, s, relayName, first)) +
		fmt.Sprintf("warning: relay message %d could not be opened (malformed) and was kept as %s; ask the sender to send it again\n", second, damagedPathOf(t, s, relayName, second)) +
		fmt.Sprintf("warning: relay message %d could not be opened (malformed); it is %s and was not kept, since %s holds at most %s\n",
			huge, store.MiB(size[huge]), s.DamagedDir(), store.MiB(10000))
	if warnings != want {
		t.Fatalf("stderr:\n%s\nwant:\n%s", warnings, want)
	}
	// The second evicted the first; the huge one is nowhere.
	if _, err := os.Stat(damagedPathOf(t, s, relayName, first)); !os.IsNotExist(err) {
		t.Fatal("the first was not evicted to make room for the second")
	}
	if _, err := os.Stat(damagedPathOf(t, s, relayName, second)); err != nil {
		t.Fatal("the second was not kept")
	}
	if _, err := os.Stat(damagedPathOf(t, s, relayName, huge)); !os.IsNotExist(err) {
		t.Fatal("a message over the budget was kept")
	}
	if n, _, err := s.DamagedKept(); err != nil || n != 1 {
		t.Fatalf("kept: %d (%v), want 1", n, err)
	}
	// All three acknowledged, the one that could not be kept included.
	if left, err := st.List(bobFP, 0, 100); err != nil || len(left) != 0 {
		t.Fatalf("the relay still holds %d (%v)", len(left), err)
	}
	out = bob.run("inbox")
	if !strings.Contains(out, fmt.Sprintf("1 damaged message(s) kept under %s;", s.DamagedDir())) {
		t.Fatalf("inbox:\n%s", out)
	}
}

// A message is acknowledged once it is safely on local disk, and the bytes
// of one nobody could open are no exception: a keep that fails is the
// fetch's failure, the relay still holds the message, and the next fetch
// keeps it.
func TestAMessageThatCannotBeKeptIsNotAcknowledged(t *testing.T) {
	srv, st, messages := startRelayOnDisk(t, relay.Config{Limits: relay.DefaultLimits()})
	alice := newUser(t, "alice", srv.URL)
	bob := newUser(t, "bob", srv.URL)
	alice.run("peers", "add", bob.exportLine())
	bob.run("peers", "add", alice.exportLine())
	alice.run("allow", "push")
	bob.run("allow", "push")
	bobFP := bob.exportFingerprint()
	relayName := bob.defaultRelayName()

	alice.run("send", "--to", "bob", "--subject", "from the future", "hello")
	queued, err := st.List(bobFP, 0, 10)
	if err != nil || len(queued) != 1 {
		t.Fatalf("queued %d (%v)", len(queued), err)
	}
	id := queued[0].ID
	editFile(t, storedFile(messages, bobFP, id), `"v":1`, `"v":2`)

	// damaged/ is a file, so nothing can be kept under it.
	s, err := store.Open(bob.home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.DamagedDir(), []byte("in the way\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr string
	stderr = captureStderr(t, func() { _, err = bob.tryRun("inbox") })
	if err == nil || !strings.HasPrefix(err.Error(), fmt.Sprintf("keeping relay message %d under %s: ", id, s.DamagedDir())) {
		t.Fatalf("inbox with damaged/ in the way: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr %q, want nothing said about a message that was not kept", stderr)
	}
	if left, err := st.List(bobFP, 0, 10); err != nil || len(left) != 1 {
		t.Fatalf("the relay holds %d (%v) after the failed keep, want the message still there", len(left), err)
	}

	// Out of the way, the next fetch keeps and acknowledges it.
	if err := os.Remove(s.DamagedDir()); err != nil {
		t.Fatal(err)
	}
	var inbox inboxJSON
	var out string
	captureStderr(t, func() { out = bob.run("inbox", "--json") })
	if err := json.Unmarshal([]byte(out), &inbox); err != nil {
		t.Fatal(err)
	}
	if inbox.Fetch.Kept != 1 {
		t.Fatalf("fetch after the way was cleared: %+v", inbox.Fetch)
	}
	if _, err := os.Stat(damagedPathOf(t, s, relayName, id)); err != nil {
		t.Fatal(err)
	}
	if left, err := st.List(bobFP, 0, 10); err != nil || len(left) != 0 {
		t.Fatalf("the relay holds %d (%v) after the keep, want 0", len(left), err)
	}
}

// damagedPathOf is DamagedPath for a test that knows the relay name is
// valid.
func damagedPathOf(t *testing.T, s *store.Store, relay string, id int64) string {
	t.Helper()
	path, err := s.DamagedPath(relay, id)
	if err != nil {
		t.Fatal(err)
	}
	return path
}
