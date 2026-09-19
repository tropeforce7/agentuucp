//go:build e2e

package e2e

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Stored messages vandalised: on the relay, where one file holds one
// queued message, and on the client, where one file holds one delivered
// message. Alice writes, bob reads.
var messageRows = []matrixRow{
	{"M01", "relay_file_byte_flipped", "one byte of a queued message file on the relay flipped, length unchanged", m01},
	{"M02", "relay_file_truncated", "a queued message file on the relay truncated to half, then the relay restarted", m02},
	{"M03", "relay_file_deleted", "a queued message file deleted from the relay's disk, its row kept", m03},
	{"M04", "relay_files_swapped", "two queued message files of equal size swapped on the relay's disk", m04},
	{"M05", "relay_row_deleted", "a queued message's database row deleted, its file kept", m05},
	{"M06", "stream_payload_truncated", "a queued stream's file on the relay truncated inside the payload", m06},
	{"M07", "stream_manifest_flipped", "one byte of a queued stream's manifest chunk flipped on the relay", m07},
	{"M07b", "stream_payload_flipped", "one byte of a queued stream's payload flipped on the relay", m07b},
	{"M08", "inbox_text_edited", "the text of a delivered message edited in bob's inbox file", m08},
	{"M09", "inbox_file_truncated", "a delivered message's file in bob's inbox truncated", m09},
	{"M10", "attachment_digest_edited", "an attachment's recorded sha256 edited in bob's inbox file", m10},
	{"M11", "quarantine_bundle_edited", "the sender's key bundle altered in a quarantined message file", m11},
	{"M12", "sent_copy_deleted", "alice's sent copy of a message deleted before the reply arrives", m12},
}

// settle undoes a fault on a queued message's file when the row is still
// there, and otherwise removes the file, so a message the client
// acknowledged or the sweep dropped leaves no orphan behind.
func settle(t *testing.T, id int64, file string, undo func()) {
	t.Helper()
	for _, q := range queued(t, state.bobFP) {
		if q == id {
			undo()
			return
		}
	}
	relay.root("rm -f " + shq(file))
}

const (
	bobDamaged   = "/home/bob/.auu/damaged"
	keptSentence = "warning: relay message %d could not be opened (%s) and was kept as %s; ask the sender to send it again"
	keptSummary  = "%d damaged message(s) kept under " + bobDamaged + "; ask their senders to send them again"
)

// keptFile is where bob's auu keeps one relay message it could not open.
func keptFile(id int64) string {
	return fmt.Sprintf("%s/relay.example.com/%d.bin", bobDamaged, id)
}

// keptRecord asserts the record beside a kept message says what it should.
func keptRecord(t *testing.T, id int64, cause string) {
	t.Helper()
	rec := bob.read(t, strings.TrimSuffix(keptFile(id), ".bin")+".json")
	for _, want := range []string{
		fmt.Sprintf(`"relay_id": %d`, id), `"relay": "relay.example.com"`, `"received": "`, fmt.Sprintf(`"cause": "%s"`, cause),
	} {
		if !strings.Contains(rec, want) {
			t.Errorf("the record lacks %s:\n%s", want, rec)
		}
	}
}

func m01(t *testing.T) {
	id, file := queueOne(t, "--subject", "flipped", "a message of some length, so there is a byte to flip")
	size := strings.Fields(relay.stat(t, file))[1]
	var n int64
	fmt.Sscan(size, &n)
	undo := relay.flipByte(t, file, n/2)
	defer settle(t, id, file, undo)
	defer bob.root("rm -rf " + bobDamaged)
	served := relay.read(t, file)
	m := logMark()
	r := bob.auu("inbox")
	expectCode(t, r, 0)
	// The byte is in the base64 of the ciphertext: flipped to another
	// base64 character it decodes to other bytes and the AEAD refuses
	// them, flipped to anything else it does not decode and the envelope
	// is not one. The cause is one of the two, and the row records which.
	said := regexp.MustCompile("^" + regexp.QuoteMeta(fmt.Sprintf(keptSentence, id, "CAUSE", keptFile(id))) + "$")
	said = regexp.MustCompile(strings.Replace(said.String(), "CAUSE", "(did not decrypt|malformed)", 1))
	match := said.FindStringSubmatch(strings.TrimSpace(r.stderr))
	if match == nil {
		t.Errorf("stderr is\n  %q\nwant\n  %s", strings.TrimSpace(r.stderr), said)
	} else {
		keptRecord(t, id, match[1])
	}
	expectSays(t, r, 0, fmt.Sprintf(keptSummary, 1))
	expectNot(t, r, "flipped")
	// The bytes as the relay held them, byte for byte.
	if kept := bob.read(t, keptFile(id)); kept != served {
		t.Errorf("kept %d bytes, served %d, and they differ", len(kept), len(served))
	}
	if left := queued(t, state.bobFP); len(left) != 0 {
		t.Errorf("the relay still queues %v; the client was expected to acknowledge it away", left)
	}
	if log := strings.TrimSpace(relayLogSince(m)); strings.Contains(log, "level=WARN") || strings.Contains(log, "level=ERROR") {
		t.Errorf("the relay logged something:\n%s", log)
	}
	if !relay.exists(file) {
		// Acknowledged: the file went with the row.
		record(relay, "test -e "+file, "", result{stdout: "gone\n"})
	}
	// Said again, until bob removes it.
	expectSays(t, bob.auu("inbox"), 0, fmt.Sprintf(keptSummary, 1))
	verdict(t, "ok", "The message is kept under damaged/ as the bytes the relay served, with a record naming the relay, "+
		"the row and the cause in a word; the warning names the file and whom to ask, the inbox says how many are there "+
		"every time, and the relay, which never knew, logs nothing. Alice is still never told.")
}

func m02(t *testing.T) {
	id, file := queueOne(t, "--subject", "truncated", "a message of some length, so there is something to cut")
	size := strings.Fields(relay.stat(t, file))[1]
	var n int64
	fmt.Sscan(size, &n)
	undo := relay.truncate(t, file, n/2)
	defer settle(t, id, file, undo)
	m := relayRestart(t)
	log := relayLogSince(m)
	// The sweep stats every file: a size that disagrees with the row is
	// a message that is gone.
	if !strings.Contains(log, "rows_without_files=1") {
		t.Errorf("the sweep did not drop the truncated message:\n%s", log)
	}
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 0 || in.Fetch.Unreadable != 0 {
		t.Errorf("bob fetched %+v after the sweep", in.Fetch)
	}
	verdict(t, "gap", "The relay notices at its next start, by size alone, and drops the message with a count in its own log; "+
		"it tells nobody, which is decision 12 of PLAN-CONTAINERS.")
}

func m03(t *testing.T) {
	id, file := queueOne(t, "--subject", "deleted", "a message that will be deleted from the relay's disk")
	undo := relay.remove(t, file)
	defer settle(t, id, file, undo)
	r := bob.auu("inbox")
	expectCode(t, r, 0)
	expectNot(t, r, "deleted", "warning")
	if left := queued(t, state.bobFP); len(left) != 1 || left[0] != id {
		t.Errorf("queued %v, want the row %d still there", left, id)
	}
	m := relayRestart(t)
	log := waitRelayLog(t, m, "rows_without_files=1", 5*time.Second)
	if !strings.Contains(log, "the message directory did not match the database and has been reconciled") {
		t.Errorf("log:\n%s", log)
	}
	verdict(t, "gap", "The relay serves the mailbox without the row whose file is gone, and counts it off the page so bob is "+
		"not told his cursor is past mail; the row stays until the relay restarts and reconciles it away, in its own log only, "+
		"which is decision 12 of PLAN-CONTAINERS.")
}

func m04(t *testing.T) {
	// Four messages of the same length, and two of equal size among them
	// are swapped. Nothing but the bytes moves.
	var files []string
	for i := 0; i < 4; i++ {
		_, f := queueOne(t, "--subject", "swap", fmt.Sprintf("message number %d of the swap test", i))
		files = append(files, f)
	}
	sizes := map[string][]string{}
	for _, f := range files {
		sz := strings.Fields(relay.stat(t, f))[1]
		sizes[sz] = append(sizes[sz], f)
	}
	var pair []string
	for _, fs := range sizes {
		if len(fs) >= 2 {
			pair = fs[:2]
			break
		}
	}
	if pair == nil {
		drain(bob)
		t.Skip("no two of four equal-length messages had equal envelope sizes")
	}
	undo := relay.swap(t, pair[0], pair[1])
	defer func() {
		if len(queued(t, state.bobFP)) == 0 {
			relay.root("rm -f " + shq(pair[0]) + " " + shq(pair[1]))
			return
		}
		undo()
	}()
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 4 || in.Fetch.Unreadable != 0 {
		t.Errorf("bob fetched %+v, want all four", in.Fetch)
	}
	verdict(t, "observed", "Harmless by construction: each file is a whole sealed envelope, so the two arrive, in the other order.")
}

func m05(t *testing.T) {
	id, file := queueOne(t, "--subject", "rowless", "a message whose row will be deleted")
	defer dbBackup(t)()
	if !nofault {
		relay.sql(t, fmt.Sprintf("DELETE FROM messages WHERE id=%d", id))
	}
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 0 {
		t.Errorf("bob fetched %+v", in.Fetch)
	}
	if !relay.exists(file) {
		t.Errorf("the file went with the row before any sweep")
	}
	m := relayRestart(t)
	log := waitRelayLog(t, m, "files_without_rows=1", 5*time.Second)
	if relay.exists(file) {
		t.Errorf("the sweep left the orphan:\n%s", log)
	}
	verdict(t, "ok", "Not listed, and removed at the next start with a count in the relay's log. The counters are recomputed.")
}

// queueStream sends a large attachment as a stream and returns its relay
// id and file.
func queueStream(t *testing.T) (int64, string) {
	t.Helper()
	alice.exec("", "sh", "-c", "head -c 200000 /dev/urandom > /home/alice/stream.bin")
	before := queued(t, state.bobFP)
	s := sendJSON(t, alice, "bob", "--subject", "a stream", "--attach", "/home/alice/stream.bin", "streamed")
	if s.Kind != "stream" {
		t.Fatalf("not a stream: %+v", s)
	}
	after := queued(t, state.bobFP)
	id := after[len(after)-1]
	if len(after) != len(before)+1 {
		t.Fatalf("queued %v then %v", before, after)
	}
	return id, relayFile(state.bobFP, id)
}

func m06(t *testing.T) {
	id, file := queueStream(t)
	size := strings.Fields(relay.stat(t, file))[1]
	var n int64
	fmt.Sscan(size, &n)
	undo := relay.truncate(t, file, n-4096)
	defer func() { settle(t, id, file, undo); drain(bob) }()
	m := logMark()
	r := bob.auu("inbox")
	stderrIs(t, r, fmt.Sprintf("warning: relay message %d was damaged on the relay and has been dropped there; "+
		"ask the sender to send it again", id))
	expectCode(t, r, 0)
	// The shipped settings are access_log minimal, so the line names the
	// message and not the mailbox, whose owner is the caller here.
	log := relayLogSince(m)
	if !strings.Contains(log, fmt.Sprintf("level=WARN msg=\"message %d is %d bytes on disk "+
		"but %d in the database; it is damaged and has been dropped\"", id, n-4096, n)) {
		t.Errorf("log:\n%s", log)
	}
	if strings.Contains(log, state.bobFP[:16]) {
		t.Errorf("the minimal log names the mailbox:\n%s", log)
	}
	if holds(queued(t, state.bobFP), id) {
		t.Errorf("queued %v, want %d gone: the relay dropped it", queued(t, state.bobFP), id)
	}
	// The next inbox is clean: the cursor moved past it.
	r = bob.auu("inbox")
	expectCode(t, r, 0)
	stderrIs(t, r, "")
	verdict(t, "ok", "The relay finds the file shorter than its row when asked to serve it, drops the row and the file, "+
		"logs the id and both sizes and, under the shipped minimal access log, not the mailbox, and answers 410; the "+
		"client names the message, says whom to ask, moves on, and the next inbox is clean.")
}

// keptManifestOnly asserts what bob kept of a stream is its manifest
// chunk and nothing of the two hundred kilobytes of payload.
func keptManifestOnly(t *testing.T, id int64) {
	t.Helper()
	size := strings.Fields(bob.stat(t, keptFile(id)))[1]
	var n int64
	fmt.Sscan(size, &n)
	// The encapsulation and the prefix, then a manifest of a few hundred
	// bytes sealed; well short of a single 63 KiB payload chunk.
	if n <= 1124 || n > 64<<10 {
		t.Errorf("kept %d bytes of the stream, want the manifest chunk alone", n)
	}
}

func m07(t *testing.T) {
	id, file := queueStream(t)
	// Inside the encapsulation, which the manifest is sealed under.
	undo := relay.flipByte(t, file, 64)
	defer settle(t, id, file, undo)
	defer bob.root("rm -rf " + bobDamaged)
	r := bob.auu("inbox")
	expectCode(t, r, 0)
	stderrIs(t, r, fmt.Sprintf(keptSentence, id, "did not decrypt", keptFile(id)))
	expectSays(t, r, 0, fmt.Sprintf(keptSummary, 1))
	keptRecord(t, id, "did not decrypt")
	keptManifestOnly(t, id)
	if left := queued(t, state.bobFP); len(left) != 0 {
		t.Errorf("queued %v, want nothing: acknowledged once kept", left)
	}
	verdict(t, "ok", "The manifest chunk is kept, the cause is named, and the payload is neither fetched nor kept.")
}

func m07b(t *testing.T) {
	id, file := queueStream(t)
	size := strings.Fields(relay.stat(t, file))[1]
	var n int64
	fmt.Sscan(size, &n)
	undo := relay.flipByte(t, file, n-2000)
	defer settle(t, id, file, undo)
	defer bob.root("rm -rf " + bobDamaged)
	r := bob.auu("inbox")
	expectCode(t, r, 0)
	stderrIs(t, r, fmt.Sprintf(keptSentence, id, "did not decrypt", keptFile(id)))
	expectSays(t, r, 0, fmt.Sprintf(keptSummary, 1))
	keptRecord(t, id, "did not decrypt")
	keptManifestOnly(t, id)
	if left := queued(t, state.bobFP); len(left) != 0 {
		t.Errorf("queued %v, want nothing: acknowledged once kept", left)
	}
	verdict(t, "ok", "A flipped payload byte fails the chunk it is in; the manifest chunk is kept, and the payload, "+
		"which is what did not survive, is not.")
}

// deliverOne sends alice's message to bob and returns bob's file for it.
func deliverOne(t *testing.T, args ...string) (sent, string) {
	t.Helper()
	s := sendJSON(t, alice, "bob", args...)
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 {
		t.Fatalf("bob fetched %+v", in.Fetch)
	}
	return s, "/home/bob/.auu/inbox/" + s.ID + ".json"
}

func m08(t *testing.T) {
	s, file := deliverOne(t, "--subject", "edited", "the text as alice wrote it")
	defer bob.edit(t, file, "the text as alice wrote it", "the text as somebody else wrote it")()
	r := bob.auu("read", s.ID)
	expectSays(t, r, 0, "the text as somebody else wrote it")
	expectNot(t, r, "warning")
	verdict(t, "gap", "Nothing on the client re-verifies a stored message: the signature is checked once, at fetch, and not kept.")
}

func m09(t *testing.T) {
	s, file := deliverOne(t, "--subject", "cut short", "a message whose file will be truncated")
	defer bob.truncate(t, file, 100)()
	r := bob.auu("inbox", "--no-fetch")
	expectCode(t, r, 0)
	expectNot(t, r, "cut short")
	stderrIs(t, r, "warning: "+file+" could not be read (unexpected end of JSON input) and is not listed")
	r = bob.auu("read", s.ID)
	expectCode(t, r, 1)
	verdict(t, "ok", "The listing says which file could not be read, why, and that it is left out, once; "+
		"read on it still prints Go's JSON error with the usage exit code, which B9 did not touch.")
}

func m10(t *testing.T) {
	alice.exec("", "sh", "-c", "printf 'attached bytes\\n' > /home/alice/att.txt")
	s, file := deliverOne(t, "--subject", "digest", "--attach", "/home/alice/att.txt", "with a file")
	defer editJSON(t, bob, file, func(v map[string]any) {
		att := v["inner"].(map[string]any)["body"].(map[string]any)["attachments"].([]any)[0].(map[string]any)
		att["sha256"] = strings.Repeat("0", 64)
	})()
	r := bob.auu("extract", s.ID, "--out", "/home/bob/m10")
	// The name is quoted in the sentence since c5911c3, where a received
	// name became something the receiver writes a safe form of.
	expectSays(t, r, 1, `auu: refusing to write "att.txt": attachment "att.txt": sha256 does not match data`)
	verdict(t, "ok", "The digest is checked on the way out, and the file is not written.")
}

func m11(t *testing.T) {
	// A quarantined message is one from a sender bob has not added. Bob's
	// mailbox admits only peers, so it is opened for the moment.
	carol := enrolCarol(t)
	expectSays(t, carol.auu("peers", "add", state.bobLine), 0, "added")
	expectSays(t, bob.auu("allow", "clear"), 0, "allow list cleared")
	defer bob.auu("allow", "push")
	expectSays(t, carol.auu("send", "--to", "bob", "--subject", "who is this", "from carol"), 0, "sent to bob")
	r := bob.auu("inbox")
	expectSays(t, r, 0, "1 quarantined from unknown senders")
	ls := bob.auu("quarantine", "ls")
	expectCode(t, ls, 0)
	id := strings.Fields(ls.stdout)[0]
	files := strings.Fields(bob.mustRoot(t, "ls /home/bob/.auu/quarantine/"+id+"*.json"))
	if len(files) != 1 {
		t.Fatalf("quarantine files %v", files)
	}
	content := bob.read(t, files[0])
	i := strings.Index(content, `"from_bundle": "`)
	if i < 0 {
		t.Fatalf("no from_bundle in %s", files[0])
	}
	head := content[i+len(`"from_bundle": "`):][:20]
	flipped := head[:19] + map[bool]string{true: "B", false: "A"}[head[19] == "A"[0]]
	defer bob.edit(t, files[0], head, flipped)()
	r = bob.auuIn("carol\n", "quarantine", "trust", id)
	expectCode(t, r, 1)
	if !strings.Contains(r.stderr, "quarantined message carries a malformed sender key") &&
		!strings.Contains(r.stderr, "quarantined message has an inconsistent sender key") {
		t.Errorf("stderr: %q", r.stderr)
	}
	verdict(t, "ok", "Trusting re-derives the sender from the stored bundle, so an altered bundle is refused by name.")
}

func m12(t *testing.T) {
	s := sendJSON(t, alice, "bob", "--subject", "no sent copy", "reply to this")
	defer alice.remove(t, "/home/alice/.auu/sent/"+s.ID+".json")()
	in := fetchJSON(t, bob)
	if in.Fetch.Delivered != 1 {
		t.Fatalf("bob fetched %+v", in.Fetch)
	}
	expectSays(t, bob.auu("reply", s.ID, "here is the reply"), 0, "sent to alice")
	var w struct {
		Found bool `json:"found"`
	}
	jsonOf(t, alice.auu("wait", "--thread", s.Thread, "--timeout", "30s", "--interval", "5s", "--json"), &w)
	if !w.Found {
		t.Error("the reply was not matched to the thread without the sent copy")
	}
	verdict(t, "ok", "The thread is in the reply itself; the sent copy is a convenience.")
}
